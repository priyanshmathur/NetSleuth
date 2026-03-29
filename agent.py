"""
agent.py — The AI brain of NetSleuth (Ollama edition — 100% free, runs locally).
Consumes anomalies from Kafka, runs a manual ReAct loop with llama3 via Ollama,
then publishes an incident report to Kafka.

ReAct loop works like this:
  1. Build a prompt that describes available tools + current anomaly
  2. Ask Ollama to reason and emit a TOOL_CALL or FINAL_REPORT
  3. Parse the response, run the tool if needed, feed result back
  4. Repeat until FINAL_REPORT is emitted (max N iterations)
"""

import json
import re
import random
import requests
from datetime import datetime, timezone
from confluent_kafka import Consumer, Producer
from rich.console import Console
from config import (
    KAFKA_BOOTSTRAP_SERVERS,
    TOPIC_ANOMALIES,
    TOPIC_AGENT_REPORTS,
)

console = Console()

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"   # swap to "mistral", "phi3", "gemma2" etc if preferred
MAX_REACT_STEPS = 5       # safety cap on tool-calling iterations


# ─── Simulated tool implementations ───────────────────────────────────────────
# In production replace these with real API calls (AbuseIPDB, your SIEM, etc.)

def lookup_ip_reputation(ip_address: str) -> dict:
    known_bad = {
        "10.0.0.99":     {"reputation": "malicious",  "tags": ["ddos-source", "botnet-c2"],  "abuse_score": 97},
        "172.16.0.45":   {"reputation": "suspicious", "tags": ["data-exfil", "known-actor"], "abuse_score": 62},
        "192.168.1.105": {"reputation": "suspicious", "tags": ["internal-scanner"],          "abuse_score": 45},
    }
    return known_bad.get(ip_address, {
        "reputation": "clean", "tags": [], "abuse_score": random.randint(0, 10),
    })


def get_historical_baseline(host: str, metric: str) -> dict:
    return {
        "host": host, "period": "last_24h",
        "latency_avg_ms": 42.3,    "latency_p99_ms": 95.0,
        "bandwidth_avg_mbps": 18.7, "bandwidth_max_mbps": 55.0,
        "connections_avg_per_sec": 34, "connections_max_per_sec": 120,
    }


def classify_attack_type(latency_ms: float, bandwidth_mbps: float,
                          connections_per_sec: int, packet_loss_pct: float = 0,
                          unique_ports: int = 1) -> dict:
    if connections_per_sec > 1000 and packet_loss_pct > 20:
        return {"attack_type": "DDoS Flood",         "confidence": 0.92, "mitigation": "Rate-limit + upstream null-route"}
    elif unique_ports > 50 and connections_per_sec > 100:
        return {"attack_type": "Port Scan",           "confidence": 0.88, "mitigation": "Block source IP, alert SOC"}
    elif bandwidth_mbps > 40 and connections_per_sec < 20:
        return {"attack_type": "Data Exfiltration",   "confidence": 0.79, "mitigation": "Block egress, forensic capture"}
    else:
        return {"attack_type": "Unknown / Anomalous", "confidence": 0.40, "mitigation": "Manual investigation required"}


def get_recent_events_from_ip(ip_address: str, limit: int = 5) -> list:
    return [
        {"timestamp": "2024-01-15T10:22:00Z", "event": "normal", "bandwidth_mbps": 12.3},
        {"timestamp": "2024-01-15T10:21:00Z", "event": "normal", "bandwidth_mbps": 14.1},
        {"timestamp": "2024-01-15T10:20:00Z", "event": "normal", "bandwidth_mbps": 11.8},
    ][:limit]


# ─── Tool dispatcher ───────────────────────────────────────────────────────────

TOOL_MAP = {
    "lookup_ip_reputation":      lookup_ip_reputation,
    "get_historical_baseline":   get_historical_baseline,
    "classify_attack_type":      classify_attack_type,
    "get_recent_events_from_ip": get_recent_events_from_ip,
}

def run_tool(tool_name: str, tool_args: dict) -> str:
    console.print(f"  [cyan]🔧 Tool: {tool_name}({json.dumps(tool_args)})[/cyan]")
    fn = TOOL_MAP.get(tool_name)
    if not fn:
        result = {"error": f"Unknown tool: {tool_name}"}
    else:
        try:
            result = fn(**tool_args)
        except Exception as e:
            result = {"error": str(e)}
    console.print(f"  [green]  ↳ {json.dumps(result)}[/green]")
    return json.dumps(result)


# ─── Ollama call ───────────────────────────────────────────────────────────────

def call_ollama(prompt: str) -> str:
    try:
        resp = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 1024},
        }, timeout=120)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        console.print("[bold red]❌ Ollama not running! Start it with: ollama serve[/bold red]")
        raise
    except Exception as e:
        console.print(f"[red]Ollama error: {e}[/red]")
        raise


# ─── Prompt builder ────────────────────────────────────────────────────────────

SYSTEM_CONTEXT = """You are NetSleuth, an expert AI network security analyst running locally via Ollama.
You have access to these tools:

TOOL: lookup_ip_reputation
  args: ip_address (string)
  desc: Check if IP is malicious, botnet, Tor node. Returns reputation + abuse score.

TOOL: get_historical_baseline
  args: host (string), metric (one of: latency | bandwidth | connections | all)
  desc: Get 24h baseline stats for a host.

TOOL: classify_attack_type
  args: latency_ms (number), bandwidth_mbps (number), connections_per_sec (number),
        packet_loss_pct (number, optional), unique_ports (number, optional)
  desc: Classify the attack type by signature matching.

TOOL: get_recent_events_from_ip
  args: ip_address (string), limit (integer, optional, default 5)
  desc: Get recent events logged from this IP.

─────────────────────────────────────────────────────────
RESPONSE FORMAT — you MUST use EXACTLY one of these two formats. No other format is accepted.

FORMAT A — to call a tool. ARGS must be a valid JSON object with curly braces and double-quoted keys:

TOOL_CALL: lookup_ip_reputation
ARGS: {"ip_address": "10.0.0.99"}
REASON: Check if this IP is known malicious.

TOOL_CALL: classify_attack_type
ARGS: {"latency_ms": 1947.0, "bandwidth_mbps": 880.0, "connections_per_sec": 5604, "packet_loss_pct": 51.6}
REASON: Classify the attack based on observed metrics.

TOOL_CALL: get_historical_baseline
ARGS: {"host": "server-01", "metric": "all"}
REASON: Compare current metrics against the 24h baseline.

FORMAT B — to submit your final report:

FINAL_REPORT:
## Summary
...your report here...

─────────────────────────────────────────────────────────
CRITICAL:
- ARGS must ALWAYS use JSON with curly braces: {"key": "value"}
- NEVER write ARGS: key="value" or ARGS: key=value — that is wrong
- Call at least 2 tools before writing FINAL_REPORT
- The FINAL_REPORT must contain: ## Summary, ## Evidence, ## Attack Classification, ## Recommended Actions, ## Severity Rating
"""


def build_prompt(anomaly: dict, history: list) -> str:
    history_text = ""
    for turn in history:
        if turn["role"] == "tool_call":
            history_text += f"\n[You called]: {turn['tool']}({json.dumps(turn['args'])})\n[Tool result]: {turn['result']}\n"
        elif turn["role"] == "thought":
            history_text += f"\n[Your previous response]:\n{turn['content']}\n"

    return f"""{SYSTEM_CONTEXT}

ANOMALY TO INVESTIGATE:
Source IP    : {anomaly['source_ip']}
Host         : {anomaly['host']}
Severity     : {anomaly['severity']}
Detected At  : {anomaly['timestamp']}

Anomaly Reasons:
{chr(10).join(f"  - {r}" for r in anomaly['anomaly_reasons'])}

Raw Metrics:
{json.dumps(anomaly['original_event'], indent=2)}
{history_text}
Now continue your investigation. Respond using TOOL_CALL or FINAL_REPORT format only.
"""


# ─── Response parser ───────────────────────────────────────────────────────────

def parse_kv_args(raw: str) -> dict:
    """
    Fallback parser: handles when llama3 outputs key="value" or key=value
    instead of proper JSON. Converts to a dict best-effort.
    Examples it handles:
      ip_address="10.0.0.99"
      latency_ms=1947.0, bandwidth_mbps=880.0
      host="server-01", metric="all"
    """
    args = {}
    # Match key=value or key="value" or key='value'
    for m in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', raw):
        args[m.group(1)] = m.group(2)
    for m in re.finditer(r"(\w+)\s*=\s*'([^']*)'", raw):
        if m.group(1) not in args:
            args[m.group(1)] = m.group(2)
    # Match unquoted numbers: key=123.45
    for m in re.finditer(r'(\w+)\s*=\s*([\d.]+)', raw):
        if m.group(1) not in args:
            try:
                args[m.group(1)] = float(m.group(2)) if '.' in m.group(2) else int(m.group(2))
            except ValueError:
                args[m.group(1)] = m.group(2)
    return args


def parse_response(text: str) -> dict:
    """
    Returns one of:
      {"type": "tool_call",    "tool": str, "args": dict, "reason": str}
      {"type": "final_report", "content": str}
      {"type": "unknown",      "raw": str}
    """
    if "FINAL_REPORT:" in text:
        idx = text.index("FINAL_REPORT:")
        return {"type": "final_report", "content": text[idx + len("FINAL_REPORT:"):].strip()}

    tool_match   = re.search(r"TOOL_CALL:\s*(\w+)", text)
    args_match   = re.search(r"ARGS:\s*(\{.*?\})", text, re.DOTALL)
    reason_match = re.search(r"REASON:\s*(.+)", text)

    if tool_match:
        # Try proper JSON first
        args = {}
        if args_match:
            try:
                args = json.loads(args_match.group(1))
            except json.JSONDecodeError:
                # JSON parse failed — fall back to key=value parser
                args = parse_kv_args(args_match.group(1))
        else:
            # No curly braces at all — scrape entire ARGS line
            args_line_match = re.search(r"ARGS:\s*(.+)", text)
            if args_line_match:
                args = parse_kv_args(args_line_match.group(1))

        if args or args_match:  # proceed even with empty args for zero-arg tools
            return {
                "type":   "tool_call",
                "tool":   tool_match.group(1).strip(),
                "args":   args,
                "reason": reason_match.group(1).strip() if reason_match else "",
            }

    return {"type": "unknown", "raw": text}


# ─── ReAct investigation loop ──────────────────────────────────────────────────

def investigate(anomaly: dict) -> str:
    console.print(f"\n[bold magenta]🤖 Ollama Agent ({OLLAMA_MODEL}) investigating {anomaly['source_ip']}...[/bold magenta]")

    history    = []
    tools_used = 0

    for step in range(MAX_REACT_STEPS):
        console.print(f"[dim]  Step {step + 1}/{MAX_REACT_STEPS}[/dim]")

        prompt   = build_prompt(anomaly, history)
        response = call_ollama(prompt)

        console.print(f"[dim magenta]  Model says: {response[:140]}{'...' if len(response) > 140 else ''}[/dim magenta]")

        parsed = parse_response(response)

        if parsed["type"] == "final_report":
            console.print(f"[bold green]✅ Done after {tools_used} tool call(s).[/bold green]")
            return parsed["content"]

        elif parsed["type"] == "tool_call":
            tools_used += 1
            result = run_tool(parsed["tool"], parsed["args"])
            history.append({"role": "thought",   "content": response})
            history.append({"role": "tool_call",  "tool": parsed["tool"], "args": parsed["args"], "result": result})

        else:
            # Model didn't follow format — nudge it
            console.print(f"[yellow]  ⚠️  Unexpected format at step {step + 1}, nudging...[/yellow]")
            history.append({
                "role":    "thought",
                "content": response + "\n[NOTE: Please use TOOL_CALL or FINAL_REPORT format strictly]",
            })

    # Hit max steps — force final report with gathered evidence
    console.print(f"[yellow]⚠️  Max steps reached — requesting final report now...[/yellow]")
    history.append({
        "role":    "thought",
        "content": "[You have reached the step limit. Write your FINAL_REPORT now using the evidence gathered so far.]",
    })
    response = call_ollama(build_prompt(anomaly, history))
    parsed   = parse_response(response)
    return parsed["content"] if parsed["type"] == "final_report" else response


# ─── Kafka delivery callback ───────────────────────────────────────────────────

def delivery_report(err, msg):
    if err:
        console.print(f"[red]✗ Failed to publish report: {err}[/red]")
    else:
        console.print(f"[bold green]📋 Incident report published → [{msg.topic()}][/bold green]")


# ─── Main loop ─────────────────────────────────────────────────────────────────

def run():
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "group.id": "netsleuth-agent",
        "auto.offset.reset": "latest",
    })
    producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS})
    consumer.subscribe([TOPIC_ANOMALIES])

    console.print(f"[bold cyan]🧠 Ollama Agent started ({OLLAMA_MODEL}) — consuming '{TOPIC_ANOMALIES}'[/bold cyan]")
    console.print(f"[dim]Make sure Ollama is running:  ollama serve[/dim]")
    console.print(f"[dim]Make sure model is pulled:    ollama pull {OLLAMA_MODEL}[/dim]\n")

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                console.print(f"[red]Consumer error: {msg.error()}[/red]")
                continue

            anomaly     = json.loads(msg.value().decode("utf-8"))
            report_text = investigate(anomaly)

            report = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": anomaly["source_ip"],
                "host":      anomaly["host"],
                "severity":  anomaly["severity"],
                "report":    report_text,
                "status":    "investigated",
                "agent":     f"ollama/{OLLAMA_MODEL}",
            }

            producer.produce(
                TOPIC_AGENT_REPORTS,
                key=anomaly["source_ip"],
                value=json.dumps(report),
                callback=delivery_report,
            )
            producer.poll(0)

    except KeyboardInterrupt:
        console.print("\n[yellow]Agent stopped.[/yellow]")
    finally:
        consumer.close()


if __name__ == "__main__":
    run()
