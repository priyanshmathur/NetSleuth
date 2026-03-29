"""
detector.py — Consumes raw-metrics, runs statistical anomaly detection,
publishes flagged events to the 'anomalies' topic for the AI agent.
"""

import json
import statistics
from collections import deque
from datetime import datetime, timezone
from confluent_kafka import Consumer, Producer
from rich.console import Console
from config import (
    KAFKA_BOOTSTRAP_SERVERS,
    TOPIC_RAW_METRICS,
    TOPIC_ANOMALIES,
    LATENCY_THRESHOLD_MS,
    PACKET_LOSS_THRESHOLD_PCT,
    BANDWIDTH_SPIKE_MULTIPLIER,
    ZSCORE_THRESHOLD,
)

console = Console()

# ─── Rolling window for z-score baseline ──────────────────────────────────────

WINDOW_SIZE = 30  # last N events per metric

class RollingStats:
    def __init__(self, maxlen=WINDOW_SIZE):
        self.latency = deque(maxlen=maxlen)
        self.bandwidth = deque(maxlen=maxlen)
        self.connections = deque(maxlen=maxlen)

    def update(self, event: dict):
        self.latency.append(event["latency_ms"])
        self.bandwidth.append(event["bandwidth_mbps"])
        self.connections.append(event["connections_per_sec"])

    def zscore(self, value: float, window: deque) -> float:
        if len(window) < 5:
            return 0.0
        mean = statistics.mean(window)
        stdev = statistics.stdev(window) or 0.001
        return abs((value - mean) / stdev)

    def baseline_bandwidth(self) -> float:
        return statistics.mean(self.bandwidth) if self.bandwidth else 0


# ─── Anomaly scoring ───────────────────────────────────────────────────────────

def detect_anomaly(event: dict, stats: RollingStats) -> dict | None:
    reasons = []
    severity = "low"

    # Rule 1: Hard threshold — high latency
    if event["latency_ms"] > LATENCY_THRESHOLD_MS:
        reasons.append(f"Latency spike: {event['latency_ms']}ms (threshold: {LATENCY_THRESHOLD_MS}ms)")
        severity = "medium"

    # Rule 2: Hard threshold — packet loss
    if event["packet_loss_pct"] > PACKET_LOSS_THRESHOLD_PCT:
        reasons.append(f"Packet loss: {event['packet_loss_pct']}% (threshold: {PACKET_LOSS_THRESHOLD_PCT}%)")
        severity = "high"

    # Rule 3: Z-score — bandwidth spike vs rolling baseline
    bw_z = stats.zscore(event["bandwidth_mbps"], stats.bandwidth)
    if bw_z > ZSCORE_THRESHOLD:
        baseline = stats.baseline_bandwidth()
        reasons.append(f"Bandwidth z-score {bw_z:.2f} (baseline: {baseline:.1f} Mbps, current: {event['bandwidth_mbps']} Mbps)")
        severity = "high"

    # Rule 4: Z-score — connection rate
    conn_z = stats.zscore(event["connections_per_sec"], stats.connections)
    if conn_z > ZSCORE_THRESHOLD:
        reasons.append(f"Connection rate z-score {conn_z:.2f} ({event['connections_per_sec']} conn/s)")
        severity = "high" if event["connections_per_sec"] > 1000 else "medium"

    # Rule 5: Port scan heuristic
    if event.get("unique_ports", 0) > 50 and event["connections_per_sec"] > 100:
        reasons.append(f"Port scan pattern: {event['unique_ports']} unique ports, {event['connections_per_sec']} conn/s")
        severity = "critical"

    if not reasons:
        return None

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "original_event": event,
        "anomaly_reasons": reasons,
        "severity": severity,
        "source_ip": event["source_ip"],
        "host": event["host"],
        "status": "pending_investigation",
    }


# ─── Delivery callback ─────────────────────────────────────────────────────────

def delivery_report(err, msg):
    if err:
        console.print(f"[red] Failed to publish anomaly: {err}[/red]")
    else:
        console.print(f"[yellow] Anomaly published → [{msg.topic()}][/yellow]")


# ─── Main detector loop ────────────────────────────────────────────────────────

def run():
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "group.id": "netsleuth-detector",
        "auto.offset.reset": "latest",
    })
    producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS})
    consumer.subscribe([TOPIC_RAW_METRICS])

    stats = RollingStats()
    console.print(f"[bold cyan] Anomaly Detector started — consuming '{TOPIC_RAW_METRICS}'[/bold cyan]\n")

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                console.print(f"[red]Consumer error: {msg.error()}[/red]")
                continue

            event = json.loads(msg.value().decode("utf-8"))
            console.print(f"[dim] {event['timestamp']} | {event['source_ip']} | latency={event['latency_ms']}ms | bw={event['bandwidth_mbps']}Mbps[/dim]")

            anomaly = detect_anomaly(event, stats)
            if anomaly:
                severity_color = {"low": "yellow", "medium": "orange3", "high": "red", "critical": "bold red"}
                color = severity_color.get(anomaly["severity"], "white")
                console.print(f"[{color}]  ANOMALY [{anomaly['severity'].upper()}] from {anomaly['source_ip']}[/{color}]")
                for r in anomaly["anomaly_reasons"]:
                    console.print(f" -> {r}")

                producer.produce(
                    TOPIC_ANOMALIES,
                    key=anomaly["source_ip"],
                    value=json.dumps(anomaly),
                    callback=delivery_report,
                )
                producer.poll(0)

            # Always update rolling stats with normal baseline
            stats.update(event)

    except KeyboardInterrupt:
        console.print("\n[yellow]Detector stopped.[/yellow]")
    finally:
        consumer.close()


if __name__ == "__main__":
    run()
