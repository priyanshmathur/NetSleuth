#  NetSleuth — AI-Powered Network Anomaly Detective

> Real-time network telemetry → Kafka → Statistical anomaly detection → Claude AI agent → Incident reports

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Kafka](https://img.shields.io/badge/Apache%20Kafka-2.13-black.svg)](https://kafka.apache.org)
[![Anthropic](https://img.shields.io/badge/Claude-AI%20Agent-orange.svg)](https://anthropic.com)

---

##  Architecture

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌──────────────┐
│  producer.py │────▶│  raw-metrics    │────▶│  detector.py     │────▶│  anomalies   │
│  (telemetry) │     │  (Kafka topic)  │     │  (z-score + rules)│     │  (Kafka topic)│
└──────────────┘     └─────────────────┘     └──────────────────┘     └──────┬───────┘
                                                                               │
                                                                               ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────────────────────────────────┐
│  reporter.py │◀────│  agent-reports  │◀────│  agent.py (Claude + Tool Calling)        │
│  (saves .md) │     │  (Kafka topic)  │     │  lookup_ip_reputation()                  │
└──────────────┘     └─────────────────┘     │  get_historical_baseline()               │
                                             │  classify_attack_type()                  │
                                             │  get_recent_events_from_ip()             │
                                             └──────────────────────────────────────────┘
```

---

## Setup & Run

### Prerequisites
- Docker + Docker Compose
- Python 3.11+
- An [Anthropic API key](https://console.anthropic.com)

---

### Step 1 — Clone & install dependencies

```bash
git clone https://github.com/priyanshmathur/NetSleuth.git
cd netsleuth
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

### Step 2 — Configure environment

```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

---

### Step 3 — Start Kafka

```bash
docker-compose up -d
```

Verify Kafka is running:
```bash
docker-compose ps
```

Open Kafka UI at → **http://localhost:8080**

---

### Step 4 — Run each component in a separate terminal

**Terminal 1 — Producer** (streams telemetry):
```bash
python producer.py
```

**Terminal 2 — Detector** (flags anomalies):
```bash
python detector.py
```

**Terminal 3 — AI Agent** (Claude investigates):
```bash
python agent.py
```

**Terminal 4 — Reporter** (saves incident files):
```bash
python reporter.py
```

---

### Step 5 — Watch the magic 

Every ~20 seconds the producer injects a simulated attack. You'll see:
1. Producer emits the event
2. Detector flags it with anomaly reasons
3. Claude agent autonomously calls tools to investigate
4. Reporter saves a full Markdown incident report to `reports/`

---

##  How the AI Agent Works

The agent uses Claude's **tool-calling** feature in a **ReAct loop**:

1. Receives anomaly from Kafka
2. Sends it to Claude with 4 tools available
3. Claude decides which tools to call and in what order
4. Tool results feed back into Claude's context
5. Claude reasons and produces a final incident report

This is the **ReAct (Reason + Act)** pattern — the foundation of modern AI agents.

---

##  Extending NetSleuth

| What | How |
|------|-----|
| Real IP threat intel | Replace `lookup_ip_reputation()` with [AbuseIPDB API](https://www.abuseipdb.com/api) |
| Real network capture | Use `scapy` in `producer.py` to capture live traffic |
| Alerting | Add a Slack/PagerDuty webhook in `reporter.py` |
| Dashboard | Add Grafana with Kafka plugin to visualize topics |
| Persistence | Add a PostgreSQL sink for anomaly history |

---

## 📄 License

MIT
