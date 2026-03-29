"""
producer.py — Streams network telemetry events into Kafka topic: raw-metrics
Simulates normal traffic + injects attack scenarios for demo purposes.
"""

import json
import time
import random
import psutil
from datetime import datetime, timezone
from confluent_kafka import Producer
from rich.console import Console
from config import KAFKA_BOOTSTRAP_SERVERS, TOPIC_RAW_METRICS

console = Console()

# ─── Attack scenario definitions ──────────────────────────────────────────────

ATTACK_SCENARIOS = {
    "port_scan": {
        "description": "Rapid sequential port scanning",
        "latency_ms": lambda: random.uniform(5, 15),       # low latency, fast probes
        "packet_loss_pct": lambda: random.uniform(0, 1),
        "bandwidth_mbps": lambda: random.uniform(0.1, 0.5),
        "connections_per_sec": lambda: random.randint(200, 500),
        "unique_ports": lambda: random.randint(100, 1024),
        "source_ip": "192.168.1.105",
    },
    "ddos": {
        "description": "DDoS flood attack",
        "latency_ms": lambda: random.uniform(500, 2000),   # huge latency spike
        "packet_loss_pct": lambda: random.uniform(30, 70),
        "bandwidth_mbps": lambda: random.uniform(800, 1000),
        "connections_per_sec": lambda: random.randint(5000, 10000),
        "unique_ports": lambda: random.randint(1, 5),
        "source_ip": "10.0.0.99",
    },
    "data_exfil": {
        "description": "Slow data exfiltration attempt",
        "latency_ms": lambda: random.uniform(80, 120),
        "packet_loss_pct": lambda: random.uniform(0, 0.5),
        "bandwidth_mbps": lambda: random.uniform(45, 60),  # sustained high upload
        "connections_per_sec": lambda: random.randint(5, 15),
        "unique_ports": lambda: random.randint(1, 3),
        "source_ip": "172.16.0.45",
    },
}

# ─── Normal traffic baseline ───────────────────────────────────────────────────

def normal_metrics() -> dict:
    net = psutil.net_io_counters()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "normal",
        "source_ip": f"192.168.1.{random.randint(1, 50)}",
        "latency_ms": round(random.uniform(10, 80), 2),
        "packet_loss_pct": round(random.uniform(0, 2), 2),
        "bandwidth_mbps": round(random.uniform(5, 40), 2),
        "connections_per_sec": random.randint(10, 80),
        "unique_ports": random.randint(1, 20),
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv,
        "host": "server-01",
    }


def attack_metrics(scenario_name: str) -> dict:
    s = ATTACK_SCENARIOS[scenario_name]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": scenario_name,
        "source_ip": s["source_ip"],
        "latency_ms": round(s["latency_ms"](), 2),
        "packet_loss_pct": round(s["packet_loss_pct"](), 2),
        "bandwidth_mbps": round(s["bandwidth_mbps"](), 2),
        "connections_per_sec": s["connections_per_sec"](),
        "unique_ports": s["unique_ports"](),
        "bytes_sent": 0,
        "bytes_recv": 0,
        "host": "server-01",
        "description": s["description"],
    }


# ─── Kafka delivery callback ───────────────────────────────────────────────────

def delivery_report(err, msg):
    if err:
        console.print(f"[red]✗ Delivery failed: {err}[/red]")
    else:
        console.print(f"[green]✓ Sent to [{msg.topic()}] partition {msg.partition()} @ offset {msg.offset()}[/green]")


# ─── Main producer loop ────────────────────────────────────────────────────────

def run():
    producer = Producer({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS})
    console.print(f"[bold cyan] NetSleuth Producer started — streaming to '{TOPIC_RAW_METRICS}'[/bold cyan]\n")

    tick = 0
    while True:
        tick += 1

        # Every 20 ticks, inject an attack scenario for demo
        if tick % 20 == 0:
            scenario = random.choice(list(ATTACK_SCENARIOS.keys()))
            metrics = attack_metrics(scenario)
            console.print(f"[bold red]  Injecting attack scenario: {scenario.upper()}[/bold red]")
        else:
            metrics = normal_metrics()

        producer.produce(
            TOPIC_RAW_METRICS,
            key=metrics["source_ip"],
            value=json.dumps(metrics),
            callback=delivery_report,
        )
        producer.poll(0)

        time.sleep(1)  # 1 event/second — adjust as needed


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Producer stopped.[/yellow]")
