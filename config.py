import os
from dotenv import load_dotenv

load_dotenv()

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

TOPIC_RAW_METRICS = os.getenv("TOPIC_RAW_METRICS", "raw-metrics")
TOPIC_ANOMALIES = os.getenv("TOPIC_ANOMALIES", "anomalies")
TOPIC_AGENT_REPORTS = os.getenv("TOPIC_AGENT_REPORTS", "agent-reports")

LATENCY_THRESHOLD_MS = float(os.getenv("LATENCY_THRESHOLD_MS", 200))
PACKET_LOSS_THRESHOLD_PCT = float(os.getenv("PACKET_LOSS_THRESHOLD_PCT", 5.0))
BANDWIDTH_SPIKE_MULTIPLIER = float(os.getenv("BANDWIDTH_SPIKE_MULTIPLIER", 3.0))
ZSCORE_THRESHOLD = float(os.getenv("ZSCORE_THRESHOLD", 2.5))
