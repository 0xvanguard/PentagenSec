from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import FastAPI, Response
import time

# --- v3.0 Sigma + DuckDB ---
sigma_hits_total = Counter(
    'antigravity_sigma_hits_total',
    'Total Sigma rule hits',
    ['rule_id', 'severity']
)
duckdb_query_duration = Histogram(
    'antigravity_duckdb_query_duration_seconds',
    'DuckDB query latency',
    ['query_type'] # 'pre_filter', 'hit_fetch', 'drill_down'
)
events_ingested_total = Counter(
    'antigravity_events_ingested_total',
    'Total events ingested via batch or stream'
)

# --- v3.2 Neo4j ---
graph_query_duration = Histogram(
    'antigravity_graph_query_duration_seconds',
    'Neo4j blast-radius query latency',
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0] # SLO 50ms
)
graph_nodes_total = Gauge(
    'antigravity_graph_nodes_total',
    'Total nodes in Neo4j graph',
    ['label'] # Process, Host, User
)

# --- v3.3 Active Learning ---
fp_predictions_total = Counter(
    'antigravity_fp_predictions_total',
    'FP classifier predictions',
    ['label'] # 'fp', 'tp'
)
fp_model_train_duration = Histogram(
    'antigravity_fp_train_duration_seconds',
    'Time to run partial_fit'
)
fp_probability = Histogram(
    'antigravity_fp_probability',
    'Distribution of P(FP) scores',
    buckets=[0.1, 0.3, 0.5, 0.7, 0.8, 0.9, 0.95, 1.0]
)

# --- v3.4 Kafka Streaming ---
kafka_lag = Gauge(
    'antigravity_kafka_consumer_lag',
    'Kafka consumer lag in messages',
    ['topic', 'partition']
)
kafka_batch_duration = Histogram(
    'antigravity_kafka_batch_duration_seconds',
    'Time to process micro-batch',
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0]
)
fp_dropped_total = Counter(
    'antigravity_fp_dropped_total',
    'Events dropped by FP filter'
)

# --- v4.0 TUI ---
tui_active_sessions = Gauge(
    'antigravity_tui_active_sessions',
    'Number of active TUI sessions'
)
tui_drill_down_duration = Histogram(
    'antigravity_tui_drill_down_duration_seconds',
    'Time to load drill-down view'
)

# FastAPI para /metrics
metrics_app = FastAPI(title="Antigravity Metrics")

@metrics_app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@metrics_app.get("/health")
def health():
    return {"status": "ok", "ts": time.time()}
