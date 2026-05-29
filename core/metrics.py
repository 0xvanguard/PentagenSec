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

# --- v4.4.4 eBPF Telemetry ---
import threading
ebpf_packets_total = Counter('antigravity_ebpf_packets_total', 'Total packets seen by XDP')
ebpf_regex_hits = Counter('antigravity_ebpf_regex_hits_total', 'Regex hits', ['rule_id'])
ebpf_consensus_drops = Counter('antigravity_ebpf_consensus_drops_total', 'Drops by SOCK_OPS')
ebpf_tail_call_fails = Gauge('antigravity_ebpf_tail_call_fails', 'Tail call misses')
ebpf_insn_per_pkt = Gauge('antigravity_ebpf_insn_per_pkt', 'Insn per packet from profile')

class EbpfMetricsThread(threading.Thread):
    def __init__(self, stats_map, interval=5):
        super().__init__(daemon=True)
        self.stats_map = stats_map # libbpf map fd or bcc table
        self.interval = interval

    def run(self):
        import ctypes as ct
        from bpf import libbpf
        # The map is BPF_MAP_TYPE_PERCPU_ARRAY. We read keys 0 to 3.
        # We need to read num_cpus values for each key.
        import multiprocessing
        cpus = multiprocessing.cpu_count()
        value_type = ct.c_uint64 * cpus
        
        while True:
            try:
                # 0=packets, 1=hits, 2=drops, 3=tail_fail
                for k, metric in [(0, ebpf_packets_total), (1, ebpf_regex_hits.labels(rule_id="all")), 
                                  (2, ebpf_consensus_drops), (3, ebpf_tail_call_fails)]:
                    key = ct.c_uint32(k)
                    val = value_type()
                    ret = libbpf.bpf_map__lookup_elem(self.stats_map, ct.byref(key), ct.sizeof(key), ct.byref(val), ct.sizeof(val), 0)
                    if ret == 0:
                        total = sum(val)
                        if isinstance(metric, Gauge):
                            metric.set(total)
                        else:
                            # Counter needs to increase, but total is absolute. Wait, prometheus client Counter cannot be set directly unless using ._value.set()
                            metric._value.set(total)
            except Exception as e:
                pass
            time.sleep(self.interval)

# FastAPI para /metrics
metrics_app = FastAPI(title="Antigravity Metrics")

@metrics_app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@metrics_app.get("/health")
def health():
    return {"status": "ok", "ts": time.time()}
