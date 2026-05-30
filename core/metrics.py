from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import FastAPI, Response
import time

# --- v3.0 Sigma + DuckDB ---
sigma_hits_total = Counter(
    'pentagensec_sigma_hits_total',
    'Total Sigma rule hits',
    ['rule_id', 'severity']
)
duckdb_query_duration = Histogram(
    'pentagensec_duckdb_query_duration_seconds',
    'DuckDB query latency',
    ['query_type'] # 'pre_filter', 'hit_fetch', 'drill_down'
)
events_ingested_total = Counter(
    'pentagensec_events_ingested_total',
    'Total events ingested via batch or stream'
)

# --- v3.2 Neo4j ---
graph_query_duration = Histogram(
    'pentagensec_graph_query_duration_seconds',
    'Neo4j blast-radius query latency',
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0] # SLO 50ms
)
graph_nodes_total = Gauge(
    'pentagensec_graph_nodes_total',
    'Total nodes in Neo4j graph',
    ['label'] # Process, Host, User
)

# --- v3.3 Active Learning ---
fp_predictions_total = Counter(
    'pentagensec_fp_predictions_total',
    'FP classifier predictions',
    ['label'] # 'fp', 'tp'
)
fp_model_train_duration = Histogram(
    'pentagensec_fp_train_duration_seconds',
    'Time to run partial_fit'
)
fp_probability = Histogram(
    'pentagensec_fp_probability',
    'Distribution of P(FP) scores',
    buckets=[0.1, 0.3, 0.5, 0.7, 0.8, 0.9, 0.95, 1.0]
)

# --- v3.4 Kafka Streaming ---
kafka_lag = Gauge(
    'pentagensec_kafka_consumer_lag',
    'Kafka consumer lag in messages',
    ['topic', 'partition']
)
kafka_batch_duration = Histogram(
    'pentagensec_kafka_batch_duration_seconds',
    'Time to process micro-batch',
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0]
)
fp_dropped_total = Counter(
    'pentagensec_fp_dropped_total',
    'Events dropped by FP filter'
)

# --- v4.0 TUI ---
tui_active_sessions = Gauge(
    'pentagensec_tui_active_sessions',
    'Number of active TUI sessions'
)
tui_drill_down_duration = Histogram(
    'pentagensec_tui_drill_down_duration_seconds',
    'Time to load drill-down view'
)

# --- v4.4.4 eBPF Telemetry ---
import threading
ebpf_packets_total = Counter('pentagensec_ebpf_packets_total', 'Total packets seen by XDP')
ebpf_regex_hits = Counter('pentagensec_ebpf_regex_hits_total', 'Regex hits', ['rule_id'])
ebpf_consensus_drops = Counter('pentagensec_ebpf_consensus_drops_total', 'Drops by SOCK_OPS')
ebpf_tail_call_fails = Gauge('pentagensec_ebpf_tail_call_fails', 'Tail call misses')
ebpf_insn_per_pkt = Gauge('pentagensec_ebpf_insn_per_pkt', 'Insn per packet from profile')
ebpf_latency = Histogram('pentagensec_ebpf_latency_seconds', 'XDP to userspace latency', buckets=[0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005])

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
metrics_app = FastAPI(title="pentagensec Metrics")

@metrics_app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@metrics_app.get("/health")
def health():
    return {"status": "ok", "ts": time.time()}

from fastapi import Request
import ctypes

@metrics_app.post("/api/v1/soar/config")
async def set_soar_config(request: Request):
    data = await request.json()
    auto = 1 if data.get("auto_block") else 0
    if hasattr(metrics_app, "bpf"):
        config_map = metrics_app.bpf.get_table("config_map")
        config_map[0] = ctypes.c_uint8(auto)
    return {"status": "ok"}

@metrics_app.get("/api/v1/soar/actions")
def get_actions():
    if not hasattr(metrics_app, "bpf"):
        return {}
    actions_map = metrics_app.bpf.get_table("actions_map")
    res = []
    for k, v in actions_map.items():
        import socket
        import struct
        ip = socket.inet_ntoa(struct.pack('I', k.ip_src))
        action_str = "TARPIT" if v.value == 2 else "DROP"
        res.append({"ip_src": ip, "action_val": v.value, "action": action_str})
    return res

@metrics_app.delete("/api/v1/soar/actions/{ip}")
def delete_action(ip: str):
    if hasattr(metrics_app, "bpf"):
        actions_map = metrics_app.bpf.get_table("actions_map")
        import socket
        import struct
        ip_int = struct.unpack('I', socket.inet_aton(ip))[0]
        # BPF table keys must be exact struct, but bcc handles it if we create the Key object
        key = actions_map.Key()
        key.ip_src = ip_int
        key.port_src = 0
        key.protocol = 0
        try:
            del actions_map[key]
        except KeyError:
            pass
    return {"status": "ok"}

@metrics_app.get("/api/v1/ml/explain/{ip}")
def explain_ml(ip: str):
    # Simulated explanation for the IP based on recent ML evaluation
    # In a real scenario, this would query a dedicated map or database containing the feature vectors
    return {
        "ip": ip,
        "score": 45.2,
        "threshold": 42.0,
        "top_features": [
            {"name": "iat_ns", "value": "287000000", "description": "Inter-arrival time implies automated beaconing"},
            {"name": "payload_entropy", "value": "7.91", "description": "High entropy suggests encrypted payload"},
            {"name": "dst_port", "value": "53", "description": "DNS port used anomalously"}
        ]
    }
