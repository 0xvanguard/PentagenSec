import threading
import time
import ctypes
import logging

from prometheus_client import Counter, Histogram

log = logging.getLogger("soar")

soar_actions_total = Counter('pentagensec_soar_actions_total', 'SOAR actions', ['type'])
soar_latency = Histogram('pentagensec_soar_latency_seconds', 'Decision latency', buckets=[0.01, 0.05, 0.1, 0.25, 0.5])
soar_map_full_total = Counter('pentagensec_soar_map_full_total', 'SOAR actions_map full errors')
tarpit_tx_total = Counter('pentagensec_tarpit_tx_total', 'TARPIT packets modified and sent back')
ml_score = Histogram('pentagensec_ml_score', 'ML Anomaly Score from XDP', buckets=[10, 20, 30, 35, 38, 40, 50, 100])

class SOARThread(threading.Thread):
    def __init__(self, bpf_obj):
        super().__init__(daemon=True)
        self.bpf = bpf_obj
        self.actions_map = bpf_obj.get_table("actions_map")
        self.config_map = bpf_obj.get_table("config_map")
        self.soar_events = bpf_obj.get_table("soar_events")

    def run(self):
        def handle_event(cpu, data, size):
            start = time.monotonic_ns()
            evt = self.bpf["soar_events"].event(data)

            # Check if ML Score Event
            if evt.rule_id >= 99990000:
                score = evt.rule_id - 99990000
                ml_score.observe(score)
                # Shadow Mode: no action taken for ML yet
                return

            # 1. Eval: ¿Es crítico?
            action_val = self.get_action(evt)
            if action_val > 0:
                key = self.actions_map.Key()
                key.ip_src = evt.src_ip
                key.port_src = evt.src_port
                key.protocol = evt.protocol
                
                # Write to actions_map (value 1 = DROP, 2 = TARPIT)
                try:
                    self.actions_map[key] = ctypes.c_uint8(action_val)
                    action_str = "tarpit" if action_val == 2 else "block"
                    soar_actions_total.labels(type=action_str).inc()
                    if action_val == 2:
                        tarpit_tx_total.inc()
                    log.warning(f"SOAR: Auto-{action_str} IP {evt.src_ip} due to rule {evt.rule_id}")
                except Exception as e:
                    soar_map_full_total.inc()
                    log.error(f"SOAR map full: {e}")

            lat = (time.monotonic_ns() - start) / 1e9
            soar_latency.observe(lat)

        self.soar_events.open_ring_buffer(handle_event)
        log.info("SOARThread listening on soar_events ringbuf...")
        while True:
            try:
                self.bpf.ring_buffer_poll(100) # 100ms timeout
            except Exception as e:
                log.error(f"SOAR poll error: {e}")
                time.sleep(1)

    def get_action(self, evt):
        # v4.5.2: Si rule.severity >= 3 -> 2 (TARPIT), else 0 (PASS)
        return 2 if evt.severity >= 3 else 0
