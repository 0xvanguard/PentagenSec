# core/ebpf_loader.py
from bcc import BPF
from prometheus_client import Counter, Histogram
import ctypes
import socket
import struct

ebpf_hits_total = Counter('antigravity_ebpf_hits_total', 'Hits from XDP', ['rule_id'])
ebpf_drop_total = Counter('antigravity_ebpf_drop_total', 'Packets dropped by XDP')
ebpf_load_duration = Histogram('antigravity_ebpf_load_duration_seconds', 'Time to load XDP')

class EventHit(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64),
        ("rule_id", ctypes.c_uint32),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("payload", ctypes.c_uint8 * 128),
    ]

class SigmaXDP:
    """v4.2: Carga reglas Sigma → eBPF maps. NIST SI-3 malicious code detection."""

    def __init__(self, iface='eth0', bpf_file='ebpf/sigma_filter.c'):
        self.iface = iface
        with ebpf_load_duration.time():
            self.bpf = BPF(src_file=bpf_file)
            self.fn = self.bpf.load_func("sigma_xdp_filter", BPF.XDP)
            self.bpf.attach_xdp(iface, self.fn, 0)

        self.rules_map = self.bpf.get_table("rules_map")
        self.hits_rb = self.bpf["hits_rb"]
        self.hits_rb.open_ring_buffer(self._ringbuf_callback)

    def _ringbuf_callback(self, cpu, data, size):
        """Kernel → Userspace: hit recibido"""
        event = ctypes.cast(data, ctypes.POINTER(EventHit)).contents
        ebpf_hits_total.labels(rule_id=event.rule_id).inc()
        # Aquí: envías a Kafka siem_raw o directo a DuckDB
        # print(f"HIT: rule={event.rule_id} src={socket.inet_ntoa(struct.pack('!I', event.src_ip))}")

    def load_sigma_rules(self, sigma_compiled: list[dict]):
        """Convierte reglas Sigma → struct sigma_rule → mapa eBPF"""
        for i, rule in enumerate(sigma_compiled):
            if i >= 1024: break
            pattern = rule['pattern'].encode('utf-8')[:64]
            self.rules_map[ctypes.c_uint32(i)] = self.rules_map.Leaf(
                rule['id'],
                rule.get('dst_port', 0),
                len(pattern),
                ctypes.cast(pattern, ctypes.POINTER(ctypes.c_uint8 * 64)).contents
            )

    def poll(self):
        """Llamar en loop para procesar ringbuf"""
        self.bpf.ring_buffer_poll()

    def detach(self):
        self.bpf.remove_xdp(self.iface, 0)
