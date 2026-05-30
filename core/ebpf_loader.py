# core/ebpf_loader.py
from bcc import BPF
from prometheus_client import Counter, Histogram
import ctypes
import socket
import struct

ebpf_hits_total = Counter('pentagensec_ebpf_hits_total', 'Hits from XDP', ['rule_id'])
ebpf_drop_total = Counter('pentagensec_ebpf_drop_total', 'Packets dropped by XDP')
ebpf_load_duration = Histogram('pentagensec_ebpf_load_duration_seconds', 'Time to load XDP')

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

    def __init__(self, iface='eth0', bpf_file='ebpf/sigma_filter.bpf.o'):
        self.iface = iface
        self.bpf_file = bpf_file
        self.pin_path = "/sys/fs/bpf/sigma_filter"
        import subprocess
        import os
        
        with ebpf_load_duration.time():
            # 1. Load object via bpftool (CO-RE native)
            os.makedirs(self.pin_path, exist_ok=True)
            subprocess.run(["bpftool", "prog", "loadall", self.bpf_file, self.pin_path, "pinmaps", self.pin_path], check=False)
            
            # 2. Attach XDP
            subprocess.run(["bpftool", "net", "attach", "xdp", "pinned", f"{self.pin_path}/sigma_xdp_filter", "dev", self.iface], check=False)

            # 3. Use BCC just for map wrappers (no compilation, no headers needed)
            self.bpf = BPF(text="")
            self.rules_map = self.bpf.get_table("rules_map", f"{self.pin_path}/rules_map")
            self.actions_map = self.bpf.get_table("actions_map", f"{self.pin_path}/actions_map")
            self.config_map = self.bpf.get_table("config_map", f"{self.pin_path}/config_map")
            self.soar_events = self.bpf.get_table("soar_events", f"{self.pin_path}/soar_events")
            
            # Note: For ringbuf, BCC's get_table can open it if pinned, but it's tricky.
            # We'll use bpf_map_get_fd_by_path and the ringbuf python wrapper if needed.
            # In v4.5.0, ringbuf is soar_events, which we'll handle in soar.py.
            # For hits_rb, it's removed in v4.4.3.

    def _ringbuf_callback(self, cpu, data, size):
        pass

    def load_sigma_rules(self, sigma_compiled: list[dict]):
        for i, rule in enumerate(sigma_compiled):
            if i >= 1024: break
            pattern = rule['pattern'].encode('utf-8')[:64]
            self.rules_map[ctypes.c_uint32(i)] = self.rules_map.Leaf(
                rule['id'],
                rule.get('dst_port', 0),
                6, # TCP
                len(pattern),
                (ctypes.c_uint8 * 64)(*pattern),
                0
            )

    def poll(self):
        self.bpf.ring_buffer_poll()

    def detach(self):
        import subprocess
        subprocess.run(["bpftool", "net", "detach", "xdp", "dev", self.iface], check=False)

import time
from pathlib import Path
import os

BPF_FS = "/sys/fs/bpf"
import ctypes as ct

class SigmaXDPv43(SigmaXDP): # Hereda de v4.2

    def __init__(self, iface: str, pin_path="/sys/fs/bpf/sigma"):
        self.iface = iface
        self.pin_path = Path(pin_path)
        self.pin_path.mkdir(parents=True, exist_ok=True)

        # v4.3: Intenta reusar mapas pineados, si no existen carga programa
        if self._maps_pinned():
            self.bpf = BPF(text="", reuse_maps=True) # Solo abre mapas
            self.rules_map = self.bpf.get_table("rules_map", str(self.pin_path / "rules_map"))
            self.control_map = self.bpf.get_table("control_map", str(self.pin_path / "control_map"))
            self.attached = self._is_xdp_attached()
        else:
            super().__init__(iface, "ebpf/sigma_filter.c")
            # v4.3: Pinea mapas tras cargar
            self.bpf["rules_map"].pin(str(self.pin_path / "rules_map"))
            self.bpf["control_map"].pin(str(self.pin_path / "control_map"))
            self.attached = True

    def _maps_pinned(self) -> bool:
        return (self.pin_path / "rules_map").exists()

    def _is_xdp_attached(self) -> bool:
        import subprocess
        try:
            out = subprocess.check_output(["bpftool", "net", "show", "dev", self.iface])
            return b"xdp" in out
        except FileNotFoundError:
            return False

    def hot_reload_rules(self, ebpf_rules: list[dict]):
        """v4.3: Actualiza reglas sin detach. NIST CM-3"""
        # 1. Incrementa epoch para invalida reglas viejas
        zero = ct.c_uint32(0)
        old_epoch = self.control_map[zero].value if zero in self.control_map else 0
        new_epoch = old_epoch + 1
        self.control_map[zero] = ct.c_uint64(new_epoch)

        # 2. Carga nuevas reglas con nuevo epoch
        for r in ebpf_rules:
            self.load_rule(r.get('idx', r.get('id', 0) % 1024), r.get('dst_port', 0), r.get('l4_proto', 6),
                           r.get('pattern', ''), r.get('id', 0), new_epoch)

        # 3. Limpia reglas con epoch viejo - no bloquea XDP
        for i in range(1024):
            key = ct.c_uint32(i)
            try:
                rule = self.rules_map[key]
                if rule.epoch < new_epoch and rule.epoch != 0:
                    del self.rules_map[key]
            except KeyError:
                pass

        return new_epoch

    def load_rule(self, idx: int, dst_port: int, l4_proto: int,
                  substr: str, rule_id: int, epoch: int = 0):
        substr_bytes = substr.encode('utf-8')[:63]
        rule = self.rules_map.Leaf()
        rule.dst_port = dst_port
        rule.l4_proto = l4_proto
        rule.pattern_len = len(substr_bytes)
        rule.pattern = (ct.c_uint8 * 64)(*substr_bytes)
        rule.rule_id = rule_id
        rule.epoch = epoch # v4.3
        self.rules_map[ct.c_uint32(idx)] = rule

    def attach(self):
        self.fn = self.bpf.load_func("sigma_xdp_filter", BPF.XDP)
        self.bpf.attach_xdp(self.iface, self.fn, 0)
        self.attached = True

    def attach_consensus(self):
        """v4.4.2: Attach consensus a cgroupv2 para scoring"""
        import os
        cgroup_path = "/sys/fs/cgroup/pentagensec"
        os.makedirs(cgroup_path, exist_ok=True)
        
        with open(os.path.join(cgroup_path, "cgroup.procs"), "w") as f:
            f.write(str(os.getpid()))

        obj = libbpf.bpf_object__open(b"/out/consensus_kern.o")
        libbpf.bpf_object__load(obj)
        prog = libbpf.bpf_object__find_program_by_name(obj, b"consensus_sockops")
        fd = libbpf.bpf_program__fd(prog)
        
        import ctypes as ct
        # cgroup_fd
        cgroup_fd = os.open(cgroup_path, os.O_RDONLY | os.O_DIRECTORY)
        BPF_CGROUP_SOCK_OPS = 3
        # Use bpf_prog_attach via libbpf or bcc, using libbpf wrapper
        libbpf.bpf_prog_attach(fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0)
        os.close(cgroup_fd)
        logging.getLogger("ebpf_loader").info(f"Attached consensus to {cgroup_path}")

# Intenta importar libbpf; si no existe, SigmaJIT no estará disponible sin él.
try:
    from bpf import libbpf
    
    class SigmaJIT:
        """v4.4.1: Carga reglas.o compiladas y las mete a prog_array"""
    
        def __init__(self, iface: str):
            self.iface = iface
            self.main_obj = libbpf.bpf_object__open(b"ebpf/sigma_main.o")
            libbpf.bpf_object__load(self.main_obj)
            self.main_fd = libbpf.bpf_program__fd(
                libbpf.bpf_object__find_program_by_name(self.main_obj, b"sigma_main")
            )
            libbpf.bpf_set_link_xdp_fd(self._ifindex(), self.main_fd, 0)
    
            self.prog_array = libbpf.bpf_object__find_map_by_name(self.main_obj, b"prog_array")
            self.next_rule_idx = libbpf.bpf_object__find_map_by_name(self.main_obj, b"next_rule_idx")
            self.stats_map = libbpf.bpf_object__find_map_by_name(self.main_obj, b"stats_map")
    
        def _ifindex(self):
            import socket, fcntl, struct
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return struct.unpack('I', fcntl.ioctl(s.fileno(), 0x8933, struct.pack('16s16x', self.iface.encode())))[0]
    
        def load_rule_obj(self, o_path: Path, idx: int):
            """v4.4.1: Carga rule_123.o y lo mete en prog_array[idx]"""
            obj = libbpf.bpf_object__open(str(o_path).encode('utf-8'))
            libbpf.bpf_object__load(obj)
            prog = libbpf.bpf_object__find_program_by_name(obj, b"sigma_regex_chunk")
            fd = libbpf.bpf_program__fd(prog)
    
            key = ct.c_uint32(idx)
            libbpf.bpf_map__update_elem(self.prog_array, ct.byref(key), ct.byref(ct.c_uint32(fd)), 0)
            # NO detach: tail_call chain se auto-actualiza
    
        def set_next_idx(self, idx: int):
            key = ct.c_uint32(0)
            val = ct.c_uint32(idx)
            libbpf.bpf_map__update_elem(self.next_rule_idx, ct.byref(key), ct.byref(val), 0)

except ImportError:
    import logging
    logging.getLogger("ebpf_loader").warning("libbpf not found. SigmaJIT will not be available.")

