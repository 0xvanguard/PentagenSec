from prometheus_client import Histogram
import os
import threading
import subprocess
import logging
import time

try:
    from pyxdp import XSK, XskSocketConfig, XskUmemConfig
except ImportError:
    pass # we handle pyxdp not being available in some environments

log = logging.getLogger("af_xdp")

from core.metrics import ebpf_latency

XDP_FLAGS_SKB_MODE = 1 << 1
XDP_FLAGS_DRV_MODE = 1 << 2
XDP_ZEROCOPY = 1 << 2
XDP_USE_NEED_WAKEUP = 1 << 3

def get_xdp_mode(iface):
    try:
        drv = subprocess.check_output(["ethtool", "-i", iface]).decode()
        if "driver: i40e" in drv or "driver: ice" in drv or "driver: mlx5" in drv:
            return XDP_FLAGS_DRV_MODE | XDP_ZEROCOPY
    except Exception:
        pass
    log.warning("AF_XDP: NIC sin ZEROCOPY. Fallback a XDP_SKB mode para lab")
    return XDP_FLAGS_SKB_MODE

class AFXDPThread(threading.Thread):
    def __init__(self, iface="lo", queue_id=0):
        super().__init__(daemon=True)
        self.iface = iface
        self.queue_id = queue_id
        
        self.xdp_flags = get_xdp_mode(iface)
        if self.xdp_flags & XDP_FLAGS_DRV_MODE:
            subprocess.run(["ethtool", "-L", iface, "combined", "4"], check=False)

        try:
            # 4K frames, 4096 frames = 16MB umem
            umem_cfg = XskUmemConfig(frame_size=4096, frame_count=4096, huge_pages=True)
            self.umem = XSK.create_umem(umem_cfg)
            
            sock_cfg = XskSocketConfig(rx_queue_size=2048, tx_queue_size=2048, libbpf_flags=0)
            sock_cfg.xdp_flags = self.xdp_flags
            sock_cfg.bind_flags = XDP_USE_NEED_WAKEUP
            if self.xdp_flags & XDP_ZEROCOPY:
                sock_cfg.bind_flags |= XDP_ZEROCOPY

            self.xsk = XSK(iface, queue_id, self.umem, sock_cfg)
            # Pin al xsks_map para que XDP vea el socket
            self.xsk.update_xsks_map("/sys/fs/bpf/xsks_map", queue_id)
            self.working = True
        except Exception as e:
            log.error(f"Error inicializando AF_XDP: {e}")
            self.working = False

    def run(self):
        if not self.working:
            return
            
        while True:
            idx = self.xsk.rx_ring_peek(64) # batch 64
            if idx <= 0:
                time.sleep(0.0001)
                continue
                
            for i in range(idx):
                start = time.perf_counter()
                desc = self.xsk.rx_descs[i]
                pkt = self.umem.get_data(desc.addr, desc.len)
                
                # Aquí iría handle_packet_zero_copy(pkt)
                
                # Medición de latencia (simulada)
                latency = time.perf_counter() - start
                ebpf_latency.observe(latency)
                
            self.xsk.rx_ring_release(idx)
