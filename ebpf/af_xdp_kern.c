// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

// Llamado desde sigma_filter.c (o sigma_main.c) tras regex match
static __always_inline int redirect_to_af_xdp(struct xdp_md *ctx) {
    __u32 key = ctx->rx_queue_index; // 1 cola = key 0
    __u32 zero = 0;

    // Lógica de fallback para evitar drops:
    if (bpf_map_lookup_elem(&xsks_map, &key) || bpf_map_lookup_elem(&xsks_map, &zero)) {
        return bpf_redirect_map(&xsks_map, key, XDP_PASS);
    }
    return XDP_PASS;
}
