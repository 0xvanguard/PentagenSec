// ebpf/sigma_main.c
// SPDX-License-Identifier: GPL-2.0
// v4.4.1: Main XDP prog que hace tail_call a reglas compiladas

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1024); // 1024 reglas JIT (chunks)
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} next_rule_idx SEC(".maps");

SEC("xdp")
int sigma_main(struct xdp_md *ctx) {
    __u32 key = 0;
    __u32 *idx = bpf_map_lookup_elem(&next_rule_idx, &key);
    if (!idx) return XDP_PASS;

    // tail_call a la primera regla chunk (índice 0 o lo que esté en next_rule_idx)
    // Cada chunk hará tail_call al siguiente hasta terminar o hacer DROP.
    bpf_tail_call(ctx, &prog_array, *idx);
    
    // Si prog_array está vacío o falla el tail call:
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
