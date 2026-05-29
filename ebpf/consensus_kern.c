// ebpf/consensus_kern.c
// SPDX-License-Identifier: GPL-2.0
// v4.4.2: Asymmetric Consensus en BPF_PROG_TYPE_SOCK_OPS

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PROCS 65536

struct process_ctx {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u8 risk_score; // 0-100
    __u32 hits; // Sigma hits count
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PROCS);
    __type(key, __u32); // pid
    __type(value, struct process_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // v4.3: persiste
} process_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); // threshold
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} control_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");

static __always_inline void increment_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val) {
        *val += 1;
    }
}

// Llamado desde XDP via bpf_tail_call o desde userspace
SEC("sockops")
int consensus_sockops(struct bpf_sock_ops *skops) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;

    struct process_ctx *ctx = bpf_map_lookup_elem(&process_cache, &pid);
    if (!ctx) {
        struct process_ctx new_ctx = {};
        new_ctx.pid = pid;
        new_ctx.ppid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; // fallback to thread id
        new_ctx.start_time = bpf_ktime_get_ns();
        new_ctx.hits = 0;
        new_ctx.risk_score = 0;
        new_ctx.last_seen = bpf_ktime_get_ns();
        bpf_map_update_elem(&process_cache, &pid, &new_ctx, BPF_ANY);
        return 0;
    }

    // v4.4.2: Lógica de scoring Asimétrico en kernel
    // 1. Decay temporal: -1 punto cada 60s sin hits
    __u64 now = bpf_ktime_get_ns();
    if (now - ctx->last_seen > 60000000000ULL) {
        ctx->risk_score = ctx->risk_score > 0 ? ctx->risk_score - 1 : 0;
    }

    // 2. Parent-child risk inheritance
    struct process_ctx *parent = bpf_map_lookup_elem(&process_cache, &ctx->ppid);
    if (parent && parent->risk_score > 50) {
        ctx->risk_score += 10; // Hereda 10% del riesgo padre
    }

    // 3. Hit count exponential
    if (ctx->hits > 0) {
        ctx->risk_score += (ctx->hits * ctx->hits); // 1,4,9,16...
    }

    if (ctx->risk_score > 100) ctx->risk_score = 100;
    ctx->last_seen = now;

    // 4. Threshold check
    __u32 zero = 0;
    __u32 *thresh = bpf_map_lookup_elem(&control_map, &zero);
    if (thresh && ctx->risk_score >= *thresh) {
        // Escalate: envía a AF_XDP o ringbuf para Python
        increment_stat(2); // v4.4.4: consensus_drops
        bpf_printk("CONSENSUS ALERT pid=%d score=%d", pid, ctx->risk_score);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
