// ebpf/trampoline.c
// SPDX-License-Identifier: GPL-2.0
// Generado por Antigravity v4.4.1 - Adaptive Core

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

struct process_ctx {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u8 risk_score;
    __u32 hits;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct process_ctx);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} process_cache SEC(".maps");

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

static __always_inline void increment_process_hits(__u32 pid) {
    struct process_ctx *ctx = bpf_map_lookup_elem(&process_cache, &pid);
    if (!ctx) {
        struct process_ctx new_ctx = {};
        new_ctx.pid = pid;
        new_ctx.last_seen = bpf_ktime_get_ns();
        new_ctx.hits = 1;
        bpf_map_update_elem(&process_cache, &pid, &new_ctx, BPF_ANY);
    } else {
        __sync_fetch_and_add(&ctx->hits, 1);
        ctx->last_seen = bpf_ktime_get_ns();
    }
}

// El JIT inyectará aquí la macro RE2C_LOGIC
#define NEXT_RULE_IDX {next_idx}

static __always_inline int match_all_re(__u8 *p, __u8 *pe) {
    __u8 *m;
    /*!re2c
    re2c:define:YYCTYPE = "unsigned char";
    re2c:define:YYCURSOR = p;
    re2c:define:YYLIMIT = pe;
    re2c:define:YYMARKER = m;
    re2c:yyfill:enable = 0;

    {re2c_rules}

    * { return 0; }
    */
}

SEC("xdp_regex")
int sigma_regex_chunk(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Offset basico para TCP payload (ignorar options por ahora para simplicidad)
    // 14 (eth) + 20 (ip) + 20 (tcp) = 54
    __u8 *p = data + 54;
    __u8 *pe = data_end;
    
    if (p + 1 > pe) return XDP_PASS; // Packet too small

    int matched_rule = match_all_re(p, pe);
    if (matched_rule > 0) {
        // En un futuro podemos notificar via ringbuf el rule_id exacto.
        // v4.4.2: Increment hits
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        increment_process_hits(pid);
        
        // v4.4.4: Increment regex_hits
        increment_stat(1);
        
        return XDP_DROP;
    }

    if (NEXT_RULE_IDX != 0xFFFFFFFF) {
        bpf_tail_call(ctx, &prog_array, NEXT_RULE_IDX);
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
