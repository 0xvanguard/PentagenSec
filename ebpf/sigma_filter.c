// ebpf/sigma_filter.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RULES 1024
#define MAX_PATTERN_LEN 64

struct sigma_rule {
    __u32 rule_id;
    __u16 dst_port; // 0 = any
    __u8 l4_proto;
    __u8 pattern_len;
    __u8 pattern[MAX_PATTERN_LEN]; // ej: "mimikatz", "powershell -enc"
    __u64 epoch; // v4.3: para hot-reload sin race
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct sigma_rule);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // Clave v4.3
} rules_map SEC(".maps");

// v4.3: Mapa de control para hot-reload
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); // current_epoch
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} control_map SEC(".maps");

// Ringbuf para pasar hits a userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} hits_rb SEC(".maps");

struct event_hit {
    __u64 ts;
    __u32 rule_id;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 payload[128]; // Truncado para SI-4
};

SEC("xdp")
int sigma_xdp_filter(struct xdp_md *ctx) {
    __u32 zero = 0;
    __u64 *epoch_ptr = bpf_map_lookup_elem(&control_map, &zero);
    __u64 current_epoch = epoch_ptr ? *epoch_ptr : 0;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    void *payload = (void *)tcp + sizeof(*tcp);
    __u64 payload_len = data_end - payload;
    if (payload_len < 1)
        return XDP_PASS;

    // v4.2: Itera reglas Sigma pre-compiladas
    #pragma unroll
    for (__u32 i = 0; i < MAX_RULES; i++) {
        struct sigma_rule *rule = bpf_map_lookup_elem(&rules_map, &i);
        if (!rule || rule->rule_id == 0)
            break; // Fin de reglas

        // v4.3: Solo aplica reglas de epoch actual
        if (rule->epoch != 0 && rule->epoch != current_epoch)
            continue;

        // Filtro L4: puerto
        if (rule->dst_port != 0 && rule->dst_port != bpf_ntohs(tcp->dest))
            continue;

        // Filtro L7: match substring simple en payload
        if (rule->pattern_len > 0 && rule->pattern_len <= payload_len) {
            __u8 *p = payload;
            __u8 found = 1;
            #pragma unroll
            for (__u8 j = 0; j < MAX_PATTERN_LEN; j++) {
                if (j >= rule->pattern_len)
                    break;
                if (p + j + 1 > (__u8 *)data_end || p[j] != rule->pattern[j]) {
                    found = 0;
                    break;
                }
            }

            if (found) {
                // HIT: envía a userspace vía ringbuf
                struct event_hit *e = bpf_ringbuf_reserve(&hits_rb, sizeof(*e), 0);
                if (e) {
                    e->ts = bpf_ktime_get_ns();
                    e->rule_id = rule->rule_id;
                    e->src_ip = ip->saddr;
                    e->dst_ip = ip->daddr;
                    e->src_port = bpf_ntohs(tcp->source);
                    e->dst_port = bpf_ntohs(tcp->dest);
                    bpf_probe_read_kernel(&e->payload, sizeof(e->payload), payload);
                    bpf_ringbuf_submit(e, 0);
                }
                return XDP_PASS; // Deja pasar para que Kafka lo capture
            }
        }
    }

    return XDP_DROP; // v4.2: Drop 99.5% ruido en kernel
}

char _license[] SEC("license") = "GPL";
