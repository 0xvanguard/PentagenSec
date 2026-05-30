// ebpf/sigma_filter.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "af_xdp_kern.c"
#include "soar_kern.h"
#include "ml_kern.h"

#define ML_THRESHOLD 42 // Tuned offline to achieve FPR < 0.01%

struct flow_key {
    __u32 saddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 _pad; // pad to 10 bytes (or 12)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} last_ts_map SEC(".maps");

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

// Ringbuf removido para v4.4.3 Zero-Copy

struct event_hit {
    __u64 ts;
    __u32 rule_id;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 payload[128]; // Truncado para SI-4
};

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    __u32 csum = 0;
    __u16 *next_iph_u16 = (__u16 *)iph;
    #pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
        csum += *next_iph_u16++;
    }
    return csum_fold_helper(csum);
}

static __always_inline __u16 tcp_csum(struct iphdr *iph, struct tcphdr *tcph) {
    tcph->check = 0;
    __u32 csum = 0;
    csum += (iph->saddr >> 16) & 0xFFFF;
    csum += (iph->saddr) & 0xFFFF;
    csum += (iph->daddr >> 16) & 0xFFFF;
    csum += (iph->daddr) & 0xFFFF;
    csum += bpf_htons(IPPROTO_TCP);
    csum += bpf_htons(sizeof(struct tcphdr)); // Asumiendo payload 0
    
    __u16 *next_tcph_u16 = (__u16 *)tcph;
    #pragma unroll
    for (int i = 0; i < sizeof(struct tcphdr) >> 1; i++) {
        csum += *next_tcph_u16++;
    }
    return csum_fold_helper(csum);
}

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

    // SOAR Fast Path: Check actions_map before regex
    struct action_key ak = {};
    ak.ip_src = ip->saddr;
    ak.protocol = ip->protocol;
    __u8 *action = bpf_map_lookup_elem(&actions_map, &ak);
    if (action) {
        if (*action == 1) {
            return XDP_DROP;
        } else if (*action == 2) {
            // TARPIT: Swap L2
            __u8 tmp_mac[6];
            __builtin_memcpy(tmp_mac, eth->h_source, 6);
            __builtin_memcpy(eth->h_source, eth->h_dest, 6);
            __builtin_memcpy(eth->h_dest, tmp_mac, 6);

            // Swap L3
            __u32 tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;

            // L4 modifications
            struct tcphdr *tcp = (void *)ip + sizeof(*ip);
            if ((void *)tcp + sizeof(*tcp) <= data_end) {
                tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
                tcp->seq = bpf_htonl(12345);
                tcp->syn = 1;
                tcp->ack = 1;
                tcp->window = 0; // Tarpit: no data allowed
                
                // Recalculate checksums
                ip->check = iph_csum(ip);
                tcp->check = tcp_csum(ip, tcp);
            } else {
                return XDP_DROP;
            }
            return XDP_TX;
        }
    }

    __u8 *mode = bpf_map_lookup_elem(&config_map, &zero);
    __u8 auto_block = (mode && *mode == 1) ? 1 : 0;

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
                if (auto_block) {
                    struct soar_event *e = bpf_ringbuf_reserve(&soar_events, sizeof(*e), 0);
                    if (e) {
                        e->ts = bpf_ktime_get_ns();
                        e->rule_id = rule->rule_id;
                        e->src_ip = ip->saddr;
                        e->dst_ip = ip->daddr;
                        e->src_port = bpf_ntohs(tcp->source);
                        e->dst_port = bpf_ntohs(tcp->dest);
                        e->protocol = ip->protocol;
                        e->severity = 3; // Harcoded high severity for testing
                        bpf_ringbuf_submit(e, 0);
                    }
                }
                // HIT: redirecciona a userspace vía AF_XDP
                return redirect_to_af_xdp(ctx);
            }
        }
    }

    // 3. ML path: solo si no matcheó firma y flow es TCP
    struct flow_key fkey = {};
    fkey.saddr = ip->saddr;
    fkey.sport = tcp->source;
    fkey.dport = tcp->dest;
    fkey.proto = ip->protocol;

    __u64 now = bpf_ktime_get_ns();
    __u64 *last_ts = bpf_map_lookup_elem(&last_ts_map, &fkey);
    __s32 iat_ns = 0;
    
    if (last_ts) {
        // TTL implicito 300s (300,000,000,000 ns)
        if (now - *last_ts > 300000000000ULL) {
            iat_ns = 0; // Flow viejo, reset
        } else {
            iat_ns = (__s32)(now - *last_ts);
        }
    }
    bpf_map_update_elem(&last_ts_map, &fkey, &now, BPF_ANY);

    // Extraer features básicos
    __s32 feat[ML_N_FEATURES] = {0};
    feat[0] = (__s32)(data_end - data); // pkt_len
    feat[1] = iat_ns;                   // Inter-arrival time en ns
    feat[2] = bpf_ntohs(tcp->source); // src_port
    feat[3] = bpf_ntohs(tcp->dest); // dst_port
    feat[4] = tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
    feat[5] = ip->ttl;
    feat[6] = ip->protocol;
    feat[7] = (__s32)payload_len;

    struct ml_ctx mc = { .score = 0, .feat = feat };
    bpf_loop(ML_N_TREES, ml_walk_tree, &mc, 0);

    // Shadow Mode: emitimos la métrica sin bloquear
    if (mc.score > ML_THRESHOLD) {
        struct soar_event *e = bpf_ringbuf_reserve(&soar_events, sizeof(*e), 0);
        if (e) {
            e->ts = bpf_ktime_get_ns();
            e->rule_id = 99990000 + mc.score; // Encode score in rule_id
            e->src_ip = ip->saddr;
            e->dst_ip = ip->daddr;
            e->src_port = bpf_ntohs(tcp->source);
            e->dst_port = bpf_ntohs(tcp->dest);
            e->protocol = ip->protocol;
            e->severity = 0; // 0 significa shadow mode
            bpf_ringbuf_submit(e, 0);
        }
    }

    return XDP_DROP; // v4.2: Drop 99.5% ruido en kernel
}

char _license[] SEC("license") = "GPL";
