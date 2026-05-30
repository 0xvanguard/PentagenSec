// SPDX-License-Identifier: GPL-2.0
#ifndef __SOAR_KERN_H
#define __SOAR_KERN_H

#include <bpf/bpf_helpers.h>

struct action_key {
    __u32 ip_src; // IPv4
    __u16 port_src;
    __u8 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536); // 65k IPs bloqueadas
    __type(key, struct action_key);
    __type(value, __u8); // 1=DROP, 2=RATELIMIT, 3=TARPIT
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} actions_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8); // 0=Monitor, 1=Auto-Block
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

struct soar_event {
    __u64 ts;
    __u32 rule_id;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 severity; // 1-4
};

// Ringbuf para pasar eventos a userspace SOAR
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} soar_events SEC(".maps");

#endif
