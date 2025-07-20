#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include "Firewall_structs.h"
#include "Firewall_consts.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct Package_Count);
} Package_Count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_IFACES_IPS);
    __type(key, struct Ip_ifindex);
    __type(value, u32);
    __array(values, 
            struct {
                __uint(type, BPF_MAP_TYPE_HASH); 
                __uint(max_entries, MAX_IFACES_PORTS);
                __type(key, u16);
                __type(value, u8);
            });
} Rule SEC(".maps");

#ifdef ENABLE_IPV6
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_IFACES_IPS);
    __type(key, struct Ip6_ifindex);
    __type(value, u32);
    __array(values, 
            struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __uint(max_entries, MAX_IFACES_PORTS);
            __type(key, u16);
            __type(value, u8); 
        });
} Rule6 SEC(".maps");
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} map_RingBuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_IFACES);
    __uint(map_flags, NO_FLAGS);
    __type(key, u32);
    __type(value, u32);
    __array(values, struct {
            __uint(type, BPF_MAP_TYPE_LPM_TRIE);
            __uint(max_entries, MAX_LPM_IPS);
            __type(key, struct Lpm_trie_key4);
            __uint(map_flags, BPF_F_NO_PREALLOC);
            __type(value, u8);
    });
} Lpm_Rule4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_IFACES);
    __uint(map_flags, NO_FLAGS);
    __type(key, u32);
    __type(value, u32);
    __array(values, struct {
                __uint(type, BPF_MAP_TYPE_LPM_TRIE);
                __uint(max_entries, MAX_LPM_IPS);
                __type(key, struct Lpm_trie_key6);
                __uint(map_flags, BPF_F_NO_PREALLOC);
                __type(value, u8); 
        });
} Lpm_Rule6 SEC(".maps");

struct {
    __uint(type,  BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROTOCOL_COUNT);
    __type(key, struct token_bucket_key);
    __type(value, struct token_bucket);
} TB_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROTOCOL_COUNT);
    __type(key, struct token_bucket_key);
    __type(value, struct rate_burst); 
} Tb_BR_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, IP_COUNT);
    __type(key, struct tokens_rate_burst_key);
    __type(value, struct rate_burst);
} Tb_RB_Pre_Ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, IP_COUNT);
    __type(key, struct tokens_rate_burst_key);
    __type(value, struct rate_burst);
} Tb_RB_Pre_Ip6 SEC(".maps");

struct {
    __uint(type,  BPF_MAP_TYPE_HASH);
    __uint(max_entries, IP_COUNT);
    __type(key, struct tokens_rate_burst_key);
    __type(value, struct token_bucket);
} TB_Ip SEC(".maps");

struct {
    __uint(type,  BPF_MAP_TYPE_HASH);
    __uint(max_entries, IP_COUNT);
    __type(key, struct tokens_rate_burst_key);
    __type(value, struct token_bucket);
} TB_Ip6 SEC(".maps");