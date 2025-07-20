#pragma once

#include "Firewall_structs.h"
#include "Firewall_consts.h"
#include <bpf/bpf_endian.h>
#include "map.h"
static __always_inline int is_ip_in_range(u32 src_ip, u32 net_ip, u8 cidr)
{
    return !((src_ip ^ net_ip) & bpf_htonl(0xFFFFFFFFu << (32 - cidr)));
}

#ifdef ENABLE_LPM_RULE
static __always_inline int Check_Lpm_Rule_v4(u32 ip, u32 ifindex) {

    struct Lpm_trie_key4 key = {};
    key.prefixlen = 32;
    key.data = ip;
    ifindex++;
    void * inner_map = bpf_map_lookup_elem(&Lpm_Rule4, &ifindex);
    if (inner_map) {
        u8 *action = (u8 *)bpf_map_lookup_elem(inner_map, &key);
        if (action) {
#ifdef ENABLE_DEBUG_LOG
        struct Debug_Log *debug_log = bpf_ringbuf_reserve(&map_RingBuf, sizeof(struct Debug_Log), 0);
        if(debug_log) {
            memset(debug_log, 0, sizeof(struct Debug_Log));
            debug_log->type = LOG_DEBUG_LPM;
            debug_log->ip = ip;
            debug_log->version = V4;
            debug_log->mode = *action;

            bpf_ringbuf_submit(debug_log, 0);
        }
#endif
            return *action;
        }
    }
    
    return FURTHER_PROCESSING;
}

#ifdef ENABLE_IPV6
static __always_inline int Check_Lpm_Rule_v6(u128 ip, u32 ifindex) {
    struct Lpm_trie_key6 key = {};
    key.prefixlen = 128;
    memcpy(key.ip, &ip, sizeof(key.ip));
    ifindex++;
    void *lpm_inner_map = bpf_map_lookup_elem(&Lpm_Rule6, &ifindex);
    if (lpm_inner_map) {
        u8 *action = (u8 *)bpf_map_lookup_elem(lpm_inner_map, &key);
        if(action) {
#ifdef ENABLE_DEBUG_LOG
        struct Debug_Log *debug_log = bpf_ringbuf_reserve(&map_RingBuf, sizeof(struct Debug_Log), 0);
        if(debug_log) {
            memset(debug_log, 0, sizeof(struct Debug_Log));
            debug_log->type = LOG_DEBUG_LPM;
            debug_log->ip6 = ip;
            debug_log->version = V6;
            debug_log->mode = *action;

            bpf_ringbuf_submit(debug_log, 0);
        }
#endif
            return *action;
        }
    }    
    return FURTHER_PROCESSING;
}

#endif //ENABLE_IPV6
#endif //ENABLE_LPM_RULE