#pragma once
#include "Firewall_consts.h"
#include "Firewall_structs.h"
#include "map.h"
#include "limit_package.h"

static __always_inline int Process_rule(struct packet_description *pkt, struct Package_Count *pc, u32 ifindex) {
    u16 src_port_host = bpf_ntohs(pkt->flow.port16[0]); 
    u32 src_ip = pkt->flow.src;
    struct Ip_ifindex key = {};
    key.ifindex = ifindex;
    key.ip = src_ip;
    
    u32 *inner_map = bpf_map_lookup_elem(&Rule, &key);
    if (inner_map) {
        u8 *action = bpf_map_lookup_elem(inner_map, &src_port_host);
        if(action && *action == XDP_PASS) {
#ifdef ENABLE_DEBUG_LOG
            struct Debug_Log *debug_log = bpf_ringbuf_reserve(&map_RingBuf, sizeof(struct Debug_Log), 0);
            if(debug_log) {
                memset(debug_log, 0, sizeof(*debug_log));
                debug_log->ip = src_ip; //32位
                debug_log->port = src_port_host;
                debug_log->protocol = bpf_ntohs(pkt->flow.proto);
                debug_log->mode = XDP_PASS;
                debug_log->version = V4;
            
                bpf_ringbuf_submit(debug_log, 0);
            }
#endif
            return XDP_PASS;
        } else if (action && *action == XDP_DROP) {
#ifdef ENABLE_DEBUG_LOG
        struct Debug_Log *debug_log = bpf_ringbuf_reserve(&map_RingBuf, sizeof(struct Debug_Log), 0);
        if(debug_log) {
            memset(debug_log, 0, sizeof(*debug_log));
            debug_log->type = LOG_DEBUG_RULE;
            debug_log->ip = src_ip;
            memset(&debug_log->ip6, 0, sizeof(debug_log->ip6));
            debug_log->port = src_port_host;
            debug_log->protocol = bpf_ntohs(pkt->flow.proto);
            debug_log->mode = XDP_DROP;
            debug_log->version = V4;

            bpf_ringbuf_submit(debug_log, 0);
        }
#endif
            pc->Dropped.Active_Dropped++;
            return XDP_DROP;
        }
    }
    return FURTHER_PROCESSING;
}

#ifdef ENABLE_IPV6
static __always_inline int Process6_rule(struct packet_description *pkt, struct Package_Count *pc, u32 ifindex) 
{
    u16 src_port_host = bpf_ntohs(pkt->flow.port16[0]);
    u128 src_ip;
    memcpy(&src_ip, pkt->flow.srcv6, sizeof(src_ip));
    struct Ip6_ifindex key = {};
    key.ifindex = ifindex;
    memcpy(&key.ip, &src_ip, sizeof(key.ip));
    u32 *inner_map = bpf_map_lookup_elem(&Rule6, &key);
    if (inner_map) {
        u8 *action = bpf_map_lookup_elem(inner_map, &src_port_host);
        if(action && *action == XDP_PASS) {
#ifdef ENABLE_DEBUG_LOG
            struct Debug_Log *debug_log = bpf_ringbuf_reserve(&map_RingBuf, sizeof(struct Debug_Log), 0);
            if(debug_log) {
                memset(debug_log, 0, sizeof(*debug_log));
                debug_log->type = LOG_DEBUG_RULE;
                debug_log->ip6 = src_ip;
                debug_log->port = src_port_host;
                debug_log->protocol = bpf_ntohs(pkt->flow.proto);
                debug_log->mode = *action;
                debug_log->version = V6;

                bpf_ringbuf_submit(debug_log, 0);
            }
#endif //ENABLE_DEBUG_LOG
            return XDP_PASS;

        } else if (action && *action == XDP_DROP) {
#ifdef ENABLE_DEBUG_LOG
        struct Debug_Log *debug_log = bpf_ringbuf_reserve(&map_RingBuf, sizeof(struct Debug_Log), 0);
        if(debug_log) {
            memset(debug_log, 0, sizeof(*debug_log));
            debug_log->ip = 0;
            debug_log->ip6 = src_ip;
            debug_log->port = src_port_host;
            debug_log->protocol = bpf_ntohs(pkt->flow.port16[0]);
            debug_log->mode = *action;
            debug_log->version = V6;

            bpf_ringbuf_submit(debug_log, 0);
        }
#endif
            pc->Dropped.Active_Dropped++;
            return XDP_DROP;
        }
    }
    return FURTHER_PROCESSING; 
}
#endif