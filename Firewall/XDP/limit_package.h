#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "Firewall_consts.h"
#include "Firewall_structs.h"
#include "check.h"
#include "map.h"

#ifdef LIMIT_GLOBAL_PACKETS

static __always_inline int Refill_bucket(u64 now, 
                                        struct packet_description *pkt,
                                        struct Package_Count *pc,
                                        u8 protocol, 
                                        bool is_ipv6,
                                        u32 ifindex) {
    u64 new_tokens;
    u64 rate = 0;
    u64 burst = 0;
    struct rate_burst* RateAndBurst;                               
    struct token_bucket_key key = {};
    struct token_bucket *tb;
    struct token_bucket new_tb = {0};
    
    key.ifindex = ifindex;

    if(protocol == TB_INDEX_TCP) {
        key.category = TB_INDEX_TCP;
    } else if(protocol == TB_INDEX_UDP) {
        key.category = TB_INDEX_UDP;
    } else {
        key.category = TB_INDEX_GLOBAL;
    }

    RateAndBurst = (struct rate_burst*)bpf_map_lookup_elem(&Tb_BR_global, &key);
    if (RateAndBurst) {
        if (RateAndBurst->rate) {
            rate = RateAndBurst->rate;
        }
        if(RateAndBurst->burst) {
            burst = RateAndBurst->burst;
        }
    } else {
        goto PASS;
    }
    if(is_ipv6) {
        u128 ip;
        memcpy(&ip, pkt->flow.srcv6, sizeof(ip));
        if(check_ip6_white(ip, pkt->flow.port16[0], ifindex) == true) {
            pc->Allowed++;
#ifdef ENABLE_DEBUG_LOG
        struct Debug_Log *debug_log = bpf_ringbuf_reserve(&map_RingBuf, sizeof(struct Debug_Log), 0);
        if(debug_log) {
            memset(debug_log, 0, sizeof(struct Debug_Log));
            if(protocol == TB_INDEX_TCP) {
                debug_log->type = LOG_DEBUG_All;
            } else if(protocol == TB_INDEX_TCP) {
                debug_log->type = LOG_DEBUG_TCP;
            } else if(protocol == TB_INDEX_UDP) {
                debug_log->type = LOG_DEBUG_UDP;
            }
            debug_log->ip6 = ip;
            debug_log->version = V6;
            debug_log->mode = XDP_PASS;

            bpf_ringbuf_submit(debug_log, 0);
        }
#endif 
            goto PASS;
        }
    } else {
        u32 ip = pkt->flow.src;
        if(check_ip4_white(ip, pkt->flow.port16[0], ifindex) == true) {
            pc->Allowed++;
#ifdef ENABLE_DEBUG_LOG
        struct Debug_Log *debug_log = bpf_ringbuf_reserve(&map_RingBuf, sizeof(struct Debug_Log), 0);
        if(debug_log) {
            memset(debug_log, 0, sizeof(struct Debug_Log));
            if(protocol == TB_INDEX_TCP) {
                debug_log->type = LOG_DEBUG_All;
            } else if(protocol == TB_INDEX_TCP) {
                debug_log->type = LOG_DEBUG_TCP;
            } else if(protocol == TB_INDEX_UDP) {
                debug_log->type = LOG_DEBUG_UDP;
            }
            debug_log->ip = ip;
            debug_log->version = V4;
            debug_log->mode = XDP_PASS;

            bpf_ringbuf_submit(debug_log, 0);
        }
#endif
            goto PASS;
        }
    }

    tb = bpf_map_lookup_elem(&TB_global, &key);
    if (!tb) {
        new_tb.last_update_time = now;
        new_tb.tokens = burst;
        bpf_map_update_elem(&TB_global, &key, &new_tb, BPF_ANY);
        goto FURTHER;
    }

    u64 time_elapsed = now - tb->last_update_time;
    if(rate != 0) {
        new_tokens = (time_elapsed * rate) / TIME_NANOS;
    } else {
        goto PASS;
    }

    if(burst != 0) {
        new_tb.last_update_time = now;
        new_tb.tokens = tb->tokens + new_tokens > burst ? burst : tb->tokens + new_tokens;
        bpf_map_update_elem(&TB_global, &key, &new_tb, BPF_ANY);
        goto FURTHER;
    } else {
        goto PASS;
    }

PASS:
    return XDP_PASS;

FURTHER:
    return FURTHER_PROCESSING;
}

static __always_inline int Limit_global_packets(struct packet_description *pkt, 
                                                struct Package_Count *pc,
                                                u8 protocol, 
                                                bool is_ipv6,
                                                u32 ifindex)
{
    u64 now = bpf_ktime_get_ns();
    struct token_bucket_key key = {};
    key.category = protocol;
    key.ifindex = ifindex;
    struct token_bucket *_tb = (struct token_bucket*)bpf_map_lookup_elem(&TB_global, &key);
    if(!_tb || (_tb && _tb->last_update_time == 0)) {
        if(_tb) {
            struct token_bucket new_tb = *_tb;
            new_tb.last_update_time = now;
            bpf_map_update_elem(&TB_global, &key, &new_tb, BPF_ANY);
        }
        if(!_tb) {
        }
        goto PASS;
    }
    int action = Refill_bucket(now, pkt, pc, protocol, is_ipv6, ifindex);
    if(action >= 0) {
        return action;
    }
    struct token_bucket tb;
    struct token_bucket *new_tb = bpf_map_lookup_elem(&TB_global, &key);
    if(new_tb) {
        tb = *new_tb;
    }
    if(tb.tokens >= TOKENS_PER_PACKET) {
        tb.tokens -= TOKENS_PER_PACKET;
        bpf_map_update_elem(&TB_global, &key, &tb, BPF_ANY);
        goto PASS;
    } else {
        return XDP_DROP;
    }

PASS:
    return XDP_PASS;
}
#endif

#ifdef LIMIT_PACKETS_PER_IP

static __always_inline int Refill_bucket_ip(u64 now, 
                                            struct packet_description *pkt,
                                            bool is_ipv6,
                                            u32 ifindex) 
{
    u64 rate = 0;
    u64 burst = 0;
    u64 new_tokens = 0;
    struct tokens_rate_burst_key key = {};
    struct rate_burst* RateAndBurst;
    struct token_bucket *tb;
    if(!is_ipv6) {
        key.ip = pkt->flow.src;
        key.ifindex = ifindex;
        RateAndBurst = (struct rate_burst*)bpf_map_lookup_elem(&Tb_RB_Pre_Ip, &key);

    } else {
        memcpy(&key.ip6, pkt->flow.srcv6, sizeof(key.ip6));
        key.ifindex = ifindex;
        RateAndBurst = bpf_map_lookup_elem(&Tb_RB_Pre_Ip6, &key);
    }

    if(RateAndBurst) {
        if(RateAndBurst->burst != 0) {
            burst = RateAndBurst->burst;
        } else {
            goto FURTHER;
        }
        if(RateAndBurst->rate != 0) {
            rate = RateAndBurst->rate;
        } else {
            goto FURTHER;
        }
    }

    if (!is_ipv6) {
        tb = bpf_map_lookup_elem(&TB_Ip, &key);
    } else {
        tb = bpf_map_lookup_elem(&TB_Ip6, &key);
    }

    u64 time_elapsed;
    if(tb) {
        time_elapsed = now - tb->last_update_time;
    } else {
        goto FURTHER;
    }

    if(rate != 0) {
        new_tokens = (time_elapsed * rate ) / TIME_NANOS;
    } else {
        goto PASS;
    }

    if(burst != 0) {
        struct token_bucket new_tb = *tb;
        new_tb.tokens = new_tokens + tb->tokens > burst ? burst : new_tokens + tb->tokens;
        new_tb.last_update_time = now;
        if (is_ipv6) {
            bpf_map_update_elem(&TB_Ip6, &key, &new_tb, BPF_ANY);
        } else {
            bpf_map_update_elem(&TB_Ip, &key, &new_tb, BPF_ANY);
        }
        goto FURTHER;
    } else {
        goto PASS;
    }

PASS:
    return XDP_PASS;

FURTHER:
    return FURTHER_PROCESSING;
}

static __always_inline int Limit_ip_packets(struct packet_description *pkt, 
                                                struct Package_Count *pc, 
                                                bool is_ipv6,
                                                u32 ifindex) 
{
    u64 now = bpf_ktime_get_ns();
    struct token_bucket *tb;
    struct tokens_rate_burst_key key = {};
    int action;

    if(!is_ipv6) {
        key.ip = pkt->flow.src;
        key.ifindex = ifindex;
        tb = bpf_map_lookup_elem(&TB_Ip, &key);
    } else {
        memcpy(&key.ip6, pkt->flow.srcv6, sizeof(key.ip6));
        key.ifindex = ifindex;
        tb = bpf_map_lookup_elem(&TB_Ip6, &key);
    }

    if(!tb || (tb && tb->last_update_time == 0)) {
        struct token_bucket new_tb = {};
        if(tb) {
            new_tb.last_update_time = now;
            new_tb.tokens = tb->tokens;
            if(is_ipv6) {
                bpf_map_update_elem(&TB_Ip6, &key, &new_tb, BPF_ANY);
            } else {
                bpf_map_update_elem(&TB_Ip, &key, &new_tb, BPF_ANY);
            }
        }
        return XDP_PASS;
    }

    action = Refill_bucket_ip(now, pkt, is_ipv6, ifindex);
    if(action >= 0) {
        return action;
    }

    if(is_ipv6) {
        tb = bpf_map_lookup_elem(&TB_Ip6, &key);
    } else {
        tb = bpf_map_lookup_elem(&TB_Ip, &key);
    }
    
    if(!tb) {
        return XDP_PASS;
    }

    if(tb->tokens >= TOKENS_PER_PACKET) {
        struct token_bucket new_tb = *tb;
        new_tb.tokens -= TOKENS_PER_PACKET;
        
        if(is_ipv6) {
            bpf_map_update_elem(&TB_Ip6, &key, &new_tb, BPF_ANY);
        } else {
            bpf_map_update_elem(&TB_Ip, &key, &new_tb, BPF_ANY);
        }
        return XDP_PASS;
    } else {
        return XDP_DROP;
    }
}
#endif