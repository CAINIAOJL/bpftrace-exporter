#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
#include "Firewall_consts.h"
#include "Firewall_structs.h"
#include "map.h"


static __always_inline bool check_ip4_white(u32 ip, u16 port, u32 ifindex) {
    struct Ip_ifindex key = {};
    key.ifindex = ifindex;
    key.ip = ip;
    u8* action;
    u32* is_in_rule = (u32*)bpf_map_lookup_elem(&Rule, &key);
    if (is_in_rule) {
        action = bpf_map_lookup_elem((void*)is_in_rule, &port);
        if (action && *action == XDP_PASS) {
            return true;
        }
    } 

    struct Lpm_trie_key4 lpm_key = {};
    lpm_key.prefixlen = 32;
    lpm_key.data = ip;
    u32 new_ifindex = ifindex + 1;
    u32 *lpm_map = bpf_map_lookup_elem(&Lpm_Rule4, &new_ifindex);
    if(lpm_map) {
        action = (u8 *)bpf_map_lookup_elem(lpm_map, &lpm_key);
        if(action && *action == XDP_PASS) {
            return true;
        }
    }
    return false;
}

#ifdef ENABLE_IPV6
static __always_inline bool check_ip6_white(u128 ip, u16 port, u32 ifindex) {
    struct Ip6_ifindex key = {};
    key.ifindex = ifindex;
    memcpy(&key.ip, &ip, sizeof(key.ip));
    u8 *action;
    u32* is_in_rule = (u32*)bpf_map_lookup_elem(&Rule6, &key);
    if (is_in_rule) {
        action = bpf_map_lookup_elem((void*)is_in_rule, &port);
        if (action && *action == XDP_PASS) {
            return true;
        }
    } 

    struct Lpm_trie_key6 lpm_key = {};
    lpm_key.prefixlen = 128;
    memcpy(&lpm_key.ip, &ip, sizeof(lpm_key.ip));
    
    u32 new_ifindex = ifindex + 1;
    u32 *lpm_map = bpf_map_lookup_elem(&Lpm_Rule6, &new_ifindex);
    if(lpm_map) {
        action = (u8 *)bpf_map_lookup_elem(lpm_map, &lpm_key);
        if(action && *action == XDP_PASS) {
            return true;
        }
    }
    
    return false;
}
#endif
static __always_inline void print_ipv4_dotted(__be32 addr) {
    unsigned int a = bpf_ntohl(addr);
    unsigned char bytes[4] = {
        (a >> 24) & 0xFF,
        (a >> 16) & 0xFF,
        (a >> 8) & 0xFF,
        a & 0xFF
    };
    
    bpf_printk("ipv4 is %u.%u.%u.%u",bytes[3], bytes[2], bytes[1], bytes[0]);
}
