#pragma once


#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include "balancer_consts.h"
#include "balancer_struct.h"
#include "balancer_helpers.h"
#include "balancer_parse.h"


struct stable_routing_header {
    __u8 connection_id[STABLE_RT_LEN];
} __attribute__((__packed__));

struct udp_stable_rt_result {
    __be32 server_id;
    bool is_stable_rt_pkt;
};

__always_inline struct udp_stable_rt_result parse_udp_stable_rt_hdr(
                            void* data, 
                            void* data_end, 
                            struct packet_description* pckt, 
                            bool is_ipv6) 
{
    struct udp_stable_rt_result res = {
        .server_id = 0,
        .is_stable_rt_pkt = false,
    };
    bool is_icmp = (pckt->flags & F_ICMP);
    __u64 off = calc_offset(is_ipv6, is_icmp);

    if(data + off + sizeof(struct udphdr) + sizeof(__u8) > data_end) {
        return res;
    }

    __u8* udp_data = (__u8*)(data + off + sizeof(struct udphdr));
    __u8* pkt_type = udp_data;
    __u8* connId = (__u8*)NULL;

    if((*pkt_type) == 82) {
        //稳定路由的头部标识
        if(udp_data + sizeof(struct stable_routing_header) > data_end) {
            return res;
        }
        connId = ((struct stable_routing_header*)udp_data)->connection_id;
        res.is_stable_rt_pkt = true;
    }

    if(!connId) {
        return res;
    }

    res.server_id = (connId[1] << 16) | (connId[2] << 8) | (connId[3]);
    return res;

}