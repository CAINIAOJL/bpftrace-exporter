#pragma once

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "balancer_consts.h"
__always_inline int decrement_ttl(
                                void* data, 
                                void* data_end, 
                                int offset, 
                                bool is_ipv6)
{
    struct iphdr* iph;
    struct ipv6hdr* ipv6h;

    if(is_ipv6) {
        if ((data + offset + sizeof(struct ipv6hdr)) > data_end) {
            return XDP_DROP;
        }
        ipv6h = (struct ipv6hdr*)(data + offset);
        if (!--ipv6h->hop_limit) {
            // ttl 0
            return XDP_DROP;
        }
        //bpf_printk("ttlv6 : %d", ipv6h->hop_limit);
    } else {
        if((data + offset + sizeof(struct iphdr)) > data_end) {
            return XDP_DROP;
        }
        iph = (struct iphdr*)(data + offset);
        __u32 csum;

        if(!--iph->ttl) {
            return XDP_DROP;
        }
        //bpf_printk("ttlv4 : %d", iph->ttl);
        csum = iph->check + 0x0001;
        iph->check = (csum & 0xffff) + (csum >> 16);
    }
    return FURTHER_PROCESSING;
}

__always_inline int recirculate(struct xdp_md* ctx) {
    int i = RECIRCULATION_INDEX;
    bpf_tail_call(ctx, &subprograms, i);
    return XDP_PASS;
}

static __always_inline void print_ipv4_dotted(__be32 addr) {
    unsigned int a = bpf_ntohl(addr);
    unsigned char bytes[4] = {
        (a >> 24) & 0xFF,
        (a >> 16) & 0xFF,
        (a >> 8) & 0xFF,
        a & 0xFF
    };
}

static __always_inline void print_real_def(struct real_definition *real) {
    bpf_printk("IPv4: 0x%x\n", real->dst);

    bpf_printk("IPv6: %x %x %x %x\n",
               real->dstv6[0], real->dstv6[1],
               real->dstv6[2], real->dstv6[3]);

    bpf_printk("Flags: 0x%x\n", real->flags);
}
