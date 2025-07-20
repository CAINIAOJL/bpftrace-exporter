#pragma once


#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "balancer_consts.h"
#include "balancer_csum_helpers.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

__always_inline long test_bpf_xdp_adjust_head(struct xdp_md* xdp_md, int delta) {
    long ret = bpf_xdp_adjust_head(xdp_md, delta);
    if(ret) {
        return ret;
    }

    if(delta >= 0) {
        return ret;
    }

    void* data = (void*)(long)xdp_md->data;
    void* data_end = (void*)(long)xdp_md->data_end;
    int offset = 0 - delta;

    if(data + offset > data_end) {
        return -1;
    }

    memset(data, 0xFF, offset);
    return ret;
}


__always_inline void create_encap_ipv6_src(__u16 port, __be32 src, __u32* saddr)
{
    saddr[0] = bpf_htonl(IPIP_V6_PREFIX1);
    saddr[1] = bpf_htonl(IPIP_V6_PREFIX2);
    saddr[2] = bpf_htonl(IPIP_V6_PREFIX3);
    saddr[3] = src ^ port;
    IPV6_TAIL_REVERT(&saddr[3]);
}

__always_inline __u32 create_encap_ipv4_src(__u16 port, __be32 src) {
    __u32 ip_suffix = bpf_htons(port);
    ip_suffix <<= 16;
    ip_suffix ^= bpf_htonl(src);
    return ((0xFFFF0000 & ip_suffix) | IPIP_V4_PREFIX);
}

__always_inline void create_v4_hdr(
                                struct iphdr* iph,
                                __u8 tos,
                                __u32 saddr,
                                __u32 daddr,
                                __u16 pkt_bytes,
                                __u8 proto)
{
    __u64 csum = 0;
    iph->version = 4;
    iph->ihl = 5;
    iph->frag_off = 0; //不分片
    iph->protocol = proto;
    iph->check = 0;
#ifdef COPY_INNER_PACKET_TOS
    iph->tos = tos;
#else 
    iph->tos = DEFAULT_TOS;
#endif
    iph->tot_len = bpf_htons(pkt_bytes + sizeof(struct iphdr));
    iph->id = 0;
    __be32 dsts = bpf_htonl(daddr);

#ifndef GUE_ENCAP
    __u32 reversed_saddr = 
        ((saddr & 0xFF000000) >> 24) |
        ((saddr & 0x00FF0000) >> 8) |
        ((saddr & 0x0000FF00) << 8) |
        ((saddr & 0x000000FF) << 24);
    __u32 srcs = bpf_htonl(reversed_saddr);
    iph->saddr = srcs;
#else
    iph->saddr = bpf_htonl(saddr);
#endif

    iph->daddr = dsts;
    iph->ttl = DEFAULT_TTL;
    ipv4_csum_inline(iph, &csum);
    iph->check = csum;
}

__always_inline void create_v6_hdr(
                                struct ipv6hdr* ip6h,
                                __u8 tc,
                                __u32* saddr,
                                __u32* daddr,
                                __u16 payload_len,
                                __u8 proto) {
    ip6h->version = 6;
    memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
#ifdef COPY_INNER_PACKET_TOS
    ip6h->priority = (tc & 0xF0) >> 4;
    ip6h->flow_lbl[0] = (tc & 0x0F) << 4;
    ip6h->flow_lbl[1] = 0;
    ip6h->flow_lbl[2] = 0;
#else
    ip6h->priority = DEFAULT_TOS;
#endif
    ip6h->nexthdr = proto;
    ip6h->payload_len = bpf_htons(payload_len);
    ip6h->hop_limit = DEFAULT_TTL;
    __be32 dstv6[4]; 
#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++) {
        dstv6[i] = bpf_htonl(daddr[i]);
    }
    __be32 srcv6[4];
#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++) {
        srcv6[i] = bpf_htonl(saddr[i]);
    }


    memcpy(ip6h->saddr.s6_addr32, srcv6, 16);
    memcpy(ip6h->daddr.s6_addr32, dstv6, 16);

}

__always_inline void create_udp_hdr(
                                struct udphdr* udph,
                                __u16 sport,
                                __u16 dport,
                                __u16 len,
                                __u16 csum) {
    udph->source = sport;
    udph->dest = dport;
    udph->len = len;
    udph->check = csum;
}