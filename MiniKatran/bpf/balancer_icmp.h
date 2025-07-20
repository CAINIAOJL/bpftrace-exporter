#pragma once

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stddef.h>

#include <bpf/bpf_endian.h>
#include <linux/bpf.h>

#include "balancer_consts.h"
#include "balancer_struct.h"
#include "balancer_map.h"
#include "balancer_helpers.h"
#include "balancer_csum_helpers.h"


__always_inline int swap_mac_and_send(void* data, void* data_end)
{
    struct ethhdr* eth;
    unsigned char mac_[ETH_ALEN];
    eth = (struct ethhdr*)data;
    memcpy(&mac_, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, &mac_, ETH_ALEN);
    return XDP_TX;
}

__always_inline int swap_mac(void* data, struct ethhdr* orig_eth) {
    struct ethhdr* eth;
    eth = (struct ethhdr*)data;
    memcpy(eth->h_source, orig_eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, orig_eth->h_source, ETH_ALEN);
    eth->h_proto = orig_eth->h_proto;
}

__always_inline int send_icmp6_reply(void* data, void* data_end) {
    struct ipv6hdr* ip6h;
    struct icmp6hdr* icmp_hdr;
    __be32 addr_[4];
    __u64 off = 0;

    if((data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr)) > data_end) {
        return XDP_DROP;
    }

    off += sizeof(struct ethhdr);
    ip6h = (struct ipv6hdr*)(data + off);
    off += sizeof(struct ipv6hdr);
    icmp_hdr = (struct icmp6hdr*)(data + off);
    icmp_hdr->icmp6_type = ICMPV6_ECHO_REPLY;

    icmp_hdr->icmp6_cksum -= 0x0001;
    ip6h->hop_limit = DEFAULT_TTL;
    memcpy(&addr_, ip6h->saddr.s6_addr32, 16);
    memcpy(ip6h->saddr.s6_addr32, ip6h->daddr.s6_addr32, 16);
    memcpy(ip6h->daddr.s6_addr32, &addr_, 16);
    return swap_mac_and_send(data, data_end);
}

__always_inline int send_icmp6_too_big(struct xdp_md* xdp) {
    int headroom = (int)sizeof(struct ipv6hdr) + (int)sizeof(struct icmp6hdr);
    if(test_bpf_xdp_adjust_head(xdp, 0 - headroom)) {
        return XDP_DROP;
    }

    void* data = (void*)(long)xdp->data;
    void* data_end = (void*)(long)xdp->data_end;
    if(data + (ICMP6_TOOBIG_SIZE + headroom) > data_end) {
        return XDP_DROP;
    }

    struct ipv6hdr* ip6h, *orig_ip6h;
    struct ethhdr* orig_eth;
    struct icmp6hdr* icmp6_hdr;

    __u64 csum = 0;
    __u64 off = 0;
    orig_eth = (struct ethhdr*)(data + headroom);
    swap_mac(data, orig_eth);
    off += sizeof(struct ethhdr);
    ip6h = (struct ipv6hdr*)(data + off);
    off += sizeof(struct ipv6hdr);
    icmp6_hdr = (struct icmp6hdr*)(data + off);
    off += sizeof(struct icmp6hdr);
    orig_ip6h = (struct ipv6hdr*)(data + off);
    ip6h->version = 6;
    ip6h->priority = 0;
    ip6h->nexthdr = IPPROTO_ICMPV6;
    ip6h->hop_limit = DEFAULT_TTL;
    ip6h->payload_len = bpf_htons(ICMP6_TOOBIG_PAYLOAD_SIZE);
    ip6h->flow_lbl[0] = 0;
    ip6h->flow_lbl[1] = 0;
    ip6h->flow_lbl[2] = 0;
    //("ip6h daddr: %u %u %u %u", bpf_ntohl(ip6h->daddr.in6_u.u6_addr32[0]),
                                          //bpf_ntohl(ip6h->daddr.in6_u.u6_addr32[1]),
                                          //bpf_ntohl(ip6h->daddr.in6_u.u6_addr32[2]),
                                          //bpf_ntohl(ip6h->daddr.in6_u.u6_addr32[3]));
    //bpf_printk("ip6h saddr: %u %u %u %u", bpf_ntohl(ip6h->saddr.in6_u.u6_addr32[0]),
                                          //bpf_ntohl(ip6h->saddr.in6_u.u6_addr32[1]),
                                          //bpf_ntohl(ip6h->saddr.in6_u.u6_addr32[2]),
                                          //bpf_ntohl(ip6h->saddr.in6_u.u6_addr32[3]));
    memcpy(ip6h->daddr.s6_addr32, orig_ip6h->saddr.s6_addr32, 16);
    memcpy(ip6h->saddr.s6_addr32, orig_ip6h->daddr.s6_addr32, 16);
    icmp6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
    icmp6_hdr->icmp6_code = 0;
    icmp6_hdr->icmp6_mtu = bpf_htonl(MAX_PCKT_SIZE - sizeof(struct ethhdr));
    icmp6_hdr->icmp6_cksum = 0;
    ipv6_csum(icmp6_hdr, ICMP6_TOOBIG_PAYLOAD_SIZE, &csum, ip6h);
    icmp6_hdr->icmp6_cksum = csum;

    return XDP_TX;
}

__always_inline int send_icmp4_too_big(struct xdp_md* ctx) {
    int headroom = (int)sizeof(struct iphdr) + (int)sizeof(struct icmphdr);
    if(test_bpf_xdp_adjust_head(ctx, 0 - headroom)) {
        return XDP_DROP;
    }

    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    if(data + (ICMP_TOOBIG_SIZE + headroom) > data_end) {
        return XDP_DROP;
    }

    struct iphdr* iph, *orig_iph;
    struct ethhdr* orig_eth;
    struct icmphdr* icmp_hdr;

    __u64 csum = 0;
    __u64 off = 0;

    orig_eth = (struct ethhdr*)(data + headroom);
    swap_mac(data, orig_eth);
    off += sizeof(struct ethhdr);
    iph = (struct iphdr*)(data + off);
    off += sizeof(struct iphdr);
    icmp_hdr = (struct icmphdr*)(data + off);
    off += sizeof(struct icmphdr);
    orig_iph = (struct iphdr*)(data + off);
    icmp_hdr->type = ICMP_DEST_UNREACH;
    icmp_hdr->code = ICMP_FRAG_NEEDED;
    icmp_hdr->un.frag.mtu = bpf_htons(MAX_PCKT_SIZE - sizeof(struct ethhdr));
    icmp_hdr->un.frag.__unused = 0;
    icmp_hdr->checksum = 0;
    ipv4_csum(icmp_hdr, ICMP_TOOBIG_PAYLOAD_SIZE, &csum);
    icmp_hdr->checksum = csum;
    iph->ttl = DEFAULT_TTL;
    iph->daddr = orig_iph->saddr;
    iph->saddr = orig_iph->daddr;
    iph->frag_off = 0;
    iph->version = 4;
    iph->ihl = 5;
    iph->protocol = IPPROTO_ICMP;
    iph->tos = 0;
    iph->tot_len = bpf_htons(ICMP_TOOBIG_SIZE + headroom - sizeof(struct ethhdr));
    iph->id = 0;
    iph->check = 0;
    csum = 0;
    ipv4_csum(iph, sizeof(struct iphdr), &csum);
    iph->check = csum;

    return XDP_TX;
}

__always_inline int send_icmp_reply(void* data, void* data_end) {
    struct icmphdr* icmp_hdr;
    struct iphdr* iph;
    __u32 add_ = 0;
    __u64 csum = 0;
    __u64 off = 0;

    if((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)) > data_end) {
        return XDP_DROP;
    }

    off += sizeof(struct ethhdr);
    iph = (struct iphdr*)(data + off);
    off += sizeof(struct iphdr);
    icmp_hdr = (struct icmphdr*)(data + off);

    icmp_hdr->type = ICMP_ECHOREPLY;
    icmp_hdr->checksum += 0x0008;
    iph->ttl = DEFAULT_TTL;
    add_ = iph->daddr;
    iph->daddr = iph->saddr;
    iph->saddr = add_;
    iph->check = 0;
    ipv4_csum_inline(iph, &csum);
    iph->check = csum;

    return swap_mac_and_send(data, data_end);
}

__always_inline int parse_icmp(
                                void* data, 
                                void* data_end, 
                                __u64 off, 
                                struct packet_description* pckt) 
{

    struct icmphdr* icmp_hdr;
    struct iphdr* iph;
    icmp_hdr = (struct icmphdr*)(data + off);
    if(icmp_hdr + 1 > data_end) {
        return XDP_DROP;
    }

    if(icmp_hdr->type == ICMP_ECHO) {
        return send_icmp_reply(data, data_end);
    }

    if(icmp_hdr->type != ICMP_DEST_UNREACH) {
        return XDP_PASS;
    }

    if(icmp_hdr->code == ICMP_FRAG_NEEDED) {
        __u32 stats_key = MAX_VIPS + ICMP_PTB_V4_STATS;
        struct lb_stats* icmp_ptb_v4_stats = (struct lb_stats*)bpf_map_lookup_elem(&stats, &stats_key);
        if(!icmp_ptb_v4_stats) {
            return XDP_DROP;
        }
        icmp_ptb_v4_stats->v1 += 1;
        __u16 mtu = bpf_ntohs(icmp_hdr->un.frag.mtu);
        if(mtu < MAX_MTU_IN_PTB_TO_DROP) {
            icmp_ptb_v4_stats->v2 += 1;
        }
    }

    off += sizeof(struct icmphdr);
    iph = (struct iphdr*)(data + off);
    if(iph + 1 > data_end) {
        return XDP_DROP;
    }

    if(iph->ihl != 5) {
        return XDP_DROP;
    }

    pckt->flow.proto = iph->protocol;
    pckt->flags |= F_ICMP;
    pckt->flow.src = iph->daddr;
    pckt->flow.dst = iph->saddr;
    return FURTHER_PROCESSING;
}

__always_inline int parse_icmpv6(
                                void* data, 
                                void* data_end, 
                                __u64 off, 
                                struct packet_description* pckt) 
{
    struct icmp6hdr* icmp_hdr;
    struct ipv6hdr* ip6h;
    icmp_hdr = (struct icmp6hdr*)(data + off);
    if(icmp_hdr + 1 > data_end) {
        return XDP_DROP;
    }

    if(icmp_hdr->icmp6_type == ICMPV6_ECHO_REQUEST) {
        return send_icmp6_reply(data, data_end);
    }

    if((icmp_hdr->icmp6_type != ICMPV6_PKT_TOOBIG) && (icmp_hdr->icmp6_type != ICMPV6_DEST_UNREACH)) {
        //bpf_printk("icmp6_type: %d: XDP_PASS", icmp_hdr->icmp6_type);
        return XDP_PASS; //交给内核栈
    }

    if(icmp_hdr->icmp6_type == ICMPV6_PKT_TOOBIG) {
        __u32 stats_key = MAX_VIPS + ICMP_PTB_V6_STATS;
        struct lb_stats* icmp_ptb_v6_stats = (struct lb_stats*)bpf_map_lookup_elem(&stats, &stats_key);
        if(!icmp_ptb_v6_stats) {
            return XDP_DROP;
        }
        icmp_ptb_v6_stats->v1 += 1;
        __u16 mtu = bpf_ntohs(icmp_hdr->icmp6_mtu);
        if(mtu < MAX_MTU_IN_PTB_TO_DROP) {
            icmp_ptb_v6_stats->v2 += 1;
        }
    }

    off += sizeof(struct icmp6hdr);

    ip6h = (struct ipv6hdr*)(data + off);

    if(ip6h + 1 > data_end) {
        return XDP_DROP;
    }

    pckt->flow.proto = ip6h->nexthdr;
    pckt->flags |= F_ICMP;
    memcpy(pckt->flow.srcv6, ip6h->daddr.s6_addr32, 16);
    memcpy(pckt->flow.dstv6, ip6h->saddr.s6_addr32, 16);
    return FURTHER_PROCESSING;
}


__always_inline int send_icmp_too_big(struct xdp_md* xdp, int pckt_size, bool is_ipv6) {
    int offset = pckt_size;
    if(is_ipv6) {
        offset -= ICMP6_TOOBIG_SIZE;
    } else {
        offset -= ICMP_TOOBIG_SIZE;
    }

    if(bpf_xdp_adjust_tail(xdp, 0 - offset)) {
        return XDP_DROP;
    }

    if(is_ipv6) {
        return send_icmp6_too_big(xdp);
    } else {
        return send_icmp4_too_big(xdp);
    }
}

__always_inline bool ignorable_quic_icmp_code(
                                            void* data, 
                                            void* data_end, 
                                            bool is_ipv6) {
  __u64 off = sizeof(struct ethhdr);
  if (is_ipv6) {
    struct icmp6hdr* icmp_hdr = data + off + sizeof(struct ipv6hdr);
    return (
        (icmp_hdr->icmp6_code == ICMPV6_ADDR_UNREACH) ||
        (icmp_hdr->icmp6_code == ICMPV6_PORT_UNREACH));
  } else {
    struct icmphdr* icmp_hdr = data + off + sizeof(struct iphdr);
    return (
        (icmp_hdr->code == ICMP_PORT_UNREACH) ||
        (icmp_hdr->code == ICMP_HOST_UNREACH));
  }
}