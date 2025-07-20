#pragma once

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include "balancer_consts.h"
#include "balancer_encap_helpers.h"


//解封装函数
//v6->v4/v6
__always_inline bool decap_v6(
                            struct xdp_md* xdp, 
                            void** data, 
                            void** data_end, 
                            bool inner_v4) {
    struct ethhdr* new_eth;
    struct ethhdr* old_eth;

    old_eth = (struct ethhdr*)*data;
    new_eth = (struct ethhdr*)(*data + sizeof(struct ipv6hdr));
    memcpy(new_eth->h_source, old_eth->h_source, 6);
    memcpy(new_eth->h_dest, old_eth->h_dest, 6);

    if(inner_v4) {
        new_eth->h_proto = BE_ETH_P_IP;
    } else {
        new_eth->h_proto = BE_ETH_P_IPV6;
    }

    if(test_bpf_xdp_adjust_head(xdp, (int)sizeof(struct ipv6hdr))) {
        return false;
    }

    *data = (void*)(long)xdp->data;
    *data_end = (void*)(long)xdp->data_end;
    return true;
}

//v4->v4
__always_inline bool decap_v4(
                            struct xdp_md* xdp, 
                            void** data, 
                            void** datat_end) {
    struct ethhdr* new_eth;
    struct ethhdr* old_eth;
    old_eth = (struct ethhdr*)*data;
    new_eth = (struct ethhdr*)(*data + sizeof(struct iphdr));
    memcpy(new_eth->h_source, old_eth->h_source, 6);
    memcpy(new_eth->h_dest, old_eth->h_dest, 6);

    new_eth->h_proto = BE_ETH_P_IP; //v4
    if(test_bpf_xdp_adjust_head(xdp, (int)sizeof(struct iphdr))) {
        return false;
    }

    *data = (void*)(long)xdp->data;
    *datat_end = (void*)(long)xdp->data_end;
    return true;
}

__always_inline bool encap_v6(
                            struct xdp_md* xdp, 
                            struct ctl_value* cval, 
                            struct packet_description* pckt, 
                            struct real_definition* dst, 
                            __u32 pkt_bytes, 
                            bool is_ipv6) 
{
    struct ipv6hdr* ipv6h;
    struct ethhdr* new_eth;
    struct ethhdr* old_eth;
    void* data;
    void* data_end;
    __u16 payload_len;
    __u32 saddr[4];
    __u8 proto;

    //向前扩展一个ipv6hdr大小
    if(test_bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct ipv6hdr))) {
        return false;
    }

    data = (void*)(long)xdp->data;
    data_end = (void*)(long)xdp->data_end;
    new_eth = data;
    ipv6h = data + sizeof(struct ethhdr);
    old_eth = data + sizeof(struct ipv6hdr);

    if(new_eth + 1 > data_end || old_eth + 1 > data_end || ipv6h + 1 > data_end) {
        return false;
    }
    memcpy(new_eth->h_dest, cval->mac, 6);
    memcpy(new_eth->h_source, old_eth->h_dest, 6);

    new_eth->h_proto = BE_ETH_P_IPV6;;

    if(is_ipv6) {
        proto = IPPROTO_IPV6;
        create_encap_ipv6_src(pckt->flow.port16[0], pckt->flow.srcv6[3], saddr);
        payload_len = pkt_bytes + sizeof(struct ipv6hdr);
    } else {
        proto = IPPROTO_IPIP;
        create_encap_ipv6_src(pckt->flow.port16[0], pckt->flow.src, saddr);
        payload_len = pkt_bytes;
    }
    create_v6_hdr(ipv6h, pckt->tos, saddr, dst->dstv6, payload_len, proto);
    return true;
}

__always_inline bool encap_v4(
                            struct xdp_md* xdp,
                            struct ctl_value* cval,
                            struct packet_description* pckt,
                            struct real_definition* dst,
                            __u32 pkt_bytes)
{
    void* data;
    void* data_end;
    struct iphdr* iph;
    struct ethhdr* new_eth;
    struct ethhdr* old_eth;
    __u32 ip_src = create_encap_ipv4_src(pckt->flow.port16[0], pckt->flow.src);
    __u64 csum = 0;
    // ipip encap
    if (test_bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(struct iphdr))) {
        return false;
    }
    data = (void*)(long)xdp->data;
    data_end = (void*)(long)xdp->data_end;
    new_eth = data;
    iph = data + sizeof(struct ethhdr);
    old_eth = data + sizeof(struct iphdr);
    if (new_eth + 1 > data_end || old_eth + 1 > data_end || iph + 1 > data_end) {
        return false;
    }
    memcpy(new_eth->h_dest, cval->mac, 6);
    memcpy(new_eth->h_source, old_eth->h_dest, 6);
    new_eth->h_proto = BE_ETH_P_IP;

    //bpf_printk("src_ip is: %u", bpf_htonl(ip_src));
    //print_ipv4_dotted(ip_src);
    //bpf_printk("dst_ip is: %u", bpf_htonl(dst->dst));
    //print_ipv4_dotted(bpf_ntohl(dst->dst));
    create_v4_hdr(iph, pckt->tos, ip_src, dst->dst, pkt_bytes, IPPROTO_IPIP);

    return true;
}

__always_inline bool gue_decap_v6(
                                struct xdp_md* xdp, 
                                void** data, 
                                void** data_end, 
                                bool inner_v4) 
{
    struct ethhdr* new_eth;
    struct ethhdr* old_eth;
    old_eth = *data;
    new_eth = *data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
    memcpy(new_eth->h_source, old_eth->h_source, 6);
    memcpy(new_eth->h_dest, old_eth->h_dest, 6);
    if(inner_v4) {
        new_eth->h_proto = BE_ETH_P_IP;
    } else {
        new_eth->h_proto = BE_ETH_P_IPV6;
    }

    if(test_bpf_xdp_adjust_head(xdp, (int)(sizeof(struct ipv6hdr) + sizeof(struct udphdr)))) {
        return false;
    }
    *data = (void*)(long)xdp->data;
    *data_end = (void*)(long)xdp->data_end;
    return true;
}

__always_inline bool gue_decap_v4(
                                struct xdp_md* xdp, 
                                void** data, 
                                void** data_end)
{
    struct ethhdr* new_eth;
    struct ethhdr* old_eth;
    old_eth = *data;
    new_eth = *data + sizeof(struct iphdr) + sizeof(struct udphdr);
    memcpy(new_eth->h_source, old_eth->h_source, 6);
    memcpy(new_eth->h_dest, old_eth->h_dest, 6);

    new_eth->h_proto = BE_ETH_P_IP;
    if(test_bpf_xdp_adjust_head(xdp, (int)(sizeof(struct iphdr) + sizeof(struct udphdr)))) {
        return false;
    }
    *data = (void*)(long)xdp->data;
    *data_end = (void*)(long)xdp->data_end;
    return true;
}

#ifdef GUE_ENCAP
__always_inline bool gue_csum(
                            void* data, 
                            void* data_end, 
                            bool outer_v6, 
                            bool inner_v6, 
                            struct packet_description* pckt, 
                            __u64* csum)
{
    __u16 outer_ip_off;
    __u16 udp_hdr_off;
    __u16 inner_ip_off;
    __u16 inner_transport_off;
    struct udphdr* udph;

    outer_ip_off = sizeof(struct ethhdr);
    udp_hdr_off = outer_v6 ? outer_ip_off + sizeof(struct ipv6hdr) : outer_ip_off + sizeof(struct iphdr);

    inner_ip_off = udp_hdr_off + sizeof(struct udphdr);
    inner_transport_off = inner_v6 ? inner_ip_off + sizeof(struct ipv6hdr) : inner_ip_off + sizeof(struct iphdr);

    if(data + inner_transport_off > data_end) {
        return false;
    }

    if(pckt->flow.proto == IPPROTO_UDP) {
        struct udphdr* inner_udp = (struct udphdr*)(data + inner_transport_off);
        if(inner_udp + 1 > data_end) {
            return false;
        }
        *csum = inner_udp->check;
    } else if(pckt->flow.proto == IPPROTO_TCP) {
        struct tcphdr* inner_tcp = (struct tcphdr*)(data + inner_transport_off);
        if(inner_tcp + 1 > data_end) {
            return false;
        }
        *csum = inner_tcp->check;
    } else {
        return false;
    }

    if(inner_v6) {
        struct ipv6hdr* outer_ip6h = data + outer_ip_off;
        udph = (void*)data + udp_hdr_off;
        struct ipv6hdr* inner_ip6h = data + inner_ip_off;
        if(outer_ip6h + 1 > data_end || udph + 1 > data_end || inner_ip6h + 1 > data_end) {
            return false;
        }
        return gue_csum_v6(outer_ip6h, udph, inner_ip6h, csum);
    } else {
        if(outer_v6) {
            struct ipv6hdr* outer_ip6h = data + outer_ip_off;
            udph = data + udp_hdr_off;
            struct iphdr* inner_iph = data + inner_ip_off;
            if(outer_ip6h + 1 > data_end || udph + 1 > data_end || inner_iph + 1 > data_end) {
                return false;
            }
            return gue_csum_v4_in_v6(outer_ip6h, udph, inner_iph, csum);
        } else {
            struct iphdr* outer_iph = data + outer_ip_off;
            udph = data + udp_hdr_off;
            struct iphdr* inner_iph = data + inner_ip_off;
            if(outer_iph + 1 > data_end || udph + 1 > data_end || inner_iph + 1 > data_end) {
                return false;
            }
            return gue_csum_v4(outer_iph, udph, inner_iph, csum);
        }
    }
    return true;
}

__always_inline bool gue_encap_v4(
                                struct xdp_md* xdp, 
                                struct ctl_value* cval, 
                                struct packet_description* pckt, 
                                struct real_definition* dst, 
                                __u32 pkt_bytes) 
{
    void* data;
    void* data_end;
    struct iphdr* iph;
    struct udphdr* udph;
    struct ethhdr* new_eth;
    struct ethhdr* old_eth;
    struct real_definition* src;

    __u16 sport = bpf_htons(pckt->flow.port16[0]);
    __u32 ipv4_src = V4_SRC_INDEX;

    src = bpf_map_lookup_elem(&pckt_srcs, &ipv4_src);
    if(!src) {
        return false;
    }

    ipv4_src = src->dst;

    sport ^= ((pckt->flow.src >> 16) & 0xFFFF);

    if(test_bpf_xdp_adjust_head(xdp, 0 - ((int)sizeof(struct iphdr) + (int)sizeof(struct udphdr)))) {
        return false;
    }

    data = (void*)(long)xdp->data;
    data_end = (void*)(long)xdp->data_end;
    new_eth = data;
    iph = data + sizeof(struct ethhdr);
    udph = (void*)iph + sizeof(struct iphdr);
    old_eth = data + sizeof(struct iphdr) + sizeof(struct udphdr);
    if (new_eth + 1 > data_end || old_eth + 1 > data_end || iph + 1 > data_end ||
        udph + 1 > data_end) {
        return false;
    }

    memcpy(new_eth->h_dest, cval->mac, sizeof(new_eth->h_dest));
    memcpy(new_eth->h_source, old_eth->h_dest, sizeof(new_eth->h_source));

    new_eth->h_proto = BE_ETH_P_IP;

    create_udp_hdr(udph, sport, GUE_DPORT, pkt_bytes + sizeof(struct udphdr), 0);
    create_v4_hdr(iph, pckt->tos, ipv4_src, dst->dst, pkt_bytes + sizeof(struct udphdr), IPPROTO_UDP);

    __u64 csum = 0;
    if(gue_csum(data, data_end, false, false, pckt, &csum)) {
        udph->check = csum & 0xFFFF;
    }
    return true;
}

__always_inline bool gue_encap_v6(
                                struct xdp_md* xdp, 
                                struct ctl_value* cval, 
                                struct packet_description* pckt, 
                                struct real_definition* dst, 
                                __u32 pkt_bytes,
                                bool is_ipv6) 
{
    void* data;
    void* data_end;
    struct ipv6hdr* ip6h;
    struct udphdr* udph;
    struct ethhdr* new_eth;
    struct ethhdr* old_eth;
    struct real_definition* src;

    __u32 key = V6_SRC_INDEX;
    __u16 payload_len;
    __u16 sport;

    src = bpf_map_lookup_elem(&pckt_srcs, &key);
    if(!src) {
        return false;
    }


    if(test_bpf_xdp_adjust_head(xdp, 0 - ((int)sizeof(struct ipv6hdr) + (int)sizeof(struct udphdr)))) {
        return false;
    }

    data = (void*)(long)xdp->data;
    data_end = (void*)(long)xdp->data_end;
    new_eth = (struct ethhdr*)data;
    ip6h = (struct ipv6hdr*)(data + sizeof(struct ethhdr));
    udph = (struct udphdr*)((void*)ip6h + sizeof(struct ipv6hdr));
    old_eth = (struct ethhdr*)(data + sizeof(struct ipv6hdr) + sizeof(struct udphdr));
    if (new_eth + 1 > data_end || old_eth + 1 > data_end || ip6h + 1 > data_end ||
        udph + 1 > data_end) {
        return false;
    }

    memcpy(new_eth->h_dest, cval->mac, sizeof(new_eth->h_dest));
    memcpy(new_eth->h_source, old_eth->h_dest, sizeof(new_eth->h_source));

    new_eth->h_proto = BE_ETH_P_IPV6;

    if(is_ipv6) {
        sport = (pckt->flow.srcv6[3] & 0xFFFF) ^ pckt->flow.port16[0];
        pkt_bytes += (sizeof(struct ipv6hdr) + sizeof(struct udphdr));
    } else {
        sport = ((pckt->flow.src >> 16) & 0xFFFF) ^ pckt->flow.port16[0];
        pkt_bytes += sizeof(struct udphdr);
    }

    create_udp_hdr(udph, sport, GUE_DPORT, pkt_bytes, 0);

    create_v6_hdr(ip6h, pckt->tos, src->dstv6, dst->dstv6, pkt_bytes, IPPROTO_UDP);

    __u64 csum = 0;
    if(gue_csum(data, data_end, true, is_ipv6, pckt, &csum)) {
        udph->check = csum & 0xFFFF;
    }
    return true;
}
#endif //GUE_ENCAP