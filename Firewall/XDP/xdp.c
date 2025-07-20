#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/prog_dispatcher.h>

#include "Rule.h"
#include "Cidr.h"
#include "Firewall_structs.h"
#include "Firewall_consts.h"
#include "limit_package.h"
#include "map.h"

static __always_inline int parse_icmp(void *data, 
                                      void *data_end, 
                                      u64 off, 
                                      struct Package_Count *pc)
{
    struct icmphdr *icmph = data + off;
    if(icmph + 1 > data_end) {
        //pc->Dropped.Passive_Dropped++;
        return XDP_DROP;
    }
    return XDP_PASS;
}

static __always_inline int parse_icmp6(void *data, 
                                      void *data_end, 
                                      u64 off, 
                                      struct Package_Count *pc)
{
    struct icmp6hdr *icmp6h = data + off;
    if(icmp6h + 1 > data_end) {
        //pc->Dropped.Passive_Dropped++;
        return XDP_DROP;
    }
    return XDP_PASS;
}

static __always_inline int parse_tcp(void *data, 
                                    void *data_end,
                                    u64 off, 
                                    struct packet_description *pkt,
                                    struct Package_Count *pc)
{
    struct tcphdr *tcph = data + off;
    if (tcph + 1 > data_end) {
        //pc->Dropped.Passive_Dropped++;
        return XDP_DROP;
    }
    pkt->flow.port16[0] = tcph->source;
    pkt->flow.port16[1] = tcph->dest;
    return 0;
}

static __always_inline int parse_udp(void *data, 
                                    void *data_end,
                                    u64 off, 
                                    struct packet_description *pkt,
                                    struct Package_Count *pc)
{
    struct udphdr *udph = data + off;
    if (udph + 1 > data_end) {
        pc->Dropped.Passive_Dropped++;
        return XDP_DROP;
    }
    pkt->flow.port16[0] = udph->source;
    pkt->flow.port16[1] = udph->dest;
    return 0;
}

static __always_inline int Process_L3_Headers(void *data, 
                                              void *data_end, 
                                              u64 *off,
                                              struct packet_description *pkt, 
                                              struct Package_Count *pc,
                                              bool is_ipv6)
{
    int action = 0;
    struct iphdr* iph;
    struct ipv6hdr* ip6h;
    if(is_ipv6) {
        ip6h = data + *off;
        if (ip6h + 1 > data_end) {
            return XDP_DROP;
        }
        pkt->flow.proto = ip6h->nexthdr;
        *off += sizeof(struct ipv6hdr);
        if(ip6h->nexthdr == IPPROTO_ICMPV6) {
            action = parse_icmp6(data, data_end, *off, pc);
            if (action > 0) {
                return action;
            }
        }
        memcpy(&pkt->flow.srcv6, &ip6h->saddr.in6_u.u6_addr32, sizeof(pkt->flow.srcv6));
        memcpy(&pkt->flow.dstv6, &ip6h->daddr.in6_u.u6_addr32, sizeof(pkt->flow.dstv6));
    } else {
        iph = data + *off;
        if(iph + 1 > data_end) {
            return XDP_DROP;
        }
        if(iph->ihl < 5) {
            return XDP_DROP;
        }
        pkt->flow.proto = iph->protocol;
        *off += sizeof(struct iphdr);
        if(iph->protocol == IPPROTO_ICMP) {
            action = parse_icmp(data, data_end, *off, pc);
            if(action > 0) {
                return action;
            }
        }
        pkt->flow.src = iph->saddr;
        pkt->flow.dst = iph->daddr;
    }
    //if (is_ipv6) {
        //bpf_printk("ipv6 is %x:", bpf_ntohl(ip6h->saddr.in6_u.u6_addr16[0]));
        //bpf_printk("%x:", bpf_ntohl(ip6h->saddr.in6_u.u6_addr16[1]));
        //bpf_printk("%x:", bpf_ntohl(ip6h->saddr.in6_u.u6_addr16[2]));
        //bpf_printk("%x:", bpf_ntohl(ip6h->saddr.in6_u.u6_addr16[3]));
        //bpf_printk("%x:", bpf_ntohl(ip6h->saddr.in6_u.u6_addr16[4]));
        //bpf_printk("%x:", bpf_ntohl(ip6h->saddr.in6_u.u6_addr16[5]));
        //bpf_printk("%x:", bpf_ntohl(ip6h->saddr.in6_u.u6_addr16[6]));
        //bpf_printk("%x:", bpf_ntohl(ip6h->saddr.in6_u.u6_addr16[7]));
    //} else {
        //print_ipv4_dotted(iph->saddr);
    //}
    return FURTHER_PROCESSING;
}

static __always_inline int process_packet(struct xdp_md* xdp, u64 off, struct Package_Count *pc, u32 ifindex, bool is_ipv6)
{
    void *data = (void*)(long)(xdp->data);
    void *data_end = (void*)(long)(xdp->data_end);
    struct packet_description pkt = {};
    u8 protocol;
    int action = Process_L3_Headers(data, data_end, &off, &pkt, pc, is_ipv6);
    if (action > 0) {
        if (action == XDP_DROP) {
            pc->Dropped.Passive_Dropped++;
            return action;
        } else if (action == XDP_PASS) {
            pc->Passed++;
        }
    }

    protocol = pkt.flow.proto;

    if(protocol == IPPROTO_TCP) {
        if(parse_tcp(data, data_end, off, &pkt, pc) != 0) {
            pc->Dropped.Passive_Dropped++;
            return XDP_DROP;
        }
        goto FURTHER;
    } else if(protocol == IPPROTO_UDP) {
        if(parse_udp(data, data_end, off, &pkt, pc) != 0) {
            pc->Dropped.Passive_Dropped++;
            return XDP_DROP;
        }
        goto FURTHER;
    } else {
        pc->Passed++;
        return XDP_PASS;
    }

FURTHER:
    action = -1;
    if (!is_ipv6) {
        action = Process_rule(&pkt, pc, ifindex);
        if (action > 0) {
            //先过滤掉被黑掉的流量
            if(action == XDP_DROP) {
                return action;
            }
        }
    }
#ifdef ENABLE_IPV6
    else {
        action = Process6_rule(&pkt, pc, ifindex);
        if (action > 0) {
            if(action == XDP_DROP) {
                return action;
            }
        }        
    }
#endif //ENABLE_IPV6
    
#ifdef ENABLE_LPM_RULE
    //v4
    if(!is_ipv6) {
        action = Check_Lpm_Rule_v4(pkt.flow.src, ifindex);
        if(action > 0) {
            if (action == XDP_DROP) {
                pc->Dropped.Active_Dropped++;
                return action;
            }
        }
    }
#ifdef ENABLE_IPV6
    //v6
    else {
        u128 src_ip6;
        memcpy(&src_ip6, &pkt.flow.srcv6, sizeof(src_ip6));
        action = Check_Lpm_Rule_v6(src_ip6, ifindex);
        if(action > 0) {
            if (action == XDP_DROP) {
                pc->Dropped.Active_Dropped++;
                return action;
            }
        }
    }
#endif //ENABLE_IPV6
#endif //ENABLE_LPM_RULE

/*
限流优先级的问题，优先级排序：（All和TCP，UDP相互排斥）ip限流大于全局和TCP，UDP规则
*/

#ifdef LIMIT_PACKETS_PER_IP
            int Action = Limit_ip_packets(&pkt, pc, is_ipv6, ifindex);
            if (Action == XDP_DROP) {
                pc->Dropped.Active_Dropped++;
                return XDP_DROP;
            }    
#endif

//全局流量
#ifdef LIMIT_GLOBAL_PACKETS
    action = Limit_global_packets(&pkt, pc, TB_INDEX_GLOBAL, is_ipv6, ifindex);
    if (action == XDP_PASS) {

        pc->Passed++;
        return XDP_PASS;
    } else if (action == XDP_DROP) {
        pc->Dropped.Active_Dropped++;
        return XDP_DROP;
    }
#endif //LIMIT_GLOBAL_PACKETS

#ifdef LIMIT_TCP_PACKETS
    if(pkt.flow.proto == IPPROTO_TCP) {
        action = Limit_global_packets(&pkt, pc, TB_INDEX_TCP, is_ipv6, ifindex);
        if (action == XDP_PASS) {
            pc->Passed++;
            return XDP_PASS;
        } else if (action == XDP_DROP) {
            pc->Dropped.Active_Dropped++;
            return XDP_DROP;
        }
    }
#endif

#ifdef LIMIT_UDP_PACKETS
    if(pkt.flow.proto == IPPROTO_UDP) {
        action = Limit_global_packets(&pkt, pc, TB_INDEX_UDP, is_ipv6, ifindex);
        if (action == XDP_PASS) {
            pc->Passed++;
            return XDP_PASS;
        } else if (action == XDP_DROP) {
            pc->Dropped.Active_Dropped++;
            return XDP_DROP;
        }
    }
#endif

    pc->Passed++;
    return XDP_PASS;
}


SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    void *data = (void*)(long)(ctx->data);
    void *data_end = (void*)(long)(ctx->data_end);
    u32 key = 0;
    struct Package_Count *pc = bpf_map_lookup_elem(&Package_Count, &key);
    if (!pc) {
        return XDP_DROP;
    }
    struct ethhdr* eth = data;
    u64 off = sizeof(struct ethhdr);
    if(data + off > data_end) {
        pc->Dropped.Passive_Dropped++;
        return XDP_DROP;
    }
    u32 ifindex = ctx->ingress_ifindex;
    if(eth->h_proto == bpf_htons(ETH_P_IP)) {
        return process_packet(ctx, off, pc, ifindex, false);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        return process_packet(ctx, off, pc, ifindex, true);
    }
    pc->Passed++;
    return XDP_PASS;
}

//char License[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);