#pragma once

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "balancer_consts.h"
#include "balancer_struct.h"
#include "balancer_map.h"

#include "balancer_helpers.h"
#include "balancer_package_encap.h"
#include "balancer_parse.h"
#include "balancer_jhash.h"
#include "balancer_stable_parsing.h"
#include "balancer_icmp.h"

__always_inline void increment_quic_cid_version_stats(
                                                    struct lb_quic_packets_stats* quic_packets_stats, 
                                                    __u8 cid_version) 
{
    if (cid_version == QUIC_CONNID_VERSION_V1) {
        quic_packets_stats->cid_v1 += 1;
    } else if (cid_version == QUIC_CONNID_VERSION_V2) {
        quic_packets_stats->cid_v2 += 1;
    } else if (cid_version == QUIC_CONNID_VERSION_V3) {
        quic_packets_stats->cid_v3 += 1;
    } else {
        quic_packets_stats->cid_v0 += 1;
    }
}

__always_inline int process_l3_headers(
    struct packet_description* pckt,
    __u8* protocol,
    __u64 off,
    __u16* pkt_bytes,
    void* data,
    void* data_end,
    bool is_ipv6)
{
    int action = 0;
    struct iphdr* iph;
    struct ipv6hdr* ipv6h;
    __u64 iph_len;
    if(is_ipv6) {
        //ipv6
        ipv6h = data + off;
        if(ipv6h + 1 > data_end) {
            return XDP_DROP;
        }

        iph_len = sizeof(struct ipv6hdr);
        *protocol = ipv6h->nexthdr;
        pckt->flow.proto = *protocol;

        pckt->tos = (ipv6h->priority << 4) & 0xF0;
        pckt->tos = pckt->tos | ((ipv6h->flow_lbl[0] >> 4) & 0x0F);
        *pkt_bytes = bpf_ntohs(ipv6h->payload_len);
        off += iph_len;
        if(*protocol == IPPROTO_FRAGMENT) {
            //分段数据包不支持
            return XDP_DROP;
        } else if(*protocol == IPPROTO_ICMPV6) {
            //icmpv6
            action = parse_icmpv6(data, data_end, off, pckt);
            if(action >= 0) {
                return action;
            }
        } else {
            memcpy(pckt->flow.srcv6, ipv6h->saddr.s6_addr32, 16);
            memcpy(pckt->flow.dstv6, ipv6h->daddr.s6_addr32, 16);
        }
    } else {
        //ipv4
        iph = data + off;
        if(iph + 1 > data_end) {
            return XDP_DROP;
        }

        if(iph->ihl != 5) {
            return XDP_DROP;
        }
        pckt->tos = iph->tos;
        *protocol = iph->protocol;
        pckt->flow.proto = *protocol;
        *pkt_bytes = bpf_ntohs(iph->tot_len);
        off += IPV4_HDR_LEN_NO_OPT; //加上无opt的ipv4长度

        if(iph->frag_off & PCKT_FRAGMENTED) {
            return XDP_DROP;
        }

        if(*protocol == IPPROTO_ICMP) {
            //icmpv4
            action = parse_icmp(data, data_end, off, pckt);
            if (action >= 0) {
                return action;
            }
        } else{
            pckt->flow.src = iph->saddr;
            pckt->flow.dst = iph->daddr;
        }
    }
    return FURTHER_PROCESSING;
}

#ifdef INLINE_DECAP_GENERIC
//检查数据包最外层的ip地址，为什么
//数据包经过路由导向到katran，传过来的是封装的数据包，我们要检查目的地址是否是本机ip地址
//如果不是本机ip地址，我们不要拆包，进入内核栈，让内核解析数据包，不归katran管
__always_inline int check_decap_dst(
                                struct packet_description* pckt, 
                                bool is_ipv6, 
                                bool* pass)
{
    struct address dst_addr = {};
    struct lb_stats* data_stats;

#ifdef DECAP_STRICT_DESTINATION
//DECAP_STRICT_DESTINATION 标志用于控制解封装时的安全性校验：
//开启严格检查：解封装后，内核会验证内层数据包的目的地址是否为 本机地址 或 当前隧道接口的地址。
//关闭严格检查：不进行目的地址校验，直接处理内层数据包（存在安全风险）。
//我们代替内核检查ip地址是否合理
//正常会进行这个段代码
    struct real_definition* host_primary_addrs;
    __u32 addr_index;

    if(is_ipv6) {
        addr_index = V6_SRC_INDEX;
        host_primary_addrs = bpf_map_lookup_elem(&pckt_srcs, &addr_index);
        if(host_primary_addrs) {
            if(host_primary_addrs->dstv6[0] != pckt->flow.dstv6[0] || 
               host_primary_addrs->dstv6[1] != pckt->flow.dstv6[1] ||
               host_primary_addrs->dstv6[2] != pckt->flow.dstv6[2] || 
               host_primary_addrs->dstv6[3] != pckt->flow.dstv6[3]) {
                //bpf_printk("pckt->flow.dstv6[0]: %u", pckt->flow.dstv6[0]);
                //bpf_printk("pckt->flow.dstv6[1]: %u", pckt->flow.dstv6[1]);
                //bpf_printk("pckt->flow.dstv6[2]: %u", pckt->flow.dstv6[2]);
                //bpf_printk("pckt->flow.dstv6[3]: %u", pckt->flow.dstv6[3]);

                //bpf_printk("host_primary_addrs->dstv6[0]: %u", host_primary_addrs->dstv6[0]);
                //bpf_printk("host_primary_addrs->dstv6[1]: %u", host_primary_addrs->dstv6[1]);
                //bpf_printk("host_primary_addrs->dstv6[2]: %u", host_primary_addrs->dstv6[2]);
                //bpf_printk("host_primary_addrs->dstv6[3]: %u", host_primary_addrs->dstv6[3]);
                //bpf_printk("1: XDP_PASS");
                return XDP_PASS; //交给内核栈
            }
        }
    } else {
        addr_index = V4_SRC_INDEX;
        host_primary_addrs = bpf_map_lookup_elem(&pckt_srcs, &addr_index);
        if(host_primary_addrs) {
            if(host_primary_addrs->dst != pckt->flow.dst) {
                //bpf_printk("pckt->flow.dst: %u", pckt->flow.dst);

                //bpf_printk("host_primary_addr: %u", host_primary_addrs->dst);
                //bpf_printk("2: XDP_PASS");
                return XDP_PASS; //交给内核栈
            }
        }
    }
#endif //DECAP_STRICT_DESTINATION

    if(is_ipv6) {
        //memcpy(dst_addr.addrv6, pckt->flow.dstv6, 16);
#pragma clang loop unroll(full)
        for (int i = 0; i < 4; i++) {
            dst_addr.addrv6[i] = bpf_ntohl(pckt->flow.dstv6[i]);
        }
    } else {
        dst_addr.addr = bpf_ntohl(pckt->flow.dst);
    }

    __u32* decap_dst_flags = bpf_map_lookup_elem(&decap_dst, &dst_addr);
    if(decap_dst_flags) {
        *pass = false;
        __u32 stats_key = MAX_VIPS + REMOTE_ENCAP_CNTRS;
        data_stats = bpf_map_lookup_elem(&stats, &stats_key);
        if(data_stats) {
            data_stats->v1 += 1;
        }
    }
    //bpf_printk("pass true");
    return FURTHER_PROCESSING;
}
#endif //INLINE_DECAP_GENERIC

#ifdef INLINE_DECAP_IPIP
//处理ipip数据包的函数
__always_inline int process_encaped_ipip_pckt(
    void** data,
    void** data_end,
    struct xdp_md* xdp,
    bool* is_ipv6, //传入指针，我们会根据内层ip header更改这个标志
    __u8* protocol,
    bool pass)
{
    int action;
    if(*protocol == IPPROTO_IPIP) {
        //处理ipip数据包
        if(*is_ipv6) {
            //外层是ipv6，开始解封
            int offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if((*data + offset) > *data_end) {
                return XDP_DROP;
            }
            action = decrement_ttl(*data, *data_end, offset, false);
            if(!decap_v6(xdp, data, data_end, true)) {
                return XDP_DROP;
            }
            *is_ipv6 = false;
        } else {
            int offset = sizeof(struct iphdr) + sizeof(struct ethhdr);
            if((*data + offset) > *data_end) {
                return XDP_DROP;
            }
            action = decrement_ttl(*data, *data_end, offset, false);
            if(!decap_v4(xdp, data, data_end)) {
                return XDP_DROP;
            }
        }
    } else if(*protocol == IPPROTO_IPV6) {
        int offset = sizeof(struct ipv6hdr) + sizeof(struct ethhdr);
        if((*data + offset) > *data_end) {
            return XDP_DROP;
        }
        action = decrement_ttl(*data, *data_end, offset, true);
        if(!decap_v6(xdp, data, data_end, false)) {
            return XDP_DROP;
        }
    }

    __u32 stats_key = MAX_VIPS + DECAP_CNTR;
    struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if(!data_stats) {
        return XDP_DROP;
    }
    if(is_ipv6) {
        data_stats->v2 += 1;
    } else {
        data_stats->v1 += 1;
    }

    if(action >= 0) {
        return action;
    }
    
    if(pass) {
        return XDP_PASS;
    }

    return recirculate(xdp);
}
#endif

#ifdef INLINE_DECAP_GUE

__always_inline void incr_decap_vip_stats(
                                        void* data, 
                                        void* data_end, 
                                        __u64 off, 
                                        bool is_ipv6) 
{
    struct packet_description inner_pckt = {};
    struct vip_definition vip = {};
    struct vip_meta* vip_info;

    __u8 inner_protocol;
    __u16 inner_pckt_bytes;
    
    //复用解析l3头部信息，
    //这里解析GUE携带的数据包
    if(process_l3_headers(&inner_pckt, &inner_protocol, off, &inner_pckt_bytes, data, data_end, is_ipv6)) {
        return;
    }

    if(is_ipv6) {
        memcpy(&vip.vip6, &inner_pckt.flow.dstv6, 16);
    } else {
        vip.vip = inner_pckt.flow.dst;
    }

    vip.proto = inner_pckt.flow.proto;

    if(inner_protocol == IPPROTO_TCP) {
        if(!parse_tcp(data, data_end, is_ipv6, &inner_pckt)) {
            return;
        }
    } else if(inner_protocol == IPPROTO_UDP) {
        if(!parse_udp(data, data_end, is_ipv6, &inner_pckt)) {
            return;
        }
    }

    vip.port = inner_pckt.flow.port16[1]; //目的端口
    vip_info = bpf_map_lookup_elem(&vip_map, &vip);
    if(vip_info) {
        __u32 vip_num = vip_info->vip_num; //reals的序号
        struct lb_stats* decap_stats = bpf_map_lookup_elem(&decap_vip_stats, &vip);
        if(decap_stats) {
            decap_stats->v1 += 1; //gue的decap统计数据
        }
    }
}

__always_inline int process_encaped_gue_pckt(
                                        void** data, 
                                        void** data_end, 
                                        struct xdp_md* xdp, 
                                        __u64 off, 
                                        bool is_ipv6, 
                                        bool pass)
{
    int offset = 0;
    int action;
    bool inner_ipv6 = false;
    if(is_ipv6) {
        __u8 v6 = 0;
        offset = sizeof(struct ipv6hdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
        if((*data + offset + 1) > *data_end) {
            return XDP_DROP;
        }
        v6 = ((__u8*)(*data))[offset];
        v6 &= GUEV1_IPV6MASK;
        inner_ipv6 = v6 ? true : false;
        if(v6) {
            action = decrement_ttl(*data, *data_end, offset, true);
            if(!gue_decap_v6(xdp, data, data_end, false)) {
                return XDP_DROP;
            }
        } else {
            action = decrement_ttl(*data, *data_end, offset, false);
            if(!gue_decap_v6(xdp, data, data_end, true)) {
                return XDP_DROP;
            }
        }
    } else {
        offset = sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
        if((*data + offset) > *data_end) {
            return XDP_DROP;
        }
        action = decrement_ttl(*data, *data_end, offset, false);
        if(!gue_decap_v4(xdp, data, data_end)) {
            return XDP_DROP;
        }
    }

    __u32 stats_key = MAX_VIPS + DECAP_CNTR;
    struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if(!data_stats) {
        return XDP_DROP;
    }

    if(is_ipv6) {
        data_stats->v2 += 1;
    } else {
        data_stats->v1 += 1;
    }

    if(action >= 0) {
        return action;
    }

    //解包之后，进入内核栈
    //bpf_printk("after decap pass is %d", pass);
    if(pass) {
        incr_decap_vip_stats(*data, *data_end, off, inner_ipv6);
        return XDP_PASS; 
    }
    return recirculate(xdp);
}
#endif

__always_inline void connection_table_lookup(
                                            struct real_definition** real, 
                                            struct packet_description* pckt, 
                                            void* lru_map, 
                                            bool isGlobalLru) {
    struct real_pos_lru* dst_lru;
    __u64 cur_time;
    __u32 key;

    dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
    if(!dst_lru) {
        return;
    }   

    if(!isGlobalLru && pckt->flow.proto == IPPROTO_UDP) {
        cur_time = bpf_ktime_get_ns();
        if(cur_time - dst_lru->atime > LRU_UDP_TIMEOUT) {
            return;
        }
        dst_lru->atime = cur_time;
    }
    key = dst_lru->pos;
    pckt->real_index = key;
    *real = bpf_map_lookup_elem(&reals, &key);
    return;
}

//tcp标志服务器统计信息
__always_inline void incr_server_id_routing_stats(__u32 vip_num, bool newConn, bool misMatchInLRU) {
    struct lb_stats* per_vip_stats = bpf_map_lookup_elem(&server_id_stats, &vip_num);
    if(!per_vip_stats) {
        return;
    }
    if(newConn) {
        //新的连接
        per_vip_stats->v1 += 1;
    }
    if(misMatchInLRU) {
        //错误lru
        per_vip_stats->v2 += 1;
    }
}

__always_inline int is_under_flood(__u64* cur_time) {
    __u32 conn_rate_key = MAX_VIPS + NEW_CONN_RATE_CNTR;
    struct lb_stats* conn_rate_state = bpf_map_lookup_elem(&stats, &conn_rate_key);
    if(!conn_rate_state) {
        return true;
    }

    *cur_time = bpf_ktime_get_ns();
    //间隔事件相差一秒，我们认为处于flood状态
    if((*cur_time - conn_rate_state->v2) > ONE_SEC) {
        //更新
        conn_rate_state->v1 = 1;
        conn_rate_state->v2 = *cur_time;
    } else {
        conn_rate_state->v1 += 1;
        if(conn_rate_state->v1 > MAX_CONN_RATE) {
            return true;
        }
    }
    return false;
}

//基于四元组流，进行lru查找
__always_inline int check_and_update_real_index_in_lru(
                                                        struct packet_description* pkt, 
                                                        void* lru_map)
{
    struct real_pos_lru* dst_lru = bpf_map_lookup_elem(lru_map, &pkt->flow);
    if(dst_lru) {
        if(dst_lru->pos == pkt->real_index) {
            return DST_MATCH_IN_LRU;
        } else {
            dst_lru->pos = pkt->real_index;
            return DST_MISMATCH_IN_LRU;
        }
    }

    //未能在lru中找到目标
    __u64 cur_time;
    if(is_under_flood(&cur_time)) {
        return DST_NOT_FOUND_IN_LRU; //lru_map中未能找到
    }

    //如果一定时间内数据包的总数未超过预定值，我们将这个流更新到lru映射中
    struct real_pos_lru new_dst_lru = {};
    new_dst_lru.pos = pkt->real_index;
    bpf_map_update_elem(lru_map, &pkt->flow, &new_dst_lru, BPF_ANY);
    return DST_NOT_FOUND_IN_LRU;
}

#ifdef GLOBAL_LRU_LOOKUP
    __always_inline int global_lru_lookup(
                                        struct real_definition** real, 
                                        struct packet_description* pckt,
                                        __u32 cpu_num,
                                        struct vip_meta* vip_info,
                                        bool is_ipv6)
{   
    //找到这个cpu上的全局lru映射
    void* g_lru_map = bpf_map_lookup_elem(&global_lru_maps, &cpu_num);
    
    __u32 global_lru_stats_key = MAX_VIPS + GLOBAL_LRU_CNTR;
    struct lb_stats* global_lru_stats = bpf_map_lookup_elem(&stats, &global_lru_stats_key);
    if(!global_lru_stats) {
        return XDP_DROP;
    }

    if(!g_lru_map) {
        g_lru_map = &fallback_glru; //缓存
        global_lru_stats->v1 += 1;
    }

    connection_table_lookup(real, pckt, g_lru_map, true); //全局lru映射查找
    if(*real) {
        //通过全局lru映射找到了dst
        global_lru_stats->v2 += 1;
    }
    return FURTHER_PROCESSING;
}
#endif

__always_inline __u32 get_packet_hash(
                                    struct packet_description* pckt, 
                                    bool is_ipv6) {
    if(is_ipv6) {
        return jhash_2words(jhash(pckt->flow.srcv6, 16, INIT_JHASH_SEED_V6), pckt->flow.ports, INIT_JHASH_SEED);
    } else {
        return jhash_2words(pckt->flow.src, pckt->flow.ports, INIT_JHASH_SEED);
    }
}

//KEY是0的情况统计
__always_inline void increment_ch_drop_real_0() {
    __u32 ch_drop_stats_key = MAX_VIPS + CH_DROP_STATS;
    struct lb_stats* ch_drop_stats = bpf_map_lookup_elem(&stats, &ch_drop_stats_key);
    if(!ch_drop_stats) {
        return;
    }
    ch_drop_stats->v2 += 1; //错误计数
}

//KEY对应服务器ip失败的情况统计
__always_inline void increment_ch_drop_no_real() {
    __u32 ch_drop_stats_key = MAX_VIPS + CH_DROP_STATS;
    struct lb_stats* ch_drop_stats = bpf_map_lookup_elem(&stats, &ch_drop_stats_key);
    if(!ch_drop_stats) {
        return;
    }
    ch_drop_stats->v1 += 1; //错误计数
}

__always_inline int get_packet_dst(
                                   struct real_definition **real, 
                                   struct packet_description* pckt, 
                                   struct vip_meta* vip_info, 
                                   void* lru_map, 
                                   bool is_ipv6) {
    struct real_pos_lru new_dst_lru = {};
    bool under_flood = false;
    bool src_found = false;
    __u32* real_pos;
    __u64 cur_time = 0;
    __u32 hash;
    __u32 key;

    under_flood = is_under_flood(&cur_time);
//lpm树查找
#ifdef LPM_SRC_LOOKUP
    if((vip_info->flags & F_SRC_ROUTING) && !under_flood) {
        __u32* lpm_val;
        if(is_ipv6) {
            struct lpm_key6 lpm_key6 = {};
            lpm_key6.prefixlen = 128;
            memcpy(&lpm_key6.addr, &pckt->flow.srcv6, 16);
            lpm_val = bpf_map_lookup_elem(&lpm_src_v6, &lpm_key6);
        } else {
            struct lpm_key4 lpm_key4 = {};
            lpm_key4.prefixlen = 32;
            memcpy(&lpm_key4.addr, &pckt->flow.src, sizeof(lpm_key4.addr));
            lpm_val = bpf_map_lookup_elem(&lpm_src_v4, &lpm_key4);
        }

        if(lpm_val) {
            src_found = true;
            key = *lpm_val;
        }

        __u32 stats_key = MAX_VIPS + LPM_SRC_CNTRS;
        struct lb_stats* lpm_stats = bpf_map_lookup_elem(&stats, &stats_key);
        if(lpm_stats) {
            if(src_found) {
                lpm_stats->v2 += 1;
            } else {
                lpm_stats->v1 += 1;
            }
        }
    }
#endif

    if(!src_found) {
        if(vip_info->flags & F_HASH_DPORT_ONLY) {
            //使用目的地址的端口来hash计算
            pckt->flow.port16[0] = pckt->flow.port16[1];
            __builtin_memset(pckt->flow.srcv6, 0, 16);
        }
        hash = get_packet_hash(pckt, is_ipv6) % RING_SIZE;
        key = RING_SIZE *(vip_info->vip_num) + hash; //获得key
        real_pos = bpf_map_lookup_elem(&ch_rings, &key);
        if(!real_pos) {
            return false;
        }
        key = *real_pos;
        if(key == 0) {
            increment_ch_drop_real_0();
            return false;
        }
    }

    pckt->real_index = key;
    *real = bpf_map_lookup_elem(&reals, &key);
    if(!(*real)) {
        increment_ch_drop_no_real();
        return false;
    }

    if(lru_map && !(vip_info->flags & F_LRU_BYPASS) && !under_flood) {
        if(pckt->flow.proto == IPPROTO_UDP) {
            new_dst_lru.atime = cur_time;
        }
        new_dst_lru.pos = key; //服务器的位置
        bpf_map_update_elem(lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
    }
    return true;
}

__always_inline int update_vip_lru_miss_stats(
                                            struct vip_definition* vip,
                                            struct packet_description* pckt,
                                            struct vip_meta* vip_info,
                                            bool is_ipv6)
{
    __u32 vip_miss_stats_key = 0;
    struct vip_definition* lru_miss_stats_vip = bpf_map_lookup_elem(&vip_miss_stats, &vip_miss_stats_key);
    if(!lru_miss_stats_vip) {
        return XDP_DROP;
    }

    bool address_match = (is_ipv6 && (lru_miss_stats_vip->vip6[0] == vip->vip6[0] && 
                                      lru_miss_stats_vip->vip6[1] == vip->vip6[1] && 
                                      lru_miss_stats_vip->vip6[2] == vip->vip6[2] && 
                                      lru_miss_stats_vip->vip6[3] == vip->vip6[3])) ||
                         (!is_ipv6 && lru_miss_stats_vip->vip == vip->vip);
    bool port_match = lru_miss_stats_vip->port == vip->port;
    bool proto_match = lru_miss_stats_vip->proto == vip->proto;
    //三者是否都满足
    bool vip_match = address_match && port_match && proto_match;
    if(vip_match) {
        __u32 lru_stats_key = pckt->real_index;
        __u32* lru_miss_stat = bpf_map_lookup_elem(&lru_miss_stats, &lru_stats_key);
        if(!lru_miss_stat) {
            return XDP_DROP;
        }
        *lru_miss_stat += 1;
    }
    return FURTHER_PROCESSING;
}

#ifdef UDP_STABLE_ROUTING
__always_inline bool process_udp_stable_routing(    
                                            void* data,
                                            void* data_end,
                                            struct real_definition** dst,
                                            struct packet_description* pckt,
                                            bool is_ipv6)
{
    __u32 stable_rt_stats_key = 0;
    struct lb_stable_rt_packets_stats* stable_rt_package_stats = 
                            bpf_map_lookup_elem(&stable_rt_stats, &stable_rt_stats_key);

    if(!stable_rt_package_stats) {
        return XDP_DROP;
    }
    struct udp_stable_rt_result udp_id = parse_udp_stable_rt_hdr(data, data_end, pckt, is_ipv6);
    if(udp_id.server_id > 0) {
        __u32 key = udp_id.server_id;
        __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
        if(real_pos) {
            key = *real_pos;
            if(key != 0) {
                pckt->real_index = key;
                *dst = bpf_map_lookup_elem(&reals, &key);
                if(!*dst) {
                    //错误
                    stable_rt_package_stats->cid_unknown_real_dropped += 1;
                    return XDP_DROP;
                }
                stable_rt_package_stats->cid_routed += 1; //路由成功加一
            }
        } else {
            stable_rt_package_stats->cid_invalid_server_id += 1;
            stable_rt_package_stats->ch_routed += 1;
        } 
    } else {
        if(!udp_id.is_stable_rt_pkt) {
            //非法数据包计数
            stable_rt_package_stats->invalid_packet_type += 1;
        }
        //可能是id为零的情况，我们不出现负数id
        stable_rt_package_stats->ch_routed += 1;
    }
}
#endif

__always_inline int process_packet(struct xdp_md *ctx, __u64 off, bool is_ipv6) { 
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ctl_value* cal; //可能我们要将包重新封装转发到正确的服务器上
    struct real_definition* dst = NULL;
    struct packet_description pckt = {};
    struct vip_definition vip = {};
    struct lb_stats* data_stats;
    struct vip_meta* vip_info;

    __u64 iph_len;
    __u8 protocol;
    __u16 original_sport; //起始端口

    int action;
    __u32 vip_num;
    __u32 mac_addr_pos = 0;
    __u16 pkt_bytes;
    action = process_l3_headers(
        &pckt, &protocol, off, &pkt_bytes, data, data_end, is_ipv6
    );
    if(action >= 0) {
        return action;
    }
    protocol = pckt.flow.proto;

#ifdef INLINE_DECAP_IPIP
    if(protocol == IPPROTO_IPIP) {
        //ipip数据包
        bool pass = true;
        //首先检查封装后的数据包外部IP地址（dst）
        action = check_decap_dst(&pckt, is_ipv6, &pass);
        if(action >= 0) {
            return action;
        }
        return process_encaped_ipip_pckt(&data, &data_end, ctx, &is_ipv6, &protocol, pass);
    } else if(protocol == IPPROTO_IPV6) {
        bool pass = true;
        action = check_decap_dst(&pckt, is_ipv6, &pass);
        if(action >= 0) {
            return action;
        }
        //数据包从这进入本机的内核栈（ipip）
        return process_encaped_ipip_pckt(&data, &data_end, ctx, &is_ipv6, &protocol, pass);
    }
#endif //INLINE_DECAP_IPIP

    if(protocol == IPPROTO_TCP) {
        if(!parse_tcp(data, data_end, is_ipv6, &pckt)) {
            return XDP_DROP;
        }
    } else if(protocol == IPPROTO_UDP) {
        if(!parse_udp(data, data_end, is_ipv6, &pckt)) {
            return XDP_DROP;
        }
#ifdef INLINE_DECAP_GUE
        if(pckt.flow.port16[1] == bpf_ntohs(GUE_DPORT)) {
            bool pass = true;
            action = check_decap_dst(&pckt, is_ipv6, &pass);
            if(action >= 0) {
                return action;
            }
            //数据包从这进入本机的内核栈（gue）
            return process_encaped_gue_pckt(&data, &data_end, ctx, off, is_ipv6, pass);
        }
#endif
    } else {
        return XDP_PASS;
    }

    if(data_end - data > MAX_PCKT_SIZE) {
        //向外界报告icmp数据包太大
#ifdef ICMP_TOOBIG_GENERATION
        //bpf_printk("ICMP_TOOBIG_GENERATION");
        __u32 stats_key = MAX_VIPS + ICMP_TOOBIG_CNTRS;
        data_stats = bpf_map_lookup_elem(&stats, &stats_key);
        if(!data_stats) {
            return XDP_DROP;
        }

        if(is_ipv6) {
            data_stats->v2 += 1;
        } else {
            data_stats->v1 += 1;
        }

        return send_icmp_too_big(ctx, data_end - data, is_ipv6);
#else
        return XDP_DROP;
#endif
    }

    //取得ip地址
    if(is_ipv6) {
        memcpy(vip.vip6, pckt.flow.dstv6, 16);
#pragma clang loop unroll(full)
        for (int i = 0; i < 4; i++) {
            vip.vip6[i] = bpf_ntohl(vip.vip6[i]);
        }
    } else {
        vip.vip = bpf_ntohl(pckt.flow.dst);
    }
    print_ipv4_dotted(vip.vip);
    vip.port = bpf_ntohs(pckt.flow.port16[1]);
    vip.proto = pckt.flow.proto;
    
    vip_info = bpf_map_lookup_elem(&vip_map, &vip);

    vip_info = bpf_map_lookup_elem(&vip_map, &vip);
    if(!vip_info) {
        vip.port = 0; //端口设0
        vip_info = bpf_map_lookup_elem(&vip_map, &vip);
        if(!vip_info) {
            return XDP_PASS;
        }

        if(!(vip_info->flags & F_HASH_DPORT_ONLY) && !(vip_info->flags & F_HASH_SRC_DST_PORT)) {
            pckt.flow.port16[1] = 0;
        }
    } 

    __u32 stats_key = MAX_VIPS + LRU_CNTRS;
    data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if(!data_stats) {
        return XDP_DROP;
    }

    data_stats->v1 += 1;

    if((vip_info->flags & F_HASH_NO_SRC_PORT)) {
        pckt.flow.port16[0] = 0;
    }

    vip_num = vip_info->vip_num;
    __u32 cpu_num = bpf_get_smp_processor_id();
    void* lru_map = bpf_map_lookup_elem(&lru_mapping, &cpu_num);
    if(!lru_map) {
        lru_map = &fallback_cache; //缓存介入
        __u32 lru_stats_key = MAX_VIPS + FALLBACK_LRU_CNTR;
        struct lb_stats* lru_stats = bpf_map_lookup_elem(&stats, &lru_stats_key);
        if(!lru_stats) {
            return XDP_DROP;
        }

        lru_stats->v1 +=1;
    }

    if(vip_info->flags & F_QUIC_VIP) {
        bool is_icmp = (pckt.flags & F_ICMP);
        if(is_icmp) {
            __u32 stats_key = MAX_VIPS + QUIC_ICMP_STATS;
            struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
        
            if (!data_stats) {
                return XDP_DROP;
            }
            data_stats->v1 += 1;
            if(ignorable_quic_icmp_code(data, data_end, is_ipv6)) {
                data_stats->v2 += 1;
            }
        } else {
            __u32 quic_packets_stats_key = 0;
            struct lb_quic_packets_stats* quic_packets_stats = 
                bpf_map_lookup_elem(&quic_stats_map, &quic_packets_stats_key);
            
            if(!quic_packets_stats) {
                return XDP_DROP;
            }

            struct quic_parse_result qpr = parse_quic(data, data_end, is_ipv6, &pckt);
            if(qpr.server_id > 0) {
                increment_quic_cid_version_stats(quic_packets_stats, qpr.cid_version);
                __u32 key = qpr.server_id;
                __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
                if(real_pos) {
                    key = *real_pos;
                    if (key == 0) {
                        quic_packets_stats->cid_invalid_server_id += 1;
                        quic_packets_stats->cid_invalid_server_id_sample = qpr.server_id;
                        quic_packets_stats->ch_routed += 1;
                    } else {
                        pckt.real_index = key;
                        dst = bpf_map_lookup_elem(&reals, &key);
                        if(!dst) {
                            quic_packets_stats->cid_unknown_real_dropped += 1;
                            return XDP_DROP;
                        }

                        int res = check_and_update_real_index_in_lru(&pckt, lru_map);
                        if(res == DST_MATCH_IN_LRU) {
                            quic_packets_stats->dst_match_in_lru += 1;
                        } else if(res == DST_MISMATCH_IN_LRU) {
                            quic_packets_stats->dst_mismatch_in_lru += 1;
                            incr_server_id_routing_stats(vip_num, false, true);
                        } else {
                            quic_packets_stats->dst_not_found_in_lru += 1;
                        }
                        quic_packets_stats->cid_routed += 1;
                    }
                } else {
                    quic_packets_stats->cid_invalid_server_id += 1;
                    quic_packets_stats->cid_invalid_server_id_sample = qpr.server_id;
                    quic_packets_stats->ch_routed += 1;
                }
            }  else if(!qpr.is_initial) {
                quic_packets_stats->ch_routed += 1;
            } else {
                quic_packets_stats->cid_initial += 1;
                incr_server_id_routing_stats(vip_num, true, false);
            }
        }
    }

//来自udp连接的持久化，我们暂时不实现quic
#ifdef UDP_STABLE_ROUTING
    if(pckt.flow.proto == IPPROTO_UDP && (vip_info->flags & F_UDP_STABLE_ROUTING_VIP)) {
        //处理逻辑类似于quic协议，我们暂不实现，过于复杂
        process_udp_stable_routing(data, data_end, &dst, &pckt, is_ipv6);
    } 

#endif // UDP_STABLE_ROUTING

    original_sport = pckt.flow.port16[0];
    
    if(!dst) {
#ifdef TCP_SERVER_ID_ROUTING
        if(pckt.flow.proto == IPPROTO_TCP) {
            __u32 tpr_packages_stats_key = 0;
            struct lb_tpr_packets_stats* tpr_packets_stats = 
                    bpf_map_lookup_elem(&tpr_stats_map, &tpr_packages_stats_key);
    
            if(!tpr_packets_stats) {
                return XDP_DROP;
            }
            //这里用于测试下,我们主动添加标志测试
            if(pckt.flags & F_SYN_SET) {
                tpr_packets_stats->tcp_syn += 1;
                incr_server_id_routing_stats(vip_num, true, false);
            } else {
                //生产环境下
                //首先查找server_id,如果没有，我们在lru映射中寻找，如果lru中没有，我们给予分配位置
                if(tcp_hdr_opt_lookup(ctx, is_ipv6, &dst, &pckt) == FURTHER_PROCESSING) {
                    tpr_packets_stats->ch_routed += 1;
                } else {
                    if(lru_map && !(vip_info->flags & F_LRU_BYPASS)) {
                        int check = check_and_update_real_index_in_lru(&pckt, lru_map);
                        if(check == DST_MISMATCH_IN_LRU) {
                            tpr_packets_stats->dst_mismatch_in_lru += 1;
                            incr_server_id_routing_stats(vip_num, false, true);
                        }
                    }
                    tpr_packets_stats->sid_routed += 1;
                }
            }
        }
#endif //TCP_SERVER_ID_ROUTING

        if(!dst && !(pckt.flags & F_SYN_SET) && !(vip_info->flags & F_LRU_BYPASS)) {
            connection_table_lookup(&dst, &pckt, lru_map, false);
        }

#ifdef GLOBAL_LRU_LOOKUP
        if(!dst && !(pckt.flags & F_SYN_SET) && !(vip_info->flags & F_LRU_BYPASS)) {
            int global_lru_lookup_result = global_lru_lookup(&dst, &pckt, cpu_num, vip_info, is_ipv6);
            if(global_lru_lookup_result >= 0) {
                return global_lru_lookup_result;
            }
        }
#endif //GLOBAL_LRU_LOOKUP

        if(!dst) {
            //通过上述server_id, lru映射还是没能找到路由地址
            if(pckt.flow.proto == IPPROTO_TCP) {
                __u32 lru_stats_key = MAX_VIPS + LRU_MISS_CNTR;
                struct lb_stats* lru_miss_stats = bpf_map_lookup_elem(&stats, &lru_stats_key);
                if(!lru_miss_stats) {
                    return XDP_DROP;
                }

                if(pckt.flags & F_SYN_SET) {
                    //第一次连接
                    lru_miss_stats->v1 += 1;
                } else {
                    lru_miss_stats->v2 += 1;
                }
            }

            //接下来，通过flow，给予位置,并且更新此cpu上的lru映射
            if(!get_packet_dst(&dst, &pckt, vip_info, lru_map, is_ipv6)) {
                return XDP_DROP;
            }

            if(update_vip_lru_miss_stats(&vip, &pckt, vip_info, is_ipv6) >= 0) {
                return XDP_DROP;
            }

            data_stats->v2 += 1;
        }    
    }

    //bpf_printk("real.dst is %u", bpf_ntohl(dst->dst));

    cal = bpf_map_lookup_elem(&ctl_array, &mac_addr_pos);
    if(!cal) {
        return XDP_DROP;
    }

    data_stats = bpf_map_lookup_elem(&stats, &vip_num);
    if(!data_stats) {
        return XDP_DROP;
    }

    data_stats->v1 += 1;
    data_stats->v2 += pkt_bytes; //数据包大小

    data_stats = bpf_map_lookup_elem(&reals_stats, &pckt.real_index);
    if(!data_stats) {
        return XDP_DROP;
    }

    data_stats->v1 += 1;
    data_stats->v2 += pkt_bytes;

#ifdef LOCAL_DELIVERY_OPTIMIZATION
    if((vip_info->flags & F_LOCAL_VIP) && (dst->flags & F_LOCAL_REAL)) {
        return XDP_PASS; //交给内核栈
    }
#endif

    pckt.flow.port16[0] = original_sport; //起始端口
    if(dst->flags & F_IPV6) {
        if(!PCKT_ENCAP_V6(ctx, cal, &pckt, dst, pkt_bytes, is_ipv6)) {
            return XDP_DROP;
        }
        bpf_printk("encap v6");
    } else {
        if(!PCKT_ENCAP_V4(ctx, cal, &pckt, dst, pkt_bytes)) {
            return XDP_DROP;
        }
        bpf_printk("encap v4");
    }
    
    return XDP_TX; //转发
}

SEC(BLANCER_PROG)
int balancer_prog(struct xdp_md *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = (struct ethhdr*)data;
    __u32 eth_proto;
    __u32 off;
    off = sizeof(struct ethhdr);

    if(data + off > data_end) {
        return XDP_DROP;
    }

    eth_proto = eth->h_proto;

    if(eth_proto == BE_ETH_P_IP) {
        return process_packet(ctx, off, false);
    } else if(eth_proto == BE_ETH_P_IPV6) {
        return process_packet(ctx, off, true);
    }
    return XDP_PASS; //交给内核栈
} 

char License[] SEC("license") = "GPL";