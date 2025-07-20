#pragma once

#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

#include "balancer_struct.h"
#include "balancer_consts.h"


__always_inline __u64 calc_offset(bool is_ipv6, bool is_icmp) {
    __u64 off = sizeof(struct ethhdr);
    if(is_ipv6) {
        off += sizeof(struct ipv6hdr);
        if(is_icmp) {
            off += (sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr));
        }
    } else {
        off += sizeof(struct iphdr);
        if(is_icmp) {
            off += (sizeof(struct icmphdr) + sizeof(struct iphdr));
        }
    }
    return off;
}


__always_inline int parse_udp(void* data, 
                              void* data_end, 
                              bool is_ipv6, 
                              struct packet_description* pkt) {
    bool is_icmp = !((pkt->flags & F_ICMP) == 0);
    __u64 off = calc_offset(is_ipv6, is_icmp);
    struct udphdr* udp;
    udp = (struct udphdr*)(data + off);

    if(udp + 1 > data_end) {
        return false;
    }

    //icmp数据包
    if(!is_icmp) {
        pkt->flow.port16[0] = udp->source;
        pkt->flow.port16[1] = udp->dest;
    } else {
        pkt->flow.port16[0] = udp->dest;
        pkt->flow.port16[1] = udp->source;
    }
    return true;
}

__always_inline int parse_tcp(void* data, 
                              void* data_end, 
                              bool is_ipv6, 
                              struct packet_description* pkt) {
    bool is_icmp = !((pkt->flags & F_ICMP) == 0);
    __u64 off = calc_offset(is_ipv6, is_icmp);
    struct tcphdr* tcp;
    tcp = (struct tcphdr*)(data + off);

    if(tcp + 1 > data_end) {
        return false;
    }

    if(tcp->syn) {
        pkt->flags |= F_SYN_SET;
    }

    //icmp数据包
    if(!is_icmp) {
        pkt->flow.port16[0] = tcp->source;
        pkt->flow.port16[1] = tcp->dest;
    } else {
        pkt->flow.port16[0] = tcp->dest;
        pkt->flow.port16[1] = tcp->source;
    }
    return true;
}

#ifdef TCP_SERVER_ID_ROUTING

//tcp的option字段：
//格式：king加上length再加上server_id 一共三个字节，这个是我们人工干预添加的，在tpr模块下
__always_inline int parse_hdr_opt(const struct xdp_md* xdp, struct hdr_opt_state* tcp_state) {
    __u8* tcp_opt, kind, hdr_len;

    //tcp option两个字节，第一个字节kind，第二个字节length
    const void* data = (void*)(long)xdp->data;
    const void* data_end = (void*)(long)xdp->data_end;

    if(!tcp_state) {
        return -1;
    }

    tcp_opt = (__u8*)(data + tcp_state->byte_offset);
    if(tcp_opt + 1 > data_end) {
        return -1;
    }

    kind = tcp_opt[0];
    if(kind == TCP_OPT_EOL) {
        return -1;
    }

    if(kind == TCP_OPT_NOP) {
        tcp_state->hdr_bytes_remaining--; //保留长度减一
        tcp_state->byte_offset++; //偏移量加一
        return 0; //继续分析
    }

    //剩余小于2或者超出长度，错误
    if(tcp_state->hdr_bytes_remaining < 2 || tcp_opt + sizeof(__u8) + sizeof(__u8) > data_end) {
        return -1;
    }

    hdr_len = tcp_opt[1];
    if(hdr_len > tcp_state->hdr_bytes_remaining) {
        return -1;
    }

    if(kind == TCP_HDR_OPT_KIND_TPR) {
        if(hdr_len != TCP_HDR_OPT_LEN_TPR) {
            return -1;
        }

        if(tcp_opt + TCP_HDR_OPT_LEN_TPR > data_end) {
            return -1;
        }

        //提取server_id，用于后续连接识别
        tcp_state->server_id = *(__u32*)&tcp_opt[2];
        return 1;
    }

    tcp_state->hdr_bytes_remaining -= hdr_len;
    tcp_state->byte_offset += hdr_len;
    return 0;
}

__always_inline int tcp_hdr_opt_lookup_server_id(const struct xdp_md* xdp, __u32** server_id, bool is_ipv6) {
    const void* data = (void*)(long)xdp->data;
    const void* data_end = (void*)(long)xdp->data_end;
    struct tcphdr* tcp_hdr;
    __u8 tcp_hdr_opt_len = 0;
    __u64 tcp_offset = 0;
    struct hdr_opt_state opt_state = {};
    int err = 0;
    //计算偏移量
    tcp_offset = calc_offset(is_ipv6, false);
    tcp_hdr = (struct tcphdr*)(data + tcp_offset);

    if(tcp_hdr + 1 > data_end) {
        return FURTHER_PROCESSING;
    }

    //总体长度字节减去标准字节
    tcp_hdr_opt_len = (tcp_hdr->doff * 4) - sizeof(struct tcphdr);
    if(tcp_hdr_opt_len < TCP_HDR_OPT_LEN_TPR) {
        //小于固定长度，意味着没有option字段
        return FURTHER_PROCESSING;
    }

    opt_state.hdr_bytes_remaining = tcp_hdr_opt_len;
    opt_state.byte_offset = sizeof(struct tcphdr) + tcp_offset;

#pragma clang loop unroll(full) //循环展开
    for(int i = 0; i < TCP_HDR_OPT_MAX_OPT_CHECKS; i++) {
        err = parse_hdr_opt(xdp, &opt_state);
        if(err || !opt_state.hdr_bytes_remaining) {
            break; //出现错误，或者option字段已经处理完毕
        }
    }
    if(!opt_state.server_id) {
        //没能找到server_id，第一次连接，我们没有分配server_id
        return FURTHER_PROCESSING; 
    }
    return 0;
}

//在tcp数据包的option选项中查找server_id
__always_inline int tcp_hdr_opt_lookup(
                                        const struct xdp_md* xdp, 
                                        bool is_ipv6, 
                                        struct real_definition** real, 
                                        struct packet_description* pckt)
{
    __u32 server_id = 0;
    int err = 0;
    if(tcp_hdr_opt_lookup_server_id(xdp, &server_id, is_ipv6) == FURTHER_PROCESSING) {
        return FURTHER_PROCESSING;
    }

    __u32 key = server_id;
    __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
    if(!real_pos) {
        return FURTHER_PROCESSING;
    }

    key = *real_pos;
    if(key == 0) {
        //映射使用array，我们不使用0位置
        return FURTHER_PROCESSING;
    }
    pckt->real_index = key;
    *real = bpf_map_lookup_elem(&reals, &key);
    if(!(*real)) { //为0
        return FURTHER_PROCESSING;
    }
    return 0;
}

#endif //TCP_SERVER_ID_ROUTING

__always_inline struct quic_parse_result parse_quic(
                                                void* data,
                                                void* data_end, 
                                                bool is_ipv6, 
                                                struct packet_description* pckt) 
{
    struct quic_parse_result result = {
        .server_id = -1,
        .cid_version = 0xFF,
        .is_initial = false
    };

    bool is_icmp = (pckt->flags & F_ICMP);
    __u64 off = calc_offset(is_ipv6, is_icmp);
    
    if((data + off + sizeof(struct udphdr) + sizeof(__u8)) > data_end) {
        return result;
    }

    __u8* quic_data = data + off + sizeof(struct udphdr);
    __u8* pkt_type = quic_data;
    __u8* connId = NULL;


    if((*pkt_type & QUIC_LONG_HEADER) == QUIC_LONG_HEADER) {
        if(quic_data + sizeof(struct quic_long_header) > data_end) {
            return result;
        }
        if((*pkt_type & QUIC_PACKET_TYPE_MASK) < QUIC_HANDSHAKE) {
            result.is_initial = true;
            return result;
        }

        struct quic_long_header* long_header = (struct quic_long_header*)quic_data;
        if(long_header->conn_id_lens < QUIC_MIN_CONNID_LEN) {
            return result;
        }
        connId = long_header->dst_connection_id;
    } else {
        if(quic_data + sizeof(struct quic_short_header) > data_end) {
            return result;
        }
        connId = ((struct quic_short_header*)quic_data)->connection_id;
    }
    if(!connId) {
        return result;
    }

    __u8 connIdVersion = (connId[0] >> 6);
    result.cid_version = connIdVersion;
    if(connIdVersion == QUIC_CONNID_VERSION_V1) {
        result.server_id = ((connId[0] & 0x3F) << 10) | (connId[1] << 2) | (connId[2] >> 6);
        return result;
    } else if(connIdVersion == QUIC_CONNID_VERSION_V2) {
        result.server_id = (connId[1] << 16) | (connId[2] << 8) | (connId[3]);
        return result;
    } else if(connIdVersion == QUIC_CONNID_VERSION_V3) {
        result.server_id = (connId[1] << 24) | (connId[2] << 16) | (connId[3] << 8) | (connId[4]);
    }
    return result;
}
