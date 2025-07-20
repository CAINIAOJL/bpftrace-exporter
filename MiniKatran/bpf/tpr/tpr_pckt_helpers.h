#pragma once


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "tpr_pckt_routing_strcuts.h"
#include "tpr_pckt_routing_consist.h"
#include "tpr_pckt_router_common.h"
#include "tpr_pckt_router_passive_hdr.h"
#include "tpr_pckt_router_active_hdr.h"

//服务器处理逻辑
__always_inline int handle_passive_cb(
                                    struct bpf_sock_ops* skops, 
                                    struct tpr_stats* stats, 
                                    const struct server_client_info* s_info)
{
    //debug
    TPR_PRINT(skops, "handle_passive_cb");
/*
第一次握手：客户端发送一个带有SYN标志的TCP报文到服务器，表示开始建立连接，并发送初始序列号seq=x。此时客户端进入SYN-SENT状态。

第二次握手：服务器收到客户端的SYN报文后，如果同意建立连接，则发送一个带有SYN和ACK标志的TCP报文，确认号ack=x+1，并发送自己的初始序列号seq=y。服务器此时进入SYN-RCVD状态。

第三次握手：客户端收到服务器的SYN+ACK报文后，发送一个ACK报文，确认号ack=y+1，序列号seq=x+1。此时，TCP连接建立，客户端进入ESTABLISHED状态。
*/
    switch(skops->op) {
        case BPF_SOCK_OPS_TCP_LISTEN_CB:
            return set_write_hdr_cb_flags(skops, stats); //向tcp的option写入

        case BPF_SOCK_OPS_PARSE_HDR_OPT_CB: //作为一个完整连接，解析tcp的option字段
            return handle_passive_parse_hdr(skops, stats, s_info);
        //为tcp的option字段添加空间
        case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
            if((skops->skb_tcp_flags & (TCPHDR_SYNACK) == TCPHDR_SYNACK) & !should_ignore_due_to_kde(skops)) {
                return handle_hdr_opt_len(skops, stats);
            } else {
                return SUCCESS;
            }
        //写入tcp的option字段
        case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
            if((skops->skb_tcp_flags & TCPHDR_SYNACK) == TCPHDR_SYNACK) {
                return handle_passive_write_hdr_opt(skops, stats, s_info);
            } else {
                return SUCCESS;
            }
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            return handle_passive_estab(skops, stats, s_info);
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        default:
            break;
    }
    return SUCCESS;
}

//客户端处理逻辑
__always_inline int handle_active_cb(
                                    struct bpf_sock_ops* skops, 
                                    struct tpr_stats* stats, 
                                    const struct server_client_info* s_info) 
{   
    TPR_PRINT(skops, "handle_active_cb", skops->op); 

    switch(skops->op) {
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
            break;
        case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
            if((skops->skb_tcp_flags & TCPHDR_SYNACK) == TCPHDR_SYNACK) {
                return handle_active_parse_hdr(skops, stats);
            } else {
                return SUCCESS;
            }
        case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
            //确保不是第一次发起连接时处理
            if((skops->skb_tcp_flags & TCPHDR_SYN) == TCPHDR_SYN) {
                return handle_hdr_opt_len(skops, stats);
            } else {
                return SUCCESS;
            }
        case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
            if((skops->skb_tcp_flags & TCPHDR_SYN) != TCPHDR_SYN) {
                return handle_active_write_hdr_opt(skops, stats);
            } else {
                return SUCCESS;
            }
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: //主动完成建立
            return handle_active_estab(skops, stats);
        case BPF_SOCK_OPS_TCP_LISTEN_CB:
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: //被动完成建立
            break;
    }
    return SUCCESS;
}