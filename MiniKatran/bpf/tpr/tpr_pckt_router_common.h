#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tpr_pckt_routing_strcuts.h"
#include "tpr_pckt_routing_consist.h"

#ifdef TPR_DEBUG
static inline const char* sk_op_str(__u32 op) {
  switch (op) {
    case BPF_SOCK_OPS_VOID:
      return "VOID";
    case BPF_SOCK_OPS_TIMEOUT_INIT:
      return "TIMEOUT_INIT";
    case BPF_SOCK_OPS_RWND_INIT:
      return "RWND_INIT";
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
      return "TCP_CONNECT_CB";
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
      return "ACTIVE_ESTABLISHED_CB";
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
      return "PASSIVE_ESTABLISHED_CB";
    case BPF_SOCK_OPS_NEEDS_ECN:
      return "NEEDS_ECN";
    case BPF_SOCK_OPS_BASE_RTT:
      return "BASE_RTT";
    case BPF_SOCK_OPS_RTO_CB:
      return "RTO_CB";
    case BPF_SOCK_OPS_RETRANS_CB:
      return "RETRANS_CB";
    case BPF_SOCK_OPS_STATE_CB:
      return "STATE_CB";
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
      return "TCP_LISTEN_CB";
    case BPF_SOCK_OPS_RTT_CB:
      return "RTT_CB";
    case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
      return "PARSE_HDR_OPT_CB";
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
      return "HDR_OPT_LEN_CB";
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
      return "WRITE_HDR_OPT_CB";
    default:
      return "UNKNOWN";
  }
}

#define TPR_PRINT(skops, fmtStr, ...)      \
  bpf_printk(                              \
      "[op=%s rport=%d lport=%d] " fmtStr, \
      sk_op_str(skops->op),                \
      bpf_ntohl(skops->remote_port),       \
      skops->local_port,                   \
      ##__VA_ARGS__);

#else
#define TPR_PRINT(skops, fmtStr, ...) ;
#endif // TPR_DEBUG


//
__always_inline int set_write_hdr_cb_flags(
                                        struct bpf_sock_ops* skops, 
                                        struct tpr_stats* stats) 
{
    //向这个sock写入写入标志的标识
    int res = bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
    if(res) {
        stats->error_sys_calls++;
    }
    return res;
}

__always_inline int unset_write_hdr_cb_flags(
                                        struct bpf_sock_ops* skops, 
                                        struct tpr_stats* stats)
{
    int res = bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
    if(res) {
        stats->error_sys_calls++;
    }
    return res;
} 

__always_inline int set_parse_hdr_cb_flags(
                                    struct bpf_sock_ops* skops,
                                    struct tpr_stats* stats)
{
    int res = bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
    if(res) {
        stats->error_sys_calls++;
    }
    return res;
}

__always_inline int unset_parse_hdr_cb_flags(
                                    struct bpf_sock_ops* skops,
                                    struct tpr_stats* stats)
{
    int res = bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
    if(res) {
        stats->error_sys_calls++;
    }
    return res;
}

__always_inline int handle_hdr_opt_len(
                                    struct bpf_sock_ops* skops, 
                                    struct tpr_stats* stats) 
{
    //整备tcp_opt大小的空间
    int res = bpf_reserve_hdr_opt(skops, sizeof(struct tcp_opt), 0);
    if(res) {
        stats->error_sys_calls++;
    }
    return res;
}