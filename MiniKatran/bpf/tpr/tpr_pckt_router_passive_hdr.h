#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "tpr_pckt_routing_consist.h"
#include "tpr_pckt_routing_strcuts.h"
#include "tpr_pckt_routing_map.h"
#include "tpr_pckt_router_common.h"

//这台服务器
__always_inline bool kde_enabled() {
    __u32 sinfo_key = SERVER_INFO_INDEX;
    struct server_client_info* s_info = bpf_map_lookup_elem(&server_client_infos, &sinfo_key);
    return (s_info && s_info->ked_enabled); //是否挂掉 
}

__always_inline bool has_syn_with_kde_opt(struct bpf_sock_ops* skops) {
    __u64 load_flags = BPF_LOAD_HDR_OPT_TCP_SYN;
    struct kde_clt_tcp_opt kde_opt = {}; //不含server_id的option字段
    return (bpf_load_hdr_opt(skops, &kde_opt, sizeof(kde_opt), load_flags) == sizeof(kde_opt));
}

__always_inline bool should_ignore_due_to_kde(struct bpf_sock_ops* skops)
{
    return kde_enabled() && has_syn_with_kde_opt(skops);
}

__always_inline int handle_passive_parse_hdr(
                                        struct bpf_sock_ops* skops, 
                                        struct tpr_stats* stats, 
                                        const struct server_client_info* s_info) 
{
    int res;
    struct tcp_opt hdr_ops = {};
    res = bpf_load_hdr_opt(skops, &hdr_ops, sizeof(struct tcp_opt), NO_FLAGS);
    if(res < 0) {
        TPR_PRINT(skops, "passive parsed hdr found np option!");
        stats->no_tcp_opt_hdr++;
        return res;
    }

    if(!hdr_ops.server_id) {
        stats->error_bad_id++;
        TPR_PRINT(skops, "passive received 0 server_id!");
        return PASS;
    }

    if(s_info->server_id != hdr_ops.server_id) {
        stats->error_bad_id++;
        TPR_PRINT(
        skops,
        "passive estab received wrong server id: option=%d, server=%d",
        hdr_ops.server_id,
        s_info->server_id);
        return PASS;
    } else {
        //s_info->server_id == hdr_ops.server_id
        stats->server_id_read++;
        TPR_PRINT(skops, "passive received server_id option");
        res = unset_parse_hdr_cb_flags(skops, stats);
        res |= unset_write_hdr_cb_flags(skops, stats);
        return res;
    }
    return SUCCESS;
}

__always_inline int handle_passive_write_hdr_opt(
                                            struct bpf_sock_ops* skops, 
                                            struct tpr_stats* stats, 
                                            const struct server_client_info* s_info) 
{
    if(should_ignore_due_to_kde(skops)) {
        stats->ignoring_due_to_kde++;
        return SUCCESS;
    }

    int err;
    struct tcp_opt hdr_opt = {};

    hdr_opt.kind = TCP_SRV_HDR_OPT_KIND;
    hdr_opt.len = TCP_HDR_OPT_LEN;
    hdr_opt.server_id = s_info->server_id;
    err = bpf_store_hdr_opt(skops, &hdr_opt, sizeof(hdr_opt), NO_FLAGS);
    if(err) {
        stats->error_write_opt++;
        return err;
    }
    stats->server_id_set++;
    TPR_PRINT(skops, "passive wrote option");
    return SUCCESS;
}

__always_inline int handle_passive_estab(
                                        struct bpf_sock_ops* skops, 
                                        struct tpr_stats* stats, 
                                        const struct server_client_info* s_info)
{
    int err;
    struct tcp_opt hdr_opt = {};
    hdr_opt.kind = TCP_HDR_OPT_KIND;
    err = bpf_load_hdr_opt(skops, &hdr_opt, sizeof(struct tcp_opt), NO_FLAGS);
    if(err < 0) {
        stats->no_tcp_opt_hdr++;
        TPR_PRINT(skops, "passive estab found no option");
        unset_write_hdr_cb_flags(skops, stats);
        unset_parse_hdr_cb_flags(skops, stats);
        return err;
    }
    //服务器id不相等
    if(s_info->server_id != hdr_opt.server_id) {
        stats->error_bad_id++;
        TPR_PRINT(
            skops,
            "passive estab received wrong server id: option=%d, server=%d",
            hdr_opt.server_id,
            s_info->server_id);
        return set_parse_hdr_cb_flags(skops, stats);
    } else {
        stats->server_id_read++;
    }

    err = unset_parse_hdr_cb_flags(skops, stats);
    err |= unset_write_hdr_cb_flags(skops, stats);
}