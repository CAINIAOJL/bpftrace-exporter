#pragma once


#include "tpr_pckt_router_common.h"
#include "tpr_pckt_routing_consist.h"
#include "tpr_pckt_routing_strcuts.h"
#include "tpr_pckt_routing_map.h"

__always_inline int load_tpr_opt(
                                struct bpf_sock_ops* skops, 
                                struct tcp_opt* hdr_opt, 
                                struct tpr_stats* stats)
{
    int res = 0;
    hdr_opt->kind = TCP_SRV_HDR_OPT_KIND;
    //从tcp的option字段读取tcp_opt结构体
    res = bpf_load_hdr_opt(skops, hdr_opt, sizeof(*hdr_opt), NO_FLAGS);
    if(res >= 0) {
        stats->new_server_opt++;
        return res;
    }

    return res;
}

__always_inline int handle_active_write_hdr_opt(
                                                struct bpf_sock_ops* skops, 
                                                struct tpr_stats* stats)
{
    int res = 0;
    struct tcp_opt hdr_opt = {};

    struct bpf_sock* sk_buff = skops->sk;
    if(_UNLIKELY(!sk_buff)) {
        return PASS;
    }
    hdr_opt.kind = TCP_HDR_OPT_KIND;
    hdr_opt.len = TCP_HDR_OPT_LEN;

    __u32* existing_id = (__u32*)bpf_sk_storage_get(&sk_sid_stroe, sk_buff, NULL, NO_FLAGS);
    if(_UNLIKELY(!existing_id)) {
        //不存在现有的与sock对应的server_id
        hdr_opt.server_id = 0;
        stats->error_bad_id++;
        TPR_PRINT(skops, "active failed to read server_id from sock storage");
    } else {
        hdr_opt.server_id = *existing_id; //现存的server_id
    }

    res = bpf_store_hdr_opt(skops, &hdr_opt, sizeof(hdr_opt), NO_FLAGS);
    if(res) {
        stats->error_write_opt++; //写入到tcp的option字段
        return PASS;
    }
    stats->server_id_set++;
    return SUCCESS;
}

__always_inline int handle_active_parse_hdr(
                                        struct bpf_sock_ops* skops, 
                                        struct tpr_stats* stats)
{
    int res;
    struct tcp_opt hdr_opt = {};

    //获得server_id
    res = load_tpr_opt(skops, &hdr_opt, stats);
    if(res < 0) {
        stats->no_tcp_opt_hdr++; //没有tcp option字段
        //不需要写入与解析的标志
        unset_parse_hdr_cb_flags(skops, stats);
        unset_write_hdr_cb_flags(skops, stats);
        return res;
    }
    if(!hdr_opt.server_id) {
        //server_id为0的情况
        stats->error_bad_id++;
        TPR_PRINT(skops, "active parsed empty server_id which is 0 from tcp option");
        return PASS;
    }

    struct bpf_sock* sk = skops->sk;
    if(_UNLIKELY(!sk)) {
        return PASS;
    }

    __u32* server_id = (__u32*)bpf_sk_storage_get(&sk_sid_stroe, sk, &hdr_opt.server_id, BPF_SK_STORAGE_GET_F_CREATE);
    if(_UNLIKELY(!server_id)) {
        stats->error_sys_calls++;
        return PASS;
    }

    //比较解析出来的server_id和当前server_id
    if(*server_id == hdr_opt.server_id) {
        stats->server_id_read++;
        unset_parse_hdr_cb_flags(skops, stats);
    } else {
        if(*server_id) {
            //TPR_PRINT(
                //skops,
                //"passive estab received wrong server id: option=%d, server=%d",
                //hdr_opt.server_id,
                //*server_id);
            stats->error_bad_id++;
        }
        *server_id = hdr_opt.server_id;
    }
    return SUCCESS;
}

__always_inline int handle_active_estab(
                                    struct bpf_sock_ops* skops, 
                                    struct tpr_stats* stats) 
{
    int res;
    struct tcp_opt hdr_opt = {};

    hdr_opt.kind = TCP_HDR_OPT_KIND;
    res = load_tpr_opt(skops, &hdr_opt, stats);
    if(res < 0) {
        stats->no_tcp_opt_hdr++;
        res = unset_parse_hdr_cb_flags(skops, stats);
        res |= unset_write_hdr_cb_flags(skops, stats);
        return res;
    }

    if(_UNLIKELY(!hdr_opt.server_id)) {
        stats->error_bad_id++;
        set_parse_hdr_cb_flags(skops, stats);
        set_write_hdr_cb_flags(skops, stats);
        return PASS;
    }

    struct bpf_sock* sk_buff = skops->sk;
    if(_UNLIKELY(!sk_buff)) {
        return PASS;
    }

    __u32* server_id = (__u32*)bpf_sk_storage_get(&sk_sid_stroe, sk_buff, &hdr_opt.server_id, BPF_SK_STORAGE_GET_F_CREATE);
    if(_UNLIKELY(!server_id || *server_id != hdr_opt.server_id)) {
        if(server_id) {
            *server_id = 0; //嵌入 0 server_id
            stats->error_bad_id++;
        } else {
            stats->error_sys_calls++;
        }

        set_write_hdr_cb_flags(skops, stats);
        set_parse_hdr_cb_flags(skops, stats);
        return PASS;
    }

    res = set_write_hdr_cb_flags(skops, stats);
    if(res) {
        res |= set_parse_hdr_cb_flags(skops, stats);
        return res;
    }
    stats->server_id_read++;
    return SUCCESS;
}