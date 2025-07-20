#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#include "tpr_pckt_routing_strcuts.h"
#include "tpr_pckt_routing_consist.h"
#include "tpr_pckt_routing_map.h"
#include "tpr_pckt_helpers.h"

SEC(TPR_PROG)
int tcp_pckt_router(struct bpf_sock_ops* skops) {
    __u32 key = GENERIC_STATS_INDEX;
    struct tpr_stats* prog_stats;
    struct server_client_info* s_info;

    prog_stats = bpf_map_lookup_elem(&stats, &key);
    if(!prog_stats) {
        return CG_ERR;
    }

    __u32 s_info_key = SERVER_INFO_INDEX;
    s_info = bpf_map_lookup_elem(&server_client_infos, &s_info_key);
    if(!s_info) {
        prog_stats->conns_skipped; //这个服务器上没有服务器信息
        return CG_OK;
    }

    __u32 exclusive_port_key = 0;
    __u32* exclusive_port = bpf_map_lookup_elem(&tpr_exclusive_port, &exclusive_port_key);
    if(!exclusive_port) {
        return CG_ERR;
    }

    if(s_info->running_mode == SERVER_MODE && *exclusive_port != 0) {
        if(skops->local_port != *exclusive_port) {
            prog_stats->conns_skipped++;
            return CG_OK;
        }
    }

    if(s_info->running_mode == SERVER_MODE) {
        if(handle_passive_cb(skops, prog_stats, s_info)) {
            prog_stats->conns_skipped++;
        }
    } else if(s_info->running_mode == CLIENT_MODE) {
        if(handle_active_cb(skops, prog_stats, s_info)) {
            prog_stats->conns_skipped++;
        }
    } else {
        prog_stats->conns_skipped++;
    }
    return CG_OK;
}