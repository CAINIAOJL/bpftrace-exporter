#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include "tpr_pckt_routing_consist.h"
#include "tpr_pckt_routing_strcuts.h"

//一台机子上有一个server_id的信息
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SERVER_CLIENT_INFO_MAP_SIZE);
    __type(key, __u32);
    __type(value, struct server_client_info);
} server_client_infos SEC(".maps");

//键类型必须为 int，max_entries 必须设置为 0。
//创建套接字本地存储的 map 时，必须使用 BPF_F_NO_PREALLOC 标志。
//存储本地套接字的映射
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(max_entries, 0); //必须是0
    __uint(map_flags, BPF_F_NO_PREALLOC); //不要提前分配内存
    __type(key, __u32);
    __type(value, __u32);
}sk_sid_stroe SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, SERVER_CLIENT_INFO_MAP_SIZE);
    __type(key, __u32);
    __type(value, struct tpr_stats);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, EXCLUSIVE_PORT_QUANTITY);
    __type(key, __u32);
    __type(value, __u32); //g_server_exclusive_port
} tpr_exclusive_port SEC(".maps");