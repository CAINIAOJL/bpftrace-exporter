#pragma once

#include <linux/types.h>

//用以区别服务器和客户端的结构体
struct server_client_info {
    __u8 running_mode;
    __u8 ked_enabled;
    __u32 server_id; //放入tcp option的字段的服务器id
};

//放入tcp的option数据段
struct tcp_opt {
    __u8 kind;
    __u8 len;
    __u32 server_id; 
} __attribute__((packed));

struct kde_clt_tcp_opt {
    __u8 kind;
    __u8 len;
} __attribute__((packed));

//统计计数信息
struct tpr_stats {
    __u64 server_id_read;
    __u64 server_id_set;
    __u64 conns_skipped;
    __u64 no_tcp_opt_hdr;
    __u64 error_bad_id;
    __u64 error_write_opt;
    __u64 error_sys_calls;
    __u64 ignoring_due_to_kde;
    __u64 legacy_server_opt;
    __u64 new_server_opt;
};