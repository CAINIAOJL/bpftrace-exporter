#pragma once

#include <linux/types.h>

//这个结构体保存着路由的mac地址
//再katran中，上层路由会把数据包导到一个katran中，但是，数据包的目的地址不是这个katran所在的服务器，
//也就是katran与服务例如nginx共存，这个数据包的归属不是这个服务器上的nginx，我们的katran会将数据包封装
//发送到机房中的正确的服务器上。
struct ctl_value {
    //__u64 value;
    //__u32 ifindex;
    __u8 mac[6];
};

struct flow_key {
    __be32 src;
    __be32 srcv6[4];

    __be32 dst;
    __be32 dstv6[4];

    __u32 ports;
    __u16 port16[2];

    __u8 proto;
};

struct packet_description {
    struct flow_key flow;
    __u32 real_index; //正确的位置
    __u8 flags;
    __u8 tos; //服务类型,我们可能会修改tcp的option字段
};

struct vip_definition {
    __be32 vip;
    __be32 vip6[4];

    __u16 port;
    __u8 proto;
};

struct vip_meta {
    __u32 flags;
    __u32 vip_num; //虚拟ip所对应的服务器序号
};

//导向的服务器ip地址
struct real_definition {
    __be32 dst;
    __be32 dstv6[4];
    __u8 flags;
};

struct lb_stats {
    __u64 v1;
    __u64 v2;
};

struct lpm_key4 {
    __u32 prefixlen;
    __u32 addr;
}__attribute__((packed));

struct lpm_key6 {
    __u32 prefixlen;
    __u8 addr[16]; //?
}__attribute__((packed));

struct address
{
    __be32 addr;
    __be32 addrv6[4];
};

//数据包发送的位置（cpu）来自LRU映射
struct real_pos_lru {
  __u32 pos;
  __u64 atime;
};

struct lb_stable_rt_packets_stats {
  __u64 ch_routed;
  __u64 cid_routed;
  __u64 cid_invalid_server_id;
  __u64 cid_unknown_real_dropped;
  __u64 invalid_packet_type;
};

struct lb_tpr_packets_stats {
  __u64 ch_routed;
  __u64 dst_mismatch_in_lru;
  __u64 sid_routed;
  __u64 tcp_syn;
};

//解析tcp的option选项的结构体
struct hdr_opt_state {
  __u32 server_id;
  __u8 byte_offset;
  __u8 hdr_bytes_remaining;
};

struct lb_quic_packets_stats {
    __u64 ch_routed;
    __u64 cid_initial;
    __u64 cid_invalid_server_id;
    __u64 cid_invalid_server_id_sample;
    __u64 cid_routed;
    __u64 cid_unknown_real_dropped;
    __u64 cid_v0;
    __u64 cid_v1;
    __u64 cid_v2;
    __u64 cid_v3;
    __u64 dst_match_in_lru;
    __u64 dst_mismatch_in_lru;
    __u64 dst_not_found_in_lru;
};


struct quic_long_header {
  __u8 flags;
  __u32 version;
  __u8 conn_id_lens;
  __u8 dst_connection_id[QUIC_MIN_CONNID_LEN];
} __attribute__((__packed__));

struct quic_short_header {
  __u8 flags;
  __u8 connection_id[QUIC_MIN_CONNID_LEN];
} __attribute__((__packed__));

struct quic_parse_result {
  int server_id;
  __u8 cid_version;
  bool is_initial;
};