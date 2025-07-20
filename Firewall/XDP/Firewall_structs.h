#pragma once

#include <linux/types.h>
typedef __uint128_t u128;
typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

typedef __s64 s64;
typedef __s32 s32;
typedef __s16 s16;

typedef __be64 be64;
typedef __be32 be32;
typedef __be16 be16;


struct Ip_ifindex {
    u32 ip; 
    u32 ifindex;
};

struct Ip6_ifindex {
    u32 ifindex;
    u8 ip[16];
};

struct Package_Dropped {
    u64 Active_Dropped; //根据规则丢弃的数据包数
    u64 Passive_Dropped; //数据包有错误的数据包数 ？？？？
};

struct Package_Count {
    u64 Allowed;
    u64 Passed;
    struct Package_Dropped Dropped;
};

//192.168.88.0/32
struct Lpm_trie_key4 {
    u32 prefixlen;
    u32 data;
};

//https://github.com/cilium/ebpf/discussions/1658
__hidden struct Lpm_trie_key4 Lpm_trie_key4;

int dummy1(struct Lpm_trie_key4 Lpm_trie_key4) {
	return 0;
}

//056E:1751:DF50:E00A:D333:928E:0E5F:2CF7/128
struct Lpm_trie_key6 {
    u32 prefixlen;
    u8 ip[16];
};

//https://github.com/cilium/ebpf/discussions/1658
__hidden struct Lpm_trie_key6 Lpm_trie_key6;

int dummy2(struct Lpm_trie_key6 Lpm_trie_key6) {
	return 0;
}

struct Cl_stats {
    u64 pps;
    u64 bps;
    u64 update_time;
};

struct Flow {
    u32 ip;
    u16 port;
    u8 protocol;
};


struct Flow6 {
    u128 ip;
    u16 port;
    u8 protocol;
};

struct Debug_Log {
    u8 type;
    u32 ip;         
    u128 ip6;        
    u16 port;      
    u8 protocol;  
    u8 mode;        
    u8 version;     
}__attribute__((packed));

struct flow_key {
  union {
    be32 src;
    be32 srcv6[4];
  };
  union {
    be32 dst;
    be32 dstv6[4];
  };
  union {
    u32 ports;
    u16 port16[2];
  };
  u8 proto;
};

struct flow_speed {
    u64 bytes;
    u64 packets;
};

struct packet_description {
  struct flow_key flow;
};

struct token_bucket_key {
    u32 ifindex;
    u8 category;
};

struct rate_burst {
    u64 rate;
    u64 burst;
};

struct token_bucket {
    u64 last_update_time; 
    u64 tokens;
};

struct tokens_rate_burst_key {
    u32 ifindex;
    u32 ip;
    u8 ip6[16];
};
