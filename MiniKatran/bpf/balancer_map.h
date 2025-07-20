#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include "balancer_consts.h"
#include "balancer_struct.h"
//虚拟ip对应的服务器的序号
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct vip_definition);
  __type(value, struct vip_meta);
  __uint(max_entries, MAX_VIPS);
  __uint(map_flags, NO_FLAGS);
} vip_map SEC(".maps");

//缓存LRU表，前端放入
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct flow_key);
  __type(value, struct real_pos_lru);
  __uint(max_entries, DEFAULT_LRU_SIZE);
  __uint(map_flags, NO_FLAGS);
} fallback_cache SEC(".maps");

//每个cpu上都有一个lru映射，分cpu会更快
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_SUPPORTED_CPUS);
  __uint(map_flags, NO_FLAGS);
  __array(
      values,
      struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, struct flow_key);
        __type(value, struct real_pos_lru);
        __uint(max_entries, DEFAULT_LRU_SIZE);
      });
} lru_mapping SEC(".maps");

//算法生成的ch_ring
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, CH_RINGS_SIZE);
  __uint(map_flags, NO_FLAGS);
} ch_rings SEC(".maps"); 

//server_id映射服务器的位置
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct real_definition);
  __uint(max_entries, MAX_REALS);
  __uint(map_flags, NO_FLAGS);
} reals SEC(".maps");

//每个real的统计信息
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct lb_stats);
  __uint(max_entries, MAX_REALS);
  __uint(map_flags, NO_FLAGS);
} reals_stats SEC(".maps");

//追踪lru查询miss的状态
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct vip_definition);
  __uint(max_entries, 1);
  __uint(map_flags, NO_FLAGS);
} vip_miss_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32); 
  __type(value, __u32);
  __uint(max_entries, MAX_REALS);
  __uint(map_flags, NO_FLAGS);
} lru_miss_stats SEC(".maps");

//每个vip的统计信息
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct lb_stats);
  __uint(max_entries, STATS_MAP_SIZE);
  __uint(map_flags, NO_FLAGS);
} stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct lb_stable_rt_packets_stats);
  __uint(max_entries, STABLE_RT_STATS_MAP_SIZE);
  __uint(map_flags, NO_FLAGS);
} stable_rt_stats SEC(".maps");

//decap数据包统计
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct lb_stats);
  __uint(max_entries, MAX_VIPS);
  __uint(map_flags, NO_FLAGS);
} decap_vip_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_NUM_SERVER_IDS);
  __uint(map_flags, NO_FLAGS);
} server_id_map SEC(".maps");

//lpm trie映射
#ifdef LPM_SRC_LOOKUP
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct lpm_key4);
  __type(value, __u32);
  __uint(max_entries, MAX_LPM_SRC);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_src_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct lpm_key6);
  __type(value, __u32);
  __uint(max_entries, MAX_LPM_SRC);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_src_v6 SEC(".maps");

#endif // of LPM_SRC_LOOKUP

#ifdef GLOBAL_LRU_LOOKUP

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_SUPPORTED_CPUS);
  __uint(map_flags, NO_FLAGS);
  __array(
      values,
      struct {
        __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
        __type(key, struct flow_key);
        __type(value, __u32);
        __uint(max_entries, DEFAULT_LRU_SIZE);
      });
} global_lru_maps SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct flow_key);
  __type(value, __u32);
  __uint(max_entries, DEFAULT_GLOBAL_LRU_SIZE);
  __uint(map_flags, NO_FLAGS);
} fallback_glru SEC(".maps");

#endif // of GLOBAL_LRU_LOOKUP

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct lb_tpr_packets_stats);
  __uint(max_entries, TPR_STATS_MAP_SIZE);
  __uint(map_flags, NO_FLAGS);
} tpr_stats_map SEC(".maps");

//服务器id的统计信息
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct lb_stats);
  __uint(max_entries, MAX_VIPS);
  __uint(map_flags, NO_FLAGS);
} server_id_stats SEC(".maps");

//确保内核开启DECAP严格认证
#if defined(GUE_ENCAP) || defined(DECAP_STRICT_DESTINATION)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct real_definition);
  __uint(max_entries, 2);
  __uint(map_flags, NO_FLAGS);
} pckt_srcs SEC(".maps");
#endif //GUE_ENCAP || DECAP_STRICT_DESTINATION

#ifdef INLINE_DECAP_GENERIC
//decap数据包统计信息映射
//如果内核没有开启严格认证decap数据包，我们要给出标记，以便xdp程序来验证
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct address);
  __type(value, __u32);
  __uint(max_entries, MAX_VIPS);
  __uint(map_flags, NO_FLAGS);
} decap_dst SEC(".maps");

//递归程序映射
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, SUBPROGRAMS_ARRAY_SIZE);
} subprograms SEC(".maps");
#endif

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct ctl_value);
  __uint(max_entries, CTL_MAP_SIZE);
  __uint(map_flags, NO_FLAGS);
} ctl_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct lb_quic_packets_stats);
  __uint(max_entries, QUIC_STATS_MAP_SIZE);
  __uint(map_flags, NO_FLAGS);
} quic_stats_map SEC(".maps");