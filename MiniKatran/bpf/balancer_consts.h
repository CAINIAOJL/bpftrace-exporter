#pragma once

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#endif

// FLAGS:
#define F_IPV6 (1 << 0)

#define F_LOCAL_REAL (1 << 1)

#define F_HASH_NO_SRC_PORT (1 << 0)

#define F_LRU_BYPASS (1 << 1)

#define F_QUIC_VIP (1 << 2)

#define F_HASH_DPORT_ONLY (1 << 3)

#define F_SRC_ROUTING (1 << 4)

#define F_LOCAL_VIP (1 << 5)

#define F_GLOBAL_LRU (1 << 6)

#define F_HASH_SRC_DST_PORT (1 << 7)

#define F_UDP_STABLE_ROUTING_VIP (1 << 8)

#define F_ICMP (1 << 0)
// 设置第一次连接标志，用于测试
#define F_SYN_SET (1 << 1)

#define INLINE_DECAP_IPIP

#define INLINE_DECAP_GENERIC

#define DECAP_STRICT_DESTINATION

#define TCP_SERVER_ID_ROUTING

#define GLOBAL_LRU_LOOKUP

#define GLOBAL_LRU_LOOKUP

#define LPM_SRC_LOOKUP

#define LOCAL_DELIVERY_OPTIMIZATION

#ifdef GUE_ENCAP
#define PCKT_ENCAP_V4 gue_encap_v4
#define PCKT_ENCAP_V6 gue_encap_v6
#else
#define PCKT_ENCAP_V4 encap_v4
#define PCKT_ENCAP_V6 encap_v6
#endif

#define UDP_STABLE_ROUTING

#define INLINE_DECAP_GUE

#define ICMP_TOOBIG_GENERATION

#define BLANCER_PROG "xdp"

#define LRU_CNTRS 0

#define LRU_MISS_CNTR 1

#define NEW_CONN_RATE_CNTR 2

#define FALLBACK_LRU_CNTR 3

#define ICMP_TOOBIG_CNTRS 4

#define LPM_SRC_CNTRS 5

#define REMOTE_ENCAP_CNTRS 6

#define GLOBAL_LRU_CNTR 8

#define CH_DROP_STATS 9

#define DECAP_CNTR 10

#define QUIC_ICMP_STATS 11

#define ICMP_PTB_V6_STATS 12

#define ICMP_PTB_V4_STATS 13

#define NO_FLAGS 0

#define MAX_VIPS 512

#define RING_SIZE 65537

#define MAX_REALS 4096

#define STATS_MAP_SIZE (MAX_VIPS * 2)

#define DEFAULT_LRU_SIZE 1000

#define MAX_SUPPORTED_CPUS 128 //支持的cpu数量，128暂定

#define CH_RINGS_SIZE (MAX_VIPS * RING_SIZE)

#define STABLE_RT_STATS_MAP_SIZE 1

#define TPR_STATS_MAP_SIZE 1

#define MAX_NUM_SERVER_IDS (1 << 24)

#define MAX_LPM_SRC 3000000

#define DEFAULT_GLOBAL_LRU_SIZE 10000

#define IPV4_HDR_LEN_NO_OPT 20

#define PCKT_FRAGMENTED 65343

#define GUEV1_IPV6MASK 0x30

#define FURTHER_PROCESSING -1

#define V4_SRC_INDEX 0

#define V6_SRC_INDEX 1

#define SUBPROGRAMS_ARRAY_SIZE 1

#define BE_ETH_P_IP 8

#define BE_ETH_P_IPV6 56710

#define RECIRCULATION_INDEX 0

#if defined(TCP_SERVER_ID_ROUTING) || defined(DECAP_TPR_STATS)
//用于tcp_server id的定义，用于解析option字段
#define TCP_HDR_OPT_KIND_TPR 0xB7

#define TCP_HDR_OPT_LEN_TPR 6

#define TCP_HDR_OPT_MAX_OPT_CHECKS 15

#define TCP_OPT_EOL 0

#define TCP_OPT_NOP 1
#endif

//lru匹配
#define DST_MATCH_IN_LRU 0

//lru未匹配
#define DST_MISMATCH_IN_LRU 1

//lru未匹配
#define DST_NOT_FOUND_IN_LRU 2

#define ONE_SEC 1000000000U //1秒-》毫秒

#define LRU_UDP_TIMEOUT 30000000000U

#define MAX_CONN_RATE 125000

#define CTL_MAP_SIZE 16

#define INIT_JHASH_SEED_V6 MAX_VIPS

#define INIT_JHASH_SEED CH_RINGS_SIZE

#define IPIP_V6_PREFIX1 1

#define IPIP_V6_PREFIX2 0

#define IPIP_V6_PREFIX3 0

#define IPIP_V4_PREFIX 4268 //172.16/10 0xAC100000

#define DEFAULT_TOS 0

#define GUE_DPORT 6080

#define COPY_INNER_PACKET_TOS 1 

#define DEFAULT_TTL 64

#define STABLE_RT_LEN 8

#define STABLE_ROUTING_HEADER 0x52

#define MAX_PCKT_SIZE 1514

#define ICMP_TOOBIG_SIZE 98
#define ICMP6_TOOBIG_SIZE 262

#define ICMP6_TOOBIG_PAYLOAD_SIZE (ICMP6_TOOBIG_SIZE - 6)
#define ICMP_TOOBIG_PAYLOAD_SIZE (ICMP_TOOBIG_SIZE - 6)

#define MAX_MTU_IN_PTB_TO_DROP 1280

#define QUIC_STATS_MAP_SIZE 1

#define QUIC_MIN_CONNID_LEN 8

#define QUIC_LONG_HEADER 0x80

#define QUIC_SHORT_HEADER 0x00

#define QUIC_CLIENT_INITIAL 0x00

#define QUIC_0RTT 0x10

#define QUIC_HANDSHAKE 0x20

#define QUIC_RETRY 0x30

#define QUIC_PACKET_TYPE_MASK 0x30

#define QUIC_CONNID_VERSION_V1 0x1

#define QUIC_CONNID_VERSION_V2 0x2

#define QUIC_CONNID_VERSION_V3 0x3

#define SWAP16_BYTES(x) ( (( (x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8) )

#define IPV6_TAIL_REVERT(p) do { \
    __u32 val = *(p); \
    __u16 high = (val >> 16) & 0xFFFF; \
    __u16 low = val & 0xFFFF; \
    *(p) = (SWAP16_BYTES(low) << 16) | high; \
} while(0)


