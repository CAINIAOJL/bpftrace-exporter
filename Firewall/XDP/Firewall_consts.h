#pragma once

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define ENABLE_IPV6
#define ENABLE_DEBUG_LOG
#define ENABLE_LPM_RULE
#define LIMIT_GLOBAL_PACKETS
#define LIMIT_PACKETS_PER_IP
#define LIMIT_PACKETS_PER_PROTOCOL
#define LIMIT_TCP_PACKETS
#define LIMIT_UDP_PACKETS

#define XDP "xdp"

#define FURTHER_PROCESSING -1

#define V4   4
#define V6   6

#define NO_FLAGS 0

#define MAX_IFACES 10

#define MAX_IFACES_IPS  1000

#define MAX_IFACES_PORTS 1000

#define MAX_LPM_IPS 10000

#define MAX_LPM_PREFIXLEN_v4 33

#define MAX_LPM_PREFIXLEN_v6 129

#define LPM_PREFIXLEN_v4 32

#define LPM_PREFIXLEN_v6 128

#define TIME_NANOS 1000000000

#define TOKENS_PER_PACKET 1

#define IP_COUNT 100000

#define IP_COUNT_V6 100000

#define PROTOCOL_COUNT 3

#define TB_INDEX_GLOBAL 0

#define TB_INDEX_TCP 1

#define TB_INDEX_UDP 2

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#endif

#define LOG_DEBUG_RULE 1

#define LOG_DEBUG_LPM 2

#define LOG_DEBUG_All 3

#define LOG_DEBUG_TCP 4

#define LOG_DEBUG_UDP 5

#define LOG_DEBUG_IP 6

#define LOG_DEBUG_IP6 7