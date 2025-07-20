#pragma once

#define TPR_PROG "sockops"

#define GENERIC_STATS_INDEX 0

#define CG_OK 1

#define CG_ERR 0

#define SERVER_CLIENT_INFO_MAP_SIZE 1

#define SERVER_INFO_INDEX 0

#define SERVER_MODE 1

#define CLIENT_MODE 2

#define EXCLUSIVE_PORT_QUANTITY 1

#define TCPHDR_SYN 0x02

#define TCPHDR_ACK 0x10

//syn ack报文
#define TCPHDR_SYNACK (TCPHDR_SYN | TCPHDR_ACK)

#define NO_FLAGS 0

#define SUCCESS 0

#define PASS -1

#define TPR_DEBUG

#define TCP_SRV_HDR_OPT_KIND 0xB6

#define TCP_HDR_OPT_KIND 0xB7

#define TCP_HDR_OPT_LEN 6

#define _LIKELY(expr) __builtin_expect(!!(expr), 1)

#define _UNLIKELY(expr) __builtin_expect(!!(expr), 0)