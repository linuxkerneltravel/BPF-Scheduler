#ifndef NET_EVENT_H
#define NET_EVENT_H

#include "sys_event.h"

#define AF_INET    2
#define AF_INET6   10
#define INET6_ADDRSTRLEN 46

#define RETRANSMIT  1
#define TLP         2

// tcp状态
// enum {
// 	TCP_ESTABLISHED = 1,
// 	TCP_SYN_SENT,
// 	TCP_SYN_RECV,
// 	TCP_FIN_WAIT1,
// 	TCP_FIN_WAIT2,
// 	TCP_TIME_WAIT,
// 	TCP_CLOSE,
// 	TCP_CLOSE_WAIT,
// 	TCP_LAST_ACK,
// 	TCP_LISTEN,
// 	TCP_CLOSING,	/* Now a valid state */
// 	TCP_NEW_SYN_RECV,
// 	TCP_BOUND_INACTIVE, /* Pseudo-state for inet_diag */

// 	TCP_MAX_STATES	/* Leave at the end! */
// };
struct tcp_retransmit_skb_event {
    unsigned short common_type;          // 通用字段: 事件类型
    unsigned char common_flags;          // 通用字段: 标志位
    unsigned char common_preempt_count;  // 通用字段: 抢占计数
    int common_pid;                      // 通用字段: 当前进程 PID

    const void *skbaddr;                 // sk_buff 地址
    const void *skaddr;                  // 套接字地址

    int state;                           // TCP 状态
    __u16 sport;                         // 源端口号
    __u16 dport;                         // 目标端口号
    __u16 family;                        // 地址族

    __u8 saddr[4];                       // IPv4 源地址
    __u8 daddr[4];                       // IPv4 目标地址
    __u8 saddr_v6[16];                   // IPv6 源地址
    __u8 daddr_v6[16];                   // IPv6 目标地址
};

struct tcp_net_latency {
    union {
        u32 saddr_v4;
        __u8 saddr_v6[16];
    } src_addr;
    union {
        u32 daddr_v4;
        __u8 daddr_v6[16];
    } dst_addr;
    char comm[TASK_COMM_LEN];
    u64 delta; // 等待时间
    u64 ts; // 事件发生时间
    u32 tgid;
    int af; // 地址族类型
    __u16 lport;// 本地端口号
    __u16 dport;// 目标端口号
};

struct tcprtt_perf_data {
    u32 data[8];
};

struct ipv4_key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    __u16 lport;
    __u16 dport;
};

struct ipv6_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u32 pid;
    char comm[TASK_COMM_LEN];
    __u16 lport;
    __u16 dport;
};

struct recv_send_bytes {
    u64 recv;
    u64 send;

    u64 last_output;// 避免同一个重复多次发送，同一个每秒发送一次
};

// 实现tcpretrans的结构
struct tcp_resubmit {
    union {
        u32 saddr_v4;
        __u8 saddr_v6[16];
    } src_addr;
    union {
        u32 daddr_v4;
        __u8 daddr_v6[16];
    } dst_addr;
    char comm[TASK_COMM_LEN];
    int af; // 地址族类型
    u16 lport;// 本地端口号
    u16 dport;// 目标端口号
    u32 pid;

    u32 seq; // 序列号
    u64 state; // tcp状态
    u64 type; // 事件类型
    u64 occur; // 发生时间
};

struct tcp_top_perf_data {
    union {
        u32 saddr_v4;
        __u8 saddr_v6[16];
    } src_addr;
    union {
        u32 daddr_v4;
        __u8 daddr_v6[16];
    } dst_addr;
    char comm[TASK_COMM_LEN];
    u64 send; // 
    u64 recv; // 
    u32 pid;
    int af; // 地址族类型
    __u16 lport;// 本地端口号
    __u16 dport;// 目标端口号
};

#endif