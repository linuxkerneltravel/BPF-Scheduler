#ifndef SYS_EVENT_H
#define SYS_EVENT_H


#include <linux/version.h>
#include <asm/types.h>
#include <string.h>


#define TASK_COMM_LEN 16
//typedef unsigned long long u64;
typedef uint64_t u64;
typedef unsigned int u32;
typedef __u16 u16;
typedef __u8 u8;

#define MSEC 1000000 // 1毫秒

#define USEC 1000 // 1微妙

#define MAX_ENTRIES 102400 // map容量

#define MAX_TASK_ENTRIES 10240

#define MAX_PROCESS_ENTRIES 2048

#define GLOBAL_HASH_SIZE 256

#define GLOBAL_HASH_BUCKET_SIZE 4


#define MAX_STACK_DEPTH 20 // 栈回溯最大深度
typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

#define DEFINE_BPF_MAP(map_name, map_type, MAX_ENTRIES, key_type, value_type) \
	struct { \
		__uint(type, map_type); \
		__uint(key_size, sizeof(key_type)); \
		__uint(value_size, sizeof(value_type)); \
		__uint(max_entries, MAX_ENTRIES); \
	} map_name SEC(".maps");

// #define DEFINE_BPF_HASH_MAP(map_name, map_type, MAX_ENTRIES, key_type, value_type ,value_num) \
// 	struct { \
// 		__uint(type, map_type); \
// 		__uint(key_size, sizeof(key_type)); \
// 		__uint(value_size, sizeof(value_type) * value_num); \
// 		__uint(max_entries, MAX_ENTRIES); \
// 	} map_name SEC(".maps");

struct data_store{
    u32 list[GLOBAL_HASH_BUCKET_SIZE + 1];
};

enum para_pass_kind{
    CPU_PARA,
    IO_PARA,
    MM_PARA,
    NET_PARA
};

struct data_list{
    u32 list[50];
    //u32 length;
};

struct task_info_simple{
    u32 pid;                
    u32 tgid;               
    u32 cpu_id; 
    char comm[TASK_COMM_LEN];
};

struct task_public_info {
    u32 pid;
    u32 tgid;
    u64 time;
    char comm[TASK_COMM_LEN];
};

struct process_public_info
{
    u32 tgid;
    u32 kids_length;
    u64 last_total_clear;
};


enum time_unit{
    MICROSECONDS,  // 微秒
    UNIT_MILLISECONDS   // 毫秒
};

struct time_window{
    enum time_unit unit;
    u32 multiplier;
};

struct ema_para{
    struct time_window window;
    u32 percent;
};

// // 栈回溯部分
// enum stack_backtrace_type {
//     STACK_CPU,      // CPU 相关的追踪事件
//     STACK_MEMORY,   // 内存相关的追踪事件
//     STACK_IO,       // I/O 相关的追踪事件
//     STACK_NET       // 网络相关的追踪事件
// };

// 栈回溯结构体
struct task_trace_event {
    __u32 pid;                  // 进程 ID
    char comm[TASK_COMM_LEN];   // 任务名称
    __s32 kstack_sz;            // 内核栈回溯的深度
    __s32 ustack_sz;            // 用户栈回溯的深度
    stack_trace_t k_stack;       // 内核栈回溯地址
    stack_trace_t u_stack;       // 用户栈回溯地址
};





#endif 
