//
// Created by ne0 on 24-10-30.
//

#ifndef CPU_EVENT_H
#define CPU_EVENT_H

#include "sys_event.h"


#define MAX_CPU_NR 64
#define SYSCALL_MIN_TIME 1E7
#define MAX_SYSCALL_COUNT 100

#define MAX_KIDS_NUM 100

#define MAX_LATENCY_BUCKETS 8 // 延迟分为 8 个区间

typedef enum {
    UPDATE_USER_TIME    = (1 << 0),  // 更新用户态时间
    UPDATE_KERNEL_TIME  = (1 << 1),  // 更新系统态时间
    UPDATE_IDLE_TIME    = (1 << 2),  // 更新空闲时间
    UPDATE_IOWAIT_TIME  = (1 << 3),  // 更新 I/O 等待时间
    UPDATE_IRQ_TIME     = (1 << 4),  // 更新硬中断时间
    UPDATE_SOFTIRQ_TIME = (1 << 5),  // 更新软中断时间
    UPDATE_RQ_LENGTH    = (1 << 6),  // 更新运行队列长度

    UPDATE_ALL = UPDATE_USER_TIME | UPDATE_KERNEL_TIME | UPDATE_IDLE_TIME | 
                 UPDATE_IOWAIT_TIME | UPDATE_IRQ_TIME | UPDATE_SOFTIRQ_TIME | UPDATE_RQ_LENGTH
} cpu_usage_update_flags;

typedef enum {
    GET_LATENCY_EMA        = (1 << 0),  
    GET_USAGE_EMA          = (1 << 1),  
    GET_TASK_CSW_EMA       = (1 << 2),  
    GET_TASK_PREEMPT_EMA   = (1 << 3),  
} ema_get_flags;


// 调度延迟部分
// cpu上的任务延迟计数
// struct cpu_latency_stats {
//     u32 cpu_id;
//     u64 total_latency;                     // 累积延迟总和
//     u64 total_count;                       // 总计数
//     u32 avg_latency;                    // 每个 CPU 的平均调度延迟

//     u64 latency_buckets[MAX_LATENCY_BUCKETS]; // 每个延迟区间的计数
// };

// 系统的任务延迟计数
struct system_latency_stats {
    u64 total_latency;                     // 系统总的延迟总和
    u64 total_count;                       // 系统总任务数
    u32 avg_latency;                    // 系统的平均调度延迟

    u64 latency_buckets[MAX_LATENCY_BUCKETS]; // 系统的不同延迟区间的计数
};

struct time_window latency_bk_window;
struct ema_para latency_ema;

// cpu整体使用情况
struct cpu_usage_stats {
    u32 cpu_id;               // CPU ID
    u32 user_percent;         // 用户态时间占比，放大 1000 倍
    u32 kernel_percent;       // 内核态时间占比
    u32 idle_percent;         // 空闲时间占比
    u32 iowait_percent;       // I/O 等待时间占比
    u32 irq_percent;          // 硬中断时间占比
    u32 softirq_percent;      // 软中断时间占比

    u64 total_times;          // kernel+usr+idle，计算时候用的

    u32 rq_length; // 当前运行队列长度
};

// 系统整体的cpu使用情况
struct sys_cpu_usage_stats{
    u32 user_percent;         // 用户态时间占比，放大 1000 倍
    u32 kernel_percent;       // 内核态时间占比
    u32 idle_percent;         // 空闲时间占比
    u32 iowait_percent;       // I/O 等待时间占比
    u32 irq_percent;          // 硬中断时间占比
    u32 softirq_percent;      // 软中断时间占比

    u32 rq_length; // 运行队列平均长度
};

// 采用ema来更新usage数据，task的和sys的一起
struct ema_para usage_ema;


struct process_struct{
    u32 tgid;
    //struct hash_table kids;
    u32 kids_length;
    bool already_output;

    u64 last_total_clear;
    u64 last_lock_clear;

    u64 total_use_time;
    u64 lock_time;
    u64 last_clear_time;

    u32 total_use_percent;
};

// 接下来都是task级

struct latency_num {
    u32 pre_size;// 先前的统计数据,方便ema,在向用户空间传数据时候存索引
    u32 size;
};

struct runqlat_perf_data{
    u32 data[8];
};

// 任务的cpu使用率
// 把cpu使用率高的任务，排除掉idle之后，关注起来做栈回溯
struct task_cpu_usage {
    struct  task_info_simple task_info;

    //bool already_backtrace;
    bool in_kernel;
    bool in_process;
    bool already_output;

    u64 user_time_ns;       
    u64 kernel_time_ns;     
    u64 total_time_ns;     
    u64 last_run_time; 
    u64 last_enqeue_time;

    u64 wait_time;
    u64 last_clear_time;
    u64 last_trace_time;

    u32 user_percent;       
    u32 kernel_percent;     
    u32 total_percent;     
};

// 上下文切换
struct task_context_switch {
    struct task_info_simple task_info;

    u32 total_switches;          // 总上下文切换数量
    u32 voluntary_switches;      // 自愿上下文切换的数量
    u32 involuntary_switches;    // 非自愿（抢占）上下文切换的数量
};

struct ema_para task_csw_ema;

struct task_preempt{
    struct task_info_simple task_info;
    
    u32 preempt_count; // 抢占别人的次数
    u32 was_preempted_count; // 被抢占的次数
};

struct ema_para task_preempt_ema;

// 由于锁事件本身比较耗性能，所以用条件编译
#ifdef ENABLE_LOCK_MONITORING
struct lock_event {
    struct task_info_simple task_info;
    u64 lock_address;         // 锁的内存地址，用于区分不同的锁
    u64 contention_start;     // 争用开始时间戳（纳秒）
    u64 contention_delay;     // 锁争用的延迟时间（纳秒）
    u32 contention_count;     // 锁的争用次数
};

// 锁争用的控制块
struct lock_ctrl {
    struct ema_para lock_ema;

    u32 sampling_rate;           // 采样率（0-100），表示百分比
    u64 contention_threshold;    // 锁争用的延迟阈值（以纳秒为单位），低于此值的事件将被忽略
};

#endif // ENABLE_LOCK_MONITORING



#endif //CPU_EVENT_H
