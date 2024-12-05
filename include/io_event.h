#ifndef IO_EVENT_H
#define IO_EVENT_H
#include "sys_event.h"

struct io_wait_perf_data {
    u32 count_list[8];
};

struct io_task_stats {
    struct task_info_simple info;
    u32 read_count;
    u32 write_count;

    u64 last_clear_time;
    u32 already_output;// 防止一个周期内多次输出
};

struct io_process_stats {
    u32 tgid;
    u32 read_count;
    u32 write_count;

    u64 last_clear_time;
    u32 already_output;// 防止一个周期内多次输出
};

struct io_stats_threhold {
    u32 read_count;
    u32 write_count;

    u64 time_window;
};

#endif //CPU_EVENT_H