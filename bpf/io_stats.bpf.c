#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "io_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


static const u32 one = 1;
static const u32 zero = 0;

struct trace_event_raw_block_rq_issue {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    dev_t dev;                  // offset: 8, size: 4
    u32 __padding;              // 用于对齐到偏移量 16
    sector_t sector;            // offset: 16, size: 8
    unsigned int nr_sector;     // offset: 24, size: 4
    unsigned int bytes;         // offset: 28, size: 4
    char rwbs[8];               // offset: 32, size: 8
    char comm[16];              // offset: 40, size: 16
    int __data_loc_cmd;         // offset: 56, size: 4
};

// 类似runqlat统计
DEFINE_BPF_MAP(io_wait_count_map,BPF_MAP_TYPE_ARRAY,8,u32,u32);
DEFINE_BPF_MAP(io_wait_map,BPF_MAP_TYPE_HASH,MAX_ENTRIES,u32,u64);

DEFINE_BPF_MAP(io_task_stats_map,BPF_MAP_TYPE_HASH,MAX_ENTRIES,u32,struct io_task_stats);
DEFINE_BPF_MAP(io_process_stats_map,BPF_MAP_TYPE_HASH,4096,u32,struct io_process_stats);

DEFINE_BPF_MAP(io_threhold_map,BPF_MAP_TYPE_ARRAY,2,u32,struct io_stats_threhold);

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);  // 环形缓冲区大小为 256 KB
} io_wait_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  // 环形缓冲区大小为 256 KB
} io_task_stats_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  // 环形缓冲区大小为 256 KB
} io_process_stats_buffer SEC(".maps");

static int io_update_wait_map_count(u64 wait_time) {
    u64 latency_bucket = wait_time / USEC;

    u32 bucket;
    if(latency_bucket == 0)
        bucket = 0;
    else if(latency_bucket < 5)
        bucket = 1;
    else if(latency_bucket < 17)
        bucket = 2;
    else if(latency_bucket < 65)
        bucket = 3;
    else if(latency_bucket < 257)
        bucket = 4;
    else if(latency_bucket < 1000)
        bucket = 5;
    else if(latency_bucket < 4000)
        bucket = 6;
    else
        bucket = 7;

    u32 *count = bpf_map_lookup_elem(&io_wait_count_map,&bucket);
    if(!count){
        bpf_map_update_elem(&io_wait_count_map,&bucket,&one,BPF_ANY);
    }
    else{
        *count = *count + 1;
        bpf_map_update_elem(&io_wait_count_map,&bucket,count,BPF_ANY);
    }
    return 0;
}

// 请求开始时间
SEC("tracepoint/block/block_rq_issue")
int io_trace_rq_issue(struct trace_event_raw_block_rq_issue *ctx) {
    u32 dev = ctx->dev;
    u64 now = bpf_ktime_get_ns(); 

    bpf_map_update_elem(&io_wait_map,&dev,&now,BPF_ANY);
    return 0;
}

// 请求结束时间
SEC("tracepoint/block/block_rq_complete")
int io_trace_rq_complete(struct trace_event_raw_block_rq_completion *ctx) {
    u32 dev = ctx->dev;
    u64 *time = bpf_map_lookup_elem(&io_wait_map,&dev);
    if(!time)
        return 0;
    u64 now = bpf_ktime_get_ns(); 
    u64 wait = now - *time;

    io_update_wait_map_count(wait);
    bpf_map_delete_elem(&io_wait_map,&dev);
    return 0;
}

SEC("perf_event")
int handle_io_wait_event(struct bpf_perf_event_data *ctx) {
    struct io_wait_perf_data *buff = bpf_ringbuf_reserve(&io_wait_buffer,sizeof(struct io_wait_perf_data),0);
    if(!buff){
        bpf_printk("io_wait_count buffer is full\n");
        return 0;
    }
    memset(buff,0,sizeof(struct io_wait_perf_data));

    for(u32 i = 0; i<8;i++){
        u32 index = i;
        u32 *data = bpf_map_lookup_elem(&io_wait_count_map,&index);
        if(!data){
            buff->count_list[i] = 0;
        }
        else{
            buff->count_list[i] = *data;
        }
    }
    bpf_ringbuf_submit(buff, 0);

    return 0;
}

static int io_task_compare_and_commit(struct io_task_stats *task) {
    struct io_stats_threhold *threhold = bpf_map_lookup_elem(&io_threhold_map,&zero);
    if(!threhold){
        bpf_printk("io_threhold map is not init\n");
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    if(task->last_clear_time + threhold->time_window < now){
        task->read_count = 0;
        task->write_count = 0;
        task->last_clear_time = now;
        task->already_output = 0;
        //bpf_printk("current pid is %u",task->info.pid);
        bpf_map_update_elem(&io_task_stats_map,&task->info.pid,task,BPF_ANY);
        return 0;
    }

    if(task->read_count >= threhold->read_count || task->write_count >= threhold->write_count){
        if(task->already_output != 0)
        {
            return 0;// 这个周期内以及输出过了
        }

        struct io_task_stats *buff = bpf_ringbuf_reserve(&io_task_stats_buffer, sizeof(struct io_task_stats), 0);
        if(!buff){
            bpf_printk("task_io_stats_buff is full\n");
            return 0;
        }
        memset(buff,0,sizeof(struct io_task_stats));
        buff->info.pid = task->info.pid;
        buff->info.tgid = task->info.tgid;
        bpf_probe_read_str(buff->info.comm,sizeof(task->info.comm),task->info.comm);  
        buff->read_count = task->read_count;
        buff->write_count = task->write_count;

        // 毕竟在刚超就截至了，所以根据剩余的time_window时间来乘个比例
        u64 time_spare = task->last_clear_time + threhold->time_window - now;
        time_spare = time_spare * 100 / threhold->time_window;
        time_spare = (u32)time_spare;
        if(time_spare > 10)
        {
            buff->write_count *= (time_spare / 10);
            buff->read_count *= (time_spare / 10);
        }
        bpf_ringbuf_submit(buff,0);

        task->already_output = 1;
        bpf_map_update_elem(&io_task_stats_map,&task->info.pid,task,BPF_ANY);
    }
    return 0;
}


static int io_process_compare_and_commit(struct io_process_stats *process) {
    struct io_stats_threhold *threhold = bpf_map_lookup_elem(&io_threhold_map,&one);
    if(!threhold){
        bpf_printk("io_threhold map is not init\n");
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    if(process->last_clear_time + threhold->time_window < now){
        process->read_count = 0;
        process->write_count = 0;
        process->last_clear_time = now;
        process->already_output = 0;
        bpf_map_update_elem(&io_process_stats_map,&process->tgid,process,BPF_ANY);
        return 0;
    }

    if(process->read_count >= threhold->read_count || process->write_count >= threhold->write_count){
        if(process->already_output != 0)
            return 0;
        struct io_process_stats *buff = bpf_ringbuf_reserve(&io_process_stats_buffer, sizeof(struct io_process_stats), 0);
        if(!buff){
            bpf_printk("process_io_stats_buff is full\n");
            return 0;
        }
        memset(buff,0,sizeof(struct io_process_stats));
        buff->tgid = process->tgid;
        buff->read_count = process->read_count;
        buff->write_count = process->write_count;
        bpf_ringbuf_submit(buff,0);
        process->already_output = 1;
        bpf_map_update_elem(&io_process_stats_map,&process->tgid,process,BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int io_trace_enter_read(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id & 0xFFFFFFFF; 
    u64 now = bpf_ktime_get_ns();

    if(pid == 0)
        return 0;

    struct io_task_stats *task = bpf_map_lookup_elem(&io_task_stats_map,&pid);
    if(!task){
        struct io_task_stats init_task;
        memset(&init_task,0,sizeof(struct io_task_stats));
        // struct task_info_simple info = {
        //     .pid = pid,
        //     .tgid = tgid
        // };
        bpf_get_current_comm(init_task.info.comm,sizeof(init_task.info.comm));
        //init_task.info = info;
        init_task.info.pid = pid;
        init_task.info.tgid = tgid;
        init_task.last_clear_time = now;
        init_task.read_count = 1;
        init_task.write_count = 0;
        bpf_map_update_elem(&io_task_stats_map,&pid,&init_task,BPF_ANY);
    }
    else{
        task->read_count += 1;
        if(task->info.pid == 0)
        {
            task->info.pid = pid;
            task->info.tgid = tgid;
        }
        bpf_map_update_elem(&io_task_stats_map,&pid,task,BPF_ANY);
        io_task_compare_and_commit(task);
    }

    struct io_process_stats *process = bpf_map_lookup_elem(&io_process_stats_map,&tgid);
    if(!process){
        struct io_process_stats init_process;
        memset(&init_process,0,sizeof(struct io_process_stats));
        init_process.tgid = tgid;
        init_process.last_clear_time = now;
        init_process.read_count = 1;
        init_process.write_count = 0;
        bpf_map_update_elem(&io_process_stats_map,&tgid,&init_process,BPF_ANY);
    }
    else{
        process->read_count += 1;
        bpf_map_update_elem(&io_process_stats_map,&tgid,process,BPF_ANY);
        io_process_compare_and_commit(process);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int io_trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id & 0xFFFFFFFF; 
    u64 now = bpf_ktime_get_ns();

    if(pid == 0)
        return 0;

    struct io_task_stats *task = bpf_map_lookup_elem(&io_task_stats_map,&pid);
    if(!task){
        struct io_task_stats init_task;
        memset(&init_task,0,sizeof(struct io_task_stats));
        // struct task_info_simple info = {
        //     .pid = pid,
        //     .tgid = tgid
        // };
        bpf_get_current_comm(init_task.info.comm,sizeof(init_task.info.comm));
        // init_task.info = info;
        init_task.info.pid = pid;
        init_task.info.tgid = tgid;
        init_task.last_clear_time = now;
        init_task.write_count = 1;
        init_task.read_count = 0;
        bpf_map_update_elem(&io_task_stats_map,&pid,&init_task,BPF_ANY);
    }
    else{
        task->write_count += 1;
        if(task->info.pid == 0)
        {
            task->info.pid = pid;
            task->info.tgid = tgid;
        }
        bpf_map_update_elem(&io_task_stats_map,&pid,task,BPF_ANY);
        io_task_compare_and_commit(task);
    }

    struct io_process_stats *process = bpf_map_lookup_elem(&io_process_stats_map,&tgid);
    if(!process){
        struct io_process_stats init_process;
        memset(&init_process,0,sizeof(struct io_process_stats));
        init_process.tgid = tgid;
        init_process.last_clear_time = now;
        init_process.write_count = 1;
        init_process.read_count = 0;
        bpf_map_update_elem(&io_process_stats_map,&tgid,&init_process,BPF_ANY);
    }
    else{
        process->write_count += 1;
        bpf_map_update_elem(&io_process_stats_map,&tgid,process,BPF_ANY);
        io_process_compare_and_commit(process);
    }

    return 0;
}


SEC("tracepoint/sched/sched_process_exit")
int BPF_PROG(handle_io_task_exit){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid & 0xFFFFFFFF;  
    u32 tgid = pid_tgid >> 32;  
    if(pid == 0 || tgid == 0)
        return 0;
    
    if(bpf_map_lookup_elem(&io_task_stats_map,&pid) != NULL)
        bpf_map_delete_elem(&io_task_stats_map,&pid);
}



