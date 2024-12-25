//
// Created by ne0 on 24-10-30.
//
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include"cpu_event.h"



char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define HALF_SECOND (500 * MSEC)

const u32 zero = 0;
const u32 one = 1;

static volatile bool init_cpus_num = false;
static volatile u32 nr_cpus;

struct cpu_usage_times{
    u64 last_idle_time;//只记录cpu上一次闲置的时间
    u64 last_softirq_time;
    u64 last_irq_time;
    u64 last_clear_time;

    u64 usr_times;
    u64 kernel_times;
    u64 idle_times;
    u64 io_wait_times;
    u64 irq_times;
    u64 softirq_times;
};

struct cpu_idle_args{
	unsigned short common_type;          // offset: 0, size: 2
    unsigned char common_flags;          // offset: 2, size: 1
    unsigned char common_preempt_count;  // offset: 3, size: 1
    int common_pid;                      // offset: 4, size: 4
    u32 state;                           // offset: 8, size: 4
    u32 cpu_id;                          // offset: 12, size: 4
};



//static struct hash_table template_table;

// 栈回溯的
DEFINE_BPF_MAP(stack_traces_map,BPF_MAP_TYPE_STACK_TRACE,2048,u32,(MAX_STACK_DEPTH*sizeof(u64)));
DEFINE_BPF_MAP(task_trace_data_map,BPF_MAP_TYPE_HASH,1024,u32,struct task_trace_event);

// 初始化的hash_table的模板，在用户态定义
// DEFINE_BPF_MAP(hash_table_model_map,BPF_MAP_TYPE_ARRAY,1,u32,struct hash_table);

// 用来传递一些用户空间的数据
DEFINE_BPF_MAP(cpu_usr_map,BPF_MAP_TYPE_ARRAY,16,u32,u32);

// 统计cpu的使用状态的map
DEFINE_BPF_MAP(cpu_usage_percent_map,BPF_MAP_TYPE_ARRAY,MAX_CPU_NR,u32,struct cpu_usage_stats);
DEFINE_BPF_MAP(cpu_usage_times_map,BPF_MAP_TYPE_ARRAY,MAX_CPU_NR,u32,struct cpu_usage_times);

// 几个EMA控制块的
DEFINE_BPF_MAP(cpu_ema_ctrl_map,BPF_MAP_TYPE_ARRAY,4,u32,struct ema_para);


// task
DEFINE_BPF_MAP(task_cpu_usage_map,BPF_MAP_TYPE_HASH,MAX_ENTRIES,u32,struct task_cpu_usage);
DEFINE_BPF_MAP(process_map,BPF_MAP_TYPE_HASH,MAX_PROCESS_ENTRIES,u32,struct process_struct);

//DEFINE_BPF_MAP(process_kids_map,BPF_MAP_TYPE_HASH,MAX_PROCESS_ENTRIES,u32,struct hash_table);

DEFINE_BPF_MAP(thread_occupied_map,BPF_MAP_TYPE_HASH,512,u32,u32);
DEFINE_BPF_MAP(process_occupied_map,BPF_MAP_TYPE_HASH,512,u32,u32);
//DEFINE_BPF_MAP(occupied_list,BPF_MAP_TYPE_ARRAY,2,u32,struct data_list);

// 任务延迟计数统计
// 对数增长,8个区间
DEFINE_BPF_MAP(runqlat_map,BPF_MAP_TYPE_ARRAY,MAX_LATENCY_BUCKETS,u32,u32);
DEFINE_BPF_MAP(runqlat_without_bad_map,BPF_MAP_TYPE_ARRAY,MAX_LATENCY_BUCKETS,u32,u32);

// 环形缓冲区传递数据
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 环形缓冲区大小为 256 KB
} cpu_usage_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  // 环形缓冲区大小为 128 KB
} task_occupied_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  // 环形缓冲区大小为 64 KB
} process_occupied_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);  // 环形缓冲区大小为 32 KB
} runqlat_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);  // 环形缓冲区大小为 64 KB
} runqlat_without_bad_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  
} task_backtrace_buffer SEC(".maps");

static inline struct ema_para *get_ema_para(ema_get_flags flag){
    struct ema_para *para;
    para = bpf_map_lookup_elem(&cpu_ema_ctrl_map,&flag);
    if(!para)
        return NULL;
    return para;
}

// static inline struct time_window *get_latency_window(void){
//     struct time_window *window;
//     window = bpf_map_lookup_elem(&latency_window_map,&window_key);
//     if(!window)
//         return NULL;
//     return window;
// }

static struct task_info_simple init_task_info(struct task_struct *p,u32 cpu_id){
    struct task_info_simple info = {
        .comm = {},
        .pid = BPF_CORE_READ(p,pid), 
        .tgid = BPF_CORE_READ(p,tgid),
        .cpu_id = cpu_id
    };
    bpf_probe_read_kernel_str(info.comm, sizeof(info.comm), BPF_CORE_READ(p, comm));
    
    return info;
}

static int perf_task_backtrace(u32 pid){
    u64 now = bpf_ktime_get_ns();
    struct task_trace_event *task;
    if(pid == 0)
        return 0;
    task = bpf_map_lookup_elem(&task_trace_data_map,&pid);
    if(!task)
        return 0;
    
    struct task_trace_event *buff = bpf_ringbuf_reserve(&task_backtrace_buffer,sizeof(struct task_trace_event),0);
    if(!buff){
        bpf_printk("backtrace buff allocate failed\n");
        return 0;
    }
    memset(buff,0,sizeof(struct task_trace_event));
    buff->pid = pid;
    bpf_probe_read_str(buff->comm,sizeof(task->comm),task->comm);
    buff->kstack_sz = task->kstack_sz;
    buff->ustack_sz = task->ustack_sz;
    for(int j=0;j<MAX_STACK_DEPTH;j++){
            if(j > task->kstack_sz)
                break;
            buff->k_stack[j] = task->k_stack[j];
    }
    for(int j=0;j<MAX_STACK_DEPTH;j++){
            if(j > task->ustack_sz)
                    break;
            buff->u_stack[j] = task->u_stack[j];
        }
    bpf_ringbuf_submit(buff, 0);

    return 0;
}

// static int update_data_list(u32 list_id,u32 id,u32 operation){
//     //bpf_printk("task occupied id is %u",id);
//     if(id == 0)
//         return 0;
//     if(list_id == 0 || list_id == 1){
//         // operation 0 delete, 1 insert
//         if(operation == 0){
//             struct data_list *list = bpf_map_lookup_elem(&occupied_list,&list_id);
//             if(!list){
//                 // struct data_list _list = {};
//                 // bpf_map_update_elem(&occupied_list,&list_id,&_list,BPF_ANY);
//                 bpf_printk("data list not init\n");
//                 return 0;
//             }
//             for(int i=0;i<50;i++){
//                 if(list->list[i] == id)
//                 {
//                     list->list[i] = 0;
//                     bpf_map_update_elem(&occupied_list,&list_id,list,BPF_ANY);
//                     break;
//                 }
//             }
//         }
//         else if(operation == 1){
//             struct data_list *list = bpf_map_lookup_elem(&occupied_list,&list_id);
//             if(!list){
//                 // struct data_list _list = {};
//                 // bpf_map_update_elem(&occupied_list,&list_id,&_list,BPF_ANY);
//                 // list = bpf_map_lookup_elem(&occupied_list,&list_id);
//                 // if(!list)
//                 bpf_printk("data list not init\n");
//                 return 0;
//             }
//             for(int i=0;i<50;i++){
//                 if(list->list[i] == 0){
//                     list->list[i] = id;
//                     //bpf_printk("task occupied id is %u",id);
//                     bpf_map_update_elem(&occupied_list,&list_id,list,BPF_ANY);
//                     break;
//                 }
//             }
//         }
//         else{
//             bpf_printk("data_list operations id error\n");
//         }
//     }
//     else{
//         bpf_printk("data_list id error\n");
//     }
//     return 0;
// }

// static int hash_table_insert(struct hash_table *table, unsigned int key) {
//     unsigned int hash_index = hash_func(key);
//     if(hash_index >= HASH_TABLE_SIZE)
//         return (unsigned int)-1;
//     unsigned int count = table->counts[hash_index];
//     if(hash_table_lookup(table,key,false) == key){
//         return 1;// 防止重复插入
//     }

//     // bpf_printk("task id is %u",key);
//     if (count < MAX_COLLISIONS) {
//         table->hash_node[hash_index][count] = key;
//         table->counts[hash_index]++;
//         if(hash_index > table->last_valid_index)
//             table->last_valid_index = hash_index;
//     } else {
//         return -1;
//     }
//     //bpf_printk("task id is %u",key);
//     return 0;
// }

static int init_process(u32 tgid,u32 pid) {
    struct process_struct ps;
    
    ps.tgid = tgid;
    ps.kids_length = 1;
    //hash_table_insert(table,pid); 
    if(tgid != pid)
    {
        //hash_table_insert(table,tgid);
        ps.kids_length = 2;
    }
    //bpf_map_update_elem(&process_kids_map,&tgid,table,BPF_ANY);
    bpf_map_update_elem(&process_map,&tgid,&ps,BPF_ANY);
    return 0;
}


static void insert_pid_to_process(u32 tgid,u32 pid){
    if(tgid == 0)
        return;
    struct process_struct *ps = bpf_map_lookup_elem(&process_map,&tgid);
    if(!ps){
        init_process(tgid,pid);
        }
    else{
        ps->kids_length += 1;
        bpf_map_update_elem(&process_map,&tgid,ps,BPF_ANY);
    }
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
    u32 pid = BPF_CORE_READ(p,pid);
    if(pid == 0)
        return 0;
    u32 tgid = BPF_CORE_READ(p,tgid);
    u32 cpu_id = bpf_get_smp_processor_id();
    struct task_cpu_usage *task_use = bpf_map_lookup_elem(&task_cpu_usage_map,&pid);
    if(!task_use){
        struct task_info_simple info = init_task_info(p,cpu_id);
        struct task_cpu_usage init_task;
        memset(&init_task,0,sizeof(struct task_cpu_usage));
        init_task.task_info = info;
        init_task.last_enqeue_time = bpf_ktime_get_ns();
        bpf_map_update_elem(&task_cpu_usage_map, &pid, &init_task, BPF_ANY);
        insert_pid_to_process(tgid,pid);
    }
    else{
        task_use->last_enqeue_time = bpf_ktime_get_ns();
        bpf_map_update_elem(&task_cpu_usage_map,&pid,task_use,BPF_ANY);
    }

    return 0;
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p){
    u32 pid = BPF_CORE_READ(p,pid);
    if(pid == 0)
        return 0;
    u32 tgid = BPF_CORE_READ(p,tgid);
    u32 cpu_id = bpf_get_smp_processor_id();
    struct task_cpu_usage *task_use = bpf_map_lookup_elem(&task_cpu_usage_map,&pid);
    if(!task_use){
        struct task_info_simple info = init_task_info(p,cpu_id);
        struct task_cpu_usage init_task;
        memset(&init_task,0,sizeof(struct task_cpu_usage));
        init_task.task_info = info;
        init_task.last_enqeue_time = bpf_ktime_get_ns();
        bpf_map_update_elem(&task_cpu_usage_map, &pid, &init_task, BPF_ANY);
        
        insert_pid_to_process(tgid,pid);
    }
    else{
        task_use->last_enqeue_time = bpf_ktime_get_ns();
        bpf_map_update_elem(&task_cpu_usage_map,&pid,task_use,BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_task_create(struct trace_event_raw_sched_process_fork *ctx){
    u32 pid_new = ctx->child_pid;
    u32 cpu_id = bpf_get_smp_processor_id();
    struct task_cpu_usage *tk = bpf_map_lookup_elem(&task_cpu_usage_map,&pid_new);
    if(!tk){
        struct task_cpu_usage init_task;
        memset(&init_task,0,sizeof(struct task_cpu_usage));
        struct task_info_simple info = {
                .pid = pid_new,
                .cpu_id = cpu_id
            };
        bpf_probe_read_kernel_str(info.comm,sizeof(ctx->child_comm),ctx->child_comm);
        init_task.task_info = info;
        bpf_map_update_elem(&task_cpu_usage_map,&pid_new,&init_task,BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int BPF_PROG(handle_task_exit){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid & 0xFFFFFFFF;  
    u32 tgid = pid_tgid >> 32;  
    if(pid == 0 || tgid == 0)
        return 0;

    bpf_map_delete_elem(&task_cpu_usage_map,&pid);
    struct process_struct *ps = bpf_map_lookup_elem(&process_map,&tgid);
    if(ps != NULL){
        if(ps->kids_length > 0)
            ps->kids_length -= 1;

        u32 *in = bpf_map_lookup_elem(&thread_occupied_map,&pid);
        if(in != NULL){
            bpf_map_delete_elem(&thread_occupied_map,&pid);
            //update_data_list(zero,pid,zero);
        }

        bpf_map_delete_elem(&task_trace_data_map,&pid);

        if(ps!=NULL && ps->kids_length == 0)
        {
            bpf_map_delete_elem(&process_map,&tgid);
            //bpf_map_delete_elem(&process_kids_map,&tgid);

            // if(bpf_map_lookup_elem(&process_occupied_map,&zero)!= NULL)
            // {
            //     struct hash_table *table = bpf_map_lookup_elem(&process_occupied_map,&zero);
            //     if(!table)
            //     {
            //         bpf_printk("process_occupied_map is not init\n");
            //         return 0;
            //     }
            //     if(hash_table_delete(table,tgid) == 0)
            //     {
            //         bpf_map_update_elem(&process_occu pied_map,&zero,table,BPF_ANY);
            //         update_data_list(one,tgid,zero);
            //     }
            // }
            in = bpf_map_lookup_elem(&process_occupied_map,&tgid);
            if(in != NULL){
                bpf_map_delete_elem(&process_occupied_map,&tgid);
                //update_data_list(one,tgid,zero);
            }
        }
        // else
        //     bpf_map_update_elem(&process_map,&tgid,ps,BPF_ANY);
    }
    return 0;
}

static int task_concerned_update(struct task_cpu_usage *task_usage, u32 threshold){
    u32 value = task_usage->total_time_ns * 100 / HALF_SECOND;
    //bpf_printk("total percent is %u",value);
    //bpf_printk("task id is %u",task_usage->task_info.pid);
    u32 pid = task_usage->task_info.pid;
    u64 now = bpf_ktime_get_ns();
    if(task_usage->last_clear_time == 0)
    {
        task_usage->last_clear_time = now;
        bpf_map_update_elem(&task_cpu_usage_map,&pid,task_usage,BPF_ANY);
        return 0;
    }
    if(!task_usage->already_output && value >= threshold && now - task_usage->last_clear_time < HALF_SECOND)
    {
        bpf_map_update_elem(&thread_occupied_map,&pid,&pid,BPF_ANY);

        struct task_cpu_usage *buff = bpf_ringbuf_reserve(&task_occupied_buffer,sizeof(struct task_cpu_usage),0);
        if(!buff){
            bpf_printk("the task_cpu buffer is full\n");
            return 0;
        }
        memset(buff,0,sizeof(struct task_cpu_usage));
        buff->task_info = task_usage->task_info;
        //u64 delta = (now - task_usage->last_clear_time)*10 / HALF_SECOND;
        u64 delta = (HALF_SECOND + task_usage->last_clear_time - now )*10 / HALF_SECOND;
        buff->total_percent = task_usage->total_time_ns * 100 * delta/ HALF_SECOND;
        buff->kernel_percent = task_usage->kernel_time_ns / task_usage->total_time_ns;
        buff->user_percent = task_usage->user_time_ns / task_usage->total_time_ns;
        bpf_ringbuf_submit(buff,0);
        
        task_usage->already_output = true;
        //bpf_map_update_elem(&task_cpu_usage_map,&pid,task_usage,BPF_ANY);

        if(task_usage->last_trace_time == 0 || now - task_usage->last_trace_time > 10 * HALF_SECOND)// 间隔至少5s
        {
            perf_task_backtrace(pid);
            task_usage->last_trace_time = now;
        }
        bpf_map_update_elem(&task_cpu_usage_map,&pid,task_usage,BPF_ANY);
    }
    else{
        if(now - task_usage->last_clear_time > HALF_SECOND)
        {
            if(task_usage->already_output == false)
                bpf_map_delete_elem(&thread_occupied_map,&pid);
            task_usage->last_clear_time = now;
            task_usage->total_time_ns = 0;
            task_usage->user_time_ns = 0;
            task_usage->kernel_time_ns = 0;
            task_usage->already_output = false;
            bpf_map_update_elem(&task_cpu_usage_map,&pid,task_usage,BPF_ANY);
        }
    }
    return 0;
}

static int process_concerned_update(struct process_struct *ps, u32 threshold){
    //bpf_printk("process %u total use time is %lu \n",ps->tgid,ps->total_use_time);
    u32 value = ps->total_use_time * 100 / HALF_SECOND;
    u64 now = bpf_ktime_get_ns();
    u32 tgid = ps->tgid;
    if(ps->last_clear_time == 0){
        ps->last_clear_time = now;
        bpf_map_update_elem(&process_map,&tgid,ps,BPF_ANY);
        return 0;
    }
    if(!ps->already_output && value >= threshold && now - ps->last_clear_time < HALF_SECOND)
    {
        bpf_map_update_elem(&process_occupied_map,&tgid,&tgid,BPF_ANY);

        struct process_struct *buff = bpf_ringbuf_reserve(&process_occupied_buffer,sizeof(struct process_struct),0);
        if(!buff){
            bpf_printk("process_cpu buffer is full\n");
            return 0;
        }
        memset(buff,0,sizeof(struct process_struct));
        //u64 delta = (now - ps->last_clear_time) * 10 / HALF_SECOND;
        u64 delta = (HALF_SECOND + ps->last_clear_time - now) * 10 / HALF_SECOND;
        buff->tgid = tgid;
        buff->kids_length = ps->kids_length;
        buff->total_use_percent = ps->total_use_time * 100 * delta / HALF_SECOND;
        bpf_ringbuf_submit(buff,0);

        ps->already_output = true;
        bpf_map_update_elem(&process_map,&tgid,ps,BPF_ANY);
    }
    else{
        if(now - ps->last_clear_time > HALF_SECOND)
        {
            if(ps->already_output == false)
                bpf_map_delete_elem(&process_occupied_map,&tgid);
            ps->last_clear_time = now;
            ps->total_use_time = 0;
            ps->already_output = false;
            bpf_map_update_elem(&process_map,&tgid,ps,BPF_ANY);
        }
    }
    return 0;
}

static int process_update_runtime(u32 tgid,u64 delta,bool reset, u64 last_cpu_clear){
    if(tgid == 0)
        return 0;
    struct process_struct *ps = bpf_map_lookup_elem(&process_map,&tgid);
    if(!ps){
        init_process(tgid,tgid);
        ps = bpf_map_lookup_elem(&process_map,&tgid);
        if(!ps)
            return -1;
    }
    // 防止多个线程让同一个进程清理
    ps->tgid = tgid;
    if(reset == true && ps->last_total_clear < last_cpu_clear)
    {
        ps->total_use_time = 0;
        ps->last_total_clear = bpf_ktime_get_ns();
    }
    ps->total_use_time += delta;
    //bpf_printk("process %u total use time is %lu \n",tgid,ps->total_use_time);
    bpf_map_update_elem(&process_map,&tgid,ps,BPF_ANY);
    process_concerned_update(ps,80);

    return 0;
}

SEC("tracepoint/sched/sched_switch")
int record_task_switch(struct trace_event_raw_sched_switch *ctx)
{
    // 使用 BPF_CORE_READ 来读取任务结构字段
    u32 prev_pid = ctx->prev_pid;
    u32 next_pid = ctx->next_pid;
    u32 cpu_id = bpf_get_smp_processor_id();
    u64 now = bpf_ktime_get_ns();

    struct cpu_usage_times *cpu_usage ;
    cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
    if (cpu_usage == NULL) {
        struct cpu_usage_times init_cpu = {};
        bpf_map_update_elem(&cpu_usage_times_map, &cpu_id, &init_cpu, BPF_ANY);

        struct cpu_usage_stats init_stats = {
            .cpu_id = cpu_id,
            .total_times = HALF_SECOND
        };
        bpf_map_update_elem(&cpu_usage_percent_map, &cpu_id, &init_stats, BPF_ANY);
    }
    cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
    if (cpu_usage == NULL) return -1;

    // 检查 idle 进程
    /*if (prev_pid == 0) {
        if(cpu_usage->last_idle_time != 0)
            cpu_usage->idle_times += now - cpu_usage->last_idle_time;
    } else*/ 
    if(prev_pid != 0){
        struct task_cpu_usage *pre_usage = bpf_map_lookup_elem(&task_cpu_usage_map, &prev_pid);
        if (!pre_usage) {
            struct task_cpu_usage init_task;
            memset(&init_task,0,sizeof(struct task_cpu_usage));
            struct task_info_simple info = {
                .pid = prev_pid,
                .cpu_id = cpu_id
            };
            bpf_probe_read_kernel_str(info.comm,sizeof(ctx->prev_comm),ctx->prev_comm);
            init_task.task_info = info;
            init_task.last_clear_time = now;
            init_task.last_run_time = now;
            bpf_map_update_elem(&task_cpu_usage_map, &prev_pid, &init_task, BPF_ANY);
        } else {
            pre_usage->task_info.pid = prev_pid;
            if (pre_usage->last_run_time != 0) {
                u64 delta = now - pre_usage->last_run_time;
                if (pre_usage->in_kernel) {
                    pre_usage->kernel_time_ns += delta;
                    cpu_usage->kernel_times += delta;
                } else {
                    pre_usage->user_time_ns += delta;
                    cpu_usage->usr_times += delta;
                }
                pre_usage->total_time_ns += delta;
                task_concerned_update(pre_usage,30);

                if(pre_usage->task_info.tgid != 0){
                    u32 tgid = pre_usage->task_info.tgid;
                    process_update_runtime(tgid,delta,false,cpu_usage->last_clear_time);
                }               
            }
            pre_usage->last_run_time = now;
            bpf_map_update_elem(&task_cpu_usage_map, &prev_pid, pre_usage, BPF_ANY);
            
        }
        //bpf_printk("cpu %u kernel time is %u \n",cpu_id,cpu_usage->kernel_times);
    }

    /*if (next_pid == 0) {
        cpu_usage->last_idle_time = now;
    } else*/ 
    if(next_pid != 0){
        struct task_cpu_usage *next_usage = bpf_map_lookup_elem(&task_cpu_usage_map, &next_pid);
        if (!next_usage) {
            struct task_cpu_usage init_task;
            memset(&init_task,0,sizeof(struct task_cpu_usage));
            struct task_info_simple info = {
                .pid = next_pid,
                .cpu_id = cpu_id
            };
            bpf_probe_read_kernel_str(info.comm,sizeof(ctx->next_comm),ctx->next_comm);
            init_task.task_info = info;
            init_task.last_clear_time = now;
            init_task.last_run_time = now;
            bpf_map_update_elem(&task_cpu_usage_map, &next_pid, &init_task, BPF_ANY);
        } else {
            next_usage->task_info.pid = next_pid;

            u64 latency_bucket = now - next_usage->last_enqeue_time;
            next_usage->wait_time = latency_bucket;

            latency_bucket /= USEC;
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
            u32 *latency = bpf_map_lookup_elem(&runqlat_map,&bucket);
            if(!latency){
                bpf_map_update_elem(&runqlat_map,&bucket,&one,BPF_ANY);
            }else{
                *latency = *latency + 1;
                bpf_map_update_elem(&runqlat_map,&bucket,latency,BPF_ANY);
            }
            
            u32 *is_bad = bpf_map_lookup_elem(&thread_occupied_map,&next_pid);
            if(is_bad != NULL){
                u32 *run_count = bpf_map_lookup_elem(&runqlat_without_bad_map,&bucket);
                if(!run_count){
                    bpf_map_update_elem(&runqlat_without_bad_map,&bucket,&one,BPF_ANY);
                }else{
                    *run_count = *run_count + 1;
                    bpf_map_update_elem(&runqlat_without_bad_map,&bucket,run_count,BPF_ANY);
                }
            }

            if(next_usage->last_run_time < cpu_usage->last_clear_time){
                // 任务这边的数据在新的时间窗口内清零
                next_usage->total_time_ns = 0;
                next_usage->kernel_time_ns = 0;
                next_usage->user_time_ns = 0;
                if(next_usage->task_info.tgid != 0)
                    process_update_runtime(next_usage->task_info.tgid,0,true,cpu_usage->last_clear_time);
            }

            next_usage->last_run_time = now;
            bpf_map_update_elem(&task_cpu_usage_map, &next_pid, next_usage, BPF_ANY);
        }
    }

    bpf_map_update_elem(&cpu_usage_times_map,&cpu_id,cpu_usage,BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int record_backtrace(struct trace_event_raw_sched_switch *ctx)
{
    u32 pid = ctx->prev_pid;
    //bpf_printk("current pid is %u",pid);
    if(pid == 0 || bpf_map_lookup_elem(&thread_occupied_map,&pid) == NULL)
        return 0;

    int stack_id = bpf_get_stackid(ctx,&stack_traces_map,BPF_F_REUSE_STACKID);
    if(stack_id < 0){
        bpf_printk("get stack error, error code is %i",stack_id);
        return 0;
    }
    
    struct task_trace_event *trace = bpf_map_lookup_elem(&task_trace_data_map,&pid);
    if(!trace){
        struct task_trace_event init;
        init.pid = pid;
        struct task_cpu_usage *task = bpf_map_lookup_elem(&task_cpu_usage_map,&pid);
        if(task != NULL){
            bpf_probe_read_kernel_str(init.comm,sizeof(task->task_info.comm),task->task_info.comm);
        }
        init.kstack_sz = 0;
        init.ustack_sz = 0;
        bpf_map_update_elem(&task_trace_data_map,&pid,&init,BPF_ANY);
    }
    else{
        struct task_cpu_usage *use = bpf_map_lookup_elem(&task_cpu_usage_map,&pid);
        // if(!use || use->already_backtrace)
        //     return 0;
    }
    trace = bpf_map_lookup_elem(&task_trace_data_map,&pid);
    if(!trace)
    {
        bpf_printk("backtrace struct init failed\n");
        return 0;
    }

    // 获取内核栈回溯
    // trace->kstack_sz = bpf_get_stackid(ctx,&stack_traces_map,BPF_F_REUSE_STACKID);
    // if(trace->kstack_sz >= 0){
    //     u64 *k_stack_data = bpf_map_lookup_elem(&stack_traces_map,&trace->kstack_sz);
    //     if(k_stack_data){
    //         bpf_probe_read_kernel(&trace->k_stack,sizeof(trace->k_stack),k_stack_data);
    //     }
    // }
    trace->kstack_sz = stack_id;
    u64 *k_stack_data = (u64 *)(stack_id * sizeof(u64));
    if (k_stack_data) {
        //bpf_printk("k_stack_data exist\n");
        bpf_probe_read_kernel(&trace->k_stack, sizeof(trace->k_stack), k_stack_data);
    }

    // 获取用户栈回溯
    // trace->ustack_sz = bpf_get_stackid(ctx,&stack_traces_map,BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
    // if(trace->ustack_sz >= 0){
    //     u64 *u_stack_data = bpf_map_lookup_elem(&stack_traces_map, &trace->ustack_sz);
    //     if(u_stack_data){
    //         bpf_probe_read_kernel(&trace->u_stack,sizeof(trace->u_stack),u_stack_data);
    //     }
    // }
    int u_stack_id = bpf_get_stackid(ctx, &stack_traces_map, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
    if (u_stack_id >= 0) {
        trace->ustack_sz = u_stack_id;
        u64 *u_stack_data = (u64 *)(u_stack_id * sizeof(u64));
        if (u_stack_data) {
            //bpf_printk("u_stack_data exist\n");
            bpf_probe_read_kernel(&trace->u_stack, sizeof(trace->u_stack), u_stack_data);
        }
    }

    bpf_map_update_elem(&task_trace_data_map,&pid,trace,BPF_ANY);

    return 0;
}

static int cpu_init(u32 cpu_id){
    struct cpu_usage_times* cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
    if(!cpu_usage)
        return 0;
    struct cpu_usage_times init_cpu = {};
    bpf_map_update_elem(&cpu_usage_times_map, &cpu_id, &init_cpu, BPF_ANY);

    struct cpu_usage_stats init_stats = {
        .cpu_id = cpu_id,
        .total_times = HALF_SECOND
    };
    bpf_map_update_elem(&cpu_usage_percent_map, &cpu_id, &init_stats, BPF_ANY);
    return 0;
}

// 闲置时间统计
SEC("tracepoint/power/cpu_idle")
int record_cpu_idle(struct cpu_idle_args *ctx){
    u32 cpu_id = ctx->cpu_id;
    u32 state = ctx->state;

    u64 now = bpf_ktime_get_ns();

    struct cpu_usage_times *cpu_usage ;
    cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
    if (cpu_usage == NULL) {
        struct cpu_usage_times init_cpu = {};
        bpf_map_update_elem(&cpu_usage_times_map, &cpu_id, &init_cpu, BPF_ANY);

        struct cpu_usage_stats init_stats = {
            .cpu_id = cpu_id,
            .total_times = HALF_SECOND
        };
        bpf_map_update_elem(&cpu_usage_percent_map, &cpu_id, &init_stats, BPF_ANY);
        return 0;
    }
    // cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
    // if (cpu_usage == NULL) return -1;

    // 比较神奇，在无符号32位里用-1表示从空闲状态退出，下面链接中可以看到
    // https://android.googlesource.com/kernel/common/+/refs/heads/android-gs-pantah-5.10-android13-qpr2/samples/bpf/cpustat_kern.c
    if(state == (u32)(-1)){
        if(cpu_usage->last_idle_time == 0)
            return 0;
        cpu_usage->idle_times += now - cpu_usage->last_idle_time;
    }else{
        cpu_usage->last_idle_time = now;
    }
    bpf_map_update_elem(&cpu_usage_times_map, &cpu_id, cpu_usage, BPF_ANY);
}


// 任务进入内核态
SEC("tracepoint/raw_syscalls/sys_enter")
int BPF_PROG(trace_sys_enter){
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid = BPF_CORE_READ(task, pid);
    u32 tgid = BPF_CORE_READ(task,tgid);
    if(pid == 0)
        return 0;

    struct task_cpu_usage *usage = bpf_map_lookup_elem(&task_cpu_usage_map, &pid);
    if(!usage){
        u32 cpu_id = bpf_get_smp_processor_id();
        struct task_info_simple info = init_task_info(task,cpu_id);

        // 相当于这里是没有初始化last_run_time的
        struct task_cpu_usage init_usage = {
            .task_info = info,
            .in_kernel = true
        };

        bpf_map_update_elem(&task_cpu_usage_map, &pid, &init_usage, BPF_ANY);
    }
    else{
        if(usage->task_info.tgid == 0)
        {
            usage->task_info.tgid = tgid;
            insert_pid_to_process(tgid,pid);
        }
        usage->in_kernel = true;
        bpf_map_update_elem(&task_cpu_usage_map, &pid, usage, BPF_ANY);
    }
    return 0;
}

// 任务退出内核态
SEC("tracepoint/raw_syscalls/sys_exit")
int BPF_PROG(trace_sys_exit){ 
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid = BPF_CORE_READ(task, pid);
    u32 tgid = BPF_CORE_READ(task,tgid);
    if(pid == 0)
        return 0;

    struct task_cpu_usage *usage = bpf_map_lookup_elem(&task_cpu_usage_map, &pid);
    if(!usage){
        u32 cpu_id = bpf_get_smp_processor_id();
        struct task_info_simple info = init_task_info(task,cpu_id);

        // 相当于这里是没有初始化last_run_time的
        struct task_cpu_usage init_usage = {
            .task_info = info,
            .in_kernel = false
        };

        bpf_map_update_elem(&task_cpu_usage_map, &pid, &init_usage, BPF_ANY);
    }
    else{
        if(usage->task_info.tgid == 0)
        {
            usage->task_info.tgid = tgid;
            insert_pid_to_process(tgid,pid);
        }
        usage->in_kernel = false;
        bpf_map_update_elem(&task_cpu_usage_map, &pid, usage, BPF_ANY);
    }
    return 0;
}

// 软中断
SEC("tracepoint/irq/softirq_entry")
int BPF_PROG(trace_cpu_softirq_entry){
    u32 cpu_id = bpf_get_smp_processor_id();

    struct cpu_usage_times *cpu_usage ;
    cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
    if (cpu_usage == NULL) {
        cpu_init(cpu_id);
        cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
        if(cpu_usage == NULL) return 0;
    }

    u64 now = bpf_ktime_get_ns();
    cpu_usage->last_softirq_time = now;
    bpf_map_update_elem(&cpu_usage_times_map,&cpu_id,cpu_usage,BPF_ANY);
    return 0;
}

SEC("tracepoint/irq/softirq_exit")
int BPF_PROG(trace_cpu_softirq_exit){
    u32 cpu_id = bpf_get_smp_processor_id();

    struct cpu_usage_times *cpu_usage ;
    cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
    if (cpu_usage == NULL) {
        cpu_init(cpu_id);
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    cpu_usage->softirq_times += now - cpu_usage->last_softirq_time;
    bpf_map_update_elem(&cpu_usage_times_map,&cpu_id,cpu_usage,BPF_ANY);
    return 0;
}

//硬中断
SEC("tracepoint/irq/irq_handler_entry")
int BPF_PROG(trace_cpu_irq_entry){
    u32 cpu_id = bpf_get_smp_processor_id();

    struct cpu_usage_times *cpu_usage ;
    cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
    if (cpu_usage == NULL) {
        cpu_init(cpu_id);
        cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
        if(cpu_usage == NULL) return 0;
    }

    u64 now = bpf_ktime_get_ns();
    cpu_usage->last_irq_time = now;
    bpf_map_update_elem(&cpu_usage_times_map,&cpu_id,cpu_usage,BPF_ANY);
    return 0;
}

SEC("tracepoint/irq/irq_handler_exit")
int BPF_PROG(trace_cpu_irq_exit){
    u32 cpu_id = bpf_get_smp_processor_id();

    struct cpu_usage_times *cpu_usage ;
    cpu_usage = bpf_map_lookup_elem(&cpu_usage_times_map, &cpu_id);
    if (cpu_usage == NULL) {
        cpu_init(cpu_id);
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    cpu_usage->irq_times += now - cpu_usage->last_irq_time;
    bpf_map_update_elem(&cpu_usage_times_map,&cpu_id,cpu_usage,BPF_ANY);
    return 0;
}

static int __update_percpu_usage_percent(u32 cpu_id,struct cpu_usage_times *data,struct cpu_usage_stats *stats){
    if(data == NULL || stats == NULL)
        return -1;

    stats->cpu_id = cpu_id;
    // 利用ema来更新数据，保留2位小数
    if(stats->idle_percent == 0 && stats->kernel_percent == 0 && stats->user_percent == 0){
        stats->user_percent = data->usr_times * 100 / HALF_SECOND;
        stats->kernel_percent = data->kernel_times * 100 / HALF_SECOND;
        stats->idle_percent = data->idle_times *100 / HALF_SECOND;
        stats->softirq_percent = data->softirq_times*100 / HALF_SECOND;
        stats->irq_percent = data->irq_times*100 / HALF_SECOND;
    }
    else{
        stats->user_percent = stats->user_percent * 60/100 + data->usr_times * 40 / HALF_SECOND;
        stats->kernel_percent = stats->kernel_percent*60/100 + data->kernel_times *40/HALF_SECOND;
        stats->idle_percent = stats->idle_percent*60/100 + data->idle_times*40/HALF_SECOND;
        //stats->idle_percent = data->idle_times *100 / HALF_SECOND;
        stats->softirq_percent = stats->softirq_percent*60/100 + data->softirq_times*40 / HALF_SECOND;
        stats->irq_percent = stats->idle_percent*60/100 + data->irq_times*40 / HALF_SECOND;
    }
    bpf_map_update_elem(&cpu_usage_percent_map,&cpu_id,stats,BPF_ANY);

    // 清零，加入下一轮
    data->idle_times = 0;
    data->kernel_times = 0;
    data->usr_times = 0;
    data->idle_times = 0;
    data->softirq_times = 0;
    
    bpf_map_update_elem(&cpu_usage_times_map,&cpu_id,data,BPF_ANY);

    // 将统计数据写入环形缓冲区
    struct cpu_usage_stats *ringbuf_data;
    ringbuf_data = bpf_ringbuf_reserve(&cpu_usage_buffer, sizeof(struct cpu_usage_stats), 0);
    if (!ringbuf_data) {
        //__builtin_memcpy(ringbuf_data, stats, sizeof(struct cpu_usage_stats));
        bpf_printk("Ring buffer reserve failed\n");
        return -1;
    }
    else{
        memset(ringbuf_data, 0, sizeof(struct cpu_usage_stats));
        ringbuf_data->cpu_id = stats->cpu_id;
        ringbuf_data->idle_percent = stats->idle_percent;
        ringbuf_data->kernel_percent = stats->kernel_percent;
        ringbuf_data->user_percent = stats->user_percent;
        bpf_ringbuf_submit(ringbuf_data, 0);
    }
    //bpf_printk("CPU ID: %u\n", stats->cpu_id);
    // bpf_printk("User Time: %u\n", stats->user_percent);
    // bpf_printk("Kernel Time: %u\n", stats->kernel_percent);
    //bpf_printk("Kernel Time: %u\n", data->kernel_times);

    return 0;
}


static int update_cpu_usage_percent(void){
    u32 cur_id;
    u32 cpu_id;
    struct cpu_usage_times *data;
    int res;
    u64 now = bpf_ktime_get_ns();

    for(cpu_id = 0;cpu_id < 128 && cpu_id < nr_cpus;cpu_id++){
        cur_id = cpu_id;
        data = bpf_map_lookup_elem(&cpu_usage_times_map,&cur_id);
        if(data != NULL){
            //bpf_printk("current cpu is %u\n", cur_id);
            struct cpu_usage_stats *stats ;
            stats = bpf_map_lookup_elem(&cpu_usage_percent_map,&cur_id);
            if(!stats){
                struct cpu_usage_stats init_stats = {
                    .cpu_id = cur_id,
                    .total_times = HALF_SECOND
                };
                bpf_map_update_elem(&cpu_usage_percent_map,&cur_id,&init_stats,BPF_ANY);
                stats = bpf_map_lookup_elem(&cpu_usage_percent_map,&cur_id);
                if(!stats) return -1;
                }
            data->last_clear_time = now;
            res = __update_percpu_usage_percent(cur_id,data,stats);
            //bpf_map_update_elem(&cpu_usage_percent_map,&cur_id,stats,BPF_ANY);
            //bpf_map_update_elem(&cpu_usage_times_map,&cur_id,data,BPF_ANY);
            if(res<0) return res;
            //bpf_map_update_elem(&cpu_usage_percent_map,&cur_id,stats,BPF_ANY);
            //bpf_map_update_elem(&cpu_usage_times_map,&cur_id,data,BPF_ANY);
        }   
        else
        {
            bpf_printk("data not found for cpu %u\n", cur_id);
            continue;
        }
    }

    return 0;
}

static int perf_runqlat(void){
    struct runqlat_perf_data *buff = bpf_ringbuf_reserve(&runqlat_buffer,sizeof(struct runqlat_perf_data),0);
    if(!buff)
    {
        bpf_printk("runqlat ringbuff reserve failed\n");
        return 0;
    }
    memset(buff,0,sizeof(struct runqlat_perf_data));
    for(u32 index=0;index<MAX_LATENCY_BUCKETS;index++){
        u32 i = index;
        u32 *size = bpf_map_lookup_elem(&runqlat_map,&i);
        if(!size)
            buff->data[index] = 0;
        else
            buff->data[index] = *size;
    }
    bpf_ringbuf_submit(buff,0);

    return 0;
}

static int perf_runqlat_without_bad(void){
    struct runqlat_perf_data *buff = bpf_ringbuf_reserve(&runqlat_without_bad_buffer,sizeof(struct runqlat_perf_data),0);
    if(!buff)
    {
        bpf_printk("runqlat ringbuff reserve failed\n");
        return 0;
    }
    memset(buff,0,sizeof(struct runqlat_perf_data));
    for(u32 index=0;index<MAX_LATENCY_BUCKETS;index++){
        u32 i = index;
        u32 *size = bpf_map_lookup_elem(&runqlat_without_bad_map,&i);
        if(!size)
            buff->data[index] = 0;
        else
            buff->data[index] = *size;
    }
    bpf_ringbuf_submit(buff,0);

    return 0;
}

SEC("perf_event")
int handle_cpu_event(struct bpf_perf_event_data *ctx){
    if(!init_cpus_num){
        u32 *nr_cpus_ptr;
        nr_cpus_ptr = bpf_map_lookup_elem(&cpu_usr_map,&zero);
        if(!nr_cpus_ptr){
            bpf_printk("get cpu nums error\n");
            return -1;
        }
        nr_cpus = *nr_cpus_ptr;
        init_cpus_num = true;
    }
    int res = update_cpu_usage_percent();
    if(res < 0)
        bpf_printk("update error\n");
    return 0;
}

SEC("perf_event")
int handle_sys_latency_event(struct bpf_perf_event_data *ctx){
    perf_runqlat();
    return 0;
}

SEC("perf_event")
int handle_sys_latency_without_bad_event(struct bpf_perf_event_data *ctx){
    perf_runqlat_without_bad();
    return 0;
}