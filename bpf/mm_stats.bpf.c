#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "mm_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 统计整体数据的map
DEFINE_BPF_MAP(task_mm_stats_map,BPF_MAP_TYPE_HASH,MAX_ENTRIES,u32,struct task_mm_stats);
DEFINE_BPF_MAP(process_mm_stats_map,BPF_MAP_TYPE_HASH,4096,u32,struct process_mm_stats);

// 统计超出阈值数据的map
// 通过计算哈希值之后，以哈希值为健，存pid或tgid，首个数字表示当前bucket有几个有效的pid
DEFINE_BPF_MAP(task_mm_occupied_list,BPF_MAP_TYPE_ARRAY,GLOBAL_HASH_SIZE,u32,struct data_store);
DEFINE_BPF_MAP(process_mm_occupied_list,BPF_MAP_TYPE_ARRAY,GLOBAL_HASH_SIZE,u32,struct data_store);

// 用户态传递阈值上来，一个存task的，一个存process的
DEFINE_BPF_MAP(threhold_map,BPF_MAP_TYPE_ARRAY,2,u32,struct mm_threhold);

// 环形缓冲区传递数据
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  
} task_mm_stats_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);  
} process_mm_stats_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  
} oom_event_buffer SEC(".maps");

static const u32 zero = 0;
static const u32 one = 1;

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
    struct oom_event *buff;
    buff = bpf_ringbuf_reserve(&oom_event_buffer, sizeof(struct oom_event), 0);
    if(!buff){
        bpf_printk("the oom_event_buff is full\n");
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    buff->kill_time = now;

    struct task_struct *task;
    bpf_probe_read(&task, sizeof(task), &oc->chosen);
    bpf_probe_read(&buff->killed_id, sizeof(buff->killed_id), &task->pid);

    // 获取被杀进程的命令名 (comm)
    bpf_probe_read(&buff->comm, sizeof(buff->comm), &task->comm);

    buff->trigger_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF; 
    bpf_ringbuf_submit(buff, 0);

    return 0;
}

static u32 get_hash_index(u32 id){
    return id % GLOBAL_HASH_SIZE;
}

static int task_compare_and_commit(struct task_mm_stats *task){
    struct mm_threhold *threhold = bpf_map_lookup_elem(&threhold_map,&zero);
    if(!threhold){
        bpf_printk("mm_threhold map is not init\n");
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    if(task->last_clear_time + threhold->time_window < now){
        task->kmem_count = 0;
        task->vmem_count = 0;
        task->slab_count = 0;
        task->last_clear_time = now;
        bpf_map_update_elem(&task_mm_stats_map,&task->info.pid,task,BPF_ANY);
        return 0;
    }

    if(task->kmem_count >= threhold->kmem_threhold || task->slab_count >= threhold->slab_threhold || task->vmem_count >= threhold->vmem_threhold){
        struct task_mm_stats *buff = bpf_ringbuf_reserve(&task_mm_stats_buffer, sizeof(struct task_mm_stats), 0);
        if(!buff){
            bpf_printk("task_mm_stats_buff is full\n");
            return 0;
        }
        memset(buff,0,sizeof(struct task_mm_stats));
        buff->info.pid = task->info.pid;
        buff->info.tgid = task->info.tgid;
        bpf_probe_read_kernel_str(buff->info.comm,sizeof(task->info.comm),task->info.comm);  
        buff->kmem_count = task->kmem_count;
        buff->slab_count = task->slab_count;
        buff->vmem_count = task->vmem_count;
        bpf_ringbuf_submit(buff,0);
    }
    return 0;
}

static int process_compare_and_commit(struct process_mm_stats *process){
    struct mm_threhold *threhold = bpf_map_lookup_elem(&threhold_map,&one);
    if(!threhold){
        bpf_printk("mm_threhold map is not init\n");
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    if(process->last_clear_time + threhold->time_window < now){
        process->kmem_count = 0;
        process->vmem_count = 0;
        process->slab_count = 0;
        process->last_clear_time = now;
        bpf_map_update_elem(&process_mm_stats_map,&process->tgid,process,BPF_ANY);
        return 0;
    }

    if(process->kmem_count >= threhold->kmem_threhold || process->slab_count >= threhold->slab_threhold || process->vmem_count >= threhold->vmem_threhold){
        struct process_mm_stats *buff = bpf_ringbuf_reserve(&process_mm_stats_buffer, sizeof(struct process_mm_stats), 0);
        if(!buff){
            bpf_printk("process_mm_stats_buff is full\n");
            return 0;
        }
        memset(buff,0,sizeof(struct process_mm_stats));
        buff->tgid = process->tgid;
        buff->kmem_count = process->kmem_count;
        buff->slab_count = process->slab_count;
        buff->vmem_count = process->vmem_count;
        bpf_ringbuf_submit(buff,0);
    }
    return 0;
}

// operation 0 is insert, 1 is delete
static int update_mm_hash_map(u32 map_index,u32 hash_index,u32 value,u32 operation){
    if(map_index == 0){
        struct data_store *task = bpf_map_lookup_elem(&task_mm_occupied_list,&hash_index);
        if(operation == 0){
            if(!task){
                struct data_store data;
                data.list[0] = 1;
                data.list[1] = value;
                bpf_map_update_elem(&task_mm_occupied_list,&hash_index,&data,BPF_ANY);
            }
            else{
                if(task->list[0] < GLOBAL_HASH_BUCKET_SIZE){
                    task->list[0] += 1;
                    u32 i = task->list[0];
                    task->list[i] = value;
                    bpf_map_update_elem(&task_mm_occupied_list,&hash_index,task,BPF_ANY);
                }
                else{
                    bpf_printk("The mm hash_list hash bucket is full\n");
                    return -1;
                }
            }
        }
        else if(operation == 1){
            if(!task){
                struct data_store data;
                data.list[0] = 0;
                bpf_map_update_elem(&task_mm_occupied_list,&hash_index,&data,BPF_ANY);
            }
            else{
                if(task->list[0] > 0){
                    u32 fin = task->list[0];
                    for(u32 i=1;i<GLOBAL_HASH_BUCKET_SIZE + 1;i++){
                        if(i > fin)
                            break;
                        if(task->list[i] == value){
                            // 和最后一个有效值交换
                            task->list[i] = task->list[fin];
                            task->list[0] -= 1;
                            break;
                        }
                    }
                }
                bpf_map_update_elem(&task_mm_occupied_list,&hash_index,task,BPF_ANY);
            }
        }
        else{
            bpf_printk("mm hash_list operation index is invalid \n");
        }
    }else if(map_index == 1){
        struct data_store *process = bpf_map_lookup_elem(&process_mm_occupied_list,&hash_index);
        if(operation == 0){
            if(!process){
                struct data_store data;
                data.list[0] = 1;
                data.list[1] = value;
                bpf_map_update_elem(&process_mm_occupied_list,&hash_index,&data,BPF_ANY);
            }
            else{
                if(process->list[0] < GLOBAL_HASH_BUCKET_SIZE){
                    process->list[0] += 1;
                    u32 i = process->list[0];
                    process->list[i] = value;
                    bpf_map_update_elem(&process_mm_occupied_list,&hash_index,process,BPF_ANY);
                }
                else{
                    bpf_printk("The mm hash_list hash bucket is full\n");
                    return -1;
                }
            }
        }
        else if(operation == 1){
            if(!process){
                struct data_store data;
                data.list[0] = 0;
                bpf_map_update_elem(&process_mm_occupied_list,&hash_index,&data,BPF_ANY);
            }
            else{
                if(process->list[0] > 0){
                    u32 fin = process->list[0];
                    for(u32 i=1;i<GLOBAL_HASH_BUCKET_SIZE + 1;i++){
                        if(i > fin)
                            break;
                        if(process->list[i] == value){
                            // 和最后一个有效值交换
                            process->list[i] = process->list[fin];
                            process->list[0] -= 1;
                            break;
                        }
                    }
                }
                bpf_map_update_elem(&process_mm_occupied_list,&hash_index,process,BPF_ANY);
            }
        }
        else{
            bpf_printk("mm hash_list operation index is invalid \n");
        }
    }else{
        bpf_printk("mm hash_map map_index is invalid \n");
    }
    
    return 0;
}

// SEC("raw_tp/sched_wakeup_new")
// int BPF_PROG(mm_sched_wakeup_new, struct task_struct *p){
//     u32 pid = BPF_CORE_READ(p,pid);
//     if(pid == 0)
//         return 0;
//     u32 tgid = BPF_CORE_READ(p,tgid);
//     u32 cpu_id = bpf_get_smp_processor_id();
//     struct task_mm_stats *task_use = bpf_map_lookup_elem(&task_mm_stats_map,&pid);
//     if(!task_use){
//         struct task_info_simple info = init_task_info(p,cpu_id);
//         struct task_mm_stats init_task = {
//                 .task_info = info
//             };
//         bpf_map_update_elem(&task_mm_stats_map, &pid, &init_task, BPF_ANY);
//     }

//     return 0;
// }

// SEC("raw_tp/sched_wakeup")
// int BPF_PROG(mm_sched_wakeup, struct task_struct *p)
// {
//     u32 pid = BPF_CORE_READ(p,pid);
//     if(pid == 0)
//         return 0;
//     u32 tgid = BPF_CORE_READ(p,tgid);
//     u32 cpu_id = bpf_get_smp_processor_id();
//     struct task_mm_stats *task_use = bpf_map_lookup_elem(&task_mm_stats_map,&pid);
//     if(!task_use){
//         struct task_info_simple info = init_task_info(p,cpu_id);
//         struct task_mm_stats init_task = {
//                 .task_info = info,
//             };
//         bpf_map_update_elem(&task_mm_stats_map, &pid, &init_task, BPF_ANY);
//     }
//     else{
//         if(task_use->task_info.tgid == 0 || task_use->task_info.pid == 0)
//         {
//             task_use->task_info.tgid = tgid;
//             task_use->task_info.pid = pid;
//             bpf_map_update_elem(&task_mm_stats_map,&pid,task_use,BPF_ANY);
//         }
//     }

//     return 0;
// }

// SEC("tracepoint/sched/sched_process_fork")
// int mm_task_create(struct trace_event_raw_sched_process_fork *ctx){
//     u32 pid_new = ctx->child_pid;
//     u32 cpu_id = bpf_get_smp_processor_id();
//     struct task_cpu_usage *tk = bpf_map_lookup_elem(&task_cpu_usage_map,&pid_new);
//     if(!tk){
//         struct task_info_simple info = {
//                 .pid = pid_new,
//                 .cpu_id = cpu_id
//             };
//         bpf_probe_read_kernel_str(info.comm,sizeof(ctx->child_comm),ctx->child_comm);
//         struct task_cpu_usage init_task = {
//             .task_info = info,
//             .in_kernel = false
//         };
//         bpf_map_update_elem(&task_cpu_usage_map,&pid_new,&init_task,BPF_ANY);
//     }
//     return 0;
// }

static struct task_mm_stats init_task_mm(u32 pid,u32 tgid){
    struct task_info_simple info = {
            .pid = pid,
            .tgid = tgid
        };
    struct task_mm_stats init_task;
    init_task.info = info;
    return init_task;
}

SEC("tracepoint/kmem/kmalloc")
int trace_kmalloc(struct trace_event_raw_kmem_alloc *ctx){
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id & 0xFFFFFFFF; 
    u64 now = bpf_ktime_get_ns();

    if(pid == 0)
        return 0;

    struct task_mm_stats *task = bpf_map_lookup_elem(&task_mm_stats_map,&pid);
    if(!task){
        struct task_mm_stats init_task = init_task_mm(pid,tgid);
        init_task.kmem_count = 1;
        init_task.last_clear_time = now;
        bpf_map_update_elem(&task_mm_stats_map,&pid,&init_task,BPF_ANY);
    }
    else{
        task->kmem_count += 1;
        bpf_map_update_elem(&task_mm_stats_map,&pid,task,BPF_ANY);
        task_compare_and_commit(task);
    }

    struct process_mm_stats *process = bpf_map_lookup_elem(&process_mm_stats_map,&tgid);
    if(!process){
        struct process_mm_stats init_process = {
            .tgid = tgid,
            .kmem_count = 1,
            .last_clear_time = now
        };
        bpf_map_update_elem(&process_mm_stats_map,&tgid,&init_process,BPF_ANY);
    }
    else{
        process->kmem_count += 1;
        bpf_map_update_elem(&process_mm_stats_map,&tgid,process,BPF_ANY);
        process_compare_and_commit(process);
    }

    return 0;
}

SEC("tracepoint/kmem/kfree")
int trace_kfree(struct trace_event_raw_kmem_kfree *ctx){
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id & 0xFFFFFFFF; 
    u64 now = bpf_ktime_get_ns();

    if(pid == 0)
        return 0;

    struct task_mm_stats *task = bpf_map_lookup_elem(&task_mm_stats_map,&pid);
    if(!task){
        struct task_mm_stats init_task = init_task_mm(pid,tgid);
        init_task.kmem_count = 1;
        init_task.last_clear_time = now;
        bpf_map_update_elem(&task_mm_stats_map,&pid,&init_task,BPF_ANY);
    }
    else{
        task->kmem_count += 1;
        bpf_map_update_elem(&task_mm_stats_map,&pid,task,BPF_ANY);
        task_compare_and_commit(task);
    }

    struct process_mm_stats *process = bpf_map_lookup_elem(&process_mm_stats_map,&tgid);
    if(!process){
        struct process_mm_stats init_process = {
            .tgid = tgid,
            .kmem_count = 1,
            .last_clear_time = now
        };
        bpf_map_update_elem(&process_mm_stats_map,&tgid,&init_process,BPF_ANY);
    }
    else{
        process->kmem_count += 1;
        bpf_map_update_elem(&process_mm_stats_map,&tgid,process,BPF_ANY);
        process_compare_and_commit(process);
    }

    return 0;
}

SEC("tracepoint/kmem/mm_page_alloc")
int BPF_PROG(trace_page_alloc){
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id & 0xFFFFFFFF; 
    u64 now = bpf_ktime_get_ns();

    if(pid == 0)
        return 0;

    struct task_mm_stats *task = bpf_map_lookup_elem(&task_mm_stats_map,&pid);
    if(!task){
        struct task_mm_stats init_task = init_task_mm(pid,tgid);
        init_task.vmem_count = 1;
        init_task.last_clear_time = now;
        bpf_map_update_elem(&task_mm_stats_map,&pid,&init_task,BPF_ANY);
    }
    else{
        task->vmem_count += 1;
        bpf_map_update_elem(&task_mm_stats_map,&pid,task,BPF_ANY);
        task_compare_and_commit(task);
    }

    struct process_mm_stats *process = bpf_map_lookup_elem(&process_mm_stats_map,&tgid);
    if(!process){
        struct process_mm_stats init_process = {
            .tgid = tgid,
            .vmem_count = 1,
            .last_clear_time = now
        };
        bpf_map_update_elem(&process_mm_stats_map,&tgid,&init_process,BPF_ANY);
    }
    else{
        process->vmem_count += 1;
        bpf_map_update_elem(&process_mm_stats_map,&tgid,process,BPF_ANY);
        process_compare_and_commit(process);
    }

    return 0;
}

SEC("tracepoint/kmem/mm_page_free")
int BPF_PROG(trace_page_free){
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id & 0xFFFFFFFF; 
    u64 now = bpf_ktime_get_ns();

    if(pid == 0)
        return 0;

    struct task_mm_stats *task = bpf_map_lookup_elem(&task_mm_stats_map,&pid);
    if(!task){
        struct task_mm_stats init_task = init_task_mm(pid,tgid);
        init_task.vmem_count = 1;
        init_task.last_clear_time = now;
        bpf_map_update_elem(&task_mm_stats_map,&pid,&init_task,BPF_ANY);
    }
    else{
        task->vmem_count += 1;
        bpf_map_update_elem(&task_mm_stats_map,&pid,task,BPF_ANY);
        task_compare_and_commit(task);
    }

    struct process_mm_stats *process = bpf_map_lookup_elem(&process_mm_stats_map,&tgid);
    if(!process){
        struct process_mm_stats init_process = {
            .tgid = tgid,
            .vmem_count = 1,
            .last_clear_time = now
        };
        bpf_map_update_elem(&process_mm_stats_map,&tgid,&init_process,BPF_ANY);
    }
    else{
        process->vmem_count += 1;
        bpf_map_update_elem(&process_mm_stats_map,&tgid,process,BPF_ANY);
        process_compare_and_commit(process);
    }

    return 0;
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int BPF_PROG(trace_cache_alloc){
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id & 0xFFFFFFFF; 
    u64 now = bpf_ktime_get_ns();

    if(pid == 0)
        return 0;

    struct task_mm_stats *task = bpf_map_lookup_elem(&task_mm_stats_map,&pid);
    if(!task){
        struct task_mm_stats init_task = init_task_mm(pid,tgid);
        init_task.slab_count = 1;
        init_task.last_clear_time = now;
        bpf_map_update_elem(&task_mm_stats_map,&pid,&init_task,BPF_ANY);
    }
    else{
        task->slab_count += 1;
        bpf_map_update_elem(&task_mm_stats_map,&pid,task,BPF_ANY);
        task_compare_and_commit(task);
    }

    struct process_mm_stats *process = bpf_map_lookup_elem(&process_mm_stats_map,&tgid);
    if(!process){
        struct process_mm_stats init_process = {
            .tgid = tgid,
            .slab_count = 1,
            .last_clear_time = now
        };
        bpf_map_update_elem(&process_mm_stats_map,&tgid,&init_process,BPF_ANY);
    }
    else{
        process->slab_count += 1;
        bpf_map_update_elem(&process_mm_stats_map,&tgid,process,BPF_ANY);
        process_compare_and_commit(process);
    }

    return 0;
}


SEC("tracepoint/kmem/kmem_cache_free")
int BPF_PROG(trace_cache_free){
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id & 0xFFFFFFFF; 
    u64 now = bpf_ktime_get_ns();

    if(pid == 0)
        return 0;

    struct task_mm_stats *task = bpf_map_lookup_elem(&task_mm_stats_map,&pid);
    if(!task){
        struct task_mm_stats init_task = init_task_mm(pid,tgid);
        init_task.slab_count = 1;
        init_task.last_clear_time = now;
        bpf_map_update_elem(&task_mm_stats_map,&pid,&init_task,BPF_ANY);
    }
    else{
        task->slab_count += 1;
        bpf_map_update_elem(&task_mm_stats_map,&pid,task,BPF_ANY);
        task_compare_and_commit(task);
    }

    struct process_mm_stats *process = bpf_map_lookup_elem(&process_mm_stats_map,&tgid);
    if(!process){
        struct process_mm_stats init_process = {
            .tgid = tgid,
            .slab_count = 1,
            .last_clear_time = now
        };
        bpf_map_update_elem(&process_mm_stats_map,&tgid,&init_process,BPF_ANY);
    }
    else{
        process->slab_count += 1;
        bpf_map_update_elem(&process_mm_stats_map,&tgid,process,BPF_ANY);
        process_compare_and_commit(process);
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int BPF_PROG(handle_mm_task_exit){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid & 0xFFFFFFFF;  
    u32 tgid = pid_tgid >> 32;  
    if(pid == 0 || tgid == 0)
        return 0;
    
    if(bpf_map_lookup_elem(&task_mm_stats_map,&pid) != NULL){
        bpf_map_delete_elem(&task_mm_stats_map,&pid);
    }

    // if(bpf_map_lookup_elem(&process_map,&tgid) == NULL && bpf_map_lookup_elem(&process_kids_map,&tgid) == NULL){
    //     bpf_map_delete_elem(&process_mm_stats_map,&tgid);
    // }
    return 0;
}



