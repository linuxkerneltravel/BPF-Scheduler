#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/select.h>
#include <unistd.h> 
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <asm/unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <assert.h>


#include "cpu_event.h"
#include "mm_event.h"

#include "cpu_stats.skel.h"
#include "blazesym.h"

#define MEMINFO_PATH "/proc/meminfo"
#define MM_INTERVAL 1  // 定时读取的间隔时间（秒）

// 初始化符号解析器
static struct blaze_symbolizer *symbolizer;

// 初始化符号解析器
static int init_symbolizer() {
    symbolizer = blaze_symbolizer_new();
    if (!symbolizer) {
        printf("Failed to initialize symbolizer\n");
        return -1;
    }
    return 0;
}

// 释放符号解析器
static void free_symbolizer() {
    if (symbolizer) {
        blaze_symbolizer_free(symbolizer);
        symbolizer = NULL;
    }
}

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
{
    // 忽略无效的栈地址
    if (addr == 0 || addr == (uintptr_t)-1) {
        return;
    }

    // If we have an input address we have a new symbol.
    if (input_addr != 0) {
        printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
        if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
            printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
        } else if (code_info != NULL && code_info->file != NULL) {
            printf(" %s:%u\n", code_info->file, code_info->line);
        } else {
            printf("\n");
        }
    } else {
        printf("%16s  %s", "", name);
        if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
            printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
        } else if (code_info != NULL && code_info->file != NULL) {
            printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
        } else {
            printf("[inlined]\n");
        }
    }
}


// 打印栈回溯
static void show_stack_trace(uint64_t *stack, int stack_sz, pid_t pid) {
    const struct blaze_syms *syms;
    const struct blaze_sym *sym;
    const struct blaze_symbolize_inlined_fn *inlined;
    int i, j;

    assert(sizeof(uintptr_t) == sizeof(uint64_t));

    if (pid) {
        // 用户空间栈回溯的符号解析
        struct blaze_symbolize_src_process src = {
            .type_size = sizeof(src),
            .pid = pid,
        };
        syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
    } else {
        // 内核空间栈回溯的符号解析
        struct blaze_symbolize_src_kernel src = {
            .type_size = sizeof(src),
        };
        syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
    }

    if (syms == NULL) {
        printf("  failed to symbolize addresses: %s\n", blaze_err_str(blaze_err_last()));
        return;
    }

    for (i = 0; i < stack_sz; i++) {
        // 检查栈地址是否为有效的地址
        if (stack[i] == 0 || stack[i] == (uintptr_t)-1) {
            continue;  // 跳过无效的栈地址
        }

        if (!syms || syms->cnt <= i || syms->syms[i].name == NULL) {
            printf("%016llx: <no-symbol>\n", stack[i]);
            continue;
        }

        sym = &syms->syms[i];
        print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

        // 如果有内联函数，打印内联符号信息
        for (j = 0; j < sym->inlined_cnt; j++) {
            inlined = &sym->inlined[j];
            print_frame(sym->name, 0, 0, 0, &inlined->code_info);
        }
    }

    blaze_syms_free(syms);
}

static int handle_usr_task_cpu_backtrace_event(void *ctx,void *data, size_t data_sz){
    struct task_trace_event *event = data;

    if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
    {
        printf("The stack size is invalid\n");
        return 1;
    }

    printf("COMM: %s (pid=%d)\n", event->comm, event->pid);

    if (event->kstack_sz > 0) {
        printf("Kernel:\n");
        show_stack_trace(event->k_stack, event->kstack_sz / sizeof(uint64_t), 0);
    } else {
        printf("No Kernel Stack\n");
    }

    if (event->ustack_sz > 0) {
        printf("Userspace:\n");
        show_stack_trace(event->u_stack, event->ustack_sz / sizeof(uint64_t), event->pid);
    } else {
        printf("No Userspace Stack\n");
    }

    printf("\n");
    return 0;
}

static int handle_cpu_usage_event(void *ctx,void *data, size_t data_sz){
    struct cpu_usage_stats *stats = data;
    float usr = stats->user_percent/100.0f;
    float kernel = stats->kernel_percent/100.0f;
    float idle = stats->idle_percent/100.0f;
    float softirq = stats->irq_percent/100.0f;
    float irq = stats->irq_percent / 100.0f;

    printf("CPU ID: %u\n", stats->cpu_id);
    printf("User Time: %f\n", usr);
    printf("Kernel Time: %f\n", kernel);
    printf("Idle Time: %f\n", idle);
    printf("Irq Time: %f\n",irq);
    printf("Softirq Time: %f\n",softirq);

    return 0;
}

static int handle_usr_task_usage_event(void *ctx,void *data, size_t data_sz){
    struct task_cpu_usage *task = data;
    u32 pid = task->task_info.pid;
    float total_percent = task->total_percent/1.0f;
    float usr_percent = task->user_percent/1.0f;
    float kernel_pericent = task->kernel_percent/1.0f;

    char comm[TASK_COMM_LEN + 1]; 
    strncpy(comm,task->task_info.comm,TASK_COMM_LEN);
    comm[TASK_COMM_LEN] = '\0';

    printf("pid: %u\n",pid);
    printf("name: %s\n",comm);
    printf("total percent: %f",total_percent);
    printf("kernel percent: %f",kernel_pericent);
    printf("usr_percent: %f\n",usr_percent);
    
    return 0;
}

static int handle_use_process_stat_event(void *ctx,void *data, size_t data_sz){
    struct process_struct *ps = data;
    u32 tgid = ps->tgid;
    u32 kis_length = ps->kids_length;
    float total_percent = ps->total_use_percent/1.0f;

    printf("tgid: %u\n",tgid);
    printf("kids_length: %u\n",kis_length);
    printf("total percent: %f\n",total_percent);
}

static int handle_usr_runqlat_event(void *ctx,void *data, size_t data_sz){
    struct latency_num *late = data;
    switch (late->pre_size)
    {
    case 0:
        printf("wait less than 1us: %u\n",late->size);
        break;
    case 1:
        printf("wait less than 4us: %u\n",late->size);
        break;
    case 2:
        printf("wait less than 16us: %u\n",late->size);
        break;
    case 3:
        printf("wait less than 64us: %u\n",late->size);
        break;
    case 4:
        printf("wait less than 256us: %u\n",late->size);
        break;
    case 5:
        printf("wait less than 1ms: %u\n",late->size);
        break;
    case 6:
        printf("wait less than 4ms: %u\n",late->size);
        break;
    case 7:
        printf("wait large than 4ms: %u\n",late->size);
        break;
    default:
        break;
    }
}

FILE *open_meminfo() {
    FILE *file = fopen(MEMINFO_PATH, "r");
    if (!file) {
        perror("Failed to open /proc/meminfo");
        exit(EXIT_FAILURE);
    }
    return file;
}

void read_meminfo(FILE *file) {
    rewind(file);

    char key[256];
    unsigned long value;
    unsigned long mem_total = 0, mem_free = 0, mem_available = 0, buffers = 0, cached = 0;
    unsigned long swap_total = 0, swap_free = 0, committed_as = 0, commit_limit = 0;

    while (fscanf(file, "%255[^:]: %lu kB\n", key, &value) == 2) {
        if (strcmp(key, "MemTotal") == 0) {
            mem_total = value;
        } else if (strcmp(key, "MemFree") == 0) {
            mem_free = value;
        } else if (strcmp(key, "MemAvailable") == 0) {
            mem_available = value;
        } else if (strcmp(key, "Buffers") == 0) {
            buffers = value;
        } else if (strcmp(key, "Cached") == 0) {
            cached = value;
        } else if (strcmp(key, "SwapTotal") == 0) {
            swap_total = value;
        } else if (strcmp(key, "SwapFree") == 0) {
            swap_free = value;
        } else if (strcmp(key, "Committed_AS") == 0) {
            committed_as = value;
        } else if (strcmp(key, "CommitLimit") == 0) {
            commit_limit = value;
        }
    }

    unsigned long used_memory = mem_total - mem_free;
    unsigned long used_swap = swap_total - swap_free;
    double used_memory_percent = (mem_total > 0) ? (100.0 * used_memory / mem_total) : 0.0;
    double available_memory_percent = (mem_total > 0) ? (100.0 * mem_available / mem_total) : 0.0;
    double used_swap_percent = (swap_total > 0) ? (100.0 * used_swap / swap_total) : 0.0;
    double commit_percent = (commit_limit > 0) ? (100.0 * committed_as / commit_limit) : 0.0;

    printf("\n--- Memory Usage ---\n");
    printf("Total Memory: %lu kB\n", mem_total);
    printf("Used Memory: %lu kB (%.2f%%)\n", used_memory, used_memory_percent);
    printf("Available Memory: %lu kB (%.2f%%)\n", mem_available, available_memory_percent);
    printf("Buffers: %lu kB\n", buffers);
    printf("Cached: %lu kB\n", cached);

    printf("\n--- Swap Memory ---\n");
    printf("Total Swap: %lu kB\n", swap_total);
    printf("Used Swap: %lu kB (%.2f%%)\n", used_swap, used_swap_percent);

    printf("\n--- Memory Commitment ---\n");
    printf("Commit Limit: %lu kB\n", commit_limit);
    printf("Committed AS: %lu kB (%.2f%%)\n", committed_as, commit_percent);
}

static int create_perf_event(u32 period_ms) {
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,          // 使用软件事件类型
        .config = PERF_COUNT_SW_CPU_CLOCK,   // 使用 CPU 时钟作为触发源
        .size = sizeof(struct perf_event_attr),
        .sample_period = period_ms * 1000000ULL, // 设置为毫秒级的间隔
        .freq = 0,                           // 使用固定间隔，而非频率
        .wakeup_events = 1,                  // 每次触发事件
    };

    // 对所有 CPU 和进程创建事件
    int fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
    if (fd < 0) {
        perror("perf_event_open");
        return -1;
    }
    return fd;
}

static struct bpf_link* attach_perf_event_to_program(struct bpf_program *prog, u32 period_ms) {
    // 创建 perf event
    int perf_fd = create_perf_event(period_ms);
    if (perf_fd < 0) {
        fprintf(stderr, "Failed to create perf_event\n");
        return NULL;
    }

    // 将 perf event 附加到指定的 BPF 程序
    struct bpf_link *link = bpf_program__attach_perf_event(prog, perf_fd);
    if (!link) {
        fprintf(stderr, "Failed to attach perf_event to BPF program: %s\n", strerror(errno));
        close(perf_fd);
        return NULL;
    }

    return link;
}


static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

/*
// 用于从 CPU 信息获取 CPU 核心数
static int get_cpu_count() {
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    int cpu_count = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "processor", 9) == 0) {
            cpu_count++;
        }
    }
    fclose(fp);

    return cpu_count;/
}*/

int main(int argc, char **argv){
    struct ring_buffer *rb_cpu = NULL;
    struct ring_buffer *rb_task = NULL;
    struct ring_buffer *rb_process = NULL;
    struct ring_buffer *rb_runqlat = NULL;
    struct ring_buffer *rb_backtrace = NULL;
    struct cpu_stats_bpf *skel;

    if(init_symbolizer()!=0)
        return -1;

    int err = 0;
    FILE *file = open_meminfo();

    skel = cpu_stats_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF program\n");
        return 1;
    }

    int nr_cpu = libbpf_num_possible_cpus();
    if(nr_cpu < 0)
    {
        fprintf(stderr,"libbpf: get cpu nums failed \n");
    }

    int map_fd = bpf_map__fd(skel->maps.cpu_usr_map);
    u32 key = 0;
    if(bpf_map_update_elem(map_fd,&key,&nr_cpu,BPF_ANY) != 0){
        perror("Failed to update nr_cpu_map");
        cpu_stats_bpf__destroy(skel);
        return 1;
    }

    u32 one = 1;
    struct data_list list = {};
    map_fd = bpf_map__fd(skel->maps.occupied_list);
    if(bpf_map_update_elem(map_fd,&key,&list,BPF_ANY)!=0 || bpf_map_update_elem(map_fd,&one,&list,BPF_ANY)!=0){
        perror("Failed to init occupied_liss");
        cpu_stats_bpf__destroy(skel);
        return 1;
    }

    struct hash_table table;
    hash_table_init(&table);
    map_fd = bpf_map__fd(skel->maps.hash_table_model_map);
    if(bpf_map_update_elem(map_fd,&key,&table,BPF_ANY) != 0){
        perror("Failed to update hash_table_model_map");
        cpu_stats_bpf__destroy(skel);
        return 1;
    }
    // map_fd = bpf_map__fd(skel->maps.process_occupied_map);
    // if(bpf_map_update_elem(map_fd,&key,&table,BPF_ANY) != 0){
    //     perror("Failed to update hash_table_model_map");
    //     cpu_stats_bpf__destroy(skel);
    //     return 1;
    // }
    // map_fd = bpf_map__fd(skel->maps.thread_occupied_map);
    // if(bpf_map_update_elem(map_fd,&key,&table,BPF_ANY) != 0){
    //     perror("Failed to update hash_table_model_map");
    //     cpu_stats_bpf__destroy(skel);
    //     return 1;
    // }

    err = cpu_stats_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    struct bpf_link *link_cpu = attach_perf_event_to_program(skel->progs.handle_cpu_event, 500);  // 500 毫秒
    if (!link_cpu) {
        goto cleanup;
    }
    skel->links.handle_cpu_event = link_cpu;

    struct bpf_link *link_task = attach_perf_event_to_program(skel->progs.handle_task_usage_event, 500);  // 500 毫秒
    if (!link_task) {
        goto cleanup;
    }
    skel->links.handle_task_usage_event = link_task;

    struct bpf_link *link_process = attach_perf_event_to_program(skel->progs.handle_process_stat_event,500);
    if(!link_process){
        goto cleanup;
    }
    skel->links.handle_process_stat_event = link_process;

    struct bpf_link *link_runqlat = attach_perf_event_to_program(skel->progs.handle_sys_latency_event,500);
    if(!link_runqlat){
        goto cleanup;
    }
    skel->links.handle_sys_latency_event = link_runqlat;

    struct bpf_link *link_backtrace = attach_perf_event_to_program(skel->progs.handle_task_backtrace_event,500);
    if(!link_backtrace){
        goto cleanup;
    }

    /*int perf_fd_cpu_usage,perf_fd_task_usage;
    // 2. 创建定时 perf_event，每 500 毫秒触发
    perf_fd_cpu_usage = create_perf_event(500);  // 500 毫秒
    if (perf_fd_cpu_usage < 0) {
        fprintf(stderr, "Failed to create perf_event\n");
        goto cleanup;
    }

    perf_fd_task_usage = create_perf_event(500);
    if(perf_fd_task_usage < 0){
        fprintf(stderr, "Failed to create perf_event\n");
        goto cleanup;
    }

    err = cpu_stats_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    struct bpf_link *link_cpu_usage = bpf_program__attach_perf_event(skel->progs.handle_cpu_event, perf_fd_cpu_usage);
    if (!link_cpu_usage) {
        fprintf(stderr, "Failed to attach perf_event to BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    skel->links.handle_cpu_event = link_cpu_usage;

    struct bpf_link *link_task_usage = bpf_program__attach_perf_event(skel->progs.handle_task_usage_event, perf_fd_task_usage);
    if (!link_task_usage) {
        fprintf(stderr, "Failed to attach perf_event to handle_task_usage_event: %s\n", strerror(errno));
        goto cleanup;
    }
    skel->links.handle_task_usage_event = link_task_usage;*/

    rb_cpu = ring_buffer__new(bpf_map__fd(skel->maps.cpu_usage_buffer), handle_cpu_usage_event, NULL, NULL);
    if (!rb_cpu) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    rb_task = ring_buffer__new(bpf_map__fd(skel->maps.task_occupied_buffer), handle_usr_task_usage_event, NULL, NULL);
    if (!rb_task) {
        fprintf(stderr, "Failed to create ring buffer for task usage\n");
        goto cleanup;
    }

    rb_process = ring_buffer__new(bpf_map__fd(skel->maps.process_occupied_buffer), handle_use_process_stat_event, NULL, NULL);
    if(!rb_process){
        fprintf(stderr, "Failed to create ring buffer for process stat\n");
        goto cleanup;
    }

    rb_runqlat = ring_buffer__new(bpf_map__fd(skel->maps.runqlat_buffer), handle_usr_runqlat_event, NULL, NULL);
    if(!rb_runqlat){
        fprintf(stderr, "Failed to create ring buffer for runqlat\n");
        goto cleanup;
    }

    rb_backtrace = ring_buffer__new(bpf_map__fd(skel->maps.task_backtrace_buffer), handle_usr_task_cpu_backtrace_event, NULL, NULL);
    if(!rb_backtrace){
        fprintf(stderr, "Failed to create ring buffer for cpu task backtrace\n");
        goto cleanup;
    }


    printf("Monitoring CPU usage... Press Ctrl+C to stop.\n");

    while (1) {
        // err = ring_buffer__poll(rb_cpu, 600 /* ms */);
        // if (err == -EINTR) {
        //     break;  // 捕捉到退出信号时停止
        // } else if (err < 0) {
        //     fprintf(stderr, "Error polling CPU usage ring buffer: %d\n", err);
        //     break;
        // }

        // err = ring_buffer__poll(rb_task, 600 /* ms */);
        // if (err == -EINTR) {
        //     break;  // 捕捉到退出信号时停止
        // } else if (err < 0) {
        //     fprintf(stderr, "Error polling task usage ring buffer: %d\n", err);
        //     break;
        // }

        // err = ring_buffer__poll(rb_process, 600 /* ms */);
        // if (err == -EINTR) {
        //     break;  // 捕捉到退出信号时停止
        // } else if (err < 0) {
        //     fprintf(stderr, "Error polling process stat ring buffer: %d\n", err);
        //     break;
        // }
        // err = ring_buffer__poll(rb_runqlat, 600 /* ms */);
        // if (err == -EINTR) {
        //     break;  // 捕捉到退出信号时停止
        // } else if (err < 0) {
        //     fprintf(stderr, "Error polling process stat ring buffer: %d\n", err);
        //     break;
        // }

        err = ring_buffer__poll(rb_backtrace,600);
        if (err == -EINTR) {
            break;  // 捕捉到退出信号时停止
        } else if (err < 0) {
            fprintf(stderr, "Error polling process stat ring buffer: %d\n", err);
            break;
        }
        //read_meminfo(file);
    }

cleanup:
    if (rb_cpu)
        ring_buffer__free(rb_cpu);
    if (rb_task)
        ring_buffer__free(rb_task);
    if (rb_process)
        ring_buffer__free(rb_process);
    if (rb_runqlat)
        ring_buffer__free(rb_runqlat);
    cpu_stats_bpf__destroy(skel);
    fclose(file);
    free_symbolizer();
    return err < 0 ? -err : 0;
}