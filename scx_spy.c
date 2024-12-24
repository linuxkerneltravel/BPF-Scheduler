#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/select.h>
#include <unistd.h> 
#include <errno.h>
#include <asm/unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <assert.h>
#include <libgen.h>
#include <inttypes.h>

#include <inttypes.h>
#include <libgen.h>
#include <scx/common.h>


#include "env.h"
#include "proc_data.h"
#include "cpu_event.h"
#include "io_event.h"
#include "net_event.h"
#include "mm_event.h"
#include "blazesym.h"
#include "scx_nest.h"

#include "cpu_stats.skel.h"
#include "io_stats.skel.h"
#include "mm_stats.skel.h"
#include "mm_leak.skel.h"
#include "net_stats.skel.h"
#include "scx_nest.skel.h"


/*----------------------共同部分---------------------------------*/
static struct env env_data = {
	.interval = 1,
    .cpu_data = false,
    .io_data = false,
    .mm_data = false,
    .net_data = false,
    .visualize = false,
    .std_output = true,
    .sched_ext = false
};

#define MAX_CSV_FILES 10
static char csv_folder_path[MAX_PATH_LEN];

static char visualize_proc_path[MAX_PATH_LEN];// 把不适合放到promthes的都放到这个文件夹

volatile sig_atomic_t stop = 0;

static time_t boot_time; // 系统启动时间

static u32 zero = 0;
static u32 one = 1;
static int create_perf_event(u32 period_ms);
static struct bpf_link* attach_perf_event_to_program(struct bpf_program *prog, u32 period_ms);

static int init_time();// 初始化系统当前时间
static int get_proc_path();
static error_t parse_arg(int key, char *arg, struct argp_state *state);

static const struct argp argp = {
    argp_options,
    parse_arg,
    NULL,
    argp_args_doc
};

// 信号处理函数，用于优雅地退出程序
void handle_sigint(int sig) {
    stop = 1;
}

/*-----------------------------------sched_ext部分--------------------------------*/
// 

#define SAMPLING_CADENCE_S 2

struct scx_nest_bpf *scx_skel = NULL;
struct bpf_link *scx_link = NULL;
struct bpf_link *link_to_cpu_mask = NULL;
struct ring_buffer *rb_cpu_mask = NULL;
u64 ecode;

int cores = 0;// 核心数

const char ignore_file[] = "./ignore.txt"; // 小心scx_nest误伤的任务
const char attention_file[] = "./attention.txt";// 要去特别注意的任务

const char *sched_txt_names[] = {
        "active_nests",
        "nest_stats",
    };

FILE *sched_txt_files[MAX_CSV_FILES];

static bool verbose;
static u32 slow_weight = 3;
static u32 slow_count = 0;

static struct scx_env sched_env = {
    .p_remove_ns = 2000 * 1000,  // 默认 2000us 转换为纳秒  3000(当前最佳)
    .r_max = 5,                  // 默认最大备用核心数  8(当前最佳)
    .r_impatient = 2,            // 默认失败次数     4(当前最佳)
    .slice_ns = 20000 * 1000,    // 默认时间片 20000us 转换为纳秒
    .find_fully_idle = false,    // 默认不查找完全空闲核心
    .verbose = false,            // 默认关闭调试信息
};

struct nest_stat {
        const char *label;
        enum nest_stat_group group;
        enum nest_stat_idx idx;
};

static int scx_libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);

#define NEST_ST(__stat, __grp, __desc) {	\
	.label = #__stat,		\
	.group = __grp,			\
	.idx = NEST_STAT(__stat)		\
},
static struct nest_stat nest_stats[NEST_STAT(NR)] = {
#include "scx_nest_stats_table.h"
};
#undef NEST_ST

static void scx_read_stats(struct scx_nest_bpf *skel, u64 *stats);
static void print_underline(const char *str);
static void scx_print_stat_grp(enum nest_stat_group grp);
static void print_active_nests(const struct scx_nest_bpf *skel);

static int attach_scx_skel(struct scx_nest_bpf *skel);
static int scx_operation();
static void scx_resource_clean();

static int handle_usr_cpu_mask_event(void *ctx, void *data, size_t data_sz);

static int sched_create_txt();

/*----------------------网络部分----------------------------------*/
// 和可视化有关的
const char *net_csv_names[] = {
        "net_latency.csv",
        "tcprtt.csv",
        "tcptop.csv",
        "tcpretrans.csv"
    };

FILE *net_csv_files[MAX_CSV_FILES];

struct ring_buffer *rb_net_latency = NULL;
struct ring_buffer *rb_tcprtt = NULL;
struct ring_buffer *rb_tcptop = NULL;
struct ring_buffer *rb_tcpretrans = NULL;
struct net_stats_bpf *net_skel = NULL;
struct sysinfo sys_data;
struct bpf_link *link_to_tcprtt = NULL;

static int net_create_csv();

static int handle_net_latency_event(void *ctx, void *data, size_t data_sz);
static int handle_usr_tcprtt_event(void *ctx, void *data, size_t data_sz);
static int handle_usr_tcptop_event(void *ctx, void *data, size_t data_sz);
static int handle_usr_tcpretrans_event(void *ctx, void *data, size_t data_sz);
static bool fentry_try_attach(int id);
static bool fentry_can_attach(const char* name, const char* mod);
static int attach_net_skel(struct net_stats_bpf *skel);
void net_resource_clean();
static int net_ring_buffer_poll();

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_MAX_STATES = 13,
};


/*--------------------------io部分-----------------------------------*/
#define MAX_IO_RESULTS 256
struct ring_buffer *rb_io_task_stats, *rb_io_process_stats, *rb_io_wait;
struct io_stats_bpf *io_skel = NULL;
struct bpf_link *link_io_wait = NULL;
DiskStatsContext* context = NULL;
DiskStats current[MAX_DEVICES];

// 和可视化有关的
const char *io_csv_names[] = {
        "io_task_stats.csv",
        "io_process_stats.csv",
        "iowait_perf.csv",
    };

FILE *io_csv_files[MAX_CSV_FILES];

static int io_create_csv();

static int handle_io_task_stats_event(void *ctx,void *data, size_t data_sz);
static int handle_io_process_stats_event(void *ctx,void *data, size_t data_sz);
static int handle_iowait_perf_event(void *ctx,void *data, size_t data_sz);
static int attach_io_skel(struct io_stats_bpf *skel);
int io_initialize_monitoring(unsigned int interval);
static void io_resource_clean();
static int io_ring_buffer_poll();


/*----------------------------mm部分--------------------------------------*/
static u64 trace_pid = 0;
int leak_allocs_fd;
int leak_stack_traces_fd;

FILE *mm_file = NULL;

// 和可视化有关的
const char *mm_csv_names[] = {
        "oom_event.csv",
        "task_mm_stats.csv",
        "process_mm_stats.csv",
    };

const char mm_stack[] = "mm_alloc";
FILE *mm_alloc_stack = NULL;

int get_mm_txt();

FILE *mm_csv_files[MAX_CSV_FILES];
static int mm_create_csv();

static struct blaze_symbolizer *mm_symbolizer;
static struct allocation *allocs;
struct ring_buffer *rb_oom, *rb_task_mm, *rb_process_mm;

struct mm_leak_bpf *leak_skel = NULL;
struct mm_stats_bpf *mm_skel = NULL;

static u64 *stack;

static int attach_leak_uprobes(struct mm_leak_bpf *skel);
static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd);
static int print_stack_frames(struct allocation *allocs, u64 nr_allocs, int stack_traces_fd);

static int handle_oom_event(void *ctx,void *data, size_t data_sz);
static int handle_task_mm_stats_event(void *ctx,void *data, size_t data_sz);
static int handle_process_mm_stats_event(void *ctx,void *data, size_t data_sz);


static int attach_leak_skel(struct mm_leak_bpf *skel);
static int attach_mm_stats_skel(struct mm_stats_bpf *skel);
static int mm_ring_buffer_poll();
static void mm_resource_clean();


/*---------------------------cpu部分---------------------------------------*/
struct ring_buffer *rb_cpu = NULL;
struct ring_buffer *rb_task = NULL;
struct ring_buffer *rb_process = NULL;
struct ring_buffer *rb_runqlat = NULL;
struct ring_buffer *rb_backtrace = NULL;
struct cpu_stats_bpf *cpu_skel = NULL;

const char *cpu_csv_names[] = {
        "cpu_usage.csv",
        "task_usage.csv",
        "process_stat.csv",
        "runqlat.csv",
    };

const char cpu_stack[] = "task_backtrace";
FILE *cpu_task_stack = NULL;

int get_cpu_txt();

FILE *cpu_csv_files[MAX_CSV_FILES];
static int cpu_create_csv();

static struct blaze_symbolizer *cpu_symbolizer;
static int init_cpu_symbolizer();
static void free_cpu_symbolizer();

static void cpu_print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info);
static void cpu_show_stack_trace(uint64_t *stack, int stack_sz, pid_t pid);
static int handle_usr_task_cpu_backtrace_event(void *ctx,void *data, size_t data_sz);
static int handle_cpu_usage_event(void *ctx,void *data, size_t data_sz);
static int handle_usr_task_usage_event(void *ctx,void *data, size_t data_sz);
static int handle_use_process_stat_event(void *ctx,void *data, size_t data_sz);
static int handle_usr_runqlat_event(void *ctx,void *data, size_t data_sz);

static int attach_cpu_skel();
static int cpu_ring_buffer_poll();
static void cpu_resource_clean();



int main(int argc, char **argv){
    int ret;
    // Parse command line arguments
    argp_parse(&argp, argc, argv, 0, NULL, &env_data);
    //parse_arg(argc, argv, &env_data);
    // 注册信号处理器，捕获Ctrl-C (SIGINT)
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

restart:
    //printf("----------------------------------------\n");
    ret = init_time();
    if(ret != 0)
        goto cleanup;

    ret = get_proc_path();
    if(ret != 0)
        goto cleanup;


    if(env_data.cpu_data){
        if(env_data.visualize){
            ret = cpu_create_csv();
            if(ret != 0)
                goto cleanup;
            ret = get_cpu_txt();
            if(ret != 0)
                goto cleanup;
        }
        ret = attach_cpu_skel();
        if(ret != 0)
            goto cleanup;
    }

    if(env_data.net_data){
        if(env_data.visualize){
            ret = net_create_csv();
            if(ret != 0)
                goto cleanup;
        }
        net_skel = net_stats_bpf__open();
        if(!net_skel){
            fprintf(stderr, "failed to open net_stats skel\n");
		    ret = 1;

		    goto cleanup;
        }

        ret = attach_net_skel(net_skel);
        if(ret != 0)
            goto cleanup;
    }

    if(env_data.io_data){
        if(env_data.visualize){
            ret = io_create_csv();
            if(ret != 0)
                goto cleanup;
        }
        io_skel = io_stats_bpf__open();
        if(!io_skel){
            fprintf(stderr, "failed to open io_stats skel\n");
		    ret = 1;

		    goto cleanup;
        }
        ret = attach_io_skel(io_skel);
        if(ret != 0)
            goto cleanup;
        
        if (io_initialize_monitoring(1) != 0) {
            fprintf(stderr, "Initialization failed.\n");
            ret = 1;
            goto cleanup;
        }
    }

    if(env_data.mm_data){
        mm_file = open_meminfo();
        if(env_data.visualize){
            ret = mm_create_csv();
            if(ret != 0)
                goto cleanup;
            ret = get_mm_txt();
            if(ret != 0)
                goto cleanup;
        }

        leak_skel = mm_leak_bpf__open();
        if(!leak_skel){
            fprintf(stderr, "failed to open mm_leak skel\n");
		    ret = 1;

		    goto cleanup;
        }

	    mm_skel = mm_stats_bpf__open();
	    if(!mm_skel){
		    fprintf(stderr, "failed to open mm_stats skel\n");
		    ret = 1;

		    goto cleanup;
	    }

        ret = attach_leak_skel(leak_skel);
	    if(ret != 0)
		    goto cleanup;
	
	    ret = attach_mm_stats_skel(mm_skel);
	    if(ret != 0)
		    goto cleanup;
    }

    if(env_data.sched_ext){
        if(env_data.visualize){
            ret = sched_create_txt();
            if(ret != 0)
                goto cleanup;
        }
        ret = attach_scx_skel(scx_skel);
        if(ret != 0)
            goto cleanup;
        // if(env_data.visualize){
        //     ret = sched_create_txt();
        //     if(ret != 0)
        //         goto cleanup;
        // }
    }

    while(stop == 0){
        if(env_data.net_data){
            if (monitor_network(env_data.visualize) != 0) {
                fprintf(stderr, "An error occurred during network monitoring.\n");
            }
            ret = net_ring_buffer_poll();
            if(ret != 0)
                goto cleanup;
        }
        if(env_data.io_data){
            ret = io_ring_buffer_poll();
            if(ret != 0)
                goto cleanup;
            if (process_disk_stats(context, current, &context->device_count_prev, 1) != 0) {
                goto cleanup;
            }
        }
        if(env_data.mm_data){
            read_meminfo(mm_file);
            print_outstanding_allocs(leak_allocs_fd,leak_stack_traces_fd);
            ret = mm_ring_buffer_poll();
		    if(ret < 0)
			    goto cleanup;
        }
        if(env_data.cpu_data){
            ret = cpu_ring_buffer_poll();
            if(ret < 0)
			    goto cleanup;
        }

        if(env_data.sched_ext){
            ret = scx_operation();
            if(ret != 0)
                goto cleanup;
        }
    }


cleanup:
    cpu_resource_clean();
    net_resource_clean();
    io_resource_clean();
    mm_resource_clean();
    scx_resource_clean();

    if(scx_skel && UEI_ECODE_RESTART(ecode))
        goto restart;

    return ret;
}


/*-----------------------------共同部分---------------------------------------*/
static int get_proc_path() {
    // 获取当前工作目录
    if (getcwd(visualize_proc_path, sizeof(visualize_proc_path)) == NULL) {
        perror("getcwd failed");
        return 1;
    }

    // 拼接 "visualize/proc" 文件夹到路径
    strncat(visualize_proc_path, "/visualize/proc", sizeof(visualize_proc_path) - strlen(visualize_proc_path) - 1);

    // 检查 "visualize/proc" 文件夹是否存在
    struct stat st;
    if (stat(visualize_proc_path, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Error: %s exists but is not a directory\n", visualize_proc_path);
            return 1;
        }
    } else {
        // 文件夹不存在，尝试创建
        if (mkdir(visualize_proc_path, 0755) != 0) {
            perror("mkdir failed");
            return 1;
        }
    }

    return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    struct env *env = state->input;

    switch (key) {
    case 'i':  // Set interval
        env->interval = atoi(arg);
        break;
    case 'c':  // Enable CPU monitoring
        env->cpu_data = true;
        break;
    case 'I':  // Enable IO monitoring
        env->io_data = true;
        break;
    case 'm':  // Enable memory monitoring
        env->mm_data = true;
        break;
    case 'n':  // Enable network monitoring
        env->net_data = true;
        break;
    case 'v':  // Enable visualization
        env->visualize = true;
        break;
    case 's':  // Output to stdout
        env->std_output = true;
        break;
    case 'e': // sched_ext
        env->sched_ext = true;
        // 如果启用了 sched_ext，则进入交互模式
        interactive_sched_ext_config(&sched_env);
        break;
    case ARGP_KEY_ARG:
    case ARGP_KEY_END:
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
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

static int init_time(){

    if(sysinfo(&sys_data) != 0){
        perror("sysinfo get failed\n");
        return 1;
    }

    time_t now = time(NULL);
    if (now == ((time_t) -1)) {
        perror("current time get failed\n");
        return 1;
    }

    boot_time = now - sys_data.uptime;

    return 0;
}

/*-----------------------------------------sched_ext部分------------------------------*/
// 函数：将任务名加载到 eBPF Map 中
int load_tasks_name_to_map(const char *filename, int map_fd) {
    // int map_fd = bpf_map__fd(scx_skel->maps.comm_ignore_map);
    // if(map_fd < 0){
    //     fprintf(stderr, "Failed to get comm_ignore_map map fd\n");
    //     return -1;
    // }
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open ignore.txt");
        return -1;
    }

    char line[256]; // 用于存储每行数据
    struct comm_info task_key;
    u32 value = 0; // 值，用于标志该任务需要被忽略
    int line_count = 0;

    while (fgets(line, sizeof(line), file)) {
        // 移除行末的换行符
        line[strcspn(line, "\n")] = '\0';

        // 初始化任务名结构体
        memset(&task_key, 0, sizeof(task_key));

        // 如果任务名超出 16 字节，则截断
        if (strlen(line) >= sizeof(task_key.comm)) {
            fprintf(stderr, "Task name '%s' exceeds 16 characters, truncating.\n", line);
            strncpy(task_key.comm, line, sizeof(task_key.comm) - 1);
        } else {
            strncpy(task_key.comm, line, sizeof(task_key.comm) - 1);
        }

        // 将任务名存入 eBPF Map
        if (bpf_map_update_elem(map_fd, &task_key, &value, BPF_ANY) < 0) {
            perror("Failed to update comm_ignore_map");
            fclose(file);
            return -1;
        }

        line_count++;
    }

    fclose(file);
    printf("Successfully loaded %d tasks into comm_ignore_map.\n", line_count);
    return 0;
}

static int sched_create_txt() {
    int ret;
    int num_txt_names = sizeof(sched_txt_names) / sizeof(sched_txt_names[0]);
    
    for(int i=0;i<MAX_CSV_FILES;i++)
        sched_txt_files[i] = NULL;

    for(int i=0;i<num_txt_names;i++){
        if(lookup_txt_file(visualize_proc_path,sched_txt_names[i],&sched_txt_files[i]) != 0){
            fprintf(stderr, "Failed to create %s\n", sched_txt_names[i]);
            return -1;
        }
    }
    
    return 0;
}

static int handle_usr_cpu_mask_event(void *ctx, void *data, size_t data_sz){
    struct cpu_mask_data *mask_data = data;
    bool visual = env_data.visualize && sched_txt_files[0];
    int idx, cpu;
    char cpus[cores + 1];

    if(visual){
        fprintf(sched_txt_files[0], "Masks\n");
        fprintf(sched_txt_files[0], "----------------------------------------\n");
    }

	print_underline("Masks");
	for (idx = 0; idx < 4; idx++) {
		const char *mask_str;
		u64 mask, total = 0;

		memset(cpus, '-', cores);
		if (idx == 0) {
			mask_str = "PRIMARY";
			mask = mask_data->stats_primary_mask;
		} else if (idx == 1) {
			mask_str = "RESERVED";
			mask = mask_data->stats_reserved_mask;
		} else if (idx == 2) {
			mask_str = "OTHER";
			mask = mask_data->stats_other_mask;
		} else {
			mask_str = "IDLE";
			mask = mask_data->stats_idle_mask;
		}
		for (cpu = 0; cpu < cores; cpu++) {
			if (mask & (1ULL << cpu)) {
				cpus[cpu] = '*';
				total++;
			}
		}
		printf("%-9s(%2" PRIu64 "): | %s |\n", mask_str, total, cpus);

        if(visual){
            fprintf(sched_txt_files[0], "%-9s(%2" PRIu64 "): | %s |\n", mask_str, total, cpus);
        }
	}

    if(visual){
        fflush(sched_txt_files[0]);
    }
}

static int attach_scx_skel()
{
    libbpf_set_print(scx_libbpf_print_fn);
    scx_skel = SCX_OPS_OPEN(nest_ops, scx_nest_bpf);
    if (!scx_skel) {
        fprintf(stderr, "Failed to open SCX skeleton.\n");
        return -1;
    }

    //int cores = 0;
    if(cores == 0)
    {
        FILE *fp = popen("grep -c '^processor' /proc/cpuinfo", "r");
        if (fp) {
            fscanf(fp, "%d", &cores);
            pclose(fp);
        }
    }
    // 初始化只读数据
    //scx_skel->rodata->nr_cpus = libbpf_num_possible_cpus();
    scx_skel->rodata->nr_cpus = cores;
    scx_skel->rodata->sampling_cadence_ns = SAMPLING_CADENCE_S * 1000 * 1000 * 1000;
    scx_skel->rodata->p_remove_ns = sched_env.p_remove_ns;
    scx_skel->rodata->r_max = sched_env.r_max;
    scx_skel->rodata->r_impatient = sched_env.r_impatient;
    scx_skel->rodata->slice_ns = sched_env.slice_ns;
    scx_skel->rodata->find_fully_idle = sched_env.find_fully_idle;

    SCX_OPS_LOAD(scx_skel, nest_ops, scx_nest_bpf, uei);

    if(cpu_skel != NULL){
        int cpu_fd = bpf_map__fd(cpu_skel->maps.thread_occupied_map);
        if(cpu_fd < 0){
            fprintf(stderr, "Failed to get thread_occupied_map map fd\n");
            return -1;
        }
        int scx_fd;
        struct bpf_map *map = bpf_object__find_map_by_name(scx_skel->obj, "cpu_filter_ids");
        if (!map) {
            fprintf(stderr, "Failed to find cpu_filter_ids map\n");
            return -1;
        }
        scx_fd = bpf_map__fd(map);
        if(scx_fd < 0){
            fprintf(stderr, "Failed to get cpu_filter_ids map fd\n");
            return -1;
        }

        int ret = bpf_map_update_elem(scx_fd, &zero, &cpu_fd, BPF_ANY);
        if(ret < 0){
            fprintf(stderr, "Failed to update cpu_filter_ids map\n");
            return -1;
        }

        scx_fd = bpf_map__fd(scx_skel->maps.cpu_task_usage_map);
        if(scx_fd < 0){
            fprintf(stderr, "Failed to get cpu_task_usage_map map fd\n");
            return -1;
        }
        cpu_fd = bpf_map__fd(cpu_skel->maps.task_cpu_usage_map);
        if(cpu_fd < 0){
            fprintf(stderr, "Failed to get task_cpu_usage_map map fd\n");
            return -1;
        }
        ret = bpf_map_update_elem(scx_fd, &zero, &cpu_fd, BPF_ANY);
        if(ret < 0){
            fprintf(stderr, "Failed to update cpu_task_usage_map map\n");
            return -1;
        }
    }
    
    int map_fd = bpf_map__fd(scx_skel->maps.comm_ignore_map);
    if(map_fd < 0){
        fprintf(stderr, "Failed to get comm_ignore_map map fd\n");
        return -1;
    }
    int ret = load_tasks_name_to_map(ignore_file, map_fd);
    if(ret < 0){
        fprintf(stderr, "Failed to load tasks name to comm_ignore_map\n");
        return -1;
    }
    map_fd = bpf_map__fd(scx_skel->maps.comm_attention_map);
    if(map_fd < 0){
        fprintf(stderr, "Failed to get comm_attention_map map fd\n");
        return -1;
    }
    ret = load_tasks_name_to_map(attention_file, map_fd);
    if(ret < 0){
        fprintf(stderr, "Failed to load tasks name to comm_attention_map\n");
        return -1;
    }

    link_to_cpu_mask = attach_perf_event_to_program(scx_skel->progs.handle_cpu_mask_event,1000);
    if(!link_to_cpu_mask){
        return -1;
    }
    scx_skel->links.handle_cpu_mask_event = link_to_cpu_mask;

    rb_cpu_mask = ring_buffer__new(bpf_map__fd(scx_skel->maps.cpu_mask_buffer),handle_usr_cpu_mask_event,NULL,NULL);

    scx_link = SCX_OPS_ATTACH(scx_skel, nest_ops, scx_nest_bpf);

    return 0;
}

static void scx_resource_clean()
{
    if(scx_link)
        bpf_link__destroy(scx_link);
    if(scx_skel)
    {
        ecode = UEI_REPORT(scx_skel, uei);
        scx_nest_bpf__destroy(scx_skel);
    }
    if(rb_cpu_mask)
        ring_buffer__free(rb_cpu_mask);
    for(int i=0;i<MAX_CSV_FILES;i++){
        if(sched_txt_files[i])
            fclose(sched_txt_files[i]);
        else   
            break;
    }
}

static int scx_operation()
{
    u64 stats[NEST_STAT(NR)];
    enum nest_stat_idx i;
    enum nest_stat_group last_grp = -1;

    if(slow_count < slow_weight){
        slow_count++;
    }
    else{
        bool visual = env_data.visualize && sched_txt_files[1];
        if(visual)
            fprintf(sched_txt_files[1], "----------------------------------------");

        scx_read_stats(scx_skel, stats);
        for (i = 0; i < NEST_STAT(NR); i++) {
            struct nest_stat *nest_stat = &nest_stats[i];
            if (nest_stat->group != last_grp) {
                scx_print_stat_grp(nest_stat->group);
                last_grp = nest_stat->group;
            }
            printf("%s=%" PRIu64 "\n", nest_stat->label, stats[nest_stat->idx]);
            if(visual)
                fprintf(sched_txt_files[1], "%s=%" PRIu64 "\n", nest_stat->label, stats[nest_stat->idx]);

        }
        printf("\n");
        if(visual)
        {
            fprintf(sched_txt_files[1], "\n");
            fflush(sched_txt_files[1]);
        }
        slow_count = 0;
    }

    // print_active_nests(scx_skel);
    int ret = ring_buffer__poll(rb_cpu_mask, 100);
    if(ret < 0)
        return -1;

    printf("\n");
    fflush(stdout);
}

static int scx_libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void scx_read_stats(struct scx_nest_bpf *skel, u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	u64 cnts[NEST_STAT(NR)][nr_cpus];
	u32 idx;

	memset(stats, 0, sizeof(stats[0]) * NEST_STAT(NR));

	for (idx = 0; idx < NEST_STAT(NR); idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

static void print_underline(const char *str)
{
	char buf[64];
	size_t len;

	len = strlen(str);
	memset(buf, '-', len);
	buf[len] = '\0';
	printf("\n\n%s\n%s\n", str, buf);
}

static void scx_print_stat_grp(enum nest_stat_group grp)
{
	const char *group;

	switch (grp) {
		case STAT_GRP_WAKEUP:
			group = "Wakeup stats";
			break;
		case STAT_GRP_NEST:
			group = "Nest stats";
			break;
		case STAT_GRP_CONSUME:
			group = "Consume stats";
			break;
		default:
			group = "Unknown stats";
			break;
	}

	print_underline(group);
}

static void print_active_nests(const struct scx_nest_bpf *skel)
{
	u64 primary = skel->bss->stats_primary_mask;
	u64 reserved = skel->bss->stats_reserved_mask;
	u64 other = skel->bss->stats_other_mask;
	u64 idle = skel->bss->stats_idle_mask;
	u32 nr_cpus = skel->rodata->nr_cpus, cpu;
	int idx;
	char cpus[nr_cpus + 1];

	memset(cpus, 0, nr_cpus + 1);

    bool visual = env_data.visualize && sched_txt_files[0];
    // bool visual = false;

    if(visual){
        fprintf(sched_txt_files[0], "Masks\n");
        fprintf(sched_txt_files[0], "----------------------------------------\n");
    }

	print_underline("Masks");
	for (idx = 0; idx < 4; idx++) {
		const char *mask_str;
		u64 mask, total = 0;

		memset(cpus, '-', nr_cpus);
		if (idx == 0) {
			mask_str = "PRIMARY";
			mask = primary;
		} else if (idx == 1) {
			mask_str = "RESERVED";
			mask = reserved;
		} else if (idx == 2) {
			mask_str = "OTHER";
			mask = other;
		} else {
			mask_str = "IDLE";
			mask = idle;
		}
		for (cpu = 0; cpu < nr_cpus; cpu++) {
			if (mask & (1ULL << cpu)) {
				cpus[cpu] = '*';
				total++;
			}
		}
		printf("%-9s(%2" PRIu64 "): | %s |\n", mask_str, total, cpus);

        if(visual){
            fprintf(sched_txt_files[0], "%-9s(%2" PRIu64 "): | %s |\n", mask_str, total, cpus);
        }
	}

    if(visual){
        fflush(sched_txt_files[0]);
    }
}



/*-----------------------------------------网络部分----------------------------------*/
static int net_create_csv(){
    int ret;
    int num_csv_names = sizeof(net_csv_names) / sizeof(net_csv_names[0]);
    
    for(int i=0;i<MAX_CSV_FILES;i++)
        net_csv_files[i] = NULL;
    
    // 获取当前工作目录
    if (getcwd(csv_folder_path, sizeof(csv_folder_path)) == NULL) {
        perror("getcwd failed");
        return 1;
    }

    // 调用 visual_create_run_file 函数
    if (visual_create_run_file(csv_folder_path, net_csv_names, num_csv_names, net_csv_files) != 0) {
        fprintf(stderr, "Failed to create run folder and CSV files\n");
        return 1;
    }
    
    return 0;
}

static int attach_net_skel(struct net_stats_bpf *skel){
    int ret;

    if (fentry_can_attach("tcp_v4_connect", NULL)) {
        bpf_program__set_attach_target(skel->progs.fentry_tcp_v4_connect,0,"tcp_v4_connect");
        bpf_program__set_attach_target(skel->progs.fentry_tcp_v6_connect,0,"tcp_v6_connect");
        bpf_program__set_attach_target(skel->progs.fentry_tcp_rcv_state_process,0,"tcp_rcv_state_process");

        bpf_program__set_autoload(skel->progs.fentry_tcp_v4_connect,false);
        bpf_program__set_autoload(skel->progs.fentry_tcp_v6_connect,false);
        bpf_program__set_autoload(skel->progs.fentry_tcp_rcv_state_process,false);
    }
    else{
        bpf_program__set_autoload(skel->progs.fentry_tcp_v4_connect,false);
        bpf_program__set_autoload(skel->progs.fentry_tcp_v6_connect,false);
        bpf_program__set_autoload(skel->progs.fentry_tcp_rcv_state_process,false);
    }

    ret = net_stats_bpf__load(skel);
    if(ret){
        fprintf(stderr, "failed to load net_stats skel\n");
        return ret;
    }

    ret = net_stats_bpf__attach(skel);
    if(ret){
        fprintf(stderr, "failed to attach net_stats bpf program(s)\n");

		return ret;
    }

    link_to_tcprtt = attach_perf_event_to_program(skel->progs.handle_tcprtt_event,500);
    if(!link_to_tcprtt){
        return -1;
    }
    skel->links.handle_tcprtt_event = link_to_tcprtt;

    rb_net_latency = ring_buffer__new(bpf_map__fd(skel->maps.net_latency_buffer),handle_net_latency_event,NULL,NULL);
    rb_tcprtt = ring_buffer__new(bpf_map__fd(skel->maps.tcprtt_buffer),handle_usr_tcprtt_event,NULL,NULL);
    rb_tcptop = ring_buffer__new(bpf_map__fd(skel->maps.tcptop_buffer),handle_usr_tcptop_event,NULL,NULL);
    rb_tcpretrans = ring_buffer__new(bpf_map__fd(skel->maps.tcpretrans_buffer),handle_usr_tcpretrans_event,NULL,NULL);

    return 0;
}

static int net_ring_buffer_poll(){
    int ret;
    ret = ring_buffer__poll(rb_net_latency,200);
    if(ret < 0)
    {
        fprintf(stderr, "Error polling net latency ring buffer: %d\n", ret);
        return ret;
    }

    ret = ring_buffer__poll(rb_tcprtt,200);
    if(ret < 0)
    {
        fprintf(stderr, "Error polling tcprtt ring buffer: %d\n", ret);
        return ret;
    }

    ret = ring_buffer__poll(rb_tcptop,200);
    if(ret < 0)
    {
        fprintf(stderr, "Error polling tcptop ring buffer: %d\n", ret);
        return ret;
    }

    ret = ring_buffer__poll(rb_tcpretrans,200);
    if(ret < 0)
    {
        fprintf(stderr, "Error polling tcpretrans ring buffer: %d\n", ret);
        return ret;
    }

    return 0;
}

void net_resource_clean(){
    if(rb_net_latency)
        ring_buffer__free(rb_net_latency);
    if(rb_tcprtt)
        ring_buffer__free(rb_tcprtt);
    if(rb_tcptop)
        ring_buffer__free(rb_tcptop);
    if(rb_tcpretrans)
        ring_buffer__free(rb_tcpretrans);
    
    for(int i=0;i<MAX_CSV_FILES;i++){
        if(net_csv_files[i] != NULL)
            fclose(net_csv_files[i]);
        else   
            break;
    }
    close_proc_net_csv_file();
    net_stats_bpf__destroy(net_skel);
}


static int handle_net_latency_event(void *ctx, void *data, size_t data_sz){
    // 检查数据大小是否符合结构体大小
    if (data_sz < sizeof(struct tcp_net_latency)) {
        fprintf(stderr, "Received data size (%zu) is smaller than expected (%zu)\n", data_sz, sizeof(struct tcp_net_latency));
        return 0; // 返回 0 表示继续处理其他事件
    }

    // 将数据指针转换为结构体指针
    struct tcp_net_latency *event = (struct tcp_net_latency *)data;

    // 定义字符串缓冲区用于存储 IP 地址
    char saddr_str[INET6_ADDRSTRLEN] = {0};
    char daddr_str[INET6_ADDRSTRLEN] = {0};

    // 根据地址族类型转换源地址和目标地址
    if (event->af == AF_INET) {
        // IPv4 地址
        struct in_addr saddr, daddr;
        saddr.s_addr = event->src_addr.saddr_v4;
        daddr.s_addr = event->dst_addr.daddr_v4;

        // 将网络字节序的地址转换为字符串
        if (inet_ntop(AF_INET, &saddr, saddr_str, sizeof(saddr_str)) == NULL) {
            perror("inet_ntop IPv4 source address failed");
            strncpy(saddr_str, "Unknown", sizeof(saddr_str));
        }

        if (inet_ntop(AF_INET, &daddr, daddr_str, sizeof(daddr_str)) == NULL) {
            perror("inet_ntop IPv4 destination address failed");
            strncpy(daddr_str, "Unknown", sizeof(daddr_str));
        }
    }
    else if (event->af == AF_INET6) {
        // IPv6 地址
        if (inet_ntop(AF_INET6, event->src_addr.saddr_v6, saddr_str, sizeof(saddr_str)) == NULL) {
            perror("inet_ntop IPv6 source address failed");
            strncpy(saddr_str, "Unknown", sizeof(saddr_str));
        }

        if (inet_ntop(AF_INET6, event->dst_addr.daddr_v6, daddr_str, sizeof(daddr_str)) == NULL) {
            perror("inet_ntop IPv6 destination address failed");
            strncpy(daddr_str, "Unknown", sizeof(daddr_str));
        }
    }
    else {
        // 未知的地址族
        strncpy(saddr_str, "Unknown AF", sizeof(saddr_str));
        strncpy(daddr_str, "Unknown AF", sizeof(daddr_str));
    }

     // 格式化时间戳
    // 将纳秒转换为秒和纳秒
    time_t relative_sec = event->ts / 1000000000;
    long relative_nsec = event->ts % 1000000000;

    // 计算绝对时间
    time_t absolute_sec = boot_time + relative_sec;
    long absolute_nsec = relative_nsec;

    // 将绝对时间转换为本地时间
    struct tm tm_info;
    if (localtime_r(&absolute_sec, &tm_info) == NULL) {
        perror("localtime_r failed");
        return 0;
    }


    // 格式化时间字符串
    char time_buf[64];
    if (strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info) == 0) {
        fprintf(stderr, "strftime returned 0");
        strncpy(time_buf, "Unknown Time", sizeof(time_buf));
    }

    if(env_data.std_output){
        printf("[%s.%09ld] TGID: %u Comm: %s | TCP Connect Delay: %llu us | %s:%u -> %s:%u\n",
           time_buf,
           absolute_nsec,
           event->tgid,
           event->comm,
           (unsigned long long)event->delta,
           saddr_str,
           ntohs(event->lport),
           daddr_str,
           ntohs(event->dport));
    }

    // 打印事件信息
    // printf("[%s.%09ld] TGID: %u Comm: %s | TCP Connect Delay: %llu us | %s:%u -> %s:%u\n",
    //        time_buf,
    //        absolute_nsec,
    //        event->tgid,
    //        event->comm,
    //        (unsigned long long)event->delta,
    //        saddr_str,
    //        ntohs(event->lport),
    //        daddr_str,
    //        ntohs(event->dport));
    
    // 将事件信息写入 CSV 文件
    if(!env_data.visualize)
        return 0;

    if (!net_csv_files[0]) {
        fprintf(stderr, "net_csv_files[0] is NULL. Cannot write to CSV\n");
        return -1;
    }

    int fd = fileno(net_csv_files[0]);
    if (fd == -1) {
        perror("fileno failed");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat failed");
        return -1;
    }

    if (st.st_size == 0) {
        fprintf(net_csv_files[0], "Timestamp,PID,Comm,Delay_us\n");
        fflush(net_csv_files[0]);
    }

    fprintf(net_csv_files[0], "%s.%09ld,%u,%.16s,%llu\n",
        time_buf,
        absolute_nsec,
        event->tgid,
        event->comm,
        (unsigned long long)event->delta);

    return 0; // 返回 0 表示继续处理其他事件
}

static int handle_usr_tcprtt_event(void *ctx, void *data, size_t data_sz){
    struct tcprtt_perf_data *event = (struct tcprtt_perf_data *)data;

    if(env_data.std_output){
        for(int i=0;i<8;i++){
        switch(i){
            case 0:
                printf("wait less than 1ms: %u\n",event->data[i]);
                continue;
            case 1:
                printf("wait less than 4ms: %u\n",event->data[i]);
                continue;
            case 2:
                printf("wait less than 16ms: %u\n",event->data[i]);
                continue;
            case 3:
                printf("wait less than 32ms: %u\n",event->data[i]);
                continue;
            case 4:
                printf("wait less than 64ms: %u\n",event->data[i]);
                continue;
            case 5:
                printf("wait less than 128ms: %u\n",event->data[i]);
                continue;
            case 6:
                printf("wait less than 256ms: %u\n",event->data[i]);
                continue;
            case 7:
                printf("wait more than 256ms: %u\n",event->data[i]);
                continue;
            default:
                continue;
        }
        }
    }
    printf("\n");

    // 写入到 CSV 文件
    if(!env_data.visualize)
        return 0;
    if (net_csv_files[1]) {
        // 获取文件描述符以检查文件大小
        int fd = fileno(net_csv_files[1]);
        if (fd == -1) {
            perror("fileno failed for net_csv_files[1]");
            return -1;
        }

        struct stat st;
        if (fstat(fd, &st) == -1) {
            perror("fstat failed for net_csv_files[1]");
            return -1;
        }

        // 如果文件为空，写入表头
        if (st.st_size == 0) {
            fprintf(net_csv_files[1],
                    "1ms,4ms,16ms,32ms,64ms,128ms,256ms,256ms+\n");
            fflush(net_csv_files[1]);
        }

        // 写入事件数据
        fprintf(net_csv_files[1], "%u,%u,%u,%u,%u,%u,%u,%u\n",
                event->data[0], event->data[1], event->data[2],
                event->data[3], event->data[4], event->data[5],
                event->data[6], event->data[7]);
    } else {
        fprintf(stderr, "net_csv_files[1] is NULL. Cannot write to CSV\n");
    }


    return 0;
}

static int handle_usr_tcptop_event(void *ctx, void *data, size_t data_sz)
{
    // 检查数据大小是否符合预期
    if (data_sz < sizeof(struct tcp_top_perf_data)) {
        fprintf(stderr, "Received data size (%zu) is smaller than expected (%zu)\n", data_sz, sizeof(struct tcp_top_perf_data));
        return 0;
    }

    // 将数据指针转换为结构体指针
    struct tcp_top_perf_data *event = (struct tcp_top_perf_data *)data;

    // 定义缓冲区用于存储IP地址字符串
    char saddr_str[INET6_ADDRSTRLEN] = {0};
    char daddr_str[INET6_ADDRSTRLEN] = {0};

    // 根据地址族转换源地址
    if (event->af == AF_INET) {
        struct in_addr saddr;
        saddr.s_addr = event->src_addr.saddr_v4;
        if (inet_ntop(AF_INET, &saddr, saddr_str, sizeof(saddr_str)) == NULL) {
            perror("inet_ntop IPv4 source address failed");
            strncpy(saddr_str, "Unknown", sizeof(saddr_str)-1);
            saddr_str[sizeof(saddr_str)-1] = '\0';
        }
    }
    else if (event->af == AF_INET6) {
        if (inet_ntop(AF_INET6, event->src_addr.saddr_v6, saddr_str, sizeof(saddr_str)) == NULL) {
            perror("inet_ntop IPv6 source address failed");
            strncpy(saddr_str, "Unknown", sizeof(saddr_str)-1);
            saddr_str[sizeof(saddr_str)-1] = '\0';
        }
    }
    else {
        strncpy(saddr_str, "Unknown AF", sizeof(saddr_str)-1);
        saddr_str[sizeof(saddr_str)-1] = '\0';
    }

    // 根据地址族转换目标地址
    if (event->af == AF_INET) {
        struct in_addr daddr;
        daddr.s_addr = event->dst_addr.daddr_v4;
        if (inet_ntop(AF_INET, &daddr, daddr_str, sizeof(daddr_str)) == NULL) {
            perror("inet_ntop IPv4 destination address failed");
            strncpy(daddr_str, "Unknown", sizeof(daddr_str)-1);
            daddr_str[sizeof(daddr_str)-1] = '\0';
        }
    }
    else if (event->af == AF_INET6) {
        if (inet_ntop(AF_INET6, event->dst_addr.daddr_v6, daddr_str, sizeof(daddr_str)) == NULL) {
            perror("inet_ntop IPv6 destination address failed");
            strncpy(daddr_str, "Unknown", sizeof(daddr_str)-1);
            daddr_str[sizeof(daddr_str)-1] = '\0';
        }
    }
    else {
        strncpy(daddr_str, "Unknown AF", sizeof(daddr_str)-1);
        daddr_str[sizeof(daddr_str)-1] = '\0';
    }

    // 将端口号从网络字节序转换为主机字节序
    u16 lport = ntohs(event->lport);
    u16 dport = ntohs(event->dport);

    // 获取当前时间戳
    time_t now = time(NULL);
    struct tm tm_info;
    char time_buf[64];
    localtime_r(&now, &tm_info);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    // 打印事件信息
    if(env_data.std_output){
        printf("[%s] PID: %u | Comm: %s | Sent: %llu bytes | Received: %llu bytes | %s:%u -> %s:%u\n",
           time_buf,
           event->pid,
           event->comm,
           (unsigned long long)event->send,
           (unsigned long long)event->recv,
           saddr_str,
           lport,
           daddr_str,
           dport);
    }
    
    if(!env_data.visualize)
        return 0;
    // 写入到 CSV 文件
    if (net_csv_files[2]) {
        // 获取文件描述符以检查文件大小
        int fd = fileno(net_csv_files[2]);
        if (fd == -1) {
            perror("fileno failed for net_csv_files[2]");
            return -1;
        }

        struct stat st;
        if (fstat(fd, &st) == -1) {
            perror("fstat failed for net_csv_files[2]");
            return -1;
        }

        // 如果文件为空，写入表头
        if (st.st_size == 0) {
            // fprintf(net_csv_files[2],
            //         "Timestamp,PID,Comm,Source_IP,Source_Port,Destination_IP,Destination_Port,Sent_Bytes,Received_Bytes\n");
            fprintf(net_csv_files[2],
                    "Timestamp,PID,Comm,Sent_Bytes,Received_Bytes\n");
            fflush(net_csv_files[2]);
        }

        fprintf(net_csv_files[2], "%s,%u,%s,%llu,%llu\n",
                time_buf,
                event->pid,
                event->comm,
                (unsigned long long)event->send,
                (unsigned long long)event->recv);
        
    } else {
        fprintf(stderr, "net_csv_files[2] is NULL. Cannot write to CSV\n");
    }

    return 0;
}

const char* tcp_state_to_string(u64 state) {
    switch (state) {
        case TCP_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_SYN_SENT:
            return "SYN_SENT";
        case TCP_SYN_RECV:
            return "SYN_RECV";
        case TCP_FIN_WAIT1:
            return "FIN_WAIT1";
        case TCP_FIN_WAIT2:
            return "FIN_WAIT2";
        case TCP_TIME_WAIT:
            return "TIME_WAIT";
        case TCP_CLOSE:
            return "CLOSE";
        case TCP_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TCP_LAST_ACK:
            return "LAST_ACK";
        case TCP_LISTEN:
            return "LISTEN";
        case TCP_CLOSING:
            return "CLOSING";
        case TCP_NEW_SYN_RECV:
            return "NEW_SYN_RECV";
        case TCP_MAX_STATES:
            return "MAX_STATES";
        default:
            return "UNKNOWN";
    }
}

static int handle_usr_tcpretrans_event(void *ctx, void *data, size_t data_sz) {
    // 检查数据大小是否符合预期
    if (data_sz < sizeof(struct tcp_resubmit)) {
        fprintf(stderr, "Received data size (%zu) is smaller than expected (%zu)\n", data_sz, sizeof(struct tcp_resubmit));
        return 0;
    }

    // 将数据指针转换为结构体指针
    struct tcp_resubmit *event = (struct tcp_resubmit *)data;

    // 定义缓冲区用于存储IP地址字符串
    char saddr_str[INET6_ADDRSTRLEN] = {0};
    char daddr_str[INET6_ADDRSTRLEN] = {0};

    // 根据地址族转换源地址
    if (event->af == AF_INET) {
        struct in_addr saddr;
        saddr.s_addr = event->src_addr.saddr_v4;
        if (inet_ntop(AF_INET, &saddr, saddr_str, sizeof(saddr_str)) == NULL) {
            perror("inet_ntop IPv4 source address failed");
            strncpy(saddr_str, "Unknown", sizeof(saddr_str)-1);
            saddr_str[sizeof(saddr_str)-1] = '\0';
        }
    }
    else if (event->af == AF_INET6) {
        if (inet_ntop(AF_INET6, event->src_addr.saddr_v6, saddr_str, sizeof(saddr_str)) == NULL) {
            perror("inet_ntop IPv6 source address failed");
            strncpy(saddr_str, "Unknown", sizeof(saddr_str)-1);
            saddr_str[sizeof(saddr_str)-1] = '\0';
        }
    }
    else {
        strncpy(saddr_str, "Unknown AF", sizeof(saddr_str)-1);
        saddr_str[sizeof(saddr_str)-1] = '\0';
    }

    // 根据地址族转换目标地址
    if (event->af == AF_INET) {
        struct in_addr daddr;
        daddr.s_addr = event->dst_addr.daddr_v4;
        if (inet_ntop(AF_INET, &daddr, daddr_str, sizeof(daddr_str)) == NULL) {
            perror("inet_ntop IPv4 destination address failed");
            strncpy(daddr_str, "Unknown", sizeof(daddr_str)-1);
            daddr_str[sizeof(daddr_str)-1] = '\0';
        }
    }
    else if (event->af == AF_INET6) {
        if (inet_ntop(AF_INET6, event->dst_addr.daddr_v6, daddr_str, sizeof(daddr_str)) == NULL) {
            perror("inet_ntop IPv6 destination address failed");
            strncpy(daddr_str, "Unknown", sizeof(daddr_str)-1);
            daddr_str[sizeof(daddr_str)-1] = '\0';
        }
    }
    else {
        strncpy(daddr_str, "Unknown AF", sizeof(daddr_str)-1);
        daddr_str[sizeof(daddr_str)-1] = '\0';
    }

    // 将端口号从网络字节序转换为主机字节序
    u16 lport = ntohs(event->lport);
    u16 dport = ntohs(event->dport);

     // 格式化时间戳
    // 将纳秒转换为秒和纳秒
    time_t relative_sec = event->occur / 1000000000;
    long relative_nsec = event->occur % 1000000000;

    // 计算绝对时间
    time_t absolute_sec = boot_time + relative_sec;
    long absolute_nsec = relative_nsec;

    // 将绝对时间转换为本地时间
    struct tm tm_info;
    if (localtime_r(&absolute_sec, &tm_info) == NULL) {
        perror("localtime_r failed");
        return 0;
    }


    // 格式化时间字符串
    char time_buf[64];
    if (strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info) == 0) {
        fprintf(stderr, "strftime returned 0");
        strncpy(time_buf, "Unknown Time", sizeof(time_buf));
    }

    // 打印事件信息
    if(env_data.std_output){
        printf("[%s] PID: %u | Comm: %s | Seq: %u | State: %s | Event Type: %llu | %s:%u -> %s:%u\n",
           time_buf,
           event->pid,
           event->comm,
           event->seq,
           tcp_state_to_string(event->state),  // 输出状态的字符形式
           event->type,
           saddr_str,
           lport,
           daddr_str,
           dport);
    }
    
    if(!env_data.visualize)
        return 0;
    // 写入到 CSV 文件
    if (net_csv_files[3]) {  // 对应重传事件的 CSV 文件
        int fd = fileno(net_csv_files[3]);
        if (fd == -1) {
            perror("fileno failed for net_csv_files[3]");
            return -1;
        }

        struct stat st;
        if (fstat(fd, &st) == -1) {
            perror("fstat failed for net_csv_files[3]");
            return -1;
        }

        // 如果文件为空，写入表头
        if (st.st_size == 0) {
            // fprintf(net_csv_files[3],
            //         "Timestamp,PID,Comm,Seq,State,Event_Type,Source_IP,Source_Port,Destination_IP,Destination_Port\n");
            fprintf(net_csv_files[3],
                    "Timestamp,PID,Comm,State,Event_Type,Source_IP,Source_Port,Destination_IP,Destination_Port\n");
            fflush(net_csv_files[3]);
        }

        fprintf(net_csv_files[3], "%s.%09ld,%u,%s,%s,%llu,%s,%u,%s,%u\n",
                time_buf,
                absolute_nsec,
                event->pid,
                event->comm,
                tcp_state_to_string(event->state),
                event->type,
                saddr_str,
                lport,
                daddr_str,
                dport);
    } else {
        fprintf(stderr, "net_csv_files[3] is NULL. Cannot write to CSV\n");
    }

    return 0;
}


static bool fentry_try_attach(int id) {
    int prog_fd, attach_fd;
    char error[4096] = {0};
    struct bpf_insn insns[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    LIBBPF_OPTS(bpf_prog_load_opts, opts,
                .expected_attach_type = BPF_TRACE_FENTRY, .attach_btf_id = id,
                .log_buf = error, .log_size = sizeof(error), );

    prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "fentry_attach", "GPL", insns,
                            sizeof(insns) / sizeof(struct bpf_insn), &opts);
    if (prog_fd < 0) {
        fprintf(stderr, "bpf_prog_load failed: %s\n", strerror(errno));
        return false;
    }

    attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
    if (attach_fd < 0) {
        fprintf(stderr, "bpf_raw_tracepoint_open failed: %s\n", strerror(errno));
        close(prog_fd);
        return false;
    }

    close(attach_fd);
    close(prog_fd);
    return true;
}

static bool fentry_can_attach(const char* name, const char* mod) {
    struct btf *btf, *vmlinux_btf, *module_btf = NULL;
    int err, id;

    vmlinux_btf = btf__load_vmlinux_btf();
    err = libbpf_get_error(vmlinux_btf);
    if (err) {
        fprintf(stderr, "Failed to load vmlinux BTF\n");
        return false;
    }

    btf = vmlinux_btf;

    if (mod) {
        module_btf = btf__load_module_btf(mod, vmlinux_btf);
        err = libbpf_get_error(module_btf);
        if (!err)
            btf = module_btf;
        else
            fprintf(stderr, "Failed to load module BTF for module %s\n", mod);
    }

    id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);

    btf__free(module_btf);
    btf__free(vmlinux_btf);

    if (id <= 0) {
        fprintf(stderr, "Function %s not found in BTF\n", name);
        return false;
    }

    return fentry_try_attach(id);
}

/*--------------------------io部分-----------------------------------*/
static int io_create_csv(){
    int ret;
    int num_csv_names = sizeof(io_csv_names) / sizeof(io_csv_names[0]);
    
    for(int i=0;i<MAX_CSV_FILES;i++)
        io_csv_files[i] = NULL;
    
    // 获取当前工作目录
    if (getcwd(csv_folder_path, sizeof(csv_folder_path)) == NULL) {
        perror("getcwd failed");
        return 1;
    }

    // 调用 visual_create_run_file 函数
    if (visual_create_run_file(csv_folder_path, io_csv_names, num_csv_names, io_csv_files) != 0) {
        fprintf(stderr, "Failed to create run folder and CSV files\n");
        return 1;
    }
    
    return 0;
}

static int handle_io_task_stats_event(void *ctx,void *data, size_t data_sz){
    struct io_task_stats *event = (struct io_task_stats *)data;

    if(env_data.std_output){
        printf("  PID: %u\n", event->info.pid);
        printf("  Command: %s\n", event->info.comm);
        printf("  read_count: %u\n", event->read_count);
        printf("  write_count: %u\n", event->write_count);
    }

    if(!env_data.visualize)
        return 0;
    
    // 检查 CSV 文件是否初始化
    if (io_csv_files[0] == NULL) {
        fprintf(stderr, "Error: CSV file not initialized for IO task stats\n");
        return -1;
    }

    // 检查文件是否为空
    struct stat st;
    if (fstat(fileno(io_csv_files[0]), &st) == -1) {
        perror("Error checking file size");
        return -1;
    }

    if (st.st_size == 0) {
        // 文件为空，写入列名
        fprintf(io_csv_files[0], "PID,Command,Read Count,Write Count\n");
        fflush(io_csv_files[0]);
    }

    // 写入数据到 CSV 文件
    fprintf(io_csv_files[0], "%u,%s,%u,%u\n", 
            event->info.pid, 
            event->info.comm, 
            event->read_count, 
            event->write_count);


    return 0;
}

static int handle_io_process_stats_event(void *ctx,void *data, size_t data_sz){
    struct io_process_stats *event = (struct io_process_stats *)data;

    if(env_data.std_output){
        printf("  tgid: %u\n", event->tgid);
        printf("  read_count: %u\n", event->read_count);
        printf("  write_count: %u\n", event->write_count);
    }

    // 如果不需要可视化，直接返回
    if (!env_data.visualize)
        return 0;

    // 检查 CSV 文件是否初始化
    if (io_csv_files[1] == NULL) {
        fprintf(stderr, "Error: CSV file not initialized for IO process stats\n");
        return -1;
    }

    // 检查文件是否为空
    struct stat st;
    if (fstat(fileno(io_csv_files[1]), &st) == -1) {
        perror("Error checking file size");
        return -1;
    }

    if (st.st_size == 0) {
        // 文件为空，写入列名
        fprintf(io_csv_files[1], "TGID,Read Count,Write Count\n");
        fflush(io_csv_files[1]); // 确保数据立即写入文件
    }

    // 写入数据到 CSV 文件
    fprintf(io_csv_files[1], "%u,%u,%u\n", 
            event->tgid, 
            event->read_count, 
            event->write_count);

    return 0;
}

static int handle_iowait_perf_event(void *ctx,void *data, size_t data_sz){
    struct io_wait_perf_data *event = (struct io_wait_perf_data *)data;

    if(env_data.std_output){
        for(int i=0;i<8;i++){
        switch(i)
        {
            case 0:
                printf("wait less than 1us: %u\n",event->count_list[i]);
                continue;
            case 1:
                printf("wait less than 4us: %u\n",event->count_list[i]);
                continue;
            case 2:
                printf("wait less than 16us: %u\n",event->count_list[i]);
                continue;
            case 3:
                printf("wait less than 64us: %u\n",event->count_list[i]);
                continue;
            case 4:
                printf("wait less than 256us: %u\n",event->count_list[i]);
                continue;
            case 5:
                printf("wait less than 1ms: %u\n",event->count_list[i]);
                continue;
            case 6:
                printf("wait less than 4ms: %u\n",event->count_list[i]);
                continue;
            case 7:
                printf("wait large than 4ms: %u\n",event->count_list[i]);
                continue;
            default:
                continue;
            }
        }
    }

    // 如果不需要可视化，直接返回
    if (!env_data.visualize)
        return 0;

    // 检查 CSV 文件是否初始化
    if (io_csv_files[2] == NULL) {
        fprintf(stderr, "Error: CSV file not initialized for IO wait perf stats\n");
        return -1;
    }

    // 检查文件是否为空
    struct stat st;
    if (fstat(fileno(io_csv_files[2]), &st) == -1) {
        perror("Error checking file size");
        return -1;
    }

    if (st.st_size == 0) {
        // 文件为空，写入列名
        fprintf(io_csv_files[2], "1us,4us,16us,64us,256us,1ms,4ms,4ms+\n");
        fflush(io_csv_files[2]); // 确保数据立即写入文件
    }

    // 写入数据到 CSV 文件
    fprintf(io_csv_files[2], "%u,%u,%u,%u,%u,%u,%u,%u\n",
            event->count_list[0], 
            event->count_list[1], 
            event->count_list[2], 
            event->count_list[3], 
            event->count_list[4], 
            event->count_list[5], 
            event->count_list[6], 
            event->count_list[7]);
    

    return 0;
}

unsigned int io_parse_arguments(int argc, char *argv[]) {
    unsigned int interval = 1; // 默认1秒
    if (argc == 2) {
        interval = atoi(argv[1]);
        if (interval == 0) {
            fprintf(stderr, "Invalid interval. Using default 1 second.\n");
            interval = 1;
        }
    }
    return interval;
}

int io_initialize_monitoring(unsigned int interval) {
    // 初始化上下文
    context = diskstats_init();
    if (!context) {
        fprintf(stderr, "Failed to initialize DiskStatsContext.\n");
        return -1;
    }

    // 读取初始统计数据
    int device_count_prev = diskstats_read(context, current, MAX_DEVICES);
    if (device_count_prev < 0) {
        fprintf(stderr, "Failed to read /proc/diskstats.\n");
        diskstats_cleanup(context);
        return -1;
    }

    context->device_count_prev = device_count_prev;
    return 0;
}

static void io_resource_clean(){
    if(rb_io_task_stats)
        ring_buffer__free(rb_io_task_stats);
    if(rb_io_process_stats)
        ring_buffer__free(rb_io_process_stats);
    if(rb_io_wait)
        ring_buffer__free(rb_io_wait);
    
    if(context){
        diskstats_cleanup(context);
    }

    for(int i=0;i<MAX_CSV_FILES;i++){
        if(io_csv_files[i] != NULL)
            fclose(io_csv_files[i]);
        else   
            break;
    }

    io_stats_bpf__destroy(io_skel);
}

static int io_ring_buffer_poll(){
    int ret;
    ret = ring_buffer__poll(rb_io_task_stats,200);
    if(ret<0)
    {
        fprintf(stderr, "Error polling io task stat ring buffer: %d\n", ret);
        return ret;
    }
    ret = ring_buffer__poll(rb_io_process_stats,200);
    if(ret < 0)
    {
        fprintf(stderr, "Error polling io process stat ring buffer: %d\n", ret);
        return ret;
    }
    ret = ring_buffer__poll(rb_io_wait,600);
    if(ret<0)
    {
        fprintf(stderr, "Error polling io wait ring buffer: %d\n", ret);
        return ret;
    }

    return 0;
}

static int attach_io_skel(struct io_stats_bpf *skel){
    int ret;

    ret = io_stats_bpf__load(skel);
    if(ret){
        fprintf(stderr, "failed to load io_stats skel\n");
        return ret;
    }

    ret = io_stats_bpf__attach(skel);
    if(ret){
        fprintf(stderr, "failed to attach io_stats bpf program(s)\n");

		return -1;
    }

    link_io_wait = attach_perf_event_to_program(skel->progs.handle_io_wait_event,500);
    if(!link_io_wait){
        return -1;
    }
    skel->links.handle_io_wait_event = link_io_wait;

    rb_io_task_stats = ring_buffer__new(bpf_map__fd(skel->maps.io_task_stats_buffer),handle_io_task_stats_event,NULL,NULL);
    rb_io_process_stats = ring_buffer__new(bpf_map__fd(skel->maps.io_process_stats_buffer),handle_io_process_stats_event,NULL,NULL);
    rb_io_wait = ring_buffer__new(bpf_map__fd(skel->maps.io_wait_buffer),handle_iowait_perf_event,NULL,NULL);

    int threhold_fd = bpf_map__fd(skel->maps.io_threhold_map);
    struct io_stats_threhold task = {
        .read_count = 50,
        .write_count = 50,
        .time_window = (1000 * MSEC)
    };
    struct io_stats_threhold process = {
        .read_count = 100,
        .write_count = 100,
        .time_window = (1000 * MSEC)
    };

    if(bpf_map_update_elem(threhold_fd,&zero,&task,BPF_ANY) != 0){
        printf("io_threhold map update error\n");
        return -1;
    }

    if(bpf_map_update_elem(threhold_fd,&one,&process,BPF_ANY) != 0){
        printf("io_threhold map update error\n");
        return -1;
    }

    return 0;
}

/*----------------------------mm部分--------------------------------------*/
static int mm_create_csv(){
    int ret;
    int num_csv_names = sizeof(mm_csv_names) / sizeof(mm_csv_names[0]);
    
    for(int i=0;i<MAX_CSV_FILES;i++)
        mm_csv_files[i] = NULL;
    
    // 获取当前工作目录
    if (getcwd(csv_folder_path, sizeof(csv_folder_path)) == NULL) {
        perror("getcwd failed");
        return 1;
    }

    // 调用 visual_create_run_file 函数
    if (visual_create_run_file(csv_folder_path, mm_csv_names, num_csv_names, mm_csv_files) != 0) {
        fprintf(stderr, "Failed to create run folder and CSV files\n");
        return 1;
    }
    
    return 0;
}

int get_mm_txt(){
    if(lookup_txt_file(visualize_proc_path,mm_stack,&mm_alloc_stack) != 0){
        fprintf(stderr, "Failed to open or create file\n");
        return 1;
    }
    return 0;
}

static int handle_oom_event(void *ctx,void *data, size_t data_sz){
	struct oom_event *event = (struct oom_event *)data;

	// 将时间戳转换为可读格式
    time_t kill_time_sec = event->kill_time / 1000000000;
    long kill_time_nsec = event->kill_time % 1000000000;

	struct tm *tm_info = localtime(&kill_time_sec);
    char time_buffer[64];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

	if(env_data.std_output){
        printf("[%s.%09ld] OOM Event:\n", time_buffer, kill_time_nsec);
        printf("  Trigger PID: %u\n", event->trigger_id);
        printf("  Killed PID: %u\n", event->killed_id);
        printf("  Command: %s\n", event->comm);
        printf("  Kill Time: %llu ns\n\n", event->kill_time);
    }

    // 如果不需要可视化，直接返回
    if (!env_data.visualize)
        return 0;

    // 检查 CSV 文件是否初始化
    if (mm_csv_files[0] == NULL) {
        fprintf(stderr, "Error: CSV file not initialized for OOM events\n");
        return -1;
    }

    // 检查文件是否为空
    struct stat st;
    if (fstat(fileno(mm_csv_files[0]), &st) == -1) {
        perror("Error checking file size");
        return -1;
    }

    if (st.st_size == 0) {
        // 文件为空，写入列名
        fprintf(mm_csv_files[0], "Timestamp,Trigger PID,Killed PID,Command,Kill Time (ns)\n");
        fflush(mm_csv_files[0]); // 确保数据立即写入文件
    }

    // 写入数据到 CSV 文件
    fprintf(mm_csv_files[0], "%s.%09ld,%u,%u,%s,%llu\n",
            time_buffer,
            kill_time_nsec,
            event->trigger_id,
            event->killed_id,
            event->comm,
            event->kill_time);

    return 0;
}

static int handle_task_mm_stats_event(void *ctx,void *data, size_t data_sz){
	struct task_mm_stats *event = (struct task_mm_stats *)data;

    if(env_data.std_output){
        printf("  PID: %u\n", event->info.pid);
        printf("  Command: %s\n", event->info.comm);
        printf("  kmem_count: %u\n", event->kmem_count);
        printf("  vmem_count: %u\n", event->vmem_count);
        printf("  slab_count: %u\n\n", event->slab_count);
    }

     // 如果不需要可视化，直接返回
    if (!env_data.visualize)
        return 0;

    // 检查 CSV 文件是否初始化
    if (mm_csv_files[1] == NULL) {
        fprintf(stderr, "Error: CSV file not initialized for task MM stats\n");
        return -1;
    }

    // 检查文件是否为空
    struct stat st;
    if (fstat(fileno(mm_csv_files[1]), &st) == -1) {
        perror("Error checking file size");
        return -1;
    }

    if (st.st_size == 0) {
        // 文件为空，写入列名
        fprintf(mm_csv_files[1], "PID,Command,Kmem Count,Vmem Count,Slab Count\n");
        fflush(mm_csv_files[1]); // 确保数据立即写入文件
    }

    // 写入数据到 CSV 文件
    fprintf(mm_csv_files[1], "%u,%s,%u,%u,%u\n",
            event->info.pid,
            event->info.comm,
            event->kmem_count,
            event->vmem_count,
            event->slab_count);
    

    return 0;
}

static int handle_process_mm_stats_event(void *ctx,void *data, size_t data_sz){
	struct process_mm_stats *event = (struct process_mm_stats *)data;

    if(env_data.std_output){
        printf("  process tgid: %u\n", event->tgid);
        printf("  kmem_count: %u\n", event->kmem_count);
        printf("  vmem_count: %u\n", event->vmem_count);
        printf("  slab_count: %u\n\n", event->slab_count);
    }

    // 如果不需要可视化，直接返回
    if (!env_data.visualize)
        return 0;

    // 检查 CSV 文件是否初始化
    if (mm_csv_files[2] == NULL) {
        fprintf(stderr, "Error: CSV file not initialized for process MM stats\n");
        return -1;
    }

    // 检查文件是否为空
    struct stat st;
    if (fstat(fileno(mm_csv_files[2]), &st) == -1) {
        perror("Error checking file size");
        return -1;
    }

    if (st.st_size == 0) {
        // 文件为空，写入列名
        fprintf(mm_csv_files[2], "TGID,Kmem Count,Vmem Count,Slab Count\n");
        fflush(mm_csv_files[2]); // 确保数据立即写入文件
    }

    // 写入数据到 CSV 文件
    fprintf(mm_csv_files[2], "%u,%u,%u,%u\n",
            event->tgid,
            event->kmem_count,
            event->vmem_count,
            event->slab_count);

    return 0;
}

static int attach_leak_skel(struct mm_leak_bpf *skel){
	int ret;

	allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));
    if (!allocs) {
		fprintf(stderr, "failed to allocate array\n");
		ret = -ENOMEM;

		return ret;
	}

    stack = calloc(PERF_MAX_STACK_DEPTH, sizeof(*stack));
	if (!stack) {
		fprintf(stderr, "failed to allocate stack array\n");
		ret = -ENOMEM;

		return ret;
	}

	ret = mm_leak_bpf__load(skel);
    if(ret){
        fprintf(stderr, "failed to load mm_leak skel\n");

		return -1;
    }

	leak_allocs_fd = bpf_map__fd(skel->maps.allocs);
    leak_stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);

    ret = mm_leak_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "failed to attach bpf program(s)\n");

		return -1;
	}

    mm_symbolizer = blaze_symbolizer_new();
    if(!mm_symbolizer){
        printf("Failed to initialize symbolizer\n");
        ret = -1;

        return ret;
    }

	return 0;
}

static int attach_mm_stats_skel(struct mm_stats_bpf *skel){
	int ret,map_fd;

	ret = mm_stats_bpf__load(skel);
	if(ret){
		fprintf(stderr, "failed to load mm_leak skel\n");
		return -1;
	}

	ret = mm_stats_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "failed to attach mm_stats bpf program(s)\n");

		return -1;
	}

	rb_oom = ring_buffer__new(bpf_map__fd(skel->maps.oom_event_buffer),handle_oom_event,NULL,NULL);
	if(!rb_oom){
		fprintf(stderr, "Failed to create oom ring buffer\n");
		return -1;
	}

	rb_task_mm = ring_buffer__new(bpf_map__fd(skel->maps.task_mm_stats_buffer),handle_task_mm_stats_event,NULL,NULL);
	if(!rb_task_mm){
		fprintf(stderr, "Failed to create task mm stats ring buffer\n");
		return -1;
	}

	rb_process_mm = ring_buffer__new(bpf_map__fd(skel->maps.process_mm_stats_buffer),handle_process_mm_stats_event,NULL,NULL);
	if(!rb_process_mm){
		fprintf(stderr, "Failed to create task mm stats ring buffer\n");
		return -1;
	}

	struct mm_threhold threhold_task = {
		.kmem_threhold = 500,
		.slab_threhold = 500,
		.vmem_threhold = 500,
		.time_window = MSEC * 1000 // 1秒
	};

	struct mm_threhold threhold_process = {
		.kmem_threhold = 1000,
		.slab_threhold = 1000,
		.vmem_threhold = 1000,
		.time_window = MSEC * 1000 // 1秒
	};

	map_fd = bpf_map__fd(skel->maps.threhold_map);
	if(bpf_map_update_elem(map_fd,&zero,&threhold_task,BPF_ANY) != 0){
		perror("Failed to update mm_threhold map\n");
		return -1;
	}

	if(bpf_map_update_elem(map_fd,&one,&threhold_process,BPF_ANY) != 0){
		perror("Failed to update mm_threhold map\n");
		return -1;
	}

	return 0;
}

static void mm_resource_clean(){
    if(rb_oom)
		ring_buffer__free(rb_oom);
	if(rb_task_mm)
		ring_buffer__free(rb_task_mm);
	if(rb_process_mm)
		ring_buffer__free(rb_process_mm);
    
    if(mm_symbolizer)
        blaze_symbolizer_free(mm_symbolizer);
    
    mm_leak_bpf__destroy(leak_skel);
	mm_stats_bpf__destroy(mm_skel);

    for(int i=0;i<MAX_CSV_FILES;i++){
        if(mm_csv_files[i] != NULL)
            fclose(mm_csv_files[i]);
        else   
            break;
    }

    if(mm_alloc_stack)
        fclose(mm_alloc_stack);

    if(mm_file)
        fclose(mm_file);
}

static int mm_ring_buffer_poll(){
	int err;

	err = ring_buffer__poll(rb_oom,500);
	if(err < 0)
	{
		fprintf(stderr, "Error polling oom ring buffer: %d\n", err);
		return err;
	}

	err = ring_buffer__poll(rb_task_mm,500);
	if(err < 0)
	{
		fprintf(stderr, "Error polling task mm stats ring buffer: %d\n", err);
		return err;
	}

	err = ring_buffer__poll(rb_process_mm,500);
	if(err < 0)
	{
		fprintf(stderr, "Error polling process mm stats ring buffer: %d\n", err);
		return err;
	}

	return 0;
}

int alloc_size_compare(const void *a, const void *b)
{
	const struct allocation *x = (struct allocation *)a;
	const struct allocation *y = (struct allocation *)b;

	// descending order

	if (x->size > y->size)
		return -1;

	if (x->size < y->size)
		return 1;

	return 0;
}

static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd){
    //const u64 allocs_key_size = bpf_map__key_size(skel->maps.allocs);

    u64 t = time(NULL);
    struct tm *tm = localtime(&t);// 获取当前时间，用于输出时的时间戳
    u64 nr_allocs = 0;// 计数器用来记录找到的分配信息的数量

    //遍历 allocs map,prev_key 和 curr_key 用来在 BPF map 中迭代查找元素
    for (u64 prev_key = 0, curr_key = 0;; prev_key = curr_key)
    {
        struct alloc_info alloc_info = {};
        memset(&alloc_info, 0, sizeof(alloc_info));
        // 获取下一个 allocs map 中的键，直到遍历完所有键，如果返回 ENOENT 错误，表示没有更多的键，可以退出循环
        if (bpf_map_get_next_key(allocs_fd,&prev_key,&curr_key))
		{
			if (errno == ENOENT)
			{
				break; // no more keys, done
			}

			perror("map get next key error");

			return -errno;
		}
    
        // 使用 bpf_map__lookup_elem() 查找当前键对应的值,如果发生 ENOENT 错误，表示当前键没有对应值，跳过该键
        if (bpf_map_lookup_elem(allocs_fd,&curr_key,&alloc_info))
		{
			if (errno == ENOENT)
				continue;

			perror("map lookup error");

			return -errno;
		}

        // 过滤掉无效的栈
        if (alloc_info.stack_id < 0)
		    {   
			    continue;
		    }

        bool stack_exists = false;

        // 遍历已存储的 allocs 数组（内存分配信息的集合）并查找相同的 stack_id
        // 如果找到了相同的堆栈 ID（意味着同一个堆栈进行了多次分配），就将 alloc_info.size 累加到已存在的分配中，且将 count 增加 1

        for (u64 i = 0; !stack_exists && i < nr_allocs; ++i)
		    {
			    struct allocation *alloc = &allocs[i];

			    if (alloc->stack_id == alloc_info.stack_id)
			    {
				    alloc->size += alloc_info.size;
				    alloc->count++;

				    stack_exists = true;
				    break;
			    }
		    }


        if (stack_exists)
			continue;

        // 如果没有找到相同的堆栈 ID，说明这是一个新的堆栈分配，创建一个新的 allocation 结构体，并将其添加到 allocs 数组中
        struct allocation alloc = {
			.stack_id = alloc_info.stack_id ,
			.size = alloc_info.size,
			.count = 1,
		};
        
        // 将新创建的 allocation 结构体复制到 allocs 数组中，并增加 nr_allocs
        memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
		nr_allocs++;
    }

    // 使用 qsort() 函数按内存大小降序排列 allocs 数组
    //qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);
    if (nr_allocs > 0) {
        qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);
    }

    printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs);
    
    for (size_t i = 0; i < nr_allocs; i++)
	{
		if (bpf_map_lookup_elem(stack_traces_fd,&allocs[i].stack_id,stack))
		{
			perror("failed to lookup stack traces!");
			return -errno;
		}
	}
    
    print_stack_frames(allocs, nr_allocs, stack_traces_fd);
    for (size_t i = 0; i < nr_allocs; i++) {
        allocs[i].stack_id = 0;
    }

	return 0;
}

void print_stack_frames_by_blazesym(u64 *stack, int stack_sz)
{
    struct blaze_syms *result;
    struct blaze_sym *sym;
    
    if(trace_pid == 0){
		struct blaze_symbolize_src_kernel src = {
        	.type_size = sizeof(src)
    	};
		result = blaze_symbolize_kernel_abs_addrs(mm_symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}
	else{
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = trace_pid,
		};
		result = blaze_symbolize_process_abs_addrs(mm_symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}
    
    // 获取符号信息
    //printf("Stack depth: %d\n", stack_sz);

    if (!result) {
        perror("Failed to symbolize stack addresses");
        return;
    }

    // 打印栈回溯信息
    for (size_t j = 0; j < result->cnt; ++j) {
        //printf("inlined count: %d\n", result->syms[j].inlined_cnt);

        const uint64_t addr = stack[j];

        if (addr == 0)
            break;

        sym = &result->syms[j];

        if (sym->name == NULL) {
            printf("No symbol found for address <0x%lx>\n", addr);
            if (mm_alloc_stack) {
                fprintf(mm_alloc_stack, "No symbol found for address <0x%lx>\n", addr);
            }
            continue;
        }

        // 打印每个栈帧的函数名和地址
        printf("\t%zu [<%016lx>] %s + 0x%lx\n", j, addr, sym->name, sym->offset);
        if (mm_alloc_stack) {
            fprintf(mm_alloc_stack, "\t%zu [<%016lx>] %s + 0x%lx\n", j, addr, sym->name, sym->offset);
        }

        // 打印源代码位置（文件、行号等）
        if (sym->code_info.file != NULL) {
            printf("\t\tSource: %s:%d:%d\n", sym->code_info.file, sym->code_info.line, sym->code_info.column);
            if (mm_alloc_stack) {
                fprintf(mm_alloc_stack, "\t\tSource: %s:%d:%d\n", sym->code_info.file, sym->code_info.line, sym->code_info.column);
            }
        }

        // 如果存在内联函数，打印内联函数信息
        if (sym->inlined_cnt > 0) {
            for (size_t k = 0; k < sym->inlined_cnt; ++k) {
                const struct blaze_symbolize_inlined_fn *inlined = &sym->inlined[k];
                printf("\t\tInlined function: %s\n", inlined->name);
                if (mm_alloc_stack) {
                    fprintf(mm_alloc_stack, "\t\tInlined function: %s\n", inlined->name);
                }
                if (inlined->code_info.file != NULL) {
                    printf("\t\t\tSource: %s:%d:%d\n", inlined->code_info.file, inlined->code_info.line, inlined->code_info.column);
                    if (mm_alloc_stack) {
                        fprintf(mm_alloc_stack, "\t\t\tSource: %s:%d:%d\n", inlined->code_info.file, inlined->code_info.line, inlined->code_info.column);
                    }
                }
            }
        }
    }

    blaze_syms_free(result);
}

int print_stack_frames(struct allocation *allocs, u64 nr_allocs, int stack_traces_fd)
{
    for (u64 i = 0; i < nr_allocs; ++i){
        const struct allocation *alloc = &allocs[i];
        printf("%zu bytes in %zu allocations from stack\n", alloc->size, alloc->count);

        if (bpf_map_lookup_elem(stack_traces_fd, &alloc->stack_id, stack)) {
			if (errno == ENOENT)
				continue;

			perror("failed to lookup stack trace");

			return -errno;
		}

        print_stack_frames_by_blazesym(stack,nr_allocs);
    }
}


static void print_frame(const char *name, u64 input_addr, u64 addr, u64 offset, const blaze_symbolize_code_info *code_info)
{
	// If we have an input address  we have a new symbol.
	if (input_addr != 0)
	{
		printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
        if (cpu_task_stack) {
            fprintf(cpu_task_stack, "%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
        }

		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL)
		{
			printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
            if (cpu_task_stack) {
                fprintf(cpu_task_stack, " %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
            }
		}
		else if (code_info != NULL && code_info->file != NULL)
		{
			printf(" %s:%u\n", code_info->file, code_info->line);
            if (cpu_task_stack) {
                fprintf(cpu_task_stack, " %s:%u\n", code_info->file, code_info->line);
            }
		}
		else
		{
			printf("\n");
            if (cpu_task_stack) {
                fprintf(cpu_task_stack, "\n");
            }
		}
	}
	else
	{
		printf("%16s  %s", "", name);
        if (cpu_task_stack) {
            fprintf(cpu_task_stack, "%16s  %s", "", name);
        }

		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL)
		{
			printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
            if (cpu_task_stack) {
                fprintf(cpu_task_stack, "@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
            }
		}
		else if (code_info != NULL && code_info->file != NULL)
		{
			printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
            if (cpu_task_stack) {
                fprintf(cpu_task_stack, "@ %s:%u [inlined]\n", code_info->file, code_info->line);
            }
		}
		else
		{
			printf("[inlined]\n");
            if (cpu_task_stack) {
                fprintf(cpu_task_stack, "[inlined]\n");
            }
		}
	}
}

/*---------------------------cpu部分---------------------------------------*/
static int cpu_create_csv(){
    int ret;
    int num_csv_names = sizeof(cpu_csv_names) / sizeof(cpu_csv_names[0]);
    
    for(int i=0;i<MAX_CSV_FILES;i++)
        cpu_csv_files[i] = NULL;
    
    // 获取当前工作目录
    if (getcwd(csv_folder_path, sizeof(csv_folder_path)) == NULL) {
        perror("getcwd failed");
        return 1;
    }

    // 调用 visual_create_run_file 函数
    if (visual_create_run_file(csv_folder_path, cpu_csv_names, num_csv_names, cpu_csv_files) != 0) {
        fprintf(stderr, "Failed to create run folder and CSV files\n");
        return 1;
    }
    
    return 0;
}

int get_cpu_txt(){
    if(lookup_txt_file(visualize_proc_path,cpu_stack,&cpu_task_stack)!=0){
        fprintf(stderr, "Failed to open or create file\n");
        return 1;
    }
    return 0;
}

// 初始化符号解析器
static int init_cpu_symbolizer() {
    cpu_symbolizer = blaze_symbolizer_new();
    if (!cpu_symbolizer) {
        printf("Failed to initialize cpu_symbolizer\n");
        return -1;
    }
    return 0;
}

// 释放符号解析器
static void free_cpu_symbolizer() {
    if (cpu_symbolizer) {
        blaze_symbolizer_free(cpu_symbolizer);
        cpu_symbolizer = NULL;
    }
}

static void cpu_print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
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
static void cpu_show_stack_trace(uint64_t *stack, int stack_sz, pid_t pid) {
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
        syms = blaze_symbolize_process_abs_addrs(cpu_symbolizer, &src, (const uintptr_t *)stack, stack_sz);
    } else {
        // 内核空间栈回溯的符号解析
        struct blaze_symbolize_src_kernel src = {
            .type_size = sizeof(src),
        };
        syms = blaze_symbolize_kernel_abs_addrs(cpu_symbolizer, &src, (const uintptr_t *)stack, stack_sz);
    }

    if (syms == NULL) {
        printf("  failed to symbolize addresses: %s\n", blaze_err_str(blaze_err_last()));
        if (cpu_task_stack) {
            fprintf(cpu_task_stack, "  failed to symbolize addresses: %s\n", blaze_err_str(blaze_err_last()));
        }
        return;
    }

    for (i = 0; i < stack_sz; i++) {
        // 检查栈地址是否为有效的地址
        if (stack[i] == 0 || stack[i] == (uintptr_t)-1) {
            continue;  // 跳过无效的栈地址
        }

        if (!syms || syms->cnt <= i || syms->syms[i].name == NULL) {
            printf("%016llx: <no-symbol>\n", stack[i]);
            if (cpu_task_stack) {
                fprintf(cpu_task_stack, "%016llx: <no-symbol>\n", stack[i]);
            }
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
    if (cpu_task_stack) {
            fprintf(cpu_task_stack, "The stack size is invalid\n");
    }

    if (event->kstack_sz > 0) {
        printf("Kernel:\n");
        if (cpu_task_stack) {
            fprintf(cpu_task_stack, "Kernel:\n");
        }
        cpu_show_stack_trace(event->k_stack, event->kstack_sz / sizeof(uint64_t), 0);
    } else {
        printf("No Kernel Stack\n");
    }

    if (event->ustack_sz > 0) {
        printf("Userspace:\n");
        if (cpu_task_stack) {
            fprintf(cpu_task_stack, "Userspace:\n");
        }
        cpu_show_stack_trace(event->u_stack, event->ustack_sz / sizeof(uint64_t), event->pid);
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

    if(env_data.std_output){
        printf("CPU ID: %u\n", stats->cpu_id);
        printf("User Time: %f\n", usr);
        printf("Kernel Time: %f\n", kernel);
        printf("Idle Time: %f\n", idle);
        printf("Irq Time: %f\n",irq);
        printf("Softirq Time: %f\n",softirq);
    }

    // 如果不需要可视化，直接返回
    if (!env_data.visualize)
        return 0;

    // 检查 CSV 文件是否初始化
    if (cpu_csv_files[0] == NULL) {
        fprintf(stderr, "Error: CSV file not initialized for CPU usage stats\n");
        return -1;
    }

    // 检查文件是否为空
    struct stat st;
    if (fstat(fileno(cpu_csv_files[0]), &st) == -1) {
        perror("Error checking file size");
        return -1;
    }

    if (st.st_size == 0) {
        // 文件为空，写入列名
        fprintf(cpu_csv_files[0], "CPU ID,User Time,Kernel Time,Idle Time,IRQ Time,SoftIRQ Time\n");
        fflush(cpu_csv_files[0]); // 确保数据立即写入文件
    }

    // 写入数据到 CSV 文件
    fprintf(cpu_csv_files[0], "%u,%f,%f,%f,%f,%f\n",
            stats->cpu_id,
            usr,
            kernel,
            idle,
            irq,
            softirq);
    
    return 0;
}

static int handle_usr_task_usage_event(void *ctx,void *data, size_t data_sz){
    struct task_cpu_usage *task = data;
    u32 pid = task->task_info.pid;
    float total_percent = task->total_percent/1.0f;
    float usr_percent = task->user_percent/1.0f;
    float kernel_percent = task->kernel_percent/1.0f;

    char comm[TASK_COMM_LEN + 1]; 
    strncpy(comm,task->task_info.comm,TASK_COMM_LEN);
    comm[TASK_COMM_LEN] = '\0';

    if(env_data.std_output){
        printf("pid: %u\n",pid);
        printf("name: %s\n",comm);
        printf("total percent: %f",total_percent);
        printf("kernel percent: %f",kernel_percent);
        printf("usr_percent: %f\n",usr_percent);
    }

    // 如果不需要可视化，直接返回
    if (!env_data.visualize)
        return 0;

    // 检查 CSV 文件是否初始化
    if (cpu_csv_files[1] == NULL) {
        fprintf(stderr, "Error: CSV file not initialized for user task usage\n");
        return -1;
    }

    // 检查文件是否为空
    struct stat st;
    if (fstat(fileno(cpu_csv_files[1]), &st) == -1) {
        perror("Error checking file size");
        return -1;
    }

    if (st.st_size == 0) {
        // 文件为空，写入列名
        fprintf(cpu_csv_files[1], "PID,Name,Total Percent,Kernel Percent,User Percent\n");
        fflush(cpu_csv_files[1]); // 确保数据立即写入文件
    }

    // 写入数据到 CSV 文件
    fprintf(cpu_csv_files[1], "%u,%s,%f,%f,%f\n",
            pid,
            comm,
            total_percent,
            kernel_percent,
            usr_percent);
    
    return 0;
}

static int handle_use_process_stat_event(void *ctx,void *data, size_t data_sz){
    struct process_struct *ps = data;
    u32 tgid = ps->tgid;
    u32 kids_length = ps->kids_length;
    float total_percent = ps->total_use_percent/1.0f;

    if(env_data.std_output){
        printf("tgid: %u\n",tgid);
        printf("kids_length: %u\n",kids_length);
        printf("total percent: %f\n",total_percent);
    }

    // 如果不需要可视化，直接返回
    if (!env_data.visualize)
        return 0;

    // 检查 CSV 文件是否初始化
    if (cpu_csv_files[2] == NULL) {
        fprintf(stderr, "Error: CSV file not initialized for process usage stats\n");
        return -1;
    }

    // 检查文件是否为空
    struct stat st;
    if (fstat(fileno(cpu_csv_files[2]), &st) == -1) {
        perror("Error checking file size");
        return -1;
    }

    if (st.st_size == 0) {
        // 文件为空，写入列名
        fprintf(cpu_csv_files[2], "TGID,Kids Length,Total Percent\n");
        fflush(cpu_csv_files[2]); // 确保数据立即写入文件
    }

    // 写入数据到 CSV 文件
    fprintf(cpu_csv_files[2], "%u,%u,%f\n",
            tgid,
            kids_length,
            total_percent);
    
    return 0;
}

static int handle_usr_runqlat_event(void *ctx,void *data, size_t data_sz){
    struct runqlat_perf_data *late = data;
    for(int i=0;i<MAX_LATENCY_BUCKETS;i++){
        switch (i)
        {
        case 0:
            printf("wait less than 1us: %u\n",late->data[i]);
            break;
        case 1:
            printf("wait less than 4us: %u\n",late->data[i]);
            break;
        case 2:
            printf("wait less than 16us: %u\n",late->data[i]);
            break;
        case 3:
            printf("wait less than 64us: %u\n",late->data[i]);
            break;
        case 4:
            printf("wait less than 256us: %u\n",late->data[i]);
            break;
        case 5:
            printf("wait less than 1ms: %u\n",late->data[i]);
            break;
        case 6:
            printf("wait less than 4ms: %u\n",late->data[i]);
            break;
        case 7:
            printf("wait large than 4ms: %u\n",late->data[i]);
            break;
        default:
            break;
        }
    }
    
    // 如果不需要可视化，直接返回
    if (!env_data.visualize)
        return 0;

    // 检查 CSV 文件是否初始化
    if (cpu_csv_files[3] == NULL) {
        fprintf(stderr, "Error: CSV file not initialized for IO wait perf stats\n");
        return -1;
    }

    // 检查文件是否为空
    struct stat st;
    if (fstat(fileno(cpu_csv_files[3]), &st) == -1) {
        perror("Error checking file size");
        return -1;
    }

    if (st.st_size == 0) {
        // 文件为空，写入列名
        fprintf(cpu_csv_files[3], "1us,4us,16us,64us,256us,1ms,4ms,4ms+\n");
        fflush(cpu_csv_files[3]); // 确保数据立即写入文件
    }

    // 写入数据到 CSV 文件
    fprintf(cpu_csv_files[3], "%u,%u,%u,%u,%u,%u,%u,%u\n",
            late->data[0], 
            late->data[1], 
            late->data[2], 
            late->data[3], 
            late->data[4], 
            late->data[5], 
            late->data[6], 
            late->data[7]);
    

    return 0;
}

static int attach_cpu_skel(){
    int err;

    if(init_cpu_symbolizer()!=0)
        return -1;

    cpu_skel = cpu_stats_bpf__open_and_load();
    if (!cpu_skel) {
        fprintf(stderr, "Failed to open and load BPF program\n");
        return 1;
    }

    //int nr_cpu = libbpf_num_possible_cpus();
    if(cores == 0){
        FILE *fp = popen("grep -c '^processor' /proc/cpuinfo", "r");
        if (fp) {
            fscanf(fp, "%d", &cores);
            pclose(fp);
        }
    }

    int nr_cpu = cores;
    if(nr_cpu < 0)
    {
        fprintf(stderr,"libbpf: get cpu nums failed \n");
    }

    int map_fd = bpf_map__fd(cpu_skel->maps.cpu_usr_map);
    if(bpf_map_update_elem(map_fd,&zero,&nr_cpu,BPF_ANY) != 0){
        perror("Failed to update nr_cpu_map");
        cpu_stats_bpf__destroy(cpu_skel);
        return 1;
    }

    // struct data_list list = {};
    // map_fd = bpf_map__fd(skel->maps.occupied_list);
    // if(bpf_map_update_elem(map_fd,&zero,&list,BPF_ANY)!=0 || bpf_map_update_elem(map_fd,&one,&list,BPF_ANY)!=0){
    //     perror("Failed to init occupied_liss");
    //     cpu_stats_bpf__destroy(skel);
    //     return 1;
    // }

    // struct hash_table table;
    // hash_table_init(&table);
    // map_fd = bpf_map__fd(skel->maps.hash_table_model_map);
    // if(bpf_map_update_elem(map_fd,&zero,&table,BPF_ANY) != 0){
    //     perror("Failed to update hash_table_model_map");
    //     cpu_stats_bpf__destroy(skel);
    //     return 1;
    // }

    err = cpu_stats_bpf__attach(cpu_skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        return err;
    }

    struct bpf_link *link_cpu = attach_perf_event_to_program(cpu_skel->progs.handle_cpu_event, 500);  // 500 毫秒
    if (!link_cpu) {
        return err;
    }
    cpu_skel->links.handle_cpu_event = link_cpu;

    // struct bpf_link *link_task = attach_perf_event_to_program(skel->progs.handle_task_usage_event, 500);  // 500 毫秒
    // if (!link_task) {
    //     return err;
    // }
    // skel->links.handle_task_usage_event = link_task;

    // struct bpf_link *link_process = attach_perf_event_to_program(skel->progs.handle_process_stat_event,500);
    // if(!link_process){
    //     return err;
    // }
    // skel->links.handle_process_stat_event = link_process;

    struct bpf_link *link_runqlat = attach_perf_event_to_program(cpu_skel->progs.handle_sys_latency_event,500);
    if(!link_runqlat){
        return err;
    }
    cpu_skel->links.handle_sys_latency_event = link_runqlat;

    // struct bpf_link *link_backtrace = attach_perf_event_to_program(skel->progs.handle_task_backtrace_event,500);
    // if(!link_backtrace){
    //     return err;
    // }

    rb_cpu = ring_buffer__new(bpf_map__fd(cpu_skel->maps.cpu_usage_buffer), handle_cpu_usage_event, NULL, NULL);
    if (!rb_cpu) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return err;
    }

    rb_task = ring_buffer__new(bpf_map__fd(cpu_skel->maps.task_occupied_buffer), handle_usr_task_usage_event, NULL, NULL);
    if (!rb_task) {
        fprintf(stderr, "Failed to create ring buffer for task usage\n");
        return err;
    }

    rb_process = ring_buffer__new(bpf_map__fd(cpu_skel->maps.process_occupied_buffer), handle_use_process_stat_event, NULL, NULL);
    if(!rb_process){
        fprintf(stderr, "Failed to create ring buffer for process stat\n");
        return err;
    }

    rb_runqlat = ring_buffer__new(bpf_map__fd(cpu_skel->maps.runqlat_buffer), handle_usr_runqlat_event, NULL, NULL);
    if(!rb_runqlat){
        fprintf(stderr, "Failed to create ring buffer for runqlat\n");
        return err;
    }

    rb_backtrace = ring_buffer__new(bpf_map__fd(cpu_skel->maps.task_backtrace_buffer), handle_usr_task_cpu_backtrace_event, NULL, NULL);
    if(!rb_backtrace){
        fprintf(stderr, "Failed to create ring buffer for cpu task backtrace\n");
        return err;
    }

    return 0;
}

static int cpu_ring_buffer_poll(){
    int err;
    err = ring_buffer__poll(rb_cpu, 600 /* ms */);
    if (err == -EINTR) {
        return err;  // 捕捉到退出信号时停止
    } else if (err < 0) {
        fprintf(stderr, "Error polling CPU usage ring buffer: %d\n", err);
        return err; 
    }

    err = ring_buffer__poll(rb_task, 600 /* ms */);
    if (err == -EINTR) {
        return err;   // 捕捉到退出信号时停止
    } else if (err < 0) {
        fprintf(stderr, "Error polling task usage ring buffer: %d\n", err);
        return err; 
    }

    err = ring_buffer__poll(rb_process, 600 /* ms */);
    if (err == -EINTR) {
        return err;   // 捕捉到退出信号时停止
    } else if (err < 0) {
        fprintf(stderr, "Error polling process stat ring buffer: %d\n", err);
        return err; 
    }
    err = ring_buffer__poll(rb_runqlat, 600 /* ms */);
    if (err == -EINTR) {
        return err;  // 捕捉到退出信号时停止
    } else if (err < 0) {
        fprintf(stderr, "Error polling process stat ring buffer: %d\n", err);
        return err; 
    }

    err = ring_buffer__poll(rb_backtrace,600);
    if (err == -EINTR) {
        return err;   // 捕捉到退出信号时停止
    } else if (err < 0) {
        fprintf(stderr, "Error polling process stat ring buffer: %d\n", err);
        return err; 
    }

    return 0;
}


static void cpu_resource_clean(){
    if (rb_cpu)
        ring_buffer__free(rb_cpu);
    if (rb_task)
        ring_buffer__free(rb_task);
    if (rb_process)
        ring_buffer__free(rb_process);
    if (rb_runqlat)
        ring_buffer__free(rb_runqlat);
    
    for(int i=0;i<MAX_CSV_FILES;i++){
        if(cpu_csv_files[i] != NULL)
            fclose(cpu_csv_files[i]);
        else   
            break;
    }

    if(cpu_task_stack)
        fclose(cpu_task_stack);
    
    cpu_stats_bpf__destroy(cpu_skel);
    free_cpu_symbolizer();
}