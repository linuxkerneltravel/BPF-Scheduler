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
#include "blazesym.h"
#include "scx_nest.h"

#include "scx_nest.skel.h"


/*----------------------共同部分---------------------------------*/
#define MAX_CSV_FILES 10
static char csv_folder_path[MAX_PATH_LEN];

static char visualize_proc_path[MAX_PATH_LEN];// 把不适合放到promthes的都放到这个文件夹

volatile sig_atomic_t stop = 0;

static time_t boot_time; // 系统启动时间

static u32 zero = 0;
static u32 one = 1;
static int create_perf_event(u32 period_ms);
static struct bpf_link* attach_perf_event_to_program(struct bpf_program *prog, u32 period_ms);

//static int init_time();// 初始化系统当前时间
static int get_proc_path();
static error_t parse_arg(int key, char *arg, struct argp_state *state);

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

int concerned_map_fd[4];

const char *concerned_names[] = {
    "comm_ignore.txt",
    "id_ignore.txt",
    "comm_attention.txt",
    "id_attention.txt",
};

// const char ignore_file[] = "./ignore.txt"; // 小心scx_nest误伤的任务
// const char attention_file[] = "./attention.txt";// 要去特别注意的任务

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

static int attach_scx_skel();
static int scx_operation();
static void scx_resource_clean();

static int update_scx_concerned();

static int handle_usr_cpu_mask_event(void *ctx, void *data, size_t data_sz);

static int sched_create_txt();



int main(int argc, char **argv){
    int ret;
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);
    interactive_sched_ext_config(&sched_env);

restart:
    //printf("----------------------------------------\n");
    ret = init_time();
    if(ret != 0)
        goto cleanup;

    ret = get_proc_path();
    if(ret != 0)
        goto cleanup;
    
    ret = sched_create_txt();
    if(ret != 0)
        goto cleanup;
    
    ret = attach_scx_skel();
    if(ret != 0)
        goto cleanup;

    while(stop == 0){
        ret = scx_operation();
        if(ret != 0)
            goto cleanup;
    }


cleanup:
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
    bool visual = sched_txt_files[0] != NULL;
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

static int update_scx_concerned(){

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

    // 下面这里是演示，对于别的满足filter_inner_map 格式的map都能放入fliter_map，
    // 你可以很轻松的把你的代码融合在我这里，把要处理的pid整合整个我这个格式的map，然后像下面这样传进来

    // struct filter_inner_map {
	// __uint(type, BPF_MAP_TYPE_HASH);
	// __uint(max_entries, 102400);
	// __type(key, u32);
	// __type(value, u32);
    // } template_map SEC(".maps");

    // int cpu_fd = bpf_map__fd(cpu_skel->maps.thread_occupied_map);
    // if(cpu_fd < 0){
    //     fprintf(stderr, "Failed to get thread_occupied_map map fd\n");
    //     return -1;
    // }
    // int scx_fd;
    // struct bpf_map *map = bpf_object__find_map_by_name(scx_skel->obj, "fliter_map");
    // if (!map) {
    //     fprintf(stderr, "Failed to find fliter_map\n");
    //     return -1;
    // }
    // scx_fd = bpf_map__fd(map);
    // if(scx_fd < 0){
    //     fprintf(stderr, "Failed to get fliter_map fd\n");
    //     return -1;
    // }

    // int ret = bpf_map_update_elem(scx_fd, &zero, &cpu_fd, BPF_ANY);
    // if(ret < 0){
    //     fprintf(stderr, "Failed to update cpu_filter_ids map\n");
    //     return -1;
    // }

    
    
    // int map_fd = bpf_map__fd(scx_skel->maps.comm_ignore_map);
    // if(map_fd < 0){
    //     fprintf(stderr, "Failed to get comm_ignore_map map fd\n");
    //     return -1;
    // }
    // int ret = load_tasks_name_to_map(ignore_file, map_fd);
    // if(ret < 0){
    //     fprintf(stderr, "Failed to load tasks name to comm_ignore_map\n");
    //     return -1;
    // }
    // map_fd = bpf_map__fd(scx_skel->maps.comm_attention_map);
    // if(map_fd < 0){
    //     fprintf(stderr, "Failed to get comm_attention_map map fd\n");
    //     return -1;
    // }
    // ret = load_tasks_name_to_map(attention_file, map_fd);
    // if(ret < 0){
    //     fprintf(stderr, "Failed to load tasks name to comm_attention_map\n");
    //     return -1;
    // }
    concerned_map_fd[0] = bpf_map__fd(scx_skel->maps.comm_ignore_map);
    if(concerned_map_fd[0] < 0){
        fprintf(stderr, "Failed to get comm_ignore_map map fd\n");
        return -1;
    }
    concerned_map_fd[1] = bpf_map__fd(scx_skel->maps.id_ignore_map);
    if(concerned_map_fd[1] < 0){
        fprintf(stderr, "Failed to get id_ignore_map map fd\n");
        return -1;
    }
    concerned_map_fd[2] = bpf_map__fd(scx_skel->maps.comm_attention_map);
    if(concerned_map_fd[2] < 0){
        fprintf(stderr, "Failed to get comm_attention_map map fd\n");
        return -1;
    }
    concerned_map_fd[3] = bpf_map__fd(scx_skel->maps.id_attention_map);
    if(concerned_map_fd[3] < 0){
        fprintf(stderr, "Failed to get id_attention_map map fd\n");
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