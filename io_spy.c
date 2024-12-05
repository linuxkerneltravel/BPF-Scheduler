#include <argp.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/select.h>
#include <errno.h>
#include <asm/unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <assert.h>

#include "io_event.h"
#include "io_stats.skel.h"

#include "proc_data.h"

#define MAX_IO_RESULTS 256

static u32 zero = 0;
static u32 one = 1;

/*---------------------------IO信息---------------------------------*/
struct ring_buffer *rb_io_task_stats, *rb_io_process_stats, *rb_io_wait;
struct io_stats_bpf *io_skel = NULL;
struct bpf_link *link_io_wait = NULL;
DiskStatsContext* context = NULL;
DiskStats current[MAX_DEVICES];

static int handle_io_task_stats_event(void *ctx,void *data, size_t data_sz){
    struct io_task_stats *event = (struct io_task_stats *)data;

    printf("  PID: %u\n", event->info.pid);
    printf("  Command: %s\n", event->info.comm);
    printf("  read_count: %u\n", event->read_count);
    printf("  write_count: %u\n", event->write_count);

    return 0;
}

static int handle_io_process_stats_event(void *ctx,void *data, size_t data_sz){
    struct io_process_stats *event = (struct io_process_stats *)data;

    printf("  tgid: %u\n", event->tgid);
    printf("  read_count: %u\n", event->read_count);
    printf("  write_count: %u\n", event->write_count);

    return 0;
}

static int handle_iowait_perf_event(void *ctx,void *data, size_t data_sz){
    struct io_wait_perf_data *event = (struct io_wait_perf_data *)data;

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

int main(int argc, char *argv[]) {
    int ret = 0;

    io_skel = io_stats_bpf__open();
    if(!io_skel){
        fprintf(stderr, "failed to open io_stats skel\n");
		ret = 1;

		goto cleanup;
    }

    ret = attach_io_skel(io_skel);
    if(ret != 0)
        goto cleanup;

    unsigned int interval = io_parse_arguments(argc, argv);

    if (io_initialize_monitoring(interval) != 0) {
        fprintf(stderr, "Initialization failed.\n");
        ret = 1;
        goto cleanup;
    }

    while (1) {
        //sleep(interval);
        usleep(USEC * 100);
        ret = io_ring_buffer_poll();
        if(ret != 0)
            goto cleanup;
        if (process_disk_stats(context, current, &context->device_count_prev, interval) != 0) {
            goto cleanup;
        }
    }


cleanup:
    io_resource_clean();
    diskstats_cleanup(context);
    return 0;
}
