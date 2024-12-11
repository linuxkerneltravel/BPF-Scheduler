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
#include <bpf/btf.h>
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <assert.h>

#include "proc_data.h"
#include "net_event.h"
#include "net_stats.skel.h"

#define MAX_CSV_FILES 10

static char csv_folder_path[MAX_PATH_LEN];

const char *net_csv_names[] = {
        "net_latency",
        "tcprtt",
        "tcptop",
        "tcpretrans"
    };

FILE *net_csv_files[MAX_CSV_FILES];

volatile sig_atomic_t stop = 0;

struct ring_buffer *rb_net_latency = NULL;
struct ring_buffer *rb_tcprtt = NULL;
struct ring_buffer *rb_tcptop = NULL;
struct ring_buffer *rb_tcpretrans = NULL;
struct net_stats_bpf *net_skel = NULL;
struct sysinfo sys_data;
static time_t boot_time; // 系统启动时间
struct bpf_link *link_to_tcprtt = NULL;


static int handle_net_latency_event(void *ctx, void *data, size_t data_sz);
static int handle_usr_tcprtt_event(void *ctx, void *data, size_t data_sz);
static int handle_usr_tcptop_event(void *ctx, void *data, size_t data_sz);
static int handle_usr_tcpretrans_event(void *ctx, void *data, size_t data_sz);
static bool fentry_try_attach(int id);
static bool fentry_can_attach(const char* name, const char* mod);
static int attach_net_skel(struct net_stats_bpf *skel);
void net_resource_clean();
static int net_ring_buffer_poll();
static int init_time();// 初始化系统当前时间

// 信号处理函数，用于优雅地退出程序
void net_handle_sigint(int sig) {
    stop = 1;
}

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

int main(int argc, char *argv[]) {
    int ret;
    unsigned int interval = 1; // 默认1秒
    // if (argc == 2) {
    //     interval = atoi(argv[1]);
    //     if (interval == 0) {
    //         fprintf(stderr, "Invalid interval. Using default 1 second.\n");
    //         interval = 1;
    //     }
    // }
    ret = init_time();
    if(ret != 0)
        goto cleanup;
    
    ret = net_create_csv();
    if(ret != 0)
        goto cleanup;
    

    net_skel = net_stats_bpf__open();
    if(!net_skel){
        fprintf(stderr, "failed to open net_stats skel\n");
		ret = 1;

		goto cleanup;
    }

    ret = attach_net_skel(net_skel);
    if(ret != 0)
        goto cleanup;


    //printf("Starting network monitoring every %u second(s)...\n", interval);

    // 注册信号处理器，捕获Ctrl-C (SIGINT)
    signal(SIGINT, net_handle_sigint);

    while (!stop) {
        // if (monitor_network() != 0) {
        //     fprintf(stderr, "An error occurred during network monitoring.\n");
        // }

        ret = net_ring_buffer_poll();
        if(ret != 0)
            goto cleanup;
        // 等待指定的时间间隔
        //sleep(interval);
        //usleep(400000);  // 暂停 400,000 微秒，即 0.4 秒
    }

    printf("\nNetwork monitoring stopped.\n");

cleanup:
    net_resource_clean();
    return ret;
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

    // 打印事件信息
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
    
    // 将事件信息写入 CSV 文件
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

    // 如果文件为空，写入表头
    if (st.st_size == 0) {
        fprintf(net_csv_files[0], "Timestamp,Source_IP,Source_Port,Destination_IP,Destination_Port,TGID,Comm,Delay_us\n");
        fflush(net_csv_files[0]);
    }

    fprintf(net_csv_files[0], "%s.%09ld,%s,%u,%s,%u,%u,%.16s,%llu\n",
        time_buf,
        absolute_nsec,
        saddr_str,
        ntohs(event->lport),
        daddr_str,
        ntohs(event->dport),
        event->tgid,
        event->comm,
        (unsigned long long)event->delta);

    return 0; // 返回 0 表示继续处理其他事件
}

static int handle_usr_tcprtt_event(void *ctx, void *data, size_t data_sz){
    struct tcprtt_perf_data *event = (struct tcprtt_perf_data *)data;

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
    printf("\n");

    // 写入到 CSV 文件
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
            fprintf(net_csv_files[2],
                    "Timestamp,PID,Comm,Source_IP,Source_Port,Destination_IP,Destination_Port,Sent_Bytes,Received_Bytes\n");
            fflush(net_csv_files[2]);
        }

        // 写入事件数据
        fprintf(net_csv_files[2], "%s,%u,%s,%s,%u,%s,%u,%llu,%llu\n",
                time_buf,
                event->pid,
                event->comm,
                saddr_str,
                lport,
                daddr_str,
                dport,
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
            fprintf(net_csv_files[3],
                    "Timestamp,PID,Comm,Seq,State,Event_Type,Source_IP,Source_Port,Destination_IP,Destination_Port\n");
            fflush(net_csv_files[3]);
        }

        // 写入事件数据
        fprintf(net_csv_files[3], "%s.%09ld,%u,%s,%u,%s,%llu,%s,%u,%s,%u\n",
                time_buf,
                absolute_nsec,
                event->pid,
                event->comm,
                event->seq,
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
