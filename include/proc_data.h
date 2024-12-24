#ifndef PROC_DATA_H
#define PROC_DATA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdbool.h> 


#define MAX_PATH_LEN 1024

/*----------------------可视化部分--------------------------------*/
int lookup_txt_file(char *txt_file_path, const char *name, FILE **txt_file) {
    // 检查输入参数
    if (txt_file_path == NULL || name == NULL || txt_file == NULL) {
        fprintf(stderr, "Invalid input arguments\n");
        return -1;
    }

    // 构造完整文件路径
    char full_file_path[MAX_PATH_LEN];
    snprintf(full_file_path, sizeof(full_file_path), "%s/%s.txt", txt_file_path, name);

    // 检查文件是否存在
    struct stat st;
    if (stat(full_file_path, &st) == 0) {
        // 文件存在，尝试打开
        *txt_file = fopen(full_file_path, "r+"); // 以读写模式打开
        if (*txt_file == NULL) {
            perror("Error opening existing file");
            return -1;
        }
    } else {
        // 文件不存在，创建新文件
        *txt_file = fopen(full_file_path, "w+"); // 以读写模式创建文件
        if (*txt_file == NULL) {
            perror("Error creating new file");
            return -1;
        }
    }

    return 0; // 成功
}

// // 创建文件夹，如果文件夹已存在则不做任何操作
// int create_folder(const char *folder_path) {
//     struct stat st = {0};

//     if (stat(folder_path, &st) == -1) {
//         if (mkdir(folder_path, 0755) == -1) {
//             perror("Failed to create folder");
//             return -1;
//         } else {
//             printf("Created folder: %s\n", folder_path);
//         }
//     } else {
//         printf("Folder already exists: %s\n", folder_path);
//     }

//     return 0;
// }

// // 创建 CSV 文件，并返回文件指针
// FILE* create_csv_in_folder(const char *folder_path, const char *csv_name) {
//     char file_path[MAX_PATH_LEN];

//     // 构造文件的完整路径
//     if (snprintf(file_path, sizeof(file_path), "%s/%s.csv", folder_path, csv_name) >= sizeof(file_path)) {
//         fprintf(stderr, "File path too long: %s/%s.csv\n", folder_path, csv_name);
//         return NULL;
//     }

//     // 创建 CSV 文件
//     FILE *csv_file = fopen(file_path, "w");
//     if (csv_file == NULL) {
//         perror("Failed to create CSV file");
//         return NULL;
//     }

//     printf("Created CSV file: %s\n", file_path);
//     return csv_file;
// }

// // 创建下一个 run[i] 文件夹，并返回其路径
// int create_run_folder(const char *base_dir, char *run_folder_path, size_t size) {
//     char visualize_path[MAX_PATH_LEN];
//     snprintf(visualize_path, sizeof(visualize_path), "%s/visualize", base_dir);

//     // 创建 "visualize" 文件夹
//     if (create_folder(visualize_path) != 0) {
//         return -1;
//     }

//     // 查找现有的 run[i] 文件夹，找到最大的 i
//     DIR *dir = opendir(visualize_path);
//     if (dir == NULL) {
//         perror("opendir failed");
//         return -1;
//     }

//     struct dirent *entry;
//     int max_run = 0;

//     while ((entry = readdir(dir)) != NULL) {
//         if (strncmp(entry->d_name, "run", 3) == 0) {
//             int num = atoi(entry->d_name + 3); // 获取 run 后的数字部分
//             if (num > max_run) {
//                 max_run = num;
//             }
//         }
//     }

//     closedir(dir);

//     // 创建下一个 run[i] 文件夹
//     int next_run = max_run + 1;
//     snprintf(run_folder_path, size, "%s/run%d", visualize_path, next_run);

//     if (create_folder(run_folder_path) != 0) {
//         return -1;
//     }

//     return 0;
// }

// // 创建 CSV 文件并返回其路径
// int visual_create_run_file(char *csv_folder_path, const char *csv_names[], int num_csv_names, FILE *csv_files[]) {
//     // 创建下一个 run[i] 文件夹
//     if (create_run_folder(csv_folder_path, csv_folder_path, MAX_PATH_LEN) != 0) {
//         return -1;
//     }

//     // 为每个 CSV 名称创建文件
//     for (int i = 0; i < num_csv_names; i++) {
//         csv_files[i] = create_csv_in_folder(csv_folder_path, csv_names[i]);
//         if (csv_files[i] == NULL) {
//             return -1;
//         }
//     }

//     return 0;
// }

// 辅助函数：检查目录是否存在，如果不存在则创建
int ensure_directory_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0; // 目录已存在
        } else {
            fprintf(stderr, "Error: %s exists but is not a directory\n", path);
            return -1;
        }
    }

    // 目录不存在，尝试创建
    if (mkdir(path, 0755) != 0) {
        perror("Error creating directory");
        return -1;
    }
    return 0;
}

// 辅助函数：在指定目录中创建 CSV 文件
FILE *create_csv_in_folder(const char *folder_path, const char *csv_name) {
    char csv_path[MAX_PATH_LEN];
    snprintf(csv_path, MAX_PATH_LEN, "%s/%s", folder_path, csv_name);

    FILE *file = fopen(csv_path, "a"); // 使用 "a" 模式，文件不存在时会创建
    if (file == NULL) {
        perror("Error creating CSV file");
    }
    return file;
}

// 主函数：创建 run 文件夹并管理 CSV 文件
int visual_create_run_file(char *csv_folder_path, const char *csv_names[], int num_csv_names, FILE *csv_files[]) {
    char run_folder_path[MAX_PATH_LEN];
    snprintf(run_folder_path, MAX_PATH_LEN, "%s/visualize/run", csv_folder_path);

    // 确保 run 文件夹存在
    if (ensure_directory_exists(run_folder_path) != 0) {
        return -1;
    }

    // 遍历 csv_names，创建 CSV 文件并关联到 csv_files
    for (int i = 0; i < num_csv_names; i++) {
        csv_files[i] = create_csv_in_folder(run_folder_path, csv_names[i]);
        if (csv_files[i] == NULL) {
            fprintf(stderr, "Error: Failed to create or open %s/%s\n", run_folder_path, csv_names[i]);
            return -1;
        }
    }

    return 0;
}


/*---------------------IO部分----------------------------------*/
#define MAX_DEVICES 256
#define DEVICE_NAME_LEN 32
#define DEFAULT_SECTOR_SIZE 512 // 默认扇区大小，可根据需要调整
#define MAX_IO_RESULTS 256


// 设备的统计信息结构体
typedef struct {
    char name[DEVICE_NAME_LEN];
    unsigned long reads_completed;
    unsigned long writes_completed;
    unsigned long sectors_read;
    unsigned long sectors_written;
    unsigned long time_spent_reading;
    unsigned long time_spent_writing;
    unsigned long weighted_time_IO;
    unsigned long time_spent_doing_IO; // 添加字段用于iowait计算
} DiskStats;

// 读写速率和IOPS的结果结构体
typedef struct {
    char device[DEVICE_NAME_LEN];
    double read_MB_per_sec;
    double write_MB_per_sec;
    unsigned long IOPS;
    double avg_iowait_ms; // 平均每次IO等待时间（毫秒）
} DiskIO;

// DiskStats库的上下文结构体
typedef struct {
    DiskStats previous[MAX_DEVICES];
    int device_count_prev;
} DiskStatsContext;

// 内部辅助函数：检查设备是否需要监控
static int is_monitored_device(const char* device) {
    // 这里只监控以 "sd", "nvme", "vd", "mmcblk" 开头的设备
    const char* prefixes[] = {"sd", "nvme", "vd", "mmcblk"};
    int num_prefixes = sizeof(prefixes) / sizeof(prefixes[0]);
    for (int i = 0; i < num_prefixes; i++) {
        size_t len = strlen(prefixes[i]);
        if (strncmp(device, prefixes[i], len) == 0) {
            return 1;
        }
    }
    return 0;
}

// 初始化上下文
DiskStatsContext* diskstats_init() {
    DiskStatsContext* context = (DiskStatsContext*)malloc(sizeof(DiskStatsContext));
    if (!context) {
        perror("malloc");
        return NULL;
    }
    memset(context->previous, 0, sizeof(context->previous));
    context->device_count_prev = 0;
    return context;
}

// 清理上下文
void diskstats_cleanup(DiskStatsContext* context) {
    if (context) {
        free(context);
    }
}

// 读取并解析 /proc/diskstats
int diskstats_read(DiskStatsContext* context, DiskStats* current, int max_devices) {
    if (!context || !current) {
        return -1;
    }

    FILE *fp = fopen("/proc/diskstats", "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < max_devices) {
        unsigned int major, minor;
        char device[DEVICE_NAME_LEN];
        unsigned long fields[11];
        int parsed = sscanf(line,
                            "%u %u %s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                            &major, &minor, device,
                            &fields[0], &fields[1], &fields[2], &fields[3],
                            &fields[4], &fields[5], &fields[6], &fields[7],
                            &fields[8], &fields[9]);
        if (parsed < 13) {
            continue; // 跳过不完整的行
        }

        // 过滤不需要的设备
        if (!is_monitored_device(device)) {
            continue;
        }

        // 填充结构体
        strncpy(current[count].name, device, DEVICE_NAME_LEN - 1);
        current[count].name[DEVICE_NAME_LEN - 1] = '\0'; // 确保字符串终止
        current[count].reads_completed = fields[0];
        current[count].writes_completed = fields[4];
        current[count].sectors_read = fields[2];
        current[count].sectors_written = fields[6];
        current[count].time_spent_reading = fields[3];
        current[count].time_spent_writing = fields[7];
        current[count].weighted_time_IO = fields[9];
        current[count].time_spent_doing_IO = fields[8]; // 对应字段13
        count++;
    }

    fclose(fp);
    return count;
}

// 计算读写速率、IOPS 和 iowait
int diskstats_calculate(const DiskStats* prev, int device_count_prev,
                        const DiskStats* current, int device_count_current,
                        unsigned int interval_sec, DiskIO* io_results, int max_results) {
    if (!prev || !current || !io_results) {
        return -1;
    }

    int result_count = 0;

    for (int i = 0; i < device_count_current && result_count < max_results; i++) {
        const DiskStats* curr = &current[i];
        // 查找前一次的相同设备
        const DiskStats* prev_dev = NULL;
        for (int j = 0; j < device_count_prev; j++) {
            if (strcmp(curr->name, prev[j].name) == 0) {
                prev_dev = &prev[j];
                break;
            }
        }

        if (prev_dev) {
            unsigned long read_diff = curr->sectors_read - prev_dev->sectors_read;
            unsigned long write_diff = curr->sectors_written - prev_dev->sectors_written;
            unsigned long reads_completed_diff = curr->reads_completed - prev_dev->reads_completed;
            unsigned long writes_completed_diff = curr->writes_completed - prev_dev->writes_completed;
            unsigned long time_spent_doing_IO_diff = curr->time_spent_doing_IO - prev_dev->time_spent_doing_IO;
            unsigned long weighted_time_IO_diff = curr->weighted_time_IO - prev_dev->weighted_time_IO;

            // 动态获取扇区大小
            char sector_path[64];
            snprintf(sector_path, sizeof(sector_path), "/sys/block/%s/queue/hw_sector_size", curr->name);
            FILE *fp = fopen(sector_path, "r");
            unsigned int sector_size = DEFAULT_SECTOR_SIZE;
            if (fp) {
                if (fscanf(fp, "%u", &sector_size) != 1) {
                    sector_size = DEFAULT_SECTOR_SIZE;
                }
                fclose(fp);
            }

            double read_MB_per_sec = ((double)(read_diff * sector_size) / (1024.0 * 1024.0)) / interval_sec;
            double write_MB_per_sec = ((double)(write_diff * sector_size) / (1024.0 * 1024.0)) / interval_sec;
            unsigned long IOPS = (reads_completed_diff + writes_completed_diff) / interval_sec;

            double iowait_ms = 0.0;
            unsigned long total_IOs = reads_completed_diff + writes_completed_diff;
            if (total_IOs > 0) {
                iowait_ms = ((double)(weighted_time_IO_diff - time_spent_doing_IO_diff)) / total_IOs;
            }

            strncpy(io_results[result_count].device, curr->name, DEVICE_NAME_LEN - 1);
            io_results[result_count].device[DEVICE_NAME_LEN - 1] = '\0';
            io_results[result_count].read_MB_per_sec = read_MB_per_sec;
            io_results[result_count].write_MB_per_sec = write_MB_per_sec;
            io_results[result_count].IOPS = IOPS;
            io_results[result_count].avg_iowait_ms = iowait_ms;

            result_count++;
        }
    }

    return result_count;
}

// 打印DiskIO结果，包括iowait
void diskstats_print(const DiskIO* io_results, int io_count, FILE* stream) {
    if (!io_results || io_count <= 0 || !stream) {
        return;
    }

    fprintf(stream, "Disk IO Statistics\n");
    fprintf(stream, "---------------------------------------------------------------------\n");
    fprintf(stream, "%-10s %-12s %-12s %-10s %-12s\n", "Device", "Read(MB/s)", "Write(MB/s)", "IOPS", "iowait(ms)");
    fprintf(stream, "---------------------------------------------------------------------\n");
    for (int i = 0; i < io_count; i++) {
        fprintf(stream, "%-10s %-12.2f %-12.2f %-10lu %-12.2f\n",
                io_results[i].device,
                io_results[i].read_MB_per_sec,
                io_results[i].write_MB_per_sec,
                io_results[i].IOPS,
                io_results[i].avg_iowait_ms);
    }
    fprintf(stream, "---------------------------------------------------------------------\n\n");
}

/**
 * @brief 处理一次I/O统计更新并打印结果
 * 
 * @param context 上下文指针
 * @param current 当前统计数据数组
 * @param device_count_prev 前一次的设备数量
 * @param interval_sec 时间间隔（秒）
 * @return int 成功时返回新的设备数量，失败时返回-1
 */
int process_disk_stats(DiskStatsContext* context, DiskStats* current, int* device_count_prev, unsigned int interval_sec) {
    DiskStats new_stats[MAX_DEVICES];
    int device_count_current = diskstats_read(context, new_stats, MAX_DEVICES);
    if (device_count_current < 0) {
        fprintf(stderr, "Failed to read /proc/diskstats.\n");
        return -1;
    }

    DiskIO io_results[MAX_IO_RESULTS];
    int io_count = diskstats_calculate(current, *device_count_prev,
                                       new_stats, device_count_current,
                                       interval_sec, io_results, MAX_IO_RESULTS);
    if (io_count < 0) {
        fprintf(stderr, "Failed to calculate disk IO statistics.\n");
        return -1;
    }

    // 打印结果，包括iowait
    diskstats_print(io_results, io_count, stdout);

    // 更新前一次的统计数据
    *device_count_prev = device_count_current;
    memcpy(current, new_stats, sizeof(DiskStats) * device_count_current);

    return 0;
}

/*-------------------------------网络部分----------------------------------------*/
//const char *proc_net_save = "/home/ne0/sys_competition/start/cpu_watcher/visualize/proc";
char proc_net_save[MAX_PATH_LEN];
FILE *proc_net_file = NULL; 
FILE *sys_net_file = NULL;

// 网络接口统计结构体
typedef struct {
    char name[32];
    unsigned long long bytes_recv;
    unsigned long long packets_recv;
    unsigned long long errs_recv;
    unsigned long long drop_recv;
    unsigned long long bytes_sent;
    unsigned long long packets_sent;
    unsigned long long errs_sent;
    unsigned long long drop_sent;
} NetDevStats;

static inline void safe_fclose(FILE *fp) {
    if (fp) {
        fclose(fp);
    }
}

static int get_proc_net_path(){
    int ret;
    // 获取当前工作目录
    if (getcwd(proc_net_save, sizeof(proc_net_save)) == NULL) {
        perror("getcwd failed");
        return 1;
    }

    sprintf(proc_net_save, "%s/visualize/proc", proc_net_save);
    
    return 0;
}


// 初始化 CSV 文件
void init_proc_net_csv_file() {
    int ret = get_proc_net_path();
    if(ret != 0){
        fprintf(stderr, "Failed to get proc net path\n");
        return;
    }

    char file_path[256];
    snprintf(file_path, sizeof(file_path), "%s/net.csv", proc_net_save);

    // 检查文件是否存在
    bool write_header = (access(file_path, F_OK) != 0);

    // 在这里打开文件，避免重复打开
    sys_net_file = fopen("/proc/net/dev", "r");
    if (!sys_net_file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    // 打开文件（追加模式）
    proc_net_file = fopen(file_path, "a");
    if (proc_net_file == NULL) {
        perror("Error opening CSV file");
        exit(EXIT_FAILURE);
    }

    // 如果文件是新建的，写入标题
    if (write_header) {
        fprintf(proc_net_file, "Interface,Bytes Received,Packets Received,Errs Rcv,Drops Rcv,"
                               "Bytes Sent,Packets Sent,Errs Sent,Drops Sent\n");
        fflush(proc_net_file);
    }
}

void close_proc_net_csv_file() {
    if (proc_net_file != NULL) {
        fclose(proc_net_file);
        proc_net_file = NULL;
    }

    if(sys_net_file != NULL){
        fclose(sys_net_file);
        sys_net_file = NULL;
    }
}

// 写入数据到 CSV 文件
void append_to_csv(const char *data) {
    if (proc_net_file == NULL) {
        fprintf(stderr, "Error: CSV file is not initialized\n");
        exit(EXIT_FAILURE);
    }
    fprintf(proc_net_file, "%s", data);
    //fflush(proc_net_file); 
}

// 读取 /proc/net/dev 文件，解析网络接口的统计信息
int read_net_dev(NetDevStats **stats, int *count) {
    // FILE *fp = fopen("/proc/net/dev", "r");
    // if (!fp) {
    //     perror("fopen");
    //     return -1;
    // }

    char line[512];
    int line_num = 0;
    int dev_index = 0;
    int max_devs = MAX_DEVICES;
    NetDevStats *dev_stats = malloc(max_devs * sizeof(NetDevStats));
    if (!dev_stats) {
        perror("malloc");
        fclose(sys_net_file);
        return -1;
    }

    while (fgets(line, sizeof(line), sys_net_file)) {
        line_num++;
        // 跳过前两行标题
        if (line_num <= 2)
            continue;

        // 解析每一行
        char iface[32];
        unsigned long long bytes_recv, packets_recv, errs_recv, drop_recv;
        unsigned long long bytes_sent, packets_sent, errs_sent, drop_sent;
        // 格式参考 /proc/net/dev
        // eth0: bytes packets errs drop fifo frame compressed multicast bytes packets errs drop fifo colls carrier compressed
        int scanned = sscanf(line, " %31[^:]: %llu %llu %llu %llu %*u %*u %*u %*u %llu %llu %llu %llu %*u %*u %*u %*u",
                             iface, &bytes_recv, &packets_recv, &errs_recv, &drop_recv,
                             &bytes_sent, &packets_sent, &errs_sent, &drop_sent);
        if (scanned != 9)
            continue; // 解析失败，跳过

        // 如果超过当前分配的大小，重新分配
        if (dev_index >= max_devs) {
            max_devs *= 2;
            NetDevStats *temp = realloc(dev_stats, max_devs * sizeof(NetDevStats));
            if (!temp) {
                perror("realloc");
                free(dev_stats);
                fclose(sys_net_file);
                return -1;
            }
            dev_stats = temp;
        }

        // 填充结构体
        strncpy(dev_stats[dev_index].name, iface, sizeof(dev_stats[dev_index].name) - 1);
        dev_stats[dev_index].name[sizeof(dev_stats[dev_index].name) - 1] = '\0'; // 确保字符串终止
        dev_stats[dev_index].bytes_recv = bytes_recv;
        dev_stats[dev_index].packets_recv = packets_recv;
        dev_stats[dev_index].errs_recv = errs_recv;
        dev_stats[dev_index].drop_recv = drop_recv;
        dev_stats[dev_index].bytes_sent = bytes_sent;
        dev_stats[dev_index].packets_sent = packets_sent;
        dev_stats[dev_index].errs_sent = errs_sent;
        dev_stats[dev_index].drop_sent = drop_sent;

        // 调试输出
        // printf("Parsed Interface: %s | Bytes Received: %llu | Packets Received: %llu | Errs Rcv: %llu | Drops Rcv: %llu | Bytes Sent: %llu | Packets Sent: %llu | Errs Sent: %llu | Drops Sent: %llu\n",
        //        dev_stats[dev_index].name,
        //        dev_stats[dev_index].bytes_recv,
        //        dev_stats[dev_index].packets_recv,
        //        dev_stats[dev_index].errs_recv,
        //        dev_stats[dev_index].drop_recv,
        //        dev_stats[dev_index].bytes_sent,
        //        dev_stats[dev_index].packets_sent,
        //        dev_stats[dev_index].errs_sent,
        //        dev_stats[dev_index].drop_sent);

        dev_index++;
    }

    //fclose(fp);
    *stats = dev_stats;
    *count = dev_index;
    return 0;
}


// 读取 /proc/net/tcp 文件，统计当前TCP连接数
int read_net_tcp(int *tcp_count) {
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    char line[512];
    int line_num = 0;
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        // 跳过第一行标题
        if (line_num == 1)
            continue;

        // 每一行代表一个TCP连接，简单统计行数
        count++;
    }

    fclose(fp);
    *tcp_count = count;
    return 0;
}

// 读取 /proc/net/udp 和 /proc/net/udp6 文件，统计当前UDP连接数
int read_net_udp(int *udp_count) {
    FILE *fp = fopen("/proc/net/udp", "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    char line[512];
    int line_num = 0;
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        // 跳过第一行标题
        if (line_num == 1)
            continue;

        // 每一行代表一个UDP连接，简单统计行数
        count++;
    }

    fclose(fp);

    // 同样读取 /proc/net/udp6
    fp = fopen("/proc/net/udp6", "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    line_num = 0;
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        if (line_num == 1)
            continue;
        count++;
    }

    fclose(fp);
    *udp_count = count;
    return 0;
}

// 打印网络接口的统计信息
void print_net_dev_stats(NetDevStats *stats, int count,bool visualize) {
    printf("\n=== Network Interface Statistics ===\n");
    printf("%-10s %-15s %-15s %-10s %-10s %-15s %-15s %-10s %-10s\n", 
           "Interface", "Bytes Received", "Packets Received", "Errs Rcv", "Drops Rcv", 
           "Bytes Sent", "Packets Sent", "Errs Sent", "Drops Sent");
    // 准备 CSV 数据字符串
    char csv_data[4096] = {0};
    for (int i = 0; i < count; i++) {
        printf("%-10s %-15llu %-15llu %-10llu %-10llu %-15llu %-15llu %-10llu %-10llu\n",
               stats[i].name,
               stats[i].bytes_recv,
               stats[i].packets_recv,
               stats[i].errs_recv,
               stats[i].drop_recv,
               stats[i].bytes_sent,
               stats[i].packets_sent,
               stats[i].errs_sent,
               stats[i].drop_sent);
        if(visualize){
            char line[512];
            snprintf(line, sizeof(line), "%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
                 stats[i].name,
                 stats[i].bytes_recv,
                 stats[i].packets_recv,
                 stats[i].errs_recv,
                 stats[i].drop_recv,
                 stats[i].bytes_sent,
                 stats[i].packets_sent,
                 stats[i].errs_sent,
                 stats[i].drop_sent);
            strcat(csv_data, line);
        }
    }
    // 如果需要写入 CSV 文件
    if (visualize && proc_net_file != NULL) {
        append_to_csv(csv_data); // 追加数据到全局 CSV 文件
    }
}

// 打印当前TCP连接数
void print_tcp_count(int tcp_count) {
    printf("\n=== TCP Connections ===\n");
    printf("Total TCP Connections: %d\n", tcp_count);
}

// 打印当前UDP连接数
void print_udp_count(int udp_count) {
    printf("\n=== UDP Connections ===\n");
    printf("Total UDP Connections: %d\n", udp_count);
}

// 释放网络接口统计结构的内存
void free_net_dev_stats(NetDevStats *stats) {
    if (stats)
        free(stats);
}

// 监控网络
int monitor_network(bool visualize) {
    NetDevStats *dev_stats = NULL;
    int dev_count = 0;
    int tcp_count = 0;
    int udp_count = 0;

    //if(visualize)
    init_proc_net_csv_file();

    // 读取网络接口统计
    if (read_net_dev(&dev_stats, &dev_count) != 0) {
        fprintf(stderr, "Failed to read /proc/net/dev.\n");
        return -1;
    }

    // 读取TCP连接数
    if (read_net_tcp(&tcp_count) != 0) {
        fprintf(stderr, "Failed to read /proc/net/tcp.\n");
        free_net_dev_stats(dev_stats);
        return -1;
    }

    // 读取UDP连接数
    if (read_net_udp(&udp_count) != 0) {
        fprintf(stderr, "Failed to read /proc/net/udp.\n");
        free_net_dev_stats(dev_stats);
        return -1;
    }

    // 打印统计信息
    print_net_dev_stats(dev_stats, dev_count,visualize);
    print_tcp_count(tcp_count);
    print_udp_count(udp_count);

    // 释放分配的内存
    free_net_dev_stats(dev_stats);

    return 0;
}


/*------------------------------mm部分----------------------------------------*/
#define MEMINFO_PATH "/proc/meminfo"
#define MM_INTERVAL 1  // 定时读取的间隔时间（秒）

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


#endif