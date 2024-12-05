#ifndef PROC_DATA_H
#define PROC_DATA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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



#endif