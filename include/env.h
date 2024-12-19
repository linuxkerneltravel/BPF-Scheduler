#ifndef ENV_H
#define ENV_H

#include <argp.h>       // 提供命令行参数解析功能
#include <stdio.h>      // 提供输入/输出函数，如 printf
#include <stdlib.h>     // 提供通用工具函数，如 atoi
#include <stdbool.h>    // 提供布尔类型支持
#include <string.h>     // 提供字符串处理函数，如 memset 等


struct env {
	int interval; // proc数据延迟
	bool cpu_data;
	bool io_data;
	bool mm_data;
    bool net_data;
	bool visualize;// 是否可视化
    bool std_output;// 终端输出

    bool sched_ext;
};

struct scx_env {
    __u64 p_remove_ns;         // -d: 延迟移除核心的时间（纳秒）
    __u64 r_max;               // -m: 备用巢最大核心数
    __u64 r_impatient;         // -i: 失败次数，触发扩展
    __u64 slice_ns;            // -s: 时间片长度（纳秒）
    bool find_fully_idle;      // -I: 是否优先查找完全空闲核心
    bool verbose;              // -v: 是否输出调试信息
};

// 命令行参数解析
const char argp_args_doc[] =
"Monitor various kernel subsystems\n"
"\n"
"USAGE: monitor [-h] [-i INTERVAL] [-c] [-m] [-n] [-v] [-s] [-e]\n"
"\n"
"EXAMPLES:\n"
"./monitor -i 2 -c\n"
"        Monitor CPU statistics every 2 seconds\n"
"./monitor -i 5 -m -n\n"
"        Monitor memory and network statistics every 5 seconds\n"
"./monitor -v\n"
"        Visualize the data in a graphical interface\n"
"./monitor -i 1 -s\n"
"        Output statistics to the terminal every second\n"
"./monitor -e\n"
"        Enable extended scheduler monitoring\n"
"\n"
"DEFAULTS:\n"
"Interval: 1 second\n"
"CPU, IO, and Memory monitoring are off by default\n"
"Network monitoring is on by default\n"
"Visualization is off by default, and data is output to the terminal\n"
"sched_ext monitoring is off by default\n";

static const struct argp_option argp_options[] = {
    // name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
    {"interval", 'i', "INTERVAL", 0, "Set the monitoring interval in seconds (default: 1)"},
    {"cpu", 'c', NULL, 0, "Enable CPU monitoring"},
    {"io", 'I', NULL, 0, "Enable IO monitoring"},
    {"memory", 'm', NULL, 0, "Enable memory monitoring"},
    {"network", 'n', NULL, 0, "Enable network monitoring"},
    {"visualize", 'v', NULL, 0, "Enable data visualization"},
    {"stdout", 's', NULL, 0, "Output data to the terminal (stdout)"},
    {"sched-ext", 'e', NULL, 0, "Enable extended scheduler monitoring (sched_ext)"}, // 使用短选项 -e
    {NULL, 0, NULL, 0, NULL}
};

// 定义 sched_ext 参数的交互函数
void interactive_sched_ext_config(struct scx_env *sched_env) {
    char input[64];
    printf("\nEntering sched_ext configuration mode. Leave input empty to use defaults.\n");

    // 输入延迟移除时间
    printf("Enter delay before removing an idle core (us) [default: %llu]: ", sched_env->p_remove_ns / 1000);
    if (fgets(input, sizeof(input), stdin) && input[0] != '\n') {
        sched_env->p_remove_ns = strtoull(input, NULL, 0) * 1000;
    }

    // 输入备用巢最大核心数
    printf("Enter maximum number of cores in reserve nest [default: %llu]: ", sched_env->r_max);
    if (fgets(input, sizeof(input), stdin) && input[0] != '\n') {
        sched_env->r_max = strtoull(input, NULL, 0);
    }

    // 输入失败次数
    printf("Enter number of successive placement failures tolerated [default: %llu]: ", sched_env->r_impatient);
    if (fgets(input, sizeof(input), stdin) && input[0] != '\n') {
        sched_env->r_impatient = strtoull(input, NULL, 0);
    }

    // 输入时间片长度
    printf("Enter slice duration (us) [default: %llu]: ", sched_env->slice_ns / 1000);
    if (fgets(input, sizeof(input), stdin) && input[0] != '\n') {
        sched_env->slice_ns = strtoull(input, NULL, 0) * 1000;
    }

    // 是否查找完全空闲核心
    printf("Enable finding fully idle cores? (y/n) [default: %s]: ", sched_env->find_fully_idle ? "y" : "n");
    if (fgets(input, sizeof(input), stdin) && input[0] != '\n') {
        sched_env->find_fully_idle = (input[0] == 'y' || input[0] == 'Y');
    }

    // 是否启用调试模式
    printf("Enable verbose mode? (y/n) [default: %s]: ", sched_env->verbose ? "y" : "n");
    if (fgets(input, sizeof(input), stdin) && input[0] != '\n') {
        sched_env->verbose = (input[0] == 'y' || input[0] == 'Y');
    }

    printf("\nSched_ext configuration complete:\n");
    printf("  Delay (ns): %llu\n", sched_env->p_remove_ns);
    printf("  Reserve max cores: %llu\n", sched_env->r_max);
    printf("  Impatient iterations: %llu\n", sched_env->r_impatient);
    printf("  Slice duration (ns): %llu\n", sched_env->slice_ns);
    printf("  Find fully idle cores: %s\n", sched_env->find_fully_idle ? "Enabled" : "Disabled");
    printf("  Verbose mode: %s\n", sched_env->verbose ? "Enabled" : "Disabled");

    return 0;
}

#endif 