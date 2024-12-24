#ifndef ENV_H
#define ENV_H

#include <argp.h>       // 提供命令行参数解析功能
#include <stdio.h>      // 提供输入/输出函数，如 printf
#include <stdlib.h>     // 提供通用工具函数，如 atoi
#include <stdbool.h>    // 提供布尔类型支持
#include <string.h>     // 提供字符串处理函数，如 memset 等

struct scx_env {
    __u64 p_remove_ns;         // -d: 延迟移除核心的时间（纳秒）
    __u64 r_max;               // -m: 备用巢最大核心数
    __u64 r_impatient;         // -i: 失败次数，触发扩展
    __u64 slice_ns;            // -s: 时间片长度（纳秒）
    bool find_fully_idle;      // -I: 是否优先查找完全空闲核心
    bool verbose;              // -v: 是否输出调试信息
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