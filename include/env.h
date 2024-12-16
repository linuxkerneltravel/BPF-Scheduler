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
};

const char argp_args_doc[] =
"Monitor various kernel subsystems\n"
"\n"
"USAGE: monitor [-h] [-i INTERVAL] [-c] [-m] [-n] [-v] [-s]\n"
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
"\n"
"DEFAULTS:\n"
"Interval: 1 second\n"
"CPU, IO, and Memory monitoring are off by default\n"
"Network monitoring is on by default\n"
"Visualization is off by default, and data is output to the terminal\n";

static const struct argp_option argp_options[] = {
    // name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
    {"interval", 'i', "INTERVAL", 0, "Set the monitoring interval in seconds (default: 1)"},
    {"cpu", 'c', NULL, 0, "Enable CPU monitoring"},
    {"io", 'I', NULL, 0, "Enable IO monitoring"},
    {"memory", 'm', NULL, 0, "Enable memory monitoring"},
    {"network", 'n', NULL, 0, "Enable network monitoring"},
    {"visualize", 'v', NULL, 0, "Enable data visualization"},
    {"stdout", 's', NULL, 0, "Output data to the terminal (stdout)"},
    {NULL, 0, NULL, 0, NULL}
};

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
    case ARGP_KEY_ARG:
    case ARGP_KEY_END:
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}


#endif 