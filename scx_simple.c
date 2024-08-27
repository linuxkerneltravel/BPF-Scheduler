/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_simple.bpf.skel.h"

const char help_fmt[] =
"A simple sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;// 全局变量，控制调试信息的输出
static volatile int exit_req;// 全局变量，控制程序退出

// 自定义的libbpf库打印函数，用于控制调试信息输出
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	// 如果level为LIBBPF_DEBUG且verbose为false，则不输出调试信息
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

// 信号处理函数，用于处理SIGINT和SIGTERM信号
static void sigint_handler(int simple)
{
	exit_req = 1;
}

// 读取调度器统计数据的函数
static void read_stats(struct scx_simple *skel, __u64 *stats)
{
	// 获取CPU核数
	int nr_cpus = libbpf_num_possible_cpus();
	// 二维数组，用于存储每个CPU的计数数据
	__u64 cnts[2][nr_cpus];
	__u32 idx;

	// 初始化stats数组
	memset(stats, 0, sizeof(stats[0]) * 2);

	// 遍历两个索引（通常代表不同的统计类型，例如任务计数和CPU时间）
	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		// 从BPF映射中读取计数数据
		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)// 如果读取失败，则跳过
			continue;
		// 将所有CPU的计数数据累加到stats数组中
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	struct scx_simple *skel;// BPF程序的骨架，管理BPF对象的生命周期
	struct bpf_link *link;// BPF链接对象，用于管理BPF程序的附加状态
	__u32 opt;// 用于处理命令行选项
	__u64 ecode;// 用于存储退出码或错误码

	// 设置libbpf的打印函数
	libbpf_set_print(libbpf_print_fn);
	// 设置信号处理函数，用于捕捉SIGINT和SIGTERM信号
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	// 标签，用于重新启动BPF程序
restart:
	// 打开BPF骨架程序
	skel = SCX_OPS_OPEN(simple_ops, scx_simple);

	while ((opt = getopt(argc, argv, "fvh")) != -1) {
		switch (opt) {
		// 如果指定了-f选项，启用FIFO调度
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		// 如果指定了-v选项，启用详细模式
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}
	// 加载BPF程序到内核
	SCX_OPS_LOAD(skel, simple_ops, scx_simple, uei);
	// 将BPF程序附加到适当的挂载点或钩子
	link = SCX_OPS_ATTACH(skel, simple_ops, scx_simple);

	// 主循环，直到收到退出请求或BPF程序报告退出
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[2];

		// 读取调度器统计数据
		read_stats(skel, stats);
		// 打印本地和全局的调度统计数据
		printf("local=%llu global=%llu\n", stats[0], stats[1]);
		fflush(stdout);
		sleep(1);
	}

	// 销毁BPF链接
	bpf_link__destroy(link);
	// 获取BPF程序的退出码或错误码
	ecode = UEI_REPORT(skel, uei);
	// 销毁BPF骨架，释放资源
	scx_simple__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
