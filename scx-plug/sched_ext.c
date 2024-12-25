/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 */
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>

#include "scx_nest.skel.h"
#include "scx_nest.h"
#include "env.h"

#define SAMPLING_CADENCE_S 2

static struct scx_env env = {
    .p_remove_ns = 2000 * 1000,  // 默认 2000us 转换为纳秒
    .r_max = 5,                  // 默认最大备用核心数
    .r_impatient = 2,            // 默认失败次数
    .slice_ns = 20000 * 1000,    // 默认时间片 20000us 转换为纳秒
    .find_fully_idle = false,    // 默认不查找完全空闲核心
    .verbose = false,            // 默认关闭调试信息
};

static void scx_parse_args(int argc, char **argv) {
    int opt;

    while ((opt = getopt(argc, argv, "d:m:i:s:Ivh")) != -1) {
        switch (opt) {
        case 'd':
            env.p_remove_ns = strtoull(optarg, NULL, 0) * 1000;
            break;
        case 'm':
            env.r_max = strtoull(optarg, NULL, 0);
            break;
        case 'i':
            env.r_impatient = strtoull(optarg, NULL, 0);
            break;
        case 's':
            env.slice_ns = strtoull(optarg, NULL, 0) * 1000;
            break;
        case 'I':
            env.find_fully_idle = true;
            break;
        case 'v':
            env.verbose = true;
            break;
        default:
            fprintf(stderr, help_fmt, basename(argv[0]));
            exit(opt != 'h');
        }
    }
}


static bool verbose;
static volatile int exit_req;

static int scx_libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int nest)
{
	exit_req = 1;
}

struct nest_stat {
        const char *label;
        enum nest_stat_group group;
        enum nest_stat_idx idx;
};

#define NEST_ST(__stat, __grp, __desc) {	\
	.label = #__stat,		\
	.group = __grp,			\
	.idx = NEST_STAT(__stat)		\
},
static struct nest_stat nest_stats[NEST_STAT(NR)] = {
#include "scx_nest_stats_table.h"
};
#undef NEST_ST

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
	}
}

int main(int argc, char **argv) {
    struct scx_nest_bpf *skel;
    struct bpf_link *link;
    __u64 ecode;

    // 初始化调试打印函数和信号处理
    libbpf_set_print(scx_libbpf_print_fn);
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    // 解析命令行参数
    scx_parse_args(argc, argv);

restart:
    skel = SCX_OPS_OPEN(nest_ops, scx_nest_bpf);

    // 初始化只读数据
    skel->rodata->nr_cpus = libbpf_num_possible_cpus();
    skel->rodata->sampling_cadence_ns = SAMPLING_CADENCE_S * 1000 * 1000 * 1000;
    skel->rodata->p_remove_ns = env.p_remove_ns;
    skel->rodata->r_max = env.r_max;
    skel->rodata->r_impatient = env.r_impatient;
    skel->rodata->slice_ns = env.slice_ns;
    skel->rodata->find_fully_idle = env.find_fully_idle;

    SCX_OPS_LOAD(skel, nest_ops, scx_nest_bpf, uei);
    link = SCX_OPS_ATTACH(skel, nest_ops, scx_nest_bpf);

    while (!exit_req && !UEI_EXITED(skel, uei)) {
        u64 stats[NEST_STAT(NR)];
        enum nest_stat_idx i;
        enum nest_stat_group last_grp = -1;

        scx_read_stats(skel, stats);
        for (i = 0; i < NEST_STAT(NR); i++) {
            struct nest_stat *nest_stat = &nest_stats[i];
            if (nest_stat->group != last_grp) {
                scx_print_stat_grp(nest_stat->group);
                last_grp = nest_stat->group;
            }
            printf("%s=%" PRIu64 "\n", nest_stat->label, stats[nest_stat->idx]);
        }
        printf("\n");
        print_active_nests(skel);
        printf("\n\n\n");
        fflush(stdout);
        sleep(SAMPLING_CADENCE_S);
    }

    bpf_link__destroy(link);
    ecode = UEI_REPORT(skel, uei);
    scx_nest_bpf__destroy(skel);

    if (UEI_ECODE_RESTART(ecode))
        goto restart;
    return 0;
}
