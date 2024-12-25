#ifndef __SCX_NEST_H
#define __SCX_NEST_H

struct comm_info {
	char comm[16];
};

// 官方的输出因为和内核的bss段有联系，容易出问题，这里改成用perf来输出
struct cpu_mask_data {
	u64 stats_primary_mask;
	u64 stats_reserved_mask;
	u64 stats_other_mask;
	u64 stats_idle_mask;
};

enum nest_stat_group {
	STAT_GRP_WAKEUP,
	STAT_GRP_NEST,
	STAT_GRP_CONSUME,
};

#define NEST_STAT(__stat) BPFSTAT_##__stat
#define NEST_ST(__stat, __grp, __desc) NEST_STAT(__stat),
enum nest_stat_idx {
#include "scx_nest_stats_table.h"
	NEST_ST(NR, 0, 0)
};
#undef NEST_ST

#endif /* __SCX_NEST_H */
