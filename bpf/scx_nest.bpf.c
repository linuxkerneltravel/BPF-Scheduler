/* SPDX-License-Identifier: GPL-2.0 */
/*
 * As described in [0], a Nest scheduler which encourages task placement on
 * cores that are likely to be running at higher frequency, based upon recent usage.
 *
 * [0]: https://hal.inria.fr/hal-03612592/file/paper.pdf
 *
 * It operates as a global weighted vtime scheduler (similarly to CFS), while
 * using the Nest algorithm to choose idle cores at wakup time.
 *
 * It also demonstrates the following niceties.
 *
 * - More robust task placement policies.
 * - Termination notification for userspace.
 *
 * While rather simple, this scheduler should work reasonably well on CPUs with
 * a uniform L3 cache topology. While preemption is not implemented, the fact
 * that the scheduling queue is shared across all CPUs means that whatever is
 * at the front of the queue is likely to be executed fairly quickly given
 * enough number of CPUs.
 *
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 */
#include <scx/common.bpf.h>

#include "scx_nest.h"

#define TASK_DEAD                       0x00000080

char _license[] SEC("license") = "Dual BSD/GPL";

enum {
	FALLBACK_DSQ_ID		= 0,// 默认调度队列的标识符。
	MSEC_PER_SEC		= 1000LLU,// 每秒包含的毫秒数。
	USEC_PER_MSEC		= 1000LLU,// 每毫秒包含的微秒数。
	NSEC_PER_USEC		= 1000LLU,// 每微秒包含的纳秒数。
	NSEC_PER_MSEC		= USEC_PER_MSEC * NSEC_PER_USEC,// 每毫秒包含的纳秒数。
	USEC_PER_SEC		= USEC_PER_MSEC * MSEC_PER_SEC,// 每秒包含的微秒数。
	NSEC_PER_SEC		= NSEC_PER_USEC * USEC_PER_SEC,// 每秒包含的纳秒数。
};

// 定义了一个宏，用于表示系统启动时间类型的时钟
#define CLOCK_BOOTTIME 7 // CLOCK_BOOTTIME 是一个内核时钟源，表示从系统启动到当前的挂钟时间（包括休眠时间）
#define NUMA_NO_NODE -1 // NUMA节点标识，-1表示任务未绑定到任何NUMA节点
#define COMPARE_COMM_LEN 6 // 用于比较的任务名称前缀的

// 常量定义，通常用于调度器中的各种超时和限制
const volatile u64 p_remove_ns = 2 * NSEC_PER_MSEC;// Primary nest的移除时间阈值，单位为纳秒
//const volatile u64 p_remove_ns = 4 * NSEC_PER_MSEC;// 这里根据实验改成了4ms
const volatile u64 r_max = 5; // Reserve nest的最大核心数量
const volatile u64 r_impatient = 2; // 任务切换的容忍次数阈值
const volatile u64 slice_ns = SCX_SLICE_DFL; // 默认时间片长度，具体值通过其他宏定义或配置
const volatile bool find_fully_idle = false; // 是否启用寻找完全空闲核心的策略，false表示不启用
const volatile u64 sampling_cadence_ns = 1 * NSEC_PER_SEC; // 采样间隔时间，单位为纳秒
const volatile u64 r_depth = 5; // Reserve nest的搜索深度限制

const char bad_guy[] = "stress-ng"; // 用于标识恶意任务的名称

// 用于统计信息跟踪。这些值可能会有滞后
u64 stats_primary_mask, stats_reserved_mask, stats_other_mask, stats_idle_mask;

// 用于内部跟踪的静态变量
static s32 nr_reserved;// 当前reserve nest中的核心数量

// 当前的虚拟时间戳，用于时间管理和调度器逻辑
static u64 vtime_now;

// 内核中自定义的事件，用于某些内部状态跟踪或记录日志
UEI_DEFINE(uei);

// 外部变量，表示内核配置中设置的每秒调度时钟滴答数（通常与系统定时器频率相关）
extern unsigned long CONFIG_HZ __kconfig;// CONFIG_HZ 表示系统的调度时钟频率，通常为100、250或1000

/* Per-task scheduling context */
struct task_ctx {
	/*
	 * 一个临时的 CPU 掩码，用于计算任务的 primary 和 reserve mask。
	 * 它可能存储任务当前可用核心的集合。
	 */
	struct bpf_cpumask __kptr *tmp_mask;

	/*
	 * 记录任务观察到其上次运行核心不空闲的次数。
	 * 如果连续发生 `r_impatient` 次，将尝试从 Reserve Nest 或 Fallback Nest 分配核心。
	 */
	u32 prev_misses;

	/*
	 * 任务“附加”的核心：最近连续两次以上运行的核心。
	 * 唤醒时，任务会首先尝试迁移到这个核心。
	 * 只有当核心空闲且属于 Primary Nest 时，任务才会迁移到该核心。
	 */
	s32 attached_core;

	/*
	 * 任务最后一次运行的核心。
	 * 用于决定任务是否需要附加到下一次运行的核心。
	 */
	s32 prev_cpu;
};

// 任务的 CPU 使用情况,和cpu_event那边一样,这边引入是方便动态调节时间片
struct task_info_simple{
    u32 pid;                
    u32 tgid;               
    u32 cpu_id; 
    char comm[TASK_COMM_LEN];
};

struct task_cpu_usage {
    struct  task_info_simple task_info;

    //bool already_backtrace;
    bool in_kernel;
    bool in_process;
    bool already_output;

    u64 user_time_ns;       
    u64 kernel_time_ns;     
    u64 total_time_ns;     
    u64 last_run_time; 
    u64 last_enqeue_time;

    u64 wait_time;
    u64 last_clear_time;
    u64 last_trace_time;

    u32 user_percent;       
    u32 kernel_percent;     
    u32 total_percent;     
};

// 任务的调度上下文 (task_ctx)
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

// 每个物理核心的上下文信息，主要与核心的压缩（compaction）状态相关
struct pcpu_ctx {
	/*
	 * 定时器，用于在核心从 Primary Nest 中移除时执行压缩操作。
	 */
	struct bpf_timer timer;

	/*
	 * 表示当前核心是否已被安排进行压缩。
	 */
	bool scheduled_compaction;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, s32);
	__type(value, struct pcpu_ctx);
} pcpu_ctxs SEC(".maps");

struct stats_timer {
	// 统计定时器，用于全局统计信息
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct stats_timer);
} stats_timer SEC(".maps");

/*-----------------和cpu_stats交互来抑制异常task-----------------------*/
struct cpu_bad_guys {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, u32);
	__type(value, u32);
} cpu_bad_guys_map SEC(".maps");

// struct{
// 	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
// 	__uint(max_entries, 1);
// 	__type(key, u32);
// 	__type(value, int); // 子 Map 的文件描述符
// } cpu_filter_ids SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, u32);
	__array(values,struct cpu_bad_guys);
} cpu_filter_ids SEC(".maps");


struct task_cpu_usage_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__type(key, u32);
	__type(value, struct task_cpu_usage);
} task_usage_map SEC(".maps");


struct{
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, u32);
	__array(values,struct task_cpu_usage_map);
} cpu_task_usage_map SEC(".maps");


// 处理用户态传的可能被误伤的任务名
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct comm_info);
	__type(value, u32);
} comm_ignore_map SEC(".maps");

// 处理用户态传的要去特别注意的任务
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct comm_info);
	__type(value, u32);
} comm_attention_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  
} cpu_mask_buffer SEC(".maps");

const volatile u32 nr_cpus = 1; /* !0 for veristat, set during init. */

private(NESTS) struct bpf_cpumask __kptr *primary_cpumask;// 表示 Primary Nest 中可用的核心集合
private(NESTS) struct bpf_cpumask __kptr *reserve_cpumask;// 表示 Reserve Nest 中的核心集合

// 对于每个核心，记录运行时的重要统计信息，如核心迁移、降级、提升和容量限制等行为
// 每个键代表一种统计事件，例如 PROMOTED_TO_RESERVED 表示核心被提升到 Reserve Nest
// 每个值代表该事件发生的次数
// 通过 stat_inc 调用，动态更新统计计数，用于分析和优化调度策略
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, NEST_STAT(NR));
} stats SEC(".maps");


static __always_inline void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

// 比较两个虚拟时间 a 和 b，判断 a 是否早于 b
static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

// 试图将指定核心（cpu）标记为 Reserve 核心
static __always_inline void
try_make_core_reserved(s32 cpu, struct bpf_cpumask * reserved, bool promotion)
{
	s32 tmp_nr_reserved;

	/*
	 * 这个检查可能会产生竞争条件，但问题不大。如果我们错误地
	 * 未能将核心提升到 Reserve Nest，是因为在这个小窗口中
	 * 另一个上下文添加或移除了 Reserve 核心。这种情况会在后续
	 * 唤醒中被平衡。
	 */
	tmp_nr_reserved = nr_reserved;
	// 根据当前 Reserve 核心数量（nr_reserved）判断是否可以将核心加入 Reserve Nest
	// 如果允许，将其标记为 Reserve 并更新统计信息；否则，记录达容量限制的情况
	if (tmp_nr_reserved < r_max) { 
		/*
		 * 这里可能会短时间超过 r_max 的限制，但随着更多核心被降级
		 * 或未能被提升到 Reserve Nest，这种情况会被平衡。
		 */
		__sync_fetch_and_add(&nr_reserved, 1);// 原子增加 Reserve 核心计数
		bpf_cpumask_set_cpu(cpu, reserved);// 将指定的核心加入 Reserve 掩码
		if (promotion)
			stat_inc(NEST_STAT(PROMOTED_TO_RESERVED));// 统计核心被提升次数
		else
			stat_inc(NEST_STAT(DEMOTED_TO_RESERVED)); // 统计核心被降级次数
	} else {
		bpf_cpumask_clear_cpu(cpu, reserved);// 如果 Reserve 已满，清除该核心
		stat_inc(NEST_STAT(RESERVED_AT_CAPACITY));// 统计 Reserve 达容量限制的次数
	}
}

// 更新任务上下文（task_ctx）中的核心绑定信息
// 如果任务的当前核心（new_cpu）与之前的核心（prev_cpu）相同，则将该核心设置为任务的附加核心（attached_core），以优化核心复用
static void update_attached(struct task_ctx *tctx, s32 prev_cpu, s32 new_cpu)
{
	if (tctx->prev_cpu == new_cpu)
		tctx->attached_core = new_cpu;// 如果任务的上一次核心与当前核心相同，则附加到当前核心
	tctx->prev_cpu = prev_cpu;// 更新任务的上一次核心记录
}

// 执行 Primary Nest 的核心压缩操作，将当前核心从 Primary Nest 降级到 Reserve Nest
// 当核心长时间未使用时（由定时器触发），调用该函数进行压缩
static int compact_primary_core(void *map, int *key, struct bpf_timer *timer)
{
	struct bpf_cpumask *primary, *reserve;
	s32 cpu = bpf_get_smp_processor_id();
	struct pcpu_ctx *pcpu_ctx;

	stat_inc(NEST_STAT(CALLBACK_COMPACTED));// 增加压缩操作的回调次数

	/*
	 * 如果进入了这个回调，说明定时器的回调未被取消，因此核心需要
	 * 从 Primary Nest 降级。
	 */
	pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &cpu);// 查找当前核心的上下文
	if (!pcpu_ctx) {
		scx_bpf_error("Couldn't lookup pcpu ctx");// 如果上下文为空，记录错误并退出
		return 0;
	}
	bpf_rcu_read_lock();// 加锁以保护访问
	primary = primary_cpumask; // 获取 Primary Nest 的核心掩码
	reserve = reserve_cpumask; // 获取 Reserve Nest 的核心掩码
	if (!primary || !reserve) {
		scx_bpf_error("Couldn't find primary or reserve");// 如果任何一个掩码为空，记录错误并退出
		bpf_rcu_read_unlock();
		return 0;
	}

	// 将当前核心从 Primary Nest 移除
	bpf_cpumask_clear_cpu(cpu, primary);
	// 尝试将核心降级到 Reserve Nest
	try_make_core_reserved(cpu, reserve, false);
	bpf_rcu_read_unlock();// 解锁

	// 更新核心上下文的压缩状态
	pcpu_ctx->scheduled_compaction = false;
	return 0;
}

// 对于处理过了，相当于dispatch了，就return 0，否则return 1交给正常调度
static int operate_bad_guys(struct task_struct *p,u64 enq_flags){
	// 对于内核任务直接跳了，怕影响出问题
	if(p->flags & PF_KTHREAD)
		return 1;
	struct comm_info name;
	bpf_probe_read_kernel_str(name.comm,sizeof(p->comm),p->comm);
	// 跳过误伤名单的
	u32 *ident = bpf_map_lookup_elem(&comm_ignore_map,&name);
	if(ident){
		return 1;
	}
	// 对特别关注的问题任务控制调度
	ident = bpf_map_lookup_elem(&comm_attention_map,&name);
	if(ident){
		u64 vtime = p->scx.dsq_vtime;// 获取任务的虚拟时间
		if (vtime_before(vtime, vtime_now - slice_ns))
			vtime = vtime_now - slice_ns;
		scx_bpf_dispatch_vtime(p, FALLBACK_DSQ_ID, slice_ns/2, vtime,
			       enq_flags);
		return 0;
	}
	u32 zero = 0;
	struct cpu_bad_guys *bad_guy = bpf_map_lookup_elem(&cpu_filter_ids,&zero);
	u32 pid = p->pid;
	if(bad_guy){
		ident = bpf_map_lookup_elem(bad_guy,&pid);
		if(ident){
			u64 vtime = p->scx.dsq_vtime;// 获取任务的虚拟时间
			if (vtime_before(vtime, vtime_now - slice_ns))
				vtime = vtime_now - slice_ns;
			scx_bpf_dispatch_vtime(p, FALLBACK_DSQ_ID, slice_ns/2, vtime,
			       enq_flags);
			return 0;
		}
	}

	return 1;
}

s32 BPF_STRUCT_OPS(nest_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct bpf_cpumask *p_mask, *primary, *reserve;
	s32 cpu;
	struct task_ctx *tctx;
	struct pcpu_ctx *pcpu_ctx;
	bool direct_to_primary = false, reset_impatient = true;

	// 初始化和上下文获取
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx)
		return -ENOENT;

	// 获取 Primary 和 Reserve Nest 的核心掩码，用于后续的核心选择
	bpf_rcu_read_lock();
	p_mask = tctx->tmp_mask;
	primary = primary_cpumask;
	reserve = reserve_cpumask;
	if (!p_mask || !primary || !reserve) {
		bpf_rcu_read_unlock();
		return -ENOENT;
	}

	tctx->prev_cpu = prev_cpu;

	bpf_cpumask_and(p_mask, p->cpus_ptr, cast_mask(primary));

	/* First try to wake the task on its attached core. */
	// 如果任务附加的核心（attached_core）处于空闲状态，直接选择该核心
	if (bpf_cpumask_test_cpu(tctx->attached_core, cast_mask(p_mask)) &&
	    scx_bpf_test_and_clear_cpu_idle(tctx->attached_core)) {
		cpu = tctx->attached_core;
		stat_inc(NEST_STAT(WAKEUP_ATTACHED));
		goto migrate_primary;
	}

	/*
	 * Try to stay on the previous core if it's in the primary set, and
	 * there's no hypertwin. If the previous core is the core the task is
	 * attached to, don't bother as we already just tried that above.
	 */
	// 尝试复用任务的上次核心（prev_cpu）
	// 如果任务的上次核心（prev_cpu）不等于附加核心，并且空闲，则选择上次核心
	if (prev_cpu != tctx->attached_core &&
	    bpf_cpumask_test_cpu(prev_cpu, cast_mask(p_mask)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		stat_inc(NEST_STAT(WAKEUP_PREV_PRIMARY));
		goto migrate_primary;
	}

	// Primary Nest 中寻找空闲核心
	// 如果启用了寻找完全空闲核心的策略，优先选择 Primary Nest 中完全空闲的核心
	if (find_fully_idle) {
		/* Then try any fully idle core in primary. */
		cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask),
					    SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			stat_inc(NEST_STAT(WAKEUP_FULLY_IDLE_PRIMARY));
			goto migrate_primary;
		}
	}

	/* Then try _any_ idle core in primary, even if its hypertwin is active. */
	// 如果未找到完全空闲核心，则选择任意空闲核心
	cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask), 0);
	if (cpu >= 0) {
		stat_inc(NEST_STAT(WAKEUP_ANY_IDLE_PRIMARY));
		goto migrate_primary;
	}

	// r_impatient 用于控制任务切换的容忍次数
	// 如果任务连续 r_impatient 次未能分配到 Primary Nest 中的核心，则认为任务变得 "不耐烦"
	// prev_misses 记录任务连续未能分配到 Primary Nest 中的核心的次数,记录任务未分配到合适核心的连续失败次数
	if (r_impatient > 0 && ++tctx->prev_misses >= r_impatient) {
		direct_to_primary = true;// 设置 direct_to_primary = true，表示任务在下一步会直接选择 Primary Nest 的核心
		tctx->prev_misses = 0;
		stat_inc(NEST_STAT(TASK_IMPATIENT));// 统计一次 "任务不耐烦" 事件（TASK_IMPATIENT）
	}

	reset_impatient = false;

	/* Then try any fully idle core in reserve. */
	// 如果 Primary Nest 中没有合适的核心，则转向 Reserve Nest
	bpf_cpumask_and(p_mask, p->cpus_ptr, cast_mask(reserve));
	if (find_fully_idle) {
		cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask),
					    SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			stat_inc(NEST_STAT(WAKEUP_FULLY_IDLE_RESERVE));
			goto promote_to_primary;
		}
	}

	/* Then try _any_ idle core in reserve, even if its hypertwin is active. */
	// 如果没有完全空闲核心，选择 Reserve Nest 中任意空闲核心
	cpu = scx_bpf_pick_idle_cpu(cast_mask(p_mask), 0);
	if (cpu >= 0) {
		stat_inc(NEST_STAT(WAKEUP_ANY_IDLE_RESERVE));
		goto promote_to_primary;// 如果找到核心，则将其提升到 Primary Nest
	}

	/* Then try _any_ idle core in the task's cpumask. */
	// 在任务允许的 CPU 集合中寻找空闲核心
	// 如果 Primary 和 Reserve Nest 都没有可用核心，则尝试任务允许的 CPU 集合（p->cpus_ptr）
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);// 从任务允许的 CPU 集合中选择任意空闲核心
	if (cpu >= 0) {
		/*
		 * We found a core that (we didn't _think_) is in any nest.
		 * This means that we need to either promote the core to the
		 * reserve nest, or if we're going direct to primary due to
		 * r_impatient being exceeded, promote directly to primary.
		 *
		 * We have to do one final check here to see if the core is in
		 * the primary or reserved cpumask because we could potentially
		 * race with the core changing states between AND'ing the
		 * primary and reserve masks with p->cpus_ptr above, and
		 * atomically reserving it from the idle mask with
		 * scx_bpf_pick_idle_cpu(). This is also technically true of
		 * the checks above, but in all of those cases we just put the
		 * core directly into the primary mask so it's not really that
		 * big of a problem. Here, we want to make sure that we don't
		 * accidentally put a core into the reserve nest that was e.g.
		 * already in the primary nest. This is unlikely, but we check
		 * for it on what should be a relatively cold path regardless.
		 */
		stat_inc(NEST_STAT(WAKEUP_IDLE_OTHER));
		if (bpf_cpumask_test_cpu(cpu, cast_mask(primary)))// 如果核心属于 Primary Nest，直接迁移
			goto migrate_primary;
		else if (bpf_cpumask_test_cpu(cpu, cast_mask(reserve)))// 如果核心属于 Reserve Nest，提升到 Primary Nest
			goto promote_to_primary;
		else if (direct_to_primary)// 当任务连续r_impatient次未分配到Primary Nest的核心，就会直接进入promote_to_primary路径
			goto promote_to_primary;
		else
			try_make_core_reserved(cpu, reserve, true);// 如果不属于任何 Nest，将其标记为 Reserve 核心
		bpf_rcu_read_unlock();
		return cpu;
	}

	bpf_rcu_read_unlock();
	return prev_cpu;


// promote_to_primary 和 migrate_primary 是处理核心状态调整的两个关键路径
// 分别实现核心从 Reserve 提升到 Primary 和直接迁移到 Primary
// promote_to_primary就多了个统计PROMOTED_TO_PRIMARY 提升事件
promote_to_primary:
	stat_inc(NEST_STAT(PROMOTED_TO_PRIMARY));
migrate_primary:// 直接迁移到 Primary
	// 如果 reset_impatient 为真（任务在 Reserve Nest 未达到 r_impatient 阈值时分配到核心）
	// 则重置 prev_misses 计数，表示任务分配成功，结束当前连续失败状态
	if (reset_impatient)
		tctx->prev_misses = 0;
	pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &cpu);
	// 如果核心已被标记为即将从 Primary Nest 移除（scheduled_compaction 为真），则取消对应的压缩定时器，防止核心被错误移除
	if (pcpu_ctx) {
		if (pcpu_ctx->scheduled_compaction) {
			// 如果核心被标记为即将被压缩，从 Primary Nest 移除，则取消定时器
			// 核心被压缩（compaction），指的是将Primary Nest 中长时间未使用或低优先级的核心移出 Primary Nest，并将其降级到 Reserve Nest 或其他状态
			if (bpf_timer_cancel(&pcpu_ctx->timer) < 0)
				scx_bpf_error("Failed to cancel pcpu timer");
			// 重新设置核心压缩的回调函数
			if (bpf_timer_set_callback(&pcpu_ctx->timer, compact_primary_core))
				scx_bpf_error("Failed to re-arm pcpu timer");
			// 标记核心不再处于压缩计划中
			pcpu_ctx->scheduled_compaction = false;
			// 记录统计事件：压缩定时器被取消
			stat_inc(NEST_STAT(CANCELLED_COMPACTION));
		}
	} else {
		scx_bpf_error("Failed to lookup pcpu ctx");
	}
	// 标记核心为 Primary 成员
	bpf_cpumask_set_cpu(cpu, primary);
	/*
	 * Check to see whether the CPU is in the reserved nest. This can
	 * happen if the core is compacted concurrently with us trying to place
	 * the currently-waking task onto it. Similarly, this is the expected
	 * state of the core if we found the core in the reserve nest and are
	 * promoting it.
	 *
	 * We don't have to worry about racing with any other waking task here
	 * because we've atomically reserved the core with (some variant of)
	 * scx_bpf_pick_idle_cpu().
	 */
	// // 如果核心同时存在于 Reserve Nest，则更新 Reserve 状态,从 Reserve Nest 中移除核心
	if (bpf_cpumask_test_cpu(cpu, cast_mask(reserve))) {
		__sync_sub_and_fetch(&nr_reserved, 1);
		bpf_cpumask_clear_cpu(cpu, reserve);
	}
	bpf_rcu_read_unlock();
	// 调用 update_attached 更新任务的附加核心（attached_core）和前一次运行核心（prev_cpu），为下一次调度做准备
	update_attached(tctx, prev_cpu, cpu);
	//scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, 0);

	// 开始过滤特殊任务
	int ret = operate_bad_guys(p,0);
	if(ret == 1)
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | cpu  , slice_ns, 0);
	//scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | cpu , slice_ns, 0);
	return cpu;
}

void BPF_STRUCT_OPS(nest_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 vtime = p->scx.dsq_vtime;// 获取任务的虚拟时间

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("Unable to find task ctx");
		return;
	}

	/*
	 * 限制任务的虚拟时间累计。
	 * 如果任务已经长时间未被调度，虚拟时间不应超过一个 slice。
	 */
	// 这样可以限制任务积累过多未使用的预算，避免长时间未调度的任务突然抢占大量 CPU 时间
	if (vtime_before(vtime, vtime_now - slice_ns))
		vtime = vtime_now - slice_ns;

	// 开始过滤特殊任务
	int ret = operate_bad_guys(p,enq_flags);
	if(ret == 1)
		scx_bpf_dispatch_vtime(p, FALLBACK_DSQ_ID, slice_ns, vtime,
			       enq_flags);
}

// 消耗在global dsq的任务
void BPF_STRUCT_OPS(nest_dispatch, s32 cpu, struct task_struct *prev)
{
	struct pcpu_ctx *pcpu_ctx;
	struct bpf_cpumask *primary, *reserve;
	s32 key = cpu;
	bool in_primary;

	primary = primary_cpumask;
	reserve = reserve_cpumask;
	if (!primary || !reserve) {
		scx_bpf_error("No primary or reserve cpumask");
		return;
	}

	pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &key);
	if (!pcpu_ctx) {
		scx_bpf_error("Failed to lookup pcpu ctx");
		return;
	}

	// 如果队列中的任务被消耗完了，即scx_bpf_consume(FALLBACK_DSQ_ID) 返回 false
	if (!scx_bpf_consume(FALLBACK_DSQ_ID)) {
		// 使用 bpf_cpumask_test_cpu 检测当前核心是否仍然属于 Primary Nest
		in_primary = bpf_cpumask_test_cpu(cpu, cast_mask(primary));

		// 如果上一个任务（prev）仍然在任务队列中（SCX_TASK_QUEUED），并且当前核心属于 Primary Nest，则重新派发该任务
		// 避免核心进入空闲状态，确保资源被充分利用
		// 这里逻辑总感觉有些问题，如果prev所在的cpu的scx_rq不为当前cpu，直接分派到当前cpu的scx_rq不会出问题吗
		if (prev && (prev->scx.flags & SCX_TASK_QUEUED) && in_primary) {
			scx_bpf_dispatch(prev, SCX_DSQ_LOCAL, slice_ns, 0);
			return;
		}

		// 如果当前任务队列没有任务被消费，记录一次 NOT_CONSUMED 事件，便于后续分析和优化
		stat_inc(NEST_STAT(NOT_CONSUMED));
		if (in_primary) { // 如果核心在 Primary Nest
			/*
			 * Immediately demote a primary core if the previous
			 * task on it is dying
			 *
			 * Note that we elect to not compact the "first" CPU in
			 * the mask so as to encourage at least one core to
			 * remain in the nest. It would be better to check for
			 * whether there is only one core remaining in the
			 * nest, but BPF doesn't yet have a kfunc for querying
			 * cpumask weight.
			 */
			/*
			 * 如果上一个任务已经结束，则立即压缩核心。
			 * 但保证至少有一个核心保留在 Primary Nest。
			 */
			if ((prev && prev->__state == TASK_DEAD) &&
			    (cpu != bpf_cpumask_first(cast_mask(primary)))) {
				// 立即降级核心到 Reserve Nest
				stat_inc(NEST_STAT(EAGERLY_COMPACTED));// 统计急切压缩事件
				bpf_cpumask_clear_cpu(cpu, primary);// 从 Primary Nest 中移除核心
				try_make_core_reserved(cpu, reserve, false);// 降级核心到 Reserve Nest
			} else  {
				// 延迟压缩核心
				pcpu_ctx->scheduled_compaction = true;// 标记核心需要压缩
				/*
				 * The core isn't being used anymore. Set a
				 * timer to remove the core from the nest in
				 * p_remove if it's still unused by that point.
				 */
				/*
			 	* 设置压缩定时器，在指定时间后检查核心是否仍然未被使用。
			 	*/
				bpf_timer_start(&pcpu_ctx->timer, p_remove_ns,
						BPF_F_TIMER_CPU_PIN);
				stat_inc(NEST_STAT(SCHEDULED_COMPACTION));
			}
		}
		return;
	}
	stat_inc(NEST_STAT(CONSUMED));
}

// 更新全局虚拟时间（vtime_now）以确保虚拟时间始终向前推进
// 在任务开始运行时调用，用于同步任务的虚拟时间到全局虚拟时间
void BPF_STRUCT_OPS(nest_running, struct task_struct *p)
{
	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

// 当任务停止运行时调用，根据任务的权重和剩余时间片更新任务的虚拟时间
void BPF_STRUCT_OPS(nest_stopping, struct task_struct *p, bool runnable)
{
	/* scale the execution time by the inverse of the weight and charge */
	p->scx.dsq_vtime += (slice_ns - p->scx.slice) * 100 / p->scx.weight;
}

// 初始化新任务（task_struct）的调度上下文
s32 BPF_STRUCT_OPS(nest_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;

	/*
	 * @p is new. Let's ensure that its task_ctx is available. We can sleep
	 * in this function and the following will automatically use GFP_KERNEL.
	 */
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(&tctx->tmp_mask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	tctx->attached_core = -1;
	tctx->prev_cpu = -1;

	return 0;
}

void BPF_STRUCT_OPS(nest_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

// 通过定时器周期性调用此函数，更新统计数据
static int stats_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 cpu;
	struct bpf_cpumask *primary, *reserve;
	const struct cpumask *idle;
	stats_primary_mask = 0;
	stats_reserved_mask = 0;
	stats_other_mask = 0;
	stats_idle_mask = 0;
	long err;

	bpf_rcu_read_lock();
	primary = primary_cpumask;
	reserve = reserve_cpumask;
	if (!primary || !reserve) {
		bpf_rcu_read_unlock();
		scx_bpf_error("Failed to lookup primary or reserve");
		return 0;
	}

	idle = scx_bpf_get_idle_cpumask();
	bpf_for(cpu, 0, nr_cpus) {
		if (bpf_cpumask_test_cpu(cpu, cast_mask(primary)))
			stats_primary_mask |= (1ULL << cpu);
		else if (bpf_cpumask_test_cpu(cpu, cast_mask(reserve)))
			stats_reserved_mask |= (1ULL << cpu);
		else
			stats_other_mask |= (1ULL << cpu);

		if (bpf_cpumask_test_cpu(cpu, idle))
			stats_idle_mask |= (1ULL << cpu);
	}
	bpf_rcu_read_unlock();
	scx_bpf_put_idle_cpumask(idle);

	err = bpf_timer_start(timer, sampling_cadence_ns - 5000, 0);
	if (err)
		scx_bpf_error("Failed to arm stats timer");

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(nest_init)
{
	struct bpf_cpumask *cpumask;
	s32 cpu;
	int err;
	struct bpf_timer *timer;
	u32 key = 0;

	err = scx_bpf_create_dsq(FALLBACK_DSQ_ID, NUMA_NO_NODE);
	if (err) {
		scx_bpf_error("Failed to create fallback DSQ");
		return err;
	}

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	bpf_cpumask_clear(cpumask);
	cpumask = bpf_kptr_xchg(&primary_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	bpf_cpumask_clear(cpumask);
	cpumask = bpf_kptr_xchg(&reserve_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	bpf_for(cpu, 0, nr_cpus) {
		s32 key = cpu;
		struct pcpu_ctx *ctx = bpf_map_lookup_elem(&pcpu_ctxs, &key);

		if (!ctx) {
			scx_bpf_error("Failed to lookup pcpu_ctx");
			return -ENOENT;
		}
		ctx->scheduled_compaction = false;
		if (bpf_timer_init(&ctx->timer, &pcpu_ctxs, CLOCK_BOOTTIME)) {
			scx_bpf_error("Failed to initialize pcpu timer");
			return -EINVAL;
		}
		err = bpf_timer_set_callback(&ctx->timer, compact_primary_core);
		if (err) {
			scx_bpf_error("Failed to set pcpu timer callback");
			return -EINVAL;
		}
	}

	timer = bpf_map_lookup_elem(&stats_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup central timer");
		return -ESRCH;
	}
	bpf_timer_init(timer, &stats_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, stats_timerfn);
	err = bpf_timer_start(timer, sampling_cadence_ns - 5000, 0);
	if (err)
		scx_bpf_error("Failed to arm stats timer");

	return err;
}

void BPF_STRUCT_OPS(nest_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC("perf_event")
int handle_cpu_mask_event(struct bpf_perf_event_data *ctx){
	struct cpu_mask_data *buff = bpf_ringbuf_reserve(&cpu_mask_buffer,sizeof(struct cpu_mask_data),0);
	if(!buff){
		bpf_printk("cpu mask ringbuf reserve failed\n");
		return 0;
	}
	buff->stats_primary_mask = stats_primary_mask;
	buff->stats_reserved_mask = stats_reserved_mask;
	buff->stats_other_mask = stats_other_mask;
	buff->stats_idle_mask = stats_idle_mask;
	bpf_ringbuf_submit(buff,0);
	return 0;
}

SCX_OPS_DEFINE(nest_ops,
	       .select_cpu		= (void *)nest_select_cpu,
	       .enqueue			= (void *)nest_enqueue,
	       .dispatch		= (void *)nest_dispatch,
	       .running			= (void *)nest_running,
	       .stopping		= (void *)nest_stopping,
	       .init_task		= (void *)nest_init_task,
	       .enable			= (void *)nest_enable,
	       .init			= (void *)nest_init,
	       .exit			= (void *)nest_exit,
	       .flags			= 0,
	       .name			= "nest");

