/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple five-level FIFO queue scheduler.
 *
 * There are five FIFOs implemented using BPF_MAP_TYPE_QUEUE. A task gets
 * assigned to one depending on its compound weight. Each CPU round robins
 * through the FIFOs and dispatches more from FIFOs with higher indices - 1 from
 * queue0, 2 from queue1, 4 from queue2 and so on.
 *
 * This scheduler demonstrates:
 *
 * - BPF-side queueing using PIDs.
 * - Sleepable per-task storage allocation using ops.prep_enable().
 * - Using ops.cpu_release() to handle a higher priority scheduling class taking
 *   the CPU away.
 * - Core-sched support.
 *
 * This scheduler is primarily for demonstration and testing of sched_ext
 * features and unlikely to be useful for actual workloads.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>
#include <string.h>

enum consts {
	ONE_SEC_IN_NS		= 1000000000,//一秒钟的纳秒数，用于时间计算
	SHARED_DSQ		= 0,//共享的调度队列（DSQ，Dispatch Queue）的标识符
};

char _license[] SEC("license") = "GPL";

const volatile u64 slice_ns = SCX_SLICE_DFL;// 时间片长度
const volatile u32 stall_user_nth;
const volatile u32 stall_kernel_nth;
const volatile u32 dsp_inf_loop_after;
const volatile u32 dsp_batch;
const volatile bool print_shared_dsq;// 控制是否打印共享调度队列的信息
const volatile char exp_prefix[17];
const volatile s32 disallow_tgid;
const volatile bool suppress_dump;// 控制是否抑制调度器的转储输出（如调度队列状态、错误日志等）

u32 test_error_cnt;// 用于测试的错误计数器

UEI_DEFINE(uei);// 这个宏通常用于定义用户事件接口（UEI），用于处理和记录特定的事件或状态

// 每个 qmap_me 结构定义了一个 eBPF 队列，类型为 BPF_MAP_TYPE_QUEUE。这种队列是先进先出（FIFO）类型，用于任务排队
// 容纳 4096 个条目,条目任务的 PID,定义了 5 个队列：queue0 到 queue4。这些队列用于存储不同优先级的任务
struct qmap_me {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 4096);
	__type(value, u32);
} queue0 SEC(".maps"),
  queue1 SEC(".maps"),
  queue2 SEC(".maps"),
  queue3 SEC(".maps"),
  queue4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 5);
	__type(key, int);// 键是队列的索引
	__array(values, struct qmap_me);
} queue_arr SEC(".maps") = {
	.values = {
		[0] = &queue0,
		[1] = &queue1,
		[2] = &queue2,
		[3] = &queue3,
		[4] = &queue4,
	},
};

/*
 * If enabled, CPU performance target is set according to the queue index
 * according to the following table.
 */
// CPU 性能目标
// 性能目标基于 SCX_CPUPERF_ONE 的比例计算，每个队列的目标按优先级递增
// 这种设计确保了任务越高优先级，分配的 CPU 资源越多
static const u32 qidx_to_cpuperf_target[] = {
	[0] = SCX_CPUPERF_ONE * 0 / 4,// 最低性能
	[1] = SCX_CPUPERF_ONE * 1 / 4,
	[2] = SCX_CPUPERF_ONE * 2 / 4,
	[3] = SCX_CPUPERF_ONE * 3 / 4,
	[4] = SCX_CPUPERF_ONE * 4 / 4,// 最高性能
};

/*
 * Per-queue sequence numbers to implement core-sched ordering.
 *
 * Tail seq is assigned to each queued task and incremented. Head seq tracks the
 * sequence number of the latest dispatched task. The distance between the a
 * task's seq and the associated queue's head seq is called the queue distance
 * and used when comparing two tasks for ordering. See qmap_core_sched_before().
 */
// core_sched_head_seqs 和 core_sched_tail_seqs 用于实现核心调度（core-sched）的任务顺序控制
// head指向队列的头部，即下一个要调度的任务，tail指向队列的尾部，即最后一个入队的任务
// 每个队列（共 5 个队列）都有一个头序列号（head seq）和尾序列号（tail seq）
// tail seq：分配给每个排队的任务，并在每次有新任务入队时递增
// head seq：跟踪已被调度任务的最新序列号
static u64 core_sched_head_seqs[5];
static u64 core_sched_tail_seqs[5];
// 这个尾序列号反映了任务在加入队列时的顺序
// 例如，如果一个任务加入了 queue0，它会得到 core_sched_tail_seqs[0] 的当前值作为它的序列号，然后 core_sched_tail_seqs[0] 增加 1
// 根据任务的序列号和尾序列号可以算出队列距离，用于在不同队列之间进行调度决策时衡量每个队列的负载情况

/* Per-task scheduling context */
struct task_ctx {
	bool	force_local;// 指示是否强制将任务直接调度到本地调度队列（local_dsq），绕过常规调度	/* Dispatch directly to local_dsq */
	u64	core_sched_seq;// 记录任务在核心调度中的序列号，用于保持任务在调度过程中的顺序一致性
};

// 任务上下文存储
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);// 
	__type(key, int);// 任务的标识符（如任务 ID）
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct cpu_ctx {
	u64	dsp_idx;// 当前的调度索引，用于指示 CPU 当前从哪个队列调度任务	/* dispatch index */
	u64	dsp_cnt;// 剩余的调度计数，用于控制当前队列的调度任务数量	/* remaining count */
	u32	avg_weight;// 当前调度的平均权重，用于动态调整调度策略
	u32	cpuperf_target;// 标 CPU 性能，用于调整 CPU 频率或能耗目标，以匹配当前的调度需求
};

// CPU 上下文存储
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cpu_ctx);
} cpu_ctx_stor SEC(".maps");

// 进程的内存信息
struct task_memory_info {
    u64 rss;            // 常驻内存（RSS），单位：页
    u64 total_vm;       // 虚拟内存总量，单位：页
    u64 anon_rss;       // 匿名内存页，单位：页
    u64 file_rss;       // 文件映射内存页，单位：页
    u64 swap_usage;     // 交换分区使用量，单位：页
    u64 pgfault;        // 次要页面故障数
    u64 pgmajfault;     // 主要页面故障数
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
    __type(value, struct task_memory_info);
} task_mem_map SEC(".maps");



/* Statistics */
u64 nr_enqueued, nr_dispatched, nr_reenqueued, nr_dequeued;
u64 nr_core_sched_execed, nr_expedited;
u32 cpuperf_min, cpuperf_avg, cpuperf_max;
u32 cpuperf_target_min, cpuperf_target_avg, cpuperf_target_max;

s32 BPF_STRUCT_OPS(qmap_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	s32 cpu;

	// // 获取任务的调度上下文
	// static void *(* const bpf_task_storage_get)(void *map, struct task_struct *task, void *value, __u64 flags)
	// 成功时，返回指向与指定任务关联的存储空间的指针，这个空间存储了与任务相关的上下文数据
	// 最后一个参数为1时候，如果任务未在map中，就将其初始化之后加入map,后面有这种情况的代码
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("task_ctx lookup failed");
		return -ESRCH;
	}


	// // 如果任务只能运行在一个 CPU 或前一个 CPU 现在是空闲的，选择前一个 CPU
	if (p->nr_cpus_allowed == 1 ||
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		tctx->force_local = true;
		return prev_cpu; 
	}

	// // 尝试选择一个空闲的 CPU
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
		return cpu; // // 找到空闲 CPU，返回其编号

	return prev_cpu;// 否则继续使用前一个 CPU
}

// 根据weight值选择不同的FIFO队列
static int weight_to_idx(u32 weight)
{
	/* Coarsely map the compound weight to a FIFO. */
	if (weight <= 25)
		return 0;
	else if (weight <= 50)
		return 1;
	else if (weight < 200)
		return 2;
	else if (weight < 400)
		return 3;
	else
		return 4;
}

static s32 update_task_memory_info(struct task_struct *task)
{
    if (!task)
        return -EINVAL; // 参数无效

    // 从 task_struct 中读取 PID
   /* u32 pid = BPF_CORE_READ(task, pid);
    if (!pid)
        return -ESRCH; // 未找到进程*/

	// 获取任务的 mm_struct
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) {
    	bpf_printk("Task %u has no associated mm_struct", task->pid);
    	return -ESRCH; // 任务没有关联的内存描述符
	}

    // 在 Map 中查找对应的 task_memory_info
    struct task_memory_info *mem_info = bpf_task_storage_get(&task_mem_map, task, 0, 0);
    if (!mem_info){
		bpf_printk("mem_info is NULL for pid: %u", task->pid);
		return -ENOENT; // 在 Map 中未找到对应的内存信息
	}
        

    /*// 获取任务的 mm_struct
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) {
    	bpf_printk("Task %u has no associated mm_struct", task->pid);
    	return -ESRCH; // 任务没有关联的内存描述符
	}*/


    // 从 mm_struct 中读取内存统计信息
/*    u64 file_rss = BPF_CORE_READ(mm, rss_stat.count[MM_FILEPAGES]);
    u64 anon_rss = BPF_CORE_READ(mm, rss_stat.count[MM_ANONPAGES]);
    u64 swap_usage = BPF_CORE_READ(mm, rss_stat.count[MM_SWAPENTS]);*/
     // 获取内存页数（通过 rss_stat 访问匿名页、文件页、交换分区）
    u64 total_vm = BPF_CORE_READ(mm, total_vm);
    u64 file_rss = 0, anon_rss = 0, swap_usage = 0;

    struct percpu_counter *rss_stat = BPF_CORE_READ(mm, rss_stat);
	if (!rss_stat) {
    	bpf_printk("rss_stat is NULL for pid: %u", task->pid);
    	return -ESRCH;
	}
    if (rss_stat) {
        // 通过 rss_stat 读取匿名页、文件页、交换页等内存统计信息
        bpf_probe_read_kernel(&file_rss, sizeof(u64), &rss_stat[MM_FILEPAGES].count);
        bpf_probe_read_kernel(&anon_rss, sizeof(u64), &rss_stat[MM_ANONPAGES].count);
        bpf_probe_read_kernel(&swap_usage, sizeof(u64), &rss_stat[MM_SWAPENTS].count);
    }

    // 更新 mem_info 结构体
    mem_info->file_rss = file_rss;
    mem_info->anon_rss = anon_rss;
    mem_info->rss = file_rss + anon_rss;
    mem_info->swap_usage = swap_usage;
    mem_info->total_vm = total_vm;

    // 从 task_struct 中读取页面故障计数
    mem_info->pgfault = BPF_CORE_READ(task, min_flt);
    mem_info->pgmajfault = BPF_CORE_READ(task, maj_flt);

	// 输出存储的信息
	bpf_printk("Updated memory info for pid %u:", task->pid);
	//bpf_printk(" total_vm=%llu", mem_info->total_vm);
	bpf_printk(" RSS=%llu total_vm=%llu", mem_info->rss, mem_info->total_vm);
	bpf_printk(" anon_rss=%llu file_rss=%llu", mem_info->anon_rss, mem_info->file_rss);
	bpf_printk(" swap_usage=%llu pgfault=%llu pgmajfault=%llu",
			   mem_info->swap_usage, mem_info->pgfault, mem_info->pgmajfault);
	
    return 0; // 成功
}
/*
static void print_queue_head_mm(void)
{
    int i;
	bpf_printk("Begin printing queue head memory info__________________\n");

    // Unroll the loop to satisfy the eBPF verifier
    //#pragma unroll
    for (i = 0; i < 5; i++) {
        int key = i;
        void *queue_map;
        u32 pid;
        int ret;

        // Get the queue map from the array of maps
        queue_map = bpf_map_lookup_elem(&queue_arr, &key);
        if (!queue_map) {
            bpf_printk("Queue %d not found\n", i);
            continue;
        }

        // Peek at the first element in the queue
        ret = bpf_map_peek_elem(queue_map, &pid);
        if (ret != 0) {
            bpf_printk("Queue %d is empty\n", i);
            continue;
        }

        // Look up the task_struct using pid
        struct task_struct *task = bpf_task_from_pid(pid);
        if (!task) {
            bpf_printk("Failed to get task_struct for pid %u\n", pid);
            continue;
        }

        // Get task memory info using task_struct
        struct task_memory_info *mem_info = bpf_task_storage_get(&task_mem_map, task, 0, 0);
        if (!mem_info) {
            bpf_printk("No memory info for pid %u\n", pid);
            bpf_task_release(task);  // Make sure to release task_struct reference
            continue;
        }

        // Output the memory information
        bpf_printk("Queue %d head pid %u:", i, pid);
        bpf_printk(" RSS=%llu total_vm=%llu", mem_info->rss, mem_info->total_vm);
        bpf_printk(" anon_rss=%llu file_rss=%llu", mem_info->anon_rss, mem_info->file_rss);
        bpf_printk(" swap_usage=%llu pgfault=%llu pgmajfault=%llu",
                   mem_info->swap_usage, mem_info->pgfault, mem_info->pgmajfault);

        // Ensure the task_struct reference is released after usage
        bpf_task_release(task);
    }
}*/



// 将任务入队到适当的调度队列中
void BPF_STRUCT_OPS(qmap_enqueue, struct task_struct *p, u64 enq_flags)
{
	static u32 user_cnt, kernel_cnt;
	struct task_ctx *tctx;
	u32 pid = p->pid;
	int idx = weight_to_idx(p->scx.weight);// // 根据任务权重决定队列索引
	void *ring;

	// // 如果任务是内核线程，根据stall_kernel_nth的值决定是否阻塞
	if (p->flags & PF_KTHREAD) {
		if (stall_kernel_nth && !(++kernel_cnt % stall_kernel_nth))
			return; // // 按照配置跳过部分内核线程的入队
	} else {
		if (stall_user_nth && !(++user_cnt % stall_user_nth))
			return; // 按照配置跳过部分用户线程的入队
	}

	if (test_error_cnt && !--test_error_cnt)
		scx_bpf_error("test triggering error");

	// // 获取任务上下文
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("task_ctx lookup failed");
		return;
	}

	bpf_printk("Enqueueing task %d to queue %d______________\n", pid, idx);
    s32 get_mm = update_task_memory_info(p);
    /*if(get_mm != 0){
    //    scx_bpf_error("task memory read error");
		bpf_printk("task %d memory read error\n", pid);
    //    return;
    }*/


	/*
	 * All enqueued tasks must have their core_sched_seq updated for correct
	 * core-sched ordering, which is why %SCX_OPS_ENQ_LAST is specified in
	 * qmap_ops.flags.
	 */
	// // 更新任务的核心调度序列号
	// 保持core_sched_tail_seqs指向的是队列的尾部
	tctx->core_sched_seq = core_sched_tail_seqs[idx]++;

	/*
	 * If qmap_select_cpu() is telling us to or this is the last runnable
	 * task on the CPU, enqueue locally.
	 */
	// // 如果强制本地调度或这是 CPU 上最后一个可运行任务，调度到本地队列
	if (tctx->force_local || (enq_flags & SCX_ENQ_LAST)) {
		tctx->force_local = false;
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
		return;
	}

	/*
	 * If the task was re-enqueued due to the CPU being preempted by a
	 * higher priority scheduling class, just re-enqueue the task directly
	 * on the global DSQ. As we want another CPU to pick it up, find and
	 * kick an idle CPU.
	 */
	// 如果任务由于被高优先级抢占而重新入队，直接加入全局调度队列
	if (enq_flags & SCX_ENQ_REENQ) {
		s32 cpu;

		scx_bpf_dispatch(p, SHARED_DSQ, 0, enq_flags);// // 将任务加入全局调度队列
		cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);// // 选择一个空闲的 CPU
		if (cpu >= 0)
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return;
	}

	// 查找对应索引的队列
	ring = bpf_map_lookup_elem(&queue_arr, &idx);
	if (!ring) {
		scx_bpf_error("failed to find ring %d", idx);
		return;
	}

	/* Queue on the selected FIFO. If the FIFO overflows, punt to global. */
	// // 尝试将任务加入选定的 FIFO 队列，如果失败则放入全局队列
	if (bpf_map_push_elem(ring, &pid, 0)) {
		scx_bpf_dispatch(p, SHARED_DSQ, slice_ns, enq_flags);
		return;
	}

	__sync_fetch_and_add(&nr_enqueued, 1);// 增加入队计数

}

/*
 * The BPF queue map doesn't support removal and sched_ext can handle spurious
 * dispatches. qmap_dequeue() is only used to collect statistics.
 */
// 统计任务出队的次数
void BPF_STRUCT_OPS(qmap_dequeue, struct task_struct *p, u64 deq_flags)
{
	__sync_fetch_and_add(&nr_dequeued, 1);// 增加出队任务的计数 nr_dequeued
	if (deq_flags & SCX_DEQ_CORE_SCHED_EXEC)// 如果出队标志中包含 SCX_DEQ_CORE_SCHED_EXEC，则同时增加 nr_core_sched_execed 计数
		__sync_fetch_and_add(&nr_core_sched_execed, 1);
}

static void update_core_sched_head_seq(struct task_struct *p)
{
	// 在map里找是否有任务p的上下文存储
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	int idx = weight_to_idx(p->scx.weight);// 获得任务所对应的队列索引

	// 如果任务压根不在map中，就不需要进一步更新了
	if (tctx)
		core_sched_head_seqs[idx] = tctx->core_sched_seq;// 感觉这里更新逻辑有点问题，head指向的一直都是队列最前头的任务，而当前这个任务可能并不是队列中最前面的
	else
		scx_bpf_error("task_ctx lookup failed");
}

static bool consume_shared_dsq(void)// 从共享调度队列中消费任务
{
	struct task_struct *p;
	bool consumed;

	// exp_prefix是一个前缀，如果有的话，就根据这个前缀，在队列中找这个任务名字的任务来调度
	// scx_bpf_consume用于从指定的非本地调度队列（DSQ）中提取任务，并将其转移到当前 CPU 的本地 DSQ 中执行
	if (exp_prefix[0] == '\0')// 如果没有前缀，直接消费共享调度队列
		return scx_bpf_consume(SHARED_DSQ);

	/*
	 * To demonstrate the use of scx_bpf_consume_task(), implement silly
	 * selective priority boosting mechanism by scanning SHARED_DSQ looking
	 * for matching comms and consume them first. This makes difference only
	 * when dsp_batch is larger than 1.
	 */
	consumed = false;
	__COMPAT_DSQ_FOR_EACH(p, SHARED_DSQ, 0) {// 遍历共享调度队列
		char comm[sizeof(exp_prefix)];

		memcpy(comm, p->comm, sizeof(exp_prefix) - 1);

		// // 比较任务名称与 exp_prefix，匹配则优先消费
		if (!bpf_strncmp(comm, sizeof(exp_prefix),
				 (const char *)exp_prefix) &&
		    __COMPAT_scx_bpf_consume_task(BPF_FOR_EACH_ITER, p)) {
			consumed = true;// 标记成功消费了匹配任务
			__sync_fetch_and_add(&nr_expedited, 1);// 计数消费的优先任务
		}
	}

	return consumed || scx_bpf_consume(SHARED_DSQ);
}

// 任务分派，这里也只是将队列中的任务分派到共享的队列中
void BPF_STRUCT_OPS(qmap_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_struct *p;
	struct cpu_ctx *cpuc;
	u32 zero = 0, batch = dsp_batch ?: 1;
	void *fifo;
	s32 i, pid;

	if (consume_shared_dsq())// 首先尝试从共享调度队列消费任务
		return;

	// 如果进入了无限调度循环条件（dsp_inf_loop_after），不断地调度 PID 为 2 的任务来保持调度循环
	if (dsp_inf_loop_after && nr_dispatched > dsp_inf_loop_after) {
		/*
		 * PID 2 should be kthreadd which should mostly be idle and off
		 * the scheduler. Let's keep dispatching it to force the kernel
		 * to call this function over and over again.
		 */
		p = bpf_task_from_pid(2);
		if (p) {
			scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, 0);
			bpf_task_release(p);
			return;
		}
	}

	// 查找当前 CPU 上下文 cpuc，并按顺序从 5 个调度队列中选择任务进行调度
	if (!(cpuc = bpf_map_lookup_elem(&cpu_ctx_stor, &zero))) {
		scx_bpf_error("failed to look up cpu_ctx");
		return;
	}

	for (i = 0; i < 5; i++) {
		/* Advance the dispatch cursor and pick the fifo. */
		// 如果当前队列的调度计数为 0，就切换到下一个队列
		if (!cpuc->dsp_cnt) {
			cpuc->dsp_idx = (cpuc->dsp_idx + 1) % 5;
			cpuc->dsp_cnt = 1 << cpuc->dsp_idx;// 根据队列索引调整调度计数
			// 如果优先级高的队列，执行一次任务分派时候会分派更多任务，这个计数就是控制这个的
		}

		// // 从 queue_arr 中获取当前索引的队列
		fifo = bpf_map_lookup_elem(&queue_arr, &cpuc->dsp_idx);
		if (!fifo) {
			scx_bpf_error("failed to find ring %llu", cpuc->dsp_idx);
			return;
		}

		/* Dispatch or advance. */
		// // 从当前队列中弹出任务并调度
		// 根据dsp_cnt计数调度，优先级高的这一下可以调度更多任务
		// 也可能队列没这么多任务来提供调度，任务没了就直接跳出循环，同时dsp_cnt置0
		bpf_repeat(BPF_MAX_LOOPS) {
			if (bpf_map_pop_elem(fifo, &pid))
				break;// 失败跳出循环

			p = bpf_task_from_pid(pid);
			if (!p)
				continue;// 如果任务不存在，跳过,因为没有实际调度，所以dsp_cnt不减

			update_core_sched_head_seq(p);// 更新核心调度头部序列号，确保调度状态一致
			__sync_fetch_and_add(&nr_dispatched, 1);
			scx_bpf_dispatch(p, SHARED_DSQ, slice_ns, 0);// 将任务调度到共享调度队列
			bpf_task_release(p);// 释放任务引用
			batch--;// 批处理计数减一
			cpuc->dsp_cnt--;
			if (!batch || !scx_bpf_dispatch_nr_slots()) {
				consume_shared_dsq();
				return;
			}
			if (!cpuc->dsp_cnt)
				break;
		}

		// 最后将dsp_cnt置0是为了让下一次调度时候有机会给下一个队列
		// 次数dsp_cnt本身是可能不为0的，这样置0自动让位给下一个队列，避免饥饿的方式
		cpuc->dsp_cnt = 0;
	}
}

// 用于在任务时钟滴答（tick）事件发生时更新 CPU 的性能目标（cpuperf_target）
void BPF_STRUCT_OPS(qmap_tick, struct task_struct *p)
{
	struct cpu_ctx *cpuc;
	u32 zero = 0;
	int idx;

	if (!(cpuc = bpf_map_lookup_elem(&cpu_ctx_stor, &zero))) {
		scx_bpf_error("failed to look up cpu_ctx");
		return;
	}

	/*
	 * Use the running avg of weights to select the target cpuperf level.
	 * This is a demonstration of the cpuperf feature rather than a
	 * practical strategy to regulate CPU frequency.
	 */
	// // 更新 CPU 的平均权重，采用 3/4 的当前平均值和 1/4 的当前任务权重
	cpuc->avg_weight = cpuc->avg_weight * 3 / 4 + p->scx.weight / 4;
	idx = weight_to_idx(cpuc->avg_weight);// 根据计算得到的平均权重选择对应的队列索引
	cpuc->cpuperf_target = qidx_to_cpuperf_target[idx];// 根据队列索引设置目标 CPU 性能级别

	// 设置 CPU 的性能目标
	scx_bpf_cpuperf_set(scx_bpf_task_cpu(p), cpuc->cpuperf_target);
}

/*
 * The distance from the head of the queue scaled by the weight of the queue.
 * The lower the number, the older the task and the higher the priority.
 */
// 衡量任务在调度中的相对位置,相对体现在同样的实际长度，优先级低的值根据其优先级来翻倍
static s64 task_qdist(struct task_struct *p)
{
	int idx = weight_to_idx(p->scx.weight);
	struct task_ctx *tctx;
	s64 qdist;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("task_ctx lookup failed");
		return 0;
	}

	qdist = tctx->core_sched_seq - core_sched_head_seqs[idx];

	/*
	 * As queue index increments, the priority doubles. The queue w/ index 3
	 * is dispatched twice more frequently than 2. Reflect the difference by
	 * scaling qdists accordingly. Note that the shift amount needs to be
	 * flipped depending on the sign to avoid flipping priority direction.
	 */
	if (qdist >= 0)
		return qdist << (4 - idx);
	else
		return qdist << idx;
}

/*
 * This is called to determine the task ordering when core-sched is picking
 * tasks to execute on SMT siblings and should encode about the same ordering as
 * the regular scheduling path. Use the priority-scaled distances from the head
 * of the queues to compare the two tasks which should be consistent with the
 * dispatch path behavior.
 */
bool BPF_STRUCT_OPS(qmap_core_sched_before,
		    struct task_struct *a, struct task_struct *b)
{
	return task_qdist(a) > task_qdist(b);
}

void BPF_STRUCT_OPS(qmap_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	u32 cnt;

	/*
	 * Called when @cpu is taken by a higher priority scheduling class. This
	 * makes @cpu no longer available for executing sched_ext tasks. As we
	 * don't want the tasks in @cpu's local dsq to sit there until @cpu
	 * becomes available again, re-enqueue them into the global dsq. See
	 * %SCX_ENQ_REENQ handling in qmap_enqueue().
	 */
	/*
     * 当 @cpu 被更高优先级的调度类占用时调用。此时 @cpu 不再可用于执行
     * sched_ext 任务。为了避免 @cpu 本地调度队列中的任务一直挂起，直到
     * @cpu 重新可用，将这些任务重新入队到全局调度队列中。
     * 参见 qmap_enqueue() 中对 %SCX_ENQ_REENQ 的处理。
     */
	cnt = scx_bpf_reenqueue_local();// 将本地队列任务重新入队到全局队列
	if (cnt)
		__sync_fetch_and_add(&nr_reenqueued, cnt);
}

s32 BPF_STRUCT_OPS(qmap_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	// // 如果新任务的 TGID 等于不允许的 TGID，将其标记为不允许调度
	if (p->tgid == disallow_tgid)
		p->scx.disallow = true;


	// 初始化 task_mem_map
	struct task_memory_info *mem_info = bpf_task_storage_get(&task_mem_map, p, 0,
					BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!mem_info) {
    	//bpf_printk("Error: Failed to get or create mem_info\n");
    	return -ENOMEM;
	} else {
    	//bpf_printk("Success: mem_info allocated at %p\n", mem_info);
	}

	/*s32 get_mm = update_task_memory_info(p);
    if(!get_mm){
        scx_bpf_error("task memory read error");
        return -ENOMEM;
    }*/


	/*
	 * @p is new. Let's ensure that its task_ctx is available. We can sleep
	 * in this function and the following will automatically use GFP_KERNEL.
	 */
	 /*
     * @p 是新任务。确保其任务上下文可用。我们可以在这个函数中睡眠，
     * 后续操作将自动使用 GFP_KERNEL 分配内存。
     */
	if (bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE)) //&& bpf_task_storage_get(&task_mem_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE))
		return 0;
	else
		return -ENOMEM;
}

void BPF_STRUCT_OPS(qmap_dump, struct scx_dump_ctx *dctx)// 感觉是特殊时候才被调用
{
	s32 i, pid;

	if (suppress_dump)
		return;

	bpf_for(i, 0, 5) {
		void *fifo;

		if (!(fifo = bpf_map_lookup_elem(&queue_arr, &i)))
			return;

		scx_bpf_dump("QMAP FIFO[%d]:", i);
		bpf_repeat(4096) {
			if (bpf_map_pop_elem(fifo, &pid))// 就为了个输出队列的信息，就把队列中的任务弹出来，也没恢复，不合适吧
				break;
			scx_bpf_dump(" %d", pid);
		}
		scx_bpf_dump("\n");
	}
}

void BPF_STRUCT_OPS(qmap_dump_cpu, struct scx_dump_ctx *dctx, s32 cpu, bool idle)
{
	u32 zero = 0;
	struct cpu_ctx *cpuc;

	if (suppress_dump || idle)
		return;
	if (!(cpuc = bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &zero, cpu)))// // 获取指定 CPU 的上下文信息
		return;

	// // 输出 CPU 的调度上下文，包括调度索引、调度计数、平均权重和 CPU 性能目标
	scx_bpf_dump("QMAP: dsp_idx=%llu dsp_cnt=%llu avg_weight=%u cpuperf_target=%u",
		     cpuc->dsp_idx, cpuc->dsp_cnt, cpuc->avg_weight,
		     cpuc->cpuperf_target);
}

void BPF_STRUCT_OPS(qmap_dump_task, struct scx_dump_ctx *dctx, struct task_struct *p)
{
	struct task_ctx *taskc;
    u32 pid;
    struct task_memory_info *mem_info;

	if (suppress_dump)
		return;
	if (!(taskc = bpf_task_storage_get(&task_ctx_stor, p, 0, 0)))
		return;

    // 获取任务的 PID
    pid = BPF_CORE_READ(p, pid);

    // 从 Map 中查找任务的内存信息
    mem_info = bpf_task_storage_get(&task_mem_map,p,0,0);
    if (!mem_info) {
        // 如果未找到，您可以选择输出提示或忽略
        scx_bpf_dump("QMAP: PID=%u, no memory info found", pid);
        return;
    }

	/*scx_bpf_dump("QMAP: force_local=%d core_sched_seq=%llu",
		     taskc->force_local, taskc->core_sched_seq);*/
    // 输出任务的内存信息
   /*scx_bpf_dump("QMAP: PID=%u force_local=%d core_sched_seq=%llu "
                 "RSS=%llu total_vm=%llu anon_rss=%llu file_rss=%llu "
                 "swap_usage=%llu pgfault=%llu pgmajfault=%llu",
                 pid, taskc->force_local, taskc->core_sched_seq,
                 mem_info->rss, mem_info->total_vm, mem_info->anon_rss,
                 mem_info->file_rss, mem_info->swap_usage,
                 mem_info->pgfault, mem_info->pgmajfault);*/
}

/*
 * Print out the online and possible CPU map using bpf_printk() as a
 * demonstration of using the cpumask kfuncs and ops.cpu_on/offline().
 */
// 使用 bpf_printk 打印在线（online）和可能（possible）CPU 的掩码状态
static void print_cpus(void)
{
	const struct cpumask *possible, *online;
	s32 cpu;
	char buf[128] = "", *p;
	int idx;

	possible = scx_bpf_get_possible_cpumask();
	online = scx_bpf_get_online_cpumask();

	idx = 0;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
		if (!(p = MEMBER_VPTR(buf, [idx++])))
			break;
		if (bpf_cpumask_test_cpu(cpu, online))
			*p++ = 'O';
		else if (bpf_cpumask_test_cpu(cpu, possible))
			*p++ = 'X';
		else
			*p++ = ' ';

		if ((cpu & 7) == 7) {
			if (!(p = MEMBER_VPTR(buf, [idx++])))
				break;
			*p++ = '|';
		}
	}
	buf[sizeof(buf) - 1] = '\0';

	scx_bpf_put_cpumask(online);
	scx_bpf_put_cpumask(possible);

	bpf_printk("CPUS: |%s", buf);
}


void BPF_STRUCT_OPS(qmap_cpu_online, s32 cpu)
{
	bpf_printk("CPU %d coming online", cpu);
	/* @cpu is already online at this point */
	print_cpus();
}

void BPF_STRUCT_OPS(qmap_cpu_offline, s32 cpu)
{
	bpf_printk("CPU %d going offline", cpu);
	/* @cpu is still online at this point */
	print_cpus();
}

struct monitor_timer {
	struct bpf_timer timer;// eBPF 中用于设置定时任务的定时器结构体，可以用来定时触发某些操作或回调函数
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct monitor_timer);
} monitor_timer SEC(".maps");// 只有一个定时器序列

static void monitor_mm(void){
	
}

/*
 * Print out the min, avg and max performance levels of CPUs every second to
 * demonstrate the cpuperf interface.
 */
// 收集当前所有可用的CPU的性能状态，包括当前性能和最高的性能值，还有目前所有cpu上任务的要求的性能值，包括当前的、最低要求和最高要求的性能值
static void monitor_cpuperf(void)
{
	u32 zero = 0, nr_cpu_ids;
	u64 cap_sum = 0, cur_sum = 0, cur_min = SCX_CPUPERF_ONE, cur_max = 0;
	u64 target_sum = 0, target_min = SCX_CPUPERF_ONE, target_max = 0;
	const struct cpumask *online;
	int i, nr_online_cpus = 0;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();// 获取系统中的 CPU 数量
	online = scx_bpf_get_online_cpumask(); // 获取当前在线的 CPU 掩码

	bpf_for(i, 0, nr_cpu_ids) {
		struct cpu_ctx *cpuc;
		u32 cap, cur;

		if (!bpf_cpumask_test_cpu(i, online))// 检查 CPU 是否在线
			continue;
		nr_online_cpus++;// 计数在线 CPU 的数量

		/* collect the capacity and current cpuperf */
		// 获取当前 CPU 的性能上限（capacity）和当前性能（current performance）
		cap = scx_bpf_cpuperf_cap(i);
		cur = scx_bpf_cpuperf_cur(i);

		// // 更新当前性能的最小值和最大值
		cur_min = cur < cur_min ? cur : cur_min;
		cur_max = cur > cur_max ? cur : cur_max;

		/*
		 * $cur is relative to $cap. Scale it down accordingly so that
		 * it's in the same scale as other CPUs and $cur_sum/$cap_sum
		 * makes sense.
		 */
		/*
         * $cur 是相对于 $cap 的。将其缩放到与其他 CPU 相同的比例，
         * 以便 $cur_sum/$cap_sum 有意义。
         */
		cur_sum += cur * cap / SCX_CPUPERF_ONE;// // 按比例缩放并累加当前性能
		cap_sum += cap;// 累加所有 CPU 的性能上限

		// 获取 CPU 上下文结构体中的目标性能级别
		if (!(cpuc = bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &zero, i))) {
			scx_bpf_error("failed to look up cpu_ctx");
			goto out;// 出错时跳转到资源释放部分
		}

		/* collect target */
		cur = cpuc->cpuperf_target;
		target_sum += cur;// 累加目标性能
		target_min = cur < target_min ? cur : target_min;// 更新目标性能最小值
		target_max = cur > target_max ? cur : target_max;// 更新目标性能最大值
	}

	// 计算并输出当前性能的最小值、平均值和最大值
	cpuperf_min = cur_min;
	cpuperf_avg = cur_sum * SCX_CPUPERF_ONE / cap_sum;// 平均值按比例计算
	cpuperf_max = cur_max;

	// 计算并输出目标性能的最小值、平均值和最大值
	cpuperf_target_min = target_min;
	cpuperf_target_avg = target_sum / nr_online_cpus;// 平均值直接相除
	cpuperf_target_max = target_max;
out:
	scx_bpf_put_cpumask(online);
}

/*
 * Dump the currently queued tasks in the shared DSQ to demonstrate the usage of
 * scx_bpf_dsq_nr_queued() and DSQ iterator. Raise the dispatch batch count to
 * see meaningful dumps in the trace pipe.
 */
// 输出当前在共享调度队列（SHARED_DSQ）中的任务信息，包括任务名称（comm）和 PID
static void dump_shared_dsq(void)
{
	struct task_struct *p;
	s32 nr;

	// 获取共享调度队列中的任务数量
	if (!(nr = scx_bpf_dsq_nr_queued(SHARED_DSQ)))
		return;

	bpf_printk("Dumping %d tasks in SHARED_DSQ in reverse order", nr);

	bpf_rcu_read_lock();
	// 使用 DSQ 迭代器反向遍历共享调度队列中的任务
	__COMPAT_DSQ_FOR_EACH(p, SHARED_DSQ, SCX_DSQ_ITER_REV)
		bpf_printk("%s[%d]", p->comm, p->pid);
	bpf_rcu_read_unlock();
}

static int monitor_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	monitor_cpuperf();
	//print_queue_head_mm();

	if (print_shared_dsq)
		dump_shared_dsq();

	bpf_timer_start(timer, ONE_SEC_IN_NS, 0);
	return 0;
}

// 初始化共享调度队列和定时器，配置 CPU 性能监控的定时任务
s32 BPF_STRUCT_OPS_SLEEPABLE(qmap_init)
{
	u32 key = 0;
	struct bpf_timer *timer;
	s32 ret;

	print_cpus();
	//print_queue_head_mm();

	// // 创建共享调度队列，-1 表示使用默认配置
	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret)
		return ret;

	timer = bpf_map_lookup_elem(&monitor_timer, &key);
	if (!timer)
		return -ESRCH;

	bpf_timer_init(timer, &monitor_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, monitor_timerfn);

	// 启动定时器，每隔一秒（ONE_SEC_IN_NS）触发一次回调
	return bpf_timer_start(timer, ONE_SEC_IN_NS, 0);
}

void BPF_STRUCT_OPS(qmap_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(qmap_ops,
	       .select_cpu		= (void *)qmap_select_cpu,
	       .enqueue			= (void *)qmap_enqueue,
	       .dequeue			= (void *)qmap_dequeue,
	       .dispatch		= (void *)qmap_dispatch,
	       .tick			= (void *)qmap_tick,
	       .core_sched_before	= (void *)qmap_core_sched_before,
	       .cpu_release		= (void *)qmap_cpu_release,
	       .init_task		= (void *)qmap_init_task,
	       .dump			= (void *)qmap_dump,
	       .dump_cpu		= (void *)qmap_dump_cpu,
	       .dump_task		= (void *)qmap_dump_task,
	       .cpu_online		= (void *)qmap_cpu_online,
	       .cpu_offline		= (void *)qmap_cpu_offline,
	       .init			= (void *)qmap_init,
	       .exit			= (void *)qmap_exit,
	       .flags			= SCX_OPS_ENQ_LAST,
	       .timeout_ms		= 5000U,
	       .name			= "qmap_me");

/*上述代码将被展开为：
SEC(".struct_ops.link")
struct sched_ext_ops qmap_ops = {
	.select_cpu = (void *)qmap_select_cpu,
	.enqueue = (void *)qmap_enqueue,
	.dequeue = (void *)qmap_dequeue,
	// 其他操作函数...
	.name = "qmap_me",
};
在 sched_ext 的设计架构中, 任意一个对结构体 struct sched_ext_ops 的实现都可以被载入内核作为调度器
*/