#ifndef MM_EVENT_H
#define MM_EVENT_H

#include "sys_event.h"

#define ALLOCS_MAX_ENTRIES 100000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240
#define PERF_MAX_STACK_DEPTH 128

#define __PT_PARM1_REG di
#define __PT_PARM2_REG si
#define __PT_PARM3_REG dx
#define __PT_PARM4_REG cx
#define __PT_PARM5_REG r8
#define __PT_PARM6_REG r9
/*
 * Syscall uses r10 for PARM4. See arch/x86/entry/entry_64.S:entry_SYSCALL_64
 * comments in Linux sources. And refer to syscall(2) manpage.
 */
#define __PT_PARM1_SYSCALL_REG __PT_PARM1_REG
#define __PT_PARM2_SYSCALL_REG __PT_PARM2_REG
#define __PT_PARM3_SYSCALL_REG __PT_PARM3_REG
#define __PT_PARM4_SYSCALL_REG r10
#define __PT_PARM5_SYSCALL_REG __PT_PARM5_REG
#define __PT_PARM6_SYSCALL_REG __PT_PARM6_REG

#define __PT_RET_REG sp
#define __PT_FP_REG bp
#define __PT_RC_REG ax
#define __PT_SP_REG sp
#define __PT_IP_REG ip

#define __PT_REGS_CAST(x) (x)

#define PT_REGS_RC(x) (__PT_REGS_CAST(x)->__PT_RC_REG)

/*
1. 内存分配热点
- 监测具体的内核函数或模块中频繁的内存分配操作，确定哪些代码路径导致内存压力升高
- 通过挂载在 kmalloc、kfree 等内核内存分配函数上，可以追踪分配内存的调用栈，找到内存压力的主要来源
2. 分配失败的情况
3. 内核对象缓存（SLAB 分配器）压力
4. 页回收与页面抖动
- 通过监控 try_to_free_pages、shrink_node 等函数的执行，可以评估页回收的频率和效率，以及可能的抖动现象
5. 内存回收和 OOM（Out-Of-Memory）事件
- 当系统尝试回收内存失败时，可能会触发 OOM Killer 杀死某些进程。监控 OOM 事件有助于了解哪些进程因内存压力而被终止
6. NUMA 节点的内存压力
- 在 NUMA 系统中，某些节点可能面临较高的内存压力而导致内存分配失败。监控不同 NUMA 节点的内存分配和回收情况，有助于了解节点级别的内存压力
*/

struct mm_threhold {
	u32 kmem_threhold;
	u32 vmem_threhold;
	u32 slab_threhold;

	u64 time_window;
};

struct task_mm_stats {
    struct task_info_simple info;

    u64 last_clear_time;

    u32 kmem_count;
    u32 vmem_count;
    u32 slab_count;

	u32 already_output;
};

struct process_mm_stats {
    u32 tgid;
    
    u32 kmem_count;
    u32 vmem_count;
    u32 slab_count;

	u64 last_clear_time;

	u32 already_output;
};

struct oom_event{
	u32 trigger_id;// 触发 OOM 的进程 PID
	u32 killed_id;// 被 OOM 杀死的进程 PID
	char comm[TASK_COMM_LEN];// 被杀死进程的命令名
	u64 kill_time;
};

struct alloc_info {
	u64 size;
	u64 timestamp_ns;
	int stack_id;
    //int stack_id_usr;
};

struct allocation
{
	int stack_id;
	u64 size;
	u64 count;
};

union combined_alloc_info {
    // 结构体作为位域存在,分别占用 40 位和 24 位
	struct {
		u64 total_size : 40;// 40位，表示总内存大小
		u64 number_of_allocs : 24;// 24位，表示内存分配次数
	};
	u64 bits;// 一个 64 位变量，将总内存大小和分配次数组合成一个 64 位数字
};

#endif //CPU_EVENT_H