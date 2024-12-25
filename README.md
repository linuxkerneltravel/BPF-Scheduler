# 基于eBPF的系统状况监测和基于sched_ext的自动化控制
具体赛题为 proj6 实现一个基于eBPF技术监控Linux系统稳定性的工具

## 简介

本项目主要分为两个大方面

1. 基于 eBPF 的内核观测工具开发

   该模块利用 eBPF（Extended Berkeley Packet Filter）技术，构建了一套可实时观测 Linux 内核运行状态和行为的工具集。主要涵盖以下四个方面：

   - CPU 监控：捕捉 CPU 使用率、线程以及进程的cpu占用率、任务调度延迟等关键指标
   - 内存观测：分析内存使用率、跟踪内存分配、监测OOM事件等
   - IO 分析：记录整体的IO读写延迟、线程和进程的读写量
   - 网络行为监测：处理网络延迟相关事件、记录了TCP 往返时延（RTT，Round-Trip Time）、统计和分析 TCP 连接中流量最多的会话、
     处理 TCP 重传事件，监控数据包的重传情况
2. 基于sched_ext的自动化控制

- 在上述观测数据的基础上，本项目进一步结合 Linux 内核最新引入的 sched_ext 调度扩展技术，通过实时数据驱动，实现自动化的系统性能优化和资源调度控制。
- 以往的基于ebpf的性能分析程序，除了网络部分之外，基本都是止步于监测，难以对有问题的任务进行有效而灵活的控制
- 从今年9月份sched_ext引入内核后，用户态自定义内核调度器成为可能，本项目首先对内核调度器架构进行了深入的解析
  - 任务的内核态表示 —— task_struct
  - Linux调度器子系统的整体架构
  - sched_ext的整体架构
- 在深入理解原理之上，本项目完善了一个调度器，经过测试在高压情况下要性能要明显优于系统默认的CFS调度器

补充一下，这个分支主要都是我在虚拟机上写的，一直git更新的用户就是我的GitHub账号 https://github.com/restart126

所有的视频文件都来自链接: https://pan.baidu.com/s/1h8lBofO8eoIwl1hw-mHSJA?pwd=osos 提取码: osos

## 环境搭建

对于具体的环境配置还有代码的运行环境，一切都在[这里](Document/环境搭建.md)，为了简洁这里就不多介绍了

## 对系统性能的影响

在htop的输出中可以很清晰的显示出来
![img_32.jpg](Document%2Fimg_32.jpg)

![img_33.jpg](Document%2Fimg_33.jpg)

启用sched_ext调度器会使得cpu占用率有所上升，但整体仍然不超过1%

## 代码架构

核心的文件夹是include（定义了一些结构体和函数）和bpf（这里是内核态bpf代码的部分）

```
include/                        # 头文件目录
├── bpf-compat/                 # scx需要的部分
├── scx/                        # scx需要的部分
├── sys_event.h                 # 系统整体性结构体和功能定义
├── blazesym.h                  # 符号解析或符号相关功能的定义
├── cpu_event.h                 # CPU 事件结构体和功能定义
├── io_event.h                  # IO 事件结构体和功能定义
├── mm_event.h                  # 内存事件结构体和功能定义
├── net_event.h                 # 网络事件结构体和功能定义
├── env.h                       # 环境配置相关定义
├── hash_table.h                # 哈希表工具支持，已经弃用
├── proc_data.h                 # 对于一些能直接从proc获得的整体性数据的采样分析
├── scx_nest.h                  # scx-nest部分
└── scx_nest_stats_table.h      # scx-nest部分
```

```
bpf/                                 # eBPF 程序目录
├── cpu_stats.bpf.c                 # CPU 性能统计的 eBPF 程序
├── io_stats.bpf.c                  # IO 性能监控的 eBPF 程序
├── mm_leak.bpf.c                   # 内存泄漏检测的 eBPF 程序
├── mm_stats.bpf.c                  # 内存统计的 eBPF 程序
├── net_stats.bpf.c                 # 网络性能监控的 eBPF 程序
└── scx_nest.bpf.c                  # scx-nest相关的 eBPF 程序
```

```
/                                   # 项目的用户态代码部分，各个模块都先测试，然后整合在一起
├── io_spy.c                        # IO 监控模块用户态代码
├── cpu_spy.c                       # cpu 监控模块用户态代码，因为是第一个写的模块，写的一般，在最终的os_spy和scx_spy中都改了很多
├── mm_spy.c                        # 内存模块用户态代码
├── net_spy.c                       # 网络模块用户态代码
├── os_spy.c                        # main分支的目标文件
├── scx_spy.c                       # scx分支的目标文件
├── sched_ext.c                     # scx-nest模块用户态代码
└── scx_nest.c                      # 弃用
```

```
visualize/                          # 可视化部分与文档输出
├── run/                            # 程序运行时候存储的本地csv文件
├── proc/                           # 程序运行时候不适合输出到Grafana的部分输出
├── cpu_data_analyse.py             # CPU 本地数据传递给Prometheus
├── io_data_analyse.py              # IO 本地数据传递给Prometheus
├── mm_data_analyse.py              # 内存本地数据传递给Prometheus
├── net_data_analyse.py             # 网络本地数据传递给Prometheus
├── net_test.py                     # 网络测试脚本的辅助脚本，配合net_with_delay.sh
├── net_with_delay.sh               # 网络测试脚本，里面可以自定义延迟和掉包率，测试60s
└── visual.sh                       # 运行它可以同时把所有传递Prometheus的脚本（*_data_analyse.py）都运行
```

```
Document/                           # 文档
├── sched/                          # 对内核中task_struct结构和调度子系统的解析
├── sched_ext/                         
      ├── sched_ext.md              # sched_ext整体架构和核心函数的解析
      └── README.zh.md              # scx-nest的官方中文文档
├── cpu.md                          # CPU 监控程序的思路和实验
├── io.md                           # IO 监控程序的思路和实验
├── memory.md                       # 内存监控程序的思路和实验
├── net.md                          # 网络监控程序的思路和实验
├── scx-nest.md                     # scx-nest的实验测试文档
├── ebpf编程注意点.md                # ebpf编程的时候踩过的一些坑
└── 环境搭建.md                      # 实验环境配置文档
```

我在这里进一步强调一下，scx_spy.c是scx分支的目标文件，拥有包括sched_ext的完整功能，os_spy.c是main分支的目标文件，拥有整个系统监测的功能

## cpu监测部分

编译好之后，对于普通版本和sched_ext的版本分别这样执行

```shell
sudo ./os_spy -c
sudo ./scx_spy -c
# 对于scx_spy，-e可以启用scx-nest调度模式
# 可以加上-v，这样可以把记录的数据保存在本地
# 之后的几个其他监测都是可以一起加上去的，我这里为了解释清楚只写了一个
```

内核态bpf的实现部分在[这里](bpf/cpu_stats.bpf.c)，从最后的功能实现来看，分为以下几个部分

- 每个cpu的使用情况：空闲时间占比，内核态时间占比，用户态时间占比，中断时间占比，软中断时间占比
- cpu占用率高的task的情况：包括pid、线程名、占用cpu的时间占比，在整个运行时间中内核态时间和用户态时间的占比
- cpu占用率高的进程的情况：包括进程的tgid，占用cpu的时间占比，进程中的线程数
- 任务从进入运行队列到实际调度中间的调度延迟，通过调度延迟评估系统的 cpu 压力，判断当前 cpu 是否存在过载或调度延迟问题

从调度延迟来看系统当前的cpu压力情况，这个是整体方向上的分析，通过分析每个 cpu 的使用情况，可以定位到哪个 cpu 存在高负载或异常行为，
而之后的task占用情况和process占用情况就是对具体异常任务的精确定位

具体的情况和实验请看[这里](Document/cpu.md)

## io监测部分

编译好之后，对于普通版本和sched_ext的版本分别这样执行

```shell
sudo ./os_spy -I
sudo ./scx_spy -I
# 对于scx_spy，-e可以启用scx-nest调度模式
# 可以加上-v，这样可以把记录的数据保存在本地
```

内核态的bpf代码在[这里](bpf/io_stats.bpf.c)，从最后功能来看，可以分为以下部分

- 各磁盘设备及其分区的读写的情况
- 读写频率高的task的情况：包括pid、线程名、在时间窗口内的读次数和写次数
- 读写频率高的进程的情况：包括tgid、在时间窗口内的读次数和写次数
- 任务从IO请求开始到完成请求直接的响应延迟

从响应延迟来看系统整体的IO压力，设备分区的读写情况可以看出目前IO集中在哪个具体部分，
之后对读写频率高的task和进程进行监控，找出其中导致IO瓶颈的问题任务

具体的情况和实验请看[这里](Document/io.md)

## memory监测部分

编译好之后，对于普通版本和sched_ext的版本分别这样执行

```shell
sudo ./os_spy -m
sudo ./scx_spy -m
# 对于scx_spy，-e可以启用scx-nest调度模式
# 可以加上-v，这样可以把记录的数据保存在本地
```

内核态的bpf代码在[这里](bpf/mm_stats.bpf.c)和[这里](bpf/mm_leak.bpf.c)，可以总结为以下部分

- 记录系统当前内存的情况：当前已使用的内存占比、可用内存占比、有多少swap memory等
- 参考 https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/16-memleak 记录了个内核的内存分配事件
- 内存分配或释放频率高的task的监视：包括task自身的信息、kmem、vmem、slab等分配的情况
- 内存分配或释放频率高的process的监视：包括process自身的信息、kmem、vmem、slab等分配的情况
- 监视oom事件：包括触发oom的task，被oom杀死的task和被杀死的任务名、发生oom的时间

先分析系统整体的内存情况，从整体范围观察内存的变化，然后通过记录特定task和process的内存分配情况找出问题任务，
同时在高压力情况下，捕获oom事件

具体的情况和实验请看[这里](Document/memory.md)

## net监测部分

编译好之后，对于普通版本和sched_ext的版本分别这样执行

```shell
sudo ./os_spy -n
sudo ./scx_spy -n
# 对于scx_spy，-e可以启用scx-nest调度模式
# 可以加上-v，这样可以把记录的数据保存在本地
```

内核态的bpf代码在[这里](bpf/net_stats.bpf.c)

因为net监测部分是我处理sched_ext部分以外最后一个写的，所以这时候写道思路最清晰，对于目标也最清晰，
我的想法就是直接找bcc的相关功能复现，因为bcc大部分都是python写的，我相当是针对它的功能用libbpf的架构进行了复现，
具体来说复现了以下几个部分

- 系统整体的网络接口统计信息
- tcptop
- tcprtt
- tcpretrans
- tcp连接延迟

tcprtt记录系统中基于 TCP 连接的往返时间，反映系统当前整体的网络状况，tcptop记录当前收发数据较多的任务记录下来，
tcpretrans记录系统中 TCP 重传的具体事件，精确定位是哪些任务网络出了问题，最后tcp连接延迟则是把给延迟较高的任务做个了精确的度量

具体的情况和实验请看[这里](Document/net.md)

## scx-nest调度器设计

在讲基于sched_ext的调度器设计之前，需要先补充一下Linux调度器的大体架构，我对这里做了详细的分析，文档在这里

- [task_struct结构体分析](Document/sched/任务的内核态表示.md)
- [Linux内核调度器介绍](Document/sched/调度.md)
- [sched_ext架构介绍](Document/sched_ext/sched_ext.md)

对于其他进程线程或是Linux系统的解析感兴趣的话可以看我知乎中的文章 https://www.zhihu.com/people/mr-mi-40 ，感谢支持:)

了解了上面的基础之后，接下来讲讲基于sched_ext的scx-nest的设计

### scx-nest

scx-nest整体上是基于 https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/45-scx-nest 这个的架构，
在它基础之上改进了它存在的一些问题，同时联合我的系统性能监测程序，实现了自动化控制，关于官方的scx-nest的文档在[这里](Document/sched_ext/README.zh.md)，
我这里一边分析它的源码一边讲讲我的改进思路

1. scx-nest的大体设计思路

在scx-nest调度器中，Nest 被划分为多个集合（如 Primary Nest 和 Reserve Nest），这些集合在调度过程中扮演了不同的角色，目的是优化任务分配、核心复用和性能

- Primary Nest（主集合）
  - 作用
    - Primary Nest 是当前活跃或最近活跃的核心集合，调度器优先选择其中的核心进行任务分配
    - 它的设计目的是实现核心复用，尽量减少任务被分配到长时间未使用的核心，以保持核心的高频率运行（“保持核心温暖”）
  - 特点
    - 动态调整大小，随任务数量的变化而增加或减少
    - 当某个核心在一段时间内未被任务使用，就会从 Primary Nest 移出，以保持集合的紧凑性
    - 如果任务需要一个核心但 Primary Nest 中没有空闲核心，则会尝试使用 Reserve Nest 或 CFS 默认策略
    - 主要负责高频任务的调度和核心复用
- Reserve Nest（备用集合）
  - 作用
    - Reserve Nest 是一个次级核心集合，用于存储较少使用或最近刚从 Primary Nest 移出的核心
    - 当 Primary Nest 无法提供合适的核心时，Reserve Nest 提供后备选择，减少任务分散到系统中其他完全空闲的核心
  - 特点
    - 有固定的最大大小限制
    - 如果任务频繁寻找核心但未能在 Primary Nest 中分配到空闲核心，则可能触发 Reserve Nest 的扩展
    - 核心从 Primary Nest 降级后通常会进入 Reserve Nest，而不是直接变成空闲核心
    - 提供灵活性，避免频繁降级核心导致性能抖动，任务负载变化的情况下，Reserve Nest 减少核心频繁进入深度空闲状态
- Idle Mask（空闲核心集合）
  - 作用
    - 统计和跟踪系统中完全空闲的核心，但不直接用于任务分配
    - 用于支持调度器判断是否需要扩展 Primary Nest 或 Reserve Nest
  - 特点
    - 如果启用了寻找完全空闲核心的策略（find_fully_idle），调度器可能会将某些任务分配到空闲核心，以追求更高的整体性能
    - 仅在必要时被使用，例如当 Primary 和 Reserve Nest 都没有合适的核心时
- Other Mask（其他核心集合）
  - 作用
    - 包括不属于 Primary Nest 和 Reserve Nest 的核心，通常被用作最后的选择
    - 当 Primary 和 Reserve Nest 无法满足需求时，任务会被分配到这些核心
  - 特点
    - 这些核心可能较长时间未被使用，初始频率较低
    - 频繁使用 Other Mask 会导致核心复用效率降低

大体的流程如下

- 任务分配优先级
  - 优先尝试在 Primary Nest 中寻找空闲核心
  - 如果 Primary Nest 无法满足要求，则检查 Reserve Nest
  - 如果 Reserve Nest 也无法满足，则可能尝试完全空闲核心（Idle Mask）或其他默认策略（如 CFS 分配）
- 动态调整
  - Primary Nest 缩减: 如果核心长时间未使用，则会从 Primary Nest 降级到 Reserve Nest
  - Reserve Nest 限制: 如果 Reserve Nest 达到最大容量，多余的核心将被移除
  - 任务饥饿处理: 如果任务频繁无法分配到核心，会扩大 Primary Nest 的范围以解决拥塞

2. 重要的几个ebpf_map
   存储每个物理核心的上下文信息，主要与核心的压缩（compaction）状态相关

```c
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, s32);
	__type(value, struct pcpu_ctx);
} pcpu_ctxs SEC(".maps");
```

```c
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
```

3. nest_select_cpu
   这里就是实现scx-nest的最核心的部分，大致是以下流程

```
   首选核心检查
   ├── 尝试使用任务附加的核心 (attached_core)
   │   └── 如果核心空闲，选择该核心 (goto migrate_primary)
   ├── 尝试使用上一次运行核心 (prev_cpu)
   │   └── 如果核心空闲且不是附加的核心，选择该核心 (goto migrate_primary)
   │
   在 Primary Nest 中查找核心
   ├── 如果启用了find_fully_idle(寻找完全空闲核心)策略
   │    ├── 在Primary Nest 中尝试寻找完全空闲的核心
   │        └── 如果找到，选择该核心 (goto migrate_primary)
   └── 在Primary Nest 中尝试寻找任意空闲核心
   │    └── 如果找到，选择该核心 (goto migrate_primary)
   │
   检查任务是否“不耐烦” (r_impatient)
   ├── 如果任务连续多次未分配到 Primary 核心，则标记为 "不耐烦"
   └── 记录统计数据 TASK_IMPATIENT
   │
   到此在 Primary Nest 中未找到核心，在 Reserve Nest 中查找核心
   ├── 尝试寻找完全空闲的核心
   │   └── 如果找到，选择该核心并提升到 Primary (goto promote_to_primary)
   └── 尝试寻找任意空闲核心
   │    └── 如果找到，选择该核心并提升到 Primary (goto promote_to_primary)
   │
   在任务允许的 CPU 集合中查找核心
   ├── 尝试寻找任意空闲核心
   │   ├── 如果核心在 Primary Nest，直接迁移到 Primary (goto migrate_primary)
   │   ├── 如果核心在 Reserve Nest，提升到 Primary (goto promote_to_primary)
   │   ├── 如果任务 "不耐烦"，直接提升到 Primary (goto promote_to_primary)
   │   └── 如果核心不属于任何 Nest，将其标记为 Reserve
   └── 返回找到的核心 ID
   │
   核心状态调整
   ├── promote_to_primary
   │   ├── 记录 PROMOTED_TO_PRIMARY 事件
   │   └── 跳转到 migrate_primary
   └── migrate_primary
       ├── 如果任务未达 "不耐烦" 阈值，重置失败计数 (prev_misses)
       ├── 如果核心正在被压缩，取消压缩计划并重新配置压缩计时器
       ├── 将核心标记为 Primary 成员
       ├── 如果核心在 Reserve Nest，移除其 Reserve 状态
       ├── 更新任务附加核心 (update_attached)
       └── 调度任务 (operate_bad_guys -> scx_bpf_dispatch)
```

对于scx-nest的源代码中，这里有一个非常令人疑惑的点

```c
bpf_rcu_read_unlock();
update_attached(tctx, prev_cpu, cpu);
scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, 0);// 就是这里
return cpu;
```

不知道是不是作者特地留给读者的坑，选了cpu选了半天，最终把task分配到了当前cpu的local_dsq，
相当于一切选择都白花了，于是我这里改成了

```c
scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | cpu  , slice_ns, 0);
```

具体[实验结果](Document/scx-nest.md)也显示了我这样改动才是对的

4. nest_dispatch
   干的事情总结起来就一句话，消耗global_dsq中的任务

```c
// 如果队列中的任务被消耗完了，即scx_bpf_consume(FALLBACK_DSQ_ID) 返回 false
	if (!scx_bpf_consume(FALLBACK_DSQ_ID)) {
		// 使用 bpf_cpumask_test_cpu 检测当前核心是否仍然属于 Primary Nest
		in_primary = bpf_cpumask_test_cpu(cpu, cast_mask(primary));

		// 如果上一个任务（prev）仍然在任务队列中（SCX_TASK_QUEUED），并且当前核心属于 Primary Nest，则重新派发该任务
		// 避免核心进入空闲状态，确保资源被充分利用
		if (prev && (prev->scx.flags & SCX_TASK_QUEUED) && in_primary) {
			scx_bpf_dispatch(prev, SCX_DSQ_LOCAL, slice_ns, 0);
			return;
		}

		// 如果当前任务队列没有任务被消费，记录一次 NOT_CONSUMED 事件，便于后续分析和优化
		stat_inc(NEST_STAT(NOT_CONSUMED));
		if (in_primary) { // 如果核心在 Primary Nest
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
			 	* 设置压缩定时器，在指定时间后检查核心是否仍然未被使用。
			 	*/
				bpf_timer_start(&pcpu_ctx->timer, p_remove_ns,
						BPF_F_TIMER_CPU_PIN);
				stat_inc(NEST_STAT(SCHEDULED_COMPACTION));
			}
		}
		return;
	}
```

5. 我加入的改进
   对于已经知道的”坏任务“，有个ebpf_map专门来存

```c
struct cpu_bad_guys {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, u32);
	__type(value, u32);
} cpu_bad_guys_map SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, u32);
	__array(values,struct cpu_bad_guys);
} cpu_filter_ids SEC(".maps");
```

对于这些”bad_guys“，要减少它们占用cpu的时间，具体方式是通过两个步骤

- 避免把这些任务直接放到cpu的local_dsq，都是放到global_dsq
- 减少它们的cpu使用时间slice_ns

先来看看select_cpu部分，看看它调用的时机，下面是官方文档

```c
/**
 * select_cpu - 为被唤醒的任务选择目标 CPU
 * @p: 被唤醒的任务
 * @prev_cpu: 任务 @p 睡眠前所在的 CPU
 * @wake_flags: SCX_WAKE_* 类型的唤醒标志
 *
 * 这里的决策不是最终的。任务 @p 可能在稍后被调度到任何 CPU 上执行。
 * 然而，由于此时任务 @p 尚未加入运行队列（runqueue），
 * 在此阶段选定最终的执行 CPU 可以减少后续的调度开销。
 *
 * 如果返回一个空闲的 CPU，该 CPU 将被触发唤醒并尝试分配任务。
 * 尽管可以添加显式的自定义机制，select_cpu() 作为默认方法负责唤醒空闲的 CPU。
 *
 * 任务 @p 可以通过调用 scx_bpf_dispatch() 被直接调度。
 * 如果任务被直接调度，ops.enqueue() 回调将被跳过。
 * 最后，如果任务 @p 被调度到 SCX_DSQ_LOCAL，
 * 它将被分配到此回调返回的 CPU 的本地调度队列中。
 */
s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
```

当任务被唤醒但尚未加入运行队列（runqueue）时，通过此函数选择其目标 CPU，相当于任务调用流程中开始的一个阶段，
在这里一开始直接调用scx_bpf_dispatch()可以直接调度来减轻之后的调度开销，于是我在这里直接开始过滤任务插手任务调度

```c
// 开始过滤特殊任务
	int ret = operate_bad_guys(p,0);
    // return 1代表是正常任务，正常调度就行了
	if(ret == 1)
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | cpu  , slice_ns, 0);
	return cpu;
```

对于operate_bad_guys就是我设计的过滤任务的核心函数

```c
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
    // 控制”坏任务“的调度
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
```

可以看到，所有的”坏任务“都被分配到了”FALLBACK_DSQ_ID“这个队列

```c
FALLBACK_DSQ_ID		= 0,// 默认调度队列的标识符。
```

可以看出来这个就是把global_dsq改了个名，就是global_dsq，而global_dsq中任务消耗的时机就是在nest_dispatch的时候，
而nest_dispatch调用的时机，也可以从内核源码中一窥一二

```c
/**
 * dispatch - 从 BPF 调度器调度任务并/或消费 DSQs
 * @cpu: 需要调度任务的目标 CPU
 * @prev: 上一个被切换出的任务
 *
 * 当 CPU 的本地调度队列（local DSQ）为空时调用。
 * 该操作应该通过 scx_bpf_dispatch() 将一个或多个任务从 BPF 调度器分配到 DSQs，
 * 或者通过 scx_bpf_consume() 将用户 DSQs 中的任务移入本地 DSQ。
 *
 * 在没有调用 scx_bpf_consume() 进行干预的情况下，调用 scx_bpf_dispatch() 的最大次数
 * 由 ops.dispatch_max_batch 指定。更多细节请参阅这两个函数顶部的注释。
 *
 * 如果 @prev 不为 NULL，则表示是一个任务时间片已耗尽的 SCX 任务。
 * 如果通过在 @prev->scx.flags 中设置的标志 %SCX_TASK_QUEUED 表明该任务仍然可以运行，
 * 它还未被重新加入队列，并将在 ops.dispatch() 返回后重新加入。
 * 如果希望继续执行 @prev，直接返回，不分配或消费任何任务。此外请参阅 %SCX_OPS_ENQ_LAST。
 */
void (*dispatch)(s32 cpu, struct task_struct *prev);
```

可以看到，只有cpu的local_dsq空的时候，才会去取用global_dsq中的任务来调度，所以在select_cpu的部分，把有问题的任务分配到global_dsq的原因就是这个，
通过这样可以进一步减少”坏任务”对系统造成的影响

除了这些，在入队的时候也加上对“坏任务”的过滤

```c
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
```

在内核态的bpf文件的改进的重要部分就在这里，关于基于scx-nest的调度实验，在[这里](Document/scx-nest.md)

## 总结和感想

对于一路下来的经历，在ebpf编程部分踩过的坑都记录在`Document/ebpf编程注意点.md`

在比赛的最后这段时间，我考虑过继续完善这次比赛的监测部分，但想到关于基于ebpf的系统监测，网络上已经有了很多成型和成体系的工具，
以我现在的能力更多的是去学习他们的思路和方式，难以在他们的基础上有新的创新和突破

但对于sched_ext部分，在完成项目的过程中，这方面的资料少之又少，大部分都是止于对它的介绍，
而使用和在他之上的开发除了 bpf-developer-tutorial 之外没有别的

所以我利用最后的这部分时间，把我完善的scx-nest部分进一步抽离了出来，同时进一步完善了和用户态的交互，代码放到了 scx-plug 分支，
在当前 scx 分支我也建立了个 scx-plug 文件夹，把我模块化后的 scx-plug都放到了这里，只要 scx 的环境配置通过，
这个scx-plug文件夹可以直接 make 编译，Makefile 已经调整过了，欢迎来尝试和运行

sched_ext 让热插拔的自定义调度器成为了可能，配合全面的监测数据，可以将处理任务优先级的复杂逻辑大部分移动至用户态，
实现随系统压力变化的自适应优先级调整，同时庞大的监测数据可以作为 ai 的训练数据，把 ai 引入内核调度器成为了可能。

希望我的这次项目，能带给之后对于调度器设计感兴趣的人一些参考，吸引更多人来尝试sched_ext

(✿╹◡╹)
