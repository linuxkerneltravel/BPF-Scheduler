# 基于eBPF的系统状况监测和基于sched_ext的自动化控制

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

   在上述观测数据的基础上，本项目进一步结合 Linux 内核最新引入的 sched_ext 调度扩展技术，通过实时数据驱动，实现自动化的系统性能优化和资源调度控制。

## 环境搭建
对于具体的环境配置还有代码的运行环境，一切都在[这里](Document/环境搭建.md)，为了简洁这里就不多介绍了

## 代码架构
核心的文件夹是include（定义了一些结构体和函数）和bpf（这里是内核态bpf代码的部分）
```shell
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
```shell
bpf/                                 # eBPF 程序目录
├── cpu_stats.bpf.c                 # CPU 性能统计的 eBPF 程序
├── io_stats.bpf.c                  # IO 性能监控的 eBPF 程序
├── mm_leak.bpf.c                   # 内存泄漏检测的 eBPF 程序
├── mm_stats.bpf.c                  # 内存统计的 eBPF 程序
├── net_stats.bpf.c                 # 网络性能监控的 eBPF 程序
└── scx_nest.bpf.c                  # scx-nest相关的 eBPF 程序
```
```shell
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

## 基础知识和思路的讲解
在讲基于sched_ext的调度器设计之前，我这里先补充一下Linux调度器的大体架构，详细的讲解分别在
- [task_struct结构体分析](Document/sched/任务的内核态表示.md)
- [Linux内核调度器介绍](Document/sched/调度.md)
- [sched_ext架构介绍](Document/sched_ext/sched_ext.md)

对于其他进程线程或是Linux系统的解析感兴趣的话可以看我知乎中的文章 https://www.zhihu.com/people/mr-mi-40 ，感谢支持:)

了解了上面的基础之后，接下来讲讲基于sched_ext的scx-nest的设计

### scx-nest
scx-nest整体上是基于 https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/45-scx-nest 这个的架构，
在它基础之上改进了它存在的一些问题，同时联合我的系统性能监测程序，实现了自动化控制，关于官方的scx-nest的文档在[这里](Document/sched_ext/README.zh.md)，
我这里一遍分析它的源码一遍讲讲我的改进思路















