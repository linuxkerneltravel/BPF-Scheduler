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
本项目可以从仓库中看到，分别有main和scx分支，建立在两个环境中 

### main分支
main分支是最开始在实机上写的代码，具体版本和环境配置如下
1. 系统及内核版本
```shell
root@ne0-System:~# lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.5 LTS
Release:	22.04
Codename:	jammy
```
```shell
root@ne0-System:~# uname -r
6.8.0-48-generic
```
2. LLVM工具链和rust工具链
```shell
root@ne0-System:~# clang --version
Ubuntu clang version 14.0.0-1ubuntu1.1
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```
```shell
(base) ne0@ne0-System:~$ rustup show
Default host: x86_64-unknown-linux-gnu
rustup home:  /home/ne0/.rustup

stable-x86_64-unknown-linux-gnu (default)
rustc 1.79.0 (129f3b996 2024-06-10)
```
```shell
(base) ne0@ne0-System:~$ cargo --version
cargo 1.79.0 (ffa9cf99a 2024-06-03)
```

3. 环境配置

这里只说一下重要的几个源文件的安装，具体放的路径可以直接在Makefile里看到，如果想改直接改就行了
- libbpf安装
  - 建议从源码编译安装，https://github.com/libbpf/libbpf.git
```shell
$ cd src
$ make
```
- bpftool安装
  - 同样建议从源码编译安装，https://github.com/libbpf/bpftool.git
  - 具体构建安装的流程在官网这里都有

- blazesym安装
  - 从官方编译安装，https://github.com/libbpf/blazesym.git
```shell
git clone https://github.com/libbpf/blazesym.git
cd blazesym
cargo build --release
```
  - 之后到 blazesym/capi文件夹下
```shell
cargo build --release
```
  - 最终能在target/release文件夹下看到这些就算成功
```shell
(base) ne0@ne0-System:~/sys_competition/start/blazesym/target/release$ ls
build  examples     libblazesym_c.a  libblazesym_c.rlib  libblazesym.d
deps   incremental  libblazesym_c.d  libblazesym_c.so    libblazesym.rlib
```


### scx分支
scx分支是才有sched_ext，由于sched_ext是9月份刚出的，只有最新的内核才具备这个功能，所以我是在虚拟机上，
用的6.12的内核写的，为了不影响实机的其他事情，sched_ext都是在虚拟机上跑的，环境配置多了一些其他步骤

- 首先要说明的是，sched_ext这个功能具体你的内核支不支持，可以这样检查
```shell
root@ne0-System:~# zgrep -E "CONFIG_BPF|CONFIG_BPF_EVENTS|CONFIG_BPF_JIT|CONFIG_BPF_SYSCALL|CONFIG_DEBUG_INFO_BTF|CONFIG_FTRACE|CONFIG_SCHED_CLASS_EXT" /boot/config-$(uname -r)
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
# CONFIG_BPF_PRELOAD is not set
CONFIG_BPF_LSM=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_FTRACE=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_BPF_EVENTS=y
CONFIG_BPF_KPROBE_OVERRIDE=y
CONFIG_FTRACE_MCOUNT_RECORD=y
CONFIG_FTRACE_MCOUNT_USE_CC=y
# CONFIG_FTRACE_RECORD_RECURSION is not set
# CONFIG_FTRACE_STARTUP_TEST is not set
# CONFIG_FTRACE_SORT_STARTUP_TEST is not set
```
- 上面输出是我实机的输出，对于sched_ext，需要以下这些配置
```shell
CONFIG_BPF=y
CONFIG_SCHED_CLASS_EXT=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_PAHOLE_HAS_SPLIT_BTF=y
CONFIG_PAHOLE_HAS_BTF_TAG=y
```
- 对于我虚拟机的输出，是这样的
```shell
ne1@ne1-virtual-machine:~$ zgrep -E "CONFIG_BPF|CONFIG_BPF_EVENTS|CONFIG_BPF_JIT|CONFIG_BPF_SYSCALL|CONFIG_DEBUG_INFO_BTF|CONFIG_FTRACE|CONFIG_SCHED_CLASS_EXT" /boot/config-$(uname -r)
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
# CONFIG_BPF_PRELOAD is not set
CONFIG_BPF_LSM=y
CONFIG_SCHED_CLASS_EXT=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_FTRACE=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_BPF_EVENTS=y
CONFIG_BPF_KPROBE_OVERRIDE=y
CONFIG_FTRACE_MCOUNT_RECORD=y
CONFIG_FTRACE_MCOUNT_USE_CC=y
```
- 下面把内核和系统版本，还有工具链版本都补充一下
```shell
ne1@ne1-virtual-machine:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 24.04.1 LTS
Release:	24.04
Codename:	noble

ne1@ne1-virtual-machine:~$ uname -r
6.12.0-061200-generic

ne1@ne1-virtual-machine:~$ clang --version
Ubuntu clang version 17.0.6 (9ubuntu1)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/lib/llvm-17/bin

ne1@ne1-virtual-machine:~$ rustup show
Default host: x86_64-unknown-linux-gnu
rustup home:  /home/ne1/.rustup

stable-x86_64-unknown-linux-gnu (default)
rustc 1.79.0 (129f3b996 2024-06-10)

ne1@ne1-virtual-machine:~$ cargo --version
cargo 1.75.0
```

1. 6.12内核的配置和安装
- sched_ext官方的教程是没用的，官方给的教程中
```shell
$ sudo do-release-upgrade -d
$ sudo add-apt-repository -y --enable-source ppa:canonical-kernel-team/unstable
$ sudo sed -i "s/^Suites: .*/Suites: plucky/" \
  /etc/apt/sources.list.d/canonical-kernel-team-ubuntu-unstable-plucky.sources
$ sudo apt install -y linux-generic-wip

# 到了最后这步
ne1@ne1-virtual-machine:~$ sudo apt install -y linux-generic-wip
[sudo] password for ne1: 
正在读取软件包列表... 完成
正在分析软件包的依赖关系树... 完成
正在读取状态信息... 完成                 
E: 无法定位软件包 linux-generic-wip
```
- 去官网 https://launchpad.net/~canonical-kernel-team/+archive/ubuntu/unstable 也找不到相关的
- 所以我之后具体是这样安装的
- 首先去官网下载6.12版本的 https://kernel.ubuntu.com/mainline/v6.12/ ，将
  linux-headers-6.12.0-061200-generic、linux-image-unsigned-6.12.0-061200-generic、linux-modules-6.12.0-061200-generic、
linux-headers-6.12.0-061200这些都安装到本地，之后
```shell
sudo dpkg -i linux-headers-6.12.0-061200*.deb linux-image-unsigned-6.12.0-061200-generic_*.deb linux-modules-6.12.0-061200-generic_*.deb
```
- 安装完成之后重启
```shell
sudo update-grub
sudo reboot
```
- 重启之后看内核版本，没问题的话就是我这个版本
```shell
ne1@ne1-virtual-machine:~$ uname -r
6.12.0-061200-generic
```

2. vmlinux.h的创建
- 对于6.12内核的系统，得自己生成vmlinux
```shell
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

3. 其他的libbpf、bpftool什么的都和上面流程一样了

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















