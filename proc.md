```c++
/proc
├── [PID]/                   # 每个进程的目录，PID 为进程 ID
│   ├── cmdline              # 进程启动命令行
│   ├── cwd -> /path         # 进程当前工作目录（符号链接）
│   ├── environ              # 进程的环境变量
│   ├── exe -> /path         # 进程执行的二进制文件（符号链接）
│   ├── fd/                  # 进程的文件描述符目录
│   │   ├── 0 -> /dev/pts/0  # 文件描述符 0（标准输入）
│   │   ├── 1 -> /dev/pts/0  # 文件描述符 1（标准输出）
│   │   └── 2 -> /dev/pts/0  # 文件描述符 2（标准错误）
│   ├── maps                 # 进程的内存映射
│   ├── mem                  # 进程的内存（需要权限）
│   ├── mounts               # 进程的挂载信息
│   ├── root -> /            # 进程的根目录（符号链接）
│   ├── stat                 # 进程的状态和统计信息
│   ├── status               # 进程的详细状态信息
│   └── task/                # 进程的线程信息目录
│       └── [TID]/           # 每个线程的目录，TID 为线程 ID
│           ├── stack        # 线程的内核栈
│           └── status       # 线程的状态
├── cpuinfo                  # CPU 信息
├── meminfo                  # 内存使用信息
├── uptime                   # 系统运行时间
├── loadavg                  # 系统负载平均值
├── version                  # 内核版本信息
├── devices                  # 已识别的设备列表
├── diskstats                # 磁盘 I/O 统计信息
├── partitions               # 磁盘分区信息
├── mounts                   # 当前挂载的文件系统
├── net/                     # 网络子系统信息
│   ├── dev                  # 网络设备统计
│   ├── tcp                  # TCP 连接状态
│   └── udp                  # UDP 连接状态
├── sys/                     # 系统配置参数（可写）
│   ├── kernel/
│   │   ├── hostname         # 主机名
│   │   ├── random/          # 随机数生成配置
│   │   └── ...
│   └── net/                 # 网络配置
│       └── ipv4/
│           ├── ip_forward   # IP 转发设置
│           └── ...
└── self/                    # 当前进程的符号链接

```
