## 设计思路

设计一个栈回溯结构，对所有特定条件的任务进行监视，当发生错误或是特定条件时候进行栈回溯

下面是一个例子

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 事件数据结构
struct stacktrace_event {
    int pid;
    int cpu_id;
    int kstack_sz;
    int ustack_sz;
    char comm[TASK_COMM_LEN];
    __u64 kstack[64];
    __u64 ustack[64];
};

// 通用的栈回溯函数
static __inline int capture_stack_trace(void *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    int cpu_id = bpf_get_smp_processor_id();
  
    // 分配一个事件空间用于存储栈信息
    struct stacktrace_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 1;

    event->pid = pid;
    event->cpu_id = cpu_id;
    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;

    // 获取内核栈
    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

    // 获取用户栈
    event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    // 提交事件到环形缓冲区
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/kmalloc")
int trace_kmalloc(struct pt_regs *ctx) {
    // 条件判断，例如检测特定大小的内存分配
    if (PT_REGS_PARM1(ctx) > 1024) {
        capture_stack_trace(ctx);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int on_sys_open(struct trace_event_raw_sys_enter *ctx) {
    // 检查条件，例如检测打开的文件路径是否为特定文件
    capture_stack_trace(ctx);
    return 0;
}


```



## CPU 部分

```shell
CPU 监控指标
│
├── 1. CPU 使用情况
│   ├── 总 CPU 使用率：监控用户态、系统态、空闲时间等
│   ├── CPU 核心负载均衡：查看 CPU 核心之间的负载分布
│   ├── 高 CPU 占用函数：跟踪占用 CPU 资源最多的内核函数
│   └── 频繁的系统调用：捕获高频系统调用对系统资源的消耗
│
├── 2. 上下文切换
│   ├── 上下文切换频率：监控总的上下文切换数量
│   └── 自愿和非自愿上下文切换：区分主动和抢占切换的比例
│
├── 3. 进程调度延迟
│   ├── 调度延迟：跟踪进程从准备运行到被调度的延迟
│   └── 实时进程调度延迟：确保实时进程调度的及时性
│
├── 4. 中断监控
│   ├── 硬中断处理时间：监控硬中断的处理耗时
│   ├── 软中断处理时间：监控软中断的处理耗时
│   └── 中断频率：监控硬中断和软中断的发生频率
│
├── 5. CPU 调度队列
│   ├── 运行队列长度：监控每个 CPU 的运行队列长度
│   └── 平均等待时间：计算进程在调度队列中的平均等待时间
│
├── 6. 锁争用和同步
│   ├── 锁争用延迟：捕获锁获取的延迟时间，分析锁争用情况
│   └── 关键内核锁的争用频率：如 `runqueue_lock` 等锁的争用频率
│
├── 7. CPU 缓存使用
│   └── L1/L2 缓存命中率：监控缓存命中率，降低内存访问开销
│
├── 8. 温度与功耗
│   ├── CPU 温度：监控 CPU 温度以防止高温导致的性能降级
│   └── CPU 频率：动态监控 CPU 频率，识别降频状态
│
├── 9. 任务抖动
│   └── 周期性任务的抖动：监控周期性任务的执行时间抖动情况
│
├── 10. 系统调用延迟
│   └── 系统调用延迟：监控关键系统调用的延迟，检测 IO 瓶颈
│
└── 11. 繁忙等待与自旋锁
    └── 自旋锁和繁忙等待：监控自旋锁和繁忙等待，避免 CPU 资源浪费

```
