## ebpf编程注意点
1. 用户态设置向bpf文件中传递的最方便办法就是ebpf_map，不容易出bug，否则很容易过不了验证器
2. 编写代码时候要注意，对于一般比较大的结构体或者高维数组，如果在bpf文件中，是没法直接初始化的
    - bpf文件中栈只有512字节，对于较大的结构体或数组，如果作为局部变量会导致栈溢出，通不过编译
    - 还有就是隐形的memset，下面这句是可能通不过编译的，报错，对于这种情况可以建个ebpf_map，在用户态初始化之后，作为模板，然后以模板出发来修改

3. 关于tracepoint的结构体格式，可以先去vmlinux.h中结构体成员是个啥样子的，也可以通过以下命令来直接查，以查sched_switch的tracepoint的结构体为例
```shell
root@ne0-System:/home/ne0/sys_competition/start/cpu_watcher/visualize/run# cat /sys/kernel/debug/tracing/events/sched/sched_switch/format
name: sched_switch
ID: 330
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:char prev_comm[16];	offset:8;	size:16;	signed:0;
	field:pid_t prev_pid;	offset:24;	size:4;	signed:1;
	field:int prev_prio;	offset:28;	size:4;	signed:1;
	field:long prev_state;	offset:32;	size:8;	signed:1;
	field:char next_comm[16];	offset:40;	size:16;	signed:0;
	field:pid_t next_pid;	offset:56;	size:4;	signed:1;
	field:int next_prio;	offset:60;	size:4;	signed:1;

print fmt: "prev_comm=%s prev_pid=%d prev_prio=%d prev_state=%s%s ==> next_comm=%s next_pid=%d next_prio=%d", REC->prev_comm, REC->prev_pid, REC->prev_prio, (REC->prev_state & ((((0x00000000 | 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040) + 1) << 1) - 1)) ? __print_flags(REC->prev_state & ((((0x00000000 | 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040) + 1) << 1) - 1), "|", { 0x00000001, "S" }, { 0x00000002, "D" }, { 0x00000004, "T" }, { 0x00000008, "t" }, { 0x00000010, "X" }, { 0x00000020, "Z" }, { 0x00000040, "P" }, { 0x00000080, "I" }) : "R", REC->prev_state & (((0x00000000 | 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040) + 1) << 1) ? "+" : "", REC->next_comm, REC->next_pid, REC->next_prio
```

4. 所有循环的结束条件在编译前确定，如果一定要运行时确定，至少要先加个上限

5. map类型
    - BPF_MAP_TYPE_HASH
        - 哈希表，允许使用任意的键值进行存储和查找
        - 查找时间复杂度为 O(1) 平均，取决于哈希函数和冲突处理
    - BPF_MAP_TYPE_ARRAY
        - 固定大小的数组，键是连续的整数索引，从 0 到 max_entries - 1
        - 键必须在预定义的连续范围内，无法存储任意键
    - BPF_MAP_TYPE_PERCPU_HASH 和 BPF_MAP_TYPE_PERCPU_ARRAY
        - 类似于 HASH 和 ARRAY，但为每个 CPU 都维护一个独立的副本
    - BPF_MAP_TYPE_ARRAY_OF_MAPS 和 BPF_MAP_TYPE_HASH_OF_MAPS
        - 嵌套映射，允许一个映射的值本身是另一个映射
    - BPF_MAP_TYPE_PERF_EVENT_ARRAY
        - 用于将事件从 eBPF 程序传递到用户空间，通过 perf 缓冲区
    - BPF_MAP_TYPE_RINGBUF
        - 高效的环形缓冲区，用于将数据从 eBPF 程序传递到用户空间
    - BPF_MAP_TYPE_LRU_HASH 和 BPF_MAP_TYPE_LRU_PERCPU_HASH
        - 最近最少使用（LRU）的哈希表，支持自动淘汰旧条目
        - 缓存热点数据，自动管理内存
        - 自动管理内存，避免过度增长，适用于需要缓存机制的场景
        - 复杂性增加，需要处理淘汰策略
6. 嵌套类型的map的使用
   - 在内核的bpf文件中定义时候，要注意
```c
struct cpu_bad_guys {                // 注意这里要声明成结构体，因为ebpf通常情况下都是直接匿名结构体实例化
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, u32);
	__type(value, u32);
} cpu_bad_guys_map SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, u32);
	__array(values,struct cpu_bad_guys);   // 然后在这里使用时候用上这个结构体，注意这里是__array
} cpu_filter_ids SEC(".maps");
```
    - 在用户态update的时候要注意
```c
int cpu_fd = bpf_map__fd(cpu_skel->maps.thread_occupied_map);
if(cpu_fd < 0){
    fprintf(stderr, "Failed to get thread_occupied_map map fd\n");
    return -1;
}
int scx_fd;
struct bpf_map *map = bpf_object__find_map_by_name(scx_skel->obj, "cpu_filter_ids");
if (!map) {
    fprintf(stderr, "Failed to find cpu_filter_ids map\n");
    return -1;
}
scx_fd = bpf_map__fd(map);
if(scx_fd < 0){
    fprintf(stderr, "Failed to get cpu_filter_ids map fd\n");
    return -1;
}

int ret = bpf_map_update_elem(scx_fd, &zero, &cpu_fd, BPF_ANY);  // 这里是用map的文件描述符update的
if(ret < 0){
    fprintf(stderr, "Failed to update cpu_filter_ids map\n");
    return -1;
}
```