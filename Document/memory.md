## 挂载的程序和相关钩子
```shell
root@ne0-System:~# bpftool link show
1260: kprobe  name malloc_enter  tag 2e4ae9a5ee7c4561  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 240B  jited 148B  memlock 4096B  map_ids 666,660
	btf_id 501
1262: kprobe  name free_enter  tag fc5984fdad8cdf46  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 352B  jited 213B  memlock 4096B  map_ids 661,662,666
	btf_id 501
1263: kprobe  name calloc_enter  tag 33dfaebac0a311fb  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 256B  jited 156B  memlock 4096B  map_ids 666,660
	btf_id 501
1264: kprobe  name realloc_enter  tag 95ea65071e38bc9e  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 576B  jited 340B  memlock 4096B  map_ids 661,662,666,660
	btf_id 501
1265: kprobe  name mmap_enter  tag 6d3f5f3c48ca8ee9  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 240B  jited 148B  memlock 4096B  map_ids 666,660
	btf_id 501
1266: kprobe  name munmap_enter  tag fc5984fdad8cdf46  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 352B  jited 213B  memlock 4096B  map_ids 661,662,666
	btf_id 501
1267: kprobe  name posix_memalign_enter  tag ea48ae5dc2be047f  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 344B  jited 200B  memlock 4096B  map_ids 663,666,660
	btf_id 501
1268: kprobe  name aligned_alloc_enter  tag 6d3f5f3c48ca8ee9  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 240B  jited 148B  memlock 4096B  map_ids 666,660
	btf_id 501
1269: kprobe  name valloc_enter  tag 2e4ae9a5ee7c4561  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 240B  jited 148B  memlock 4096B  map_ids 666,660
	btf_id 501
1270: kprobe  name memalign_enter  tag 6d3f5f3c48ca8ee9  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 240B  jited 148B  memlock 4096B  map_ids 666,660
	btf_id 501
1271: kprobe  name pvalloc_enter  tag 2e4ae9a5ee7c4561  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 240B  jited 148B  memlock 4096B  map_ids 666,660
	btf_id 501
1272: kprobe  name malloc_exit  tag ce5ecb314224e364  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 736B  jited 430B  memlock 4096B  map_ids 660,664,661,666,662,667
	btf_id 501
1273: kprobe  name calloc_exit  tag ce5ecb314224e364  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 736B  jited 430B  memlock 4096B  map_ids 660,664,661,666,662,667
	btf_id 501
1274: kprobe  name realloc_exit  tag ce5ecb314224e364  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 736B  jited 430B  memlock 4096B  map_ids 660,664,661,666,662,667
	btf_id 501
1275: kprobe  name mmap_exit  tag ce5ecb314224e364  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 736B  jited 430B  memlock 4096B  map_ids 660,664,661,666,662,667
	btf_id 501
1276: kprobe  name posix_memalign_exit  tag 88fa353e53959581  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 936B  jited 549B  memlock 4096B  map_ids 663,660,664,661,666,662,667
	btf_id 501
1277: kprobe  name aligned_alloc_exit  tag ce5ecb314224e364  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 736B  jited 430B  memlock 4096B  map_ids 660,664,661,666,662,667
	btf_id 501
1278: kprobe  name valloc_exit  tag ce5ecb314224e364  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 736B  jited 430B  memlock 4096B  map_ids 660,664,661,666,662,667
	btf_id 501
1279: kprobe  name memalign_exit  tag ce5ecb314224e364  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 736B  jited 430B  memlock 4096B  map_ids 660,664,661,666,662,667
	btf_id 501
1280: kprobe  name pvalloc_exit  tag ce5ecb314224e364  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 736B  jited 430B  memlock 4096B  map_ids 660,664,661,666,662,667
	btf_id 501
1281: tracepoint  name memleak__kmalloc  tag bbdda729ba968fd2  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 1096B  jited 635B  memlock 4096B  map_ids 666,660,664,661,662,667
	btf_id 501
1282: tracepoint  name memleak__kfree  tag 4c1aa144b95d034a  gpl recursion_misses 2
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 408B  jited 241B  memlock 4096B  map_ids 661,662,666
	btf_id 501
1283: tracepoint  name memleak__kmem_cache_alloc_node  tag bbdda729ba968fd2  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 1096B  jited 635B  memlock 4096B  map_ids 666,660,664,661,662,667
	btf_id 501
1284: tracepoint  name memleak__kmem_cache_free  tag 4c1aa144b95d034a  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 408B  jited 241B  memlock 4096B  map_ids 661,662,666
	btf_id 501
1285: tracepoint  name memleak__mm_page_alloc  tag f996963c6c5eaf51  gpl recursion_misses 1
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 1008B  jited 590B  memlock 4096B  map_ids 666,660,664,661,662,667
	btf_id 501
1286: tracepoint  name memleak__mm_page_free  tag 371c7edce49a5522  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 352B  jited 213B  memlock 4096B  map_ids 661,662,666
	btf_id 501
1287: tracepoint  name memleak__percpu_alloc_percpu  tag 6a9933a1487357b8  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 976B  jited 572B  memlock 4096B  map_ids 666,660,664,661,662,667
	btf_id 501
1288: tracepoint  name memleak__percpu_free_percpu  tag e471e6ba77e95c74  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 352B  jited 213B  memlock 4096B  map_ids 661,662,666
	btf_id 501
1291: kprobe  name oom_kill_process  tag c29222416dc6edb9  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 344B  jited 198B  memlock 4096B  map_ids 676,677
	btf_id 502
1292: tracepoint  name trace_kmalloc  tag 06788d6a8d9da18d  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 2104B  jited 1101B  memlock 4096B  map_ids 669,670,673,677,674,675
	btf_id 502
1293: tracepoint  name trace_kfree  tag 06788d6a8d9da18d  gpl recursion_misses 2
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 2104B  jited 1101B  memlock 4096B  map_ids 669,670,673,677,674,675
	btf_id 502
1294: tracepoint  name trace_page_alloc  tag 9e84541614dd95cf  gpl recursion_misses 1
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 2104B  jited 1101B  memlock 4096B  map_ids 669,670,673,677,674,675
	btf_id 502
1295: tracepoint  name trace_page_free  tag 9e84541614dd95cf  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 2104B  jited 1101B  memlock 4096B  map_ids 669,670,673,677,674,675
	btf_id 502
1296: tracepoint  name trace_cache_alloc  tag 2df646d571e4d41e  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 2112B  jited 1106B  memlock 4096B  map_ids 669,670,673,677,674,675
	btf_id 502
1297: tracepoint  name trace_cache_free  tag 2df646d571e4d41e  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 2112B  jited 1106B  memlock 4096B  map_ids 669,670,673,677,674,675
	btf_id 502
1298: tracepoint  name handle_mm_task_exit  tag c08bfb018faad224  gpl
	loaded_at 2024-12-22T17:27:42+0800  uid 0
	xlated 184B  jited 117B  memlock 4096B  map_ids 669,677
	btf_id 502
```
```shell
root@ne0-System:~# bpftool link show
1: tracing  prog 2  
	prog_type tracing  attach_type modify_return  
	target_obj_id 1  target_btf_id 35400  
487: perf_event  prog 1281  
	tracepoint kmalloc  
488: perf_event  prog 1282  
	tracepoint kfree  
489: perf_event  prog 1283  
	tracepoint kmem_cache_alloc  
490: perf_event  prog 1284  
	tracepoint kmem_cache_free  
491: perf_event  prog 1285  
	tracepoint mm_page_alloc  
492: perf_event  prog 1286  
	tracepoint mm_page_free  
493: perf_event  prog 1287  
	tracepoint percpu_alloc_percpu  
494: perf_event  prog 1288  
	tracepoint percpu_free_percpu  
495: perf_event  prog 1291  
	kprobe ffffffffa79bf480 oom_kill_process  
496: perf_event  prog 1292  
	tracepoint kmalloc  
497: perf_event  prog 1293  
	tracepoint kfree  
498: perf_event  prog 1294  
	tracepoint mm_page_alloc  
499: perf_event  prog 1295  
	tracepoint mm_page_free  
500: perf_event  prog 1296  
	tracepoint kmem_cache_alloc  
501: perf_event  prog 1297  
	tracepoint kmem_cache_free  
502: perf_event  prog 1298  
	tracepoint sched_process_exit  
```
挂载的程序总数24个，kprobe挂载到内核函数入口和出口，共 13 个程序，tracepoint挂载到内核事件点（如内存分配、页分配），共 11 个程序


## 系统整体的内存分配情况
通过直接在proc中获得的数据可以直接分析得到当前系统的整体情况
```
--- Memory Usage ---
Total Memory: 32672744 kB
Used Memory: 23731496 kB (72.63%)
Available Memory: 28289196 kB (86.58%)
Buffers: 1374208 kB
Cached: 17898404 kB

--- Swap Memory ---
Total Swap: 32226300 kB
Used Swap: 0 kB (0.00%)

--- Memory Commitment ---
Commit Limit: 48562672 kB
Committed AS: 13347864 kB (27.49%)
```
- Memory Usage
  - Used Memory：已使用内存，包括正在被程序、系统缓存和其他内核组件占用的内存
  - Available Memory：表示目前可供新任务使用的内存量，包括缓存可被回收的部分
  - Buffers：系统用于块设备（如硬盘） I/O 操作的缓冲区
  - Cached：系统文件和程序的缓存数据，用于加速后续访问
- Swap Memory
  - Total Swap：总交换分区
  - Used Swap：已使用交换分区
- Memory Commitment
  - Commit Limit：系统允许的最大内存承诺量，包括物理内存和交换分区
  - Committed AS：表示当前程序总共申请的内存量（虚拟地址空间）。尽管申请了这部分内存，但未必全部被物理内存实际分配


## 内核中的内存分配事件的跟踪
这里的代码具体来说就是参考 https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/16-memleak ，
想去尝试着写一下栈回溯的功能，我看网上这个就是个例子，于是尝试着复现一下，同时把它融合进我的代码，
运行的本地结果存储在[这里](visualize/proc/mm_alloc.txt)
```
	0 [<ffffffffa7a5b2f8>] __kmalloc_node_track_caller + 0x2f8
	0 [<ffffffffa7a4d892>] __alloc_pages + 0x262
	0 [<ffffffffa87a4caa>] __kmalloc_node.cold + 0x8b
	0 [<ffffffffa7a5bdef>] kmalloc_trace + 0x26f
	0 [<ffffffffa7a5a6ad>] kmem_cache_alloc_node + 0x28d
	0 [<ffffffffa7a5ae4a>] __kmalloc_node + 0x2fa
	0 [<ffffffffa7a5a220>] __kmalloc + 0x290
	0 [<ffffffffa7a5ba72>] kmem_cache_alloc + 0x272
	0 [<ffffffffa7a5b717>] kmem_cache_alloc_lru + 0x267
	0 [<ffffffffa79f9b86>] pcpu_alloc + 0x476
	0 [<ffffffffa7a5aa4a>] kmalloc_node_trace + 0x29a
	0 [<ffffffffa7a5b2f8>] __kmalloc_node_track_caller + 0x2f8
```
复现过程中遇到了很多问题，最终算是到了上面这个程度，算是能精确定位到内核的内存分配事件



## task和process的内存分配频率记录
- 挂载点：程序挂载到以下内核 tracepoint 节点，记录内存分配与释放的频率
  - 分配相关
    - `tracepoint/kmem/kmalloc`
    - `tracepoint/kmem/mm_page_alloc`
    - `tracepoint/kmem/kmem_cache_alloc`
  - 释放相关
    - `tracepoint/kmem/kfree`
    - `tracepoint/kmem/mm_page_free`
    - `tracepoint/kmem/kmem_cache_free`
- 记录维度
  - 任务级：每个任务的内存分配频率统计
    - 使用 task_compare_and_commit(struct task_mm_stats *task) 函数
    - 捕获频繁进行内存分配和释放的异常任务
  - 进程级：每个进程的内存分配频率统计
    - 使用 process_compare_and_commit(struct process_mm_stats *process) 函数
    - 对异常进程的内存操作进行记录

捕获高频率分配或释放内存的任务和进程，定位内存泄漏或频繁内存操作引发的性能问题

数据在本地的[这里](visualize/run/task_mm_stats.csv)和[这里](visualize/run/process_mm_stats.csv)


```
PID,Command,Kmem Count,Vmem Count,Slab Count
76316,cpptools,0,500,71
76318,cpptools,9,75,500
77572,cpptools-srv,18,51,500
76167,code,28,500,44
76310,cpptools,500,8,333
76493,cpptools-srv,500,31,334
76208,code,9,500,21
76084,Chrome_IOThread,2,500,17
3863,Xorg,500,2,85
76170,ThreadPoolForeg,0,500,3
78661,os_spy,500,19,98
76188,Compositor,21,500,81
76171,ThreadPoolForeg,0,500,0
3863,Xorg,500,1,94
4033,xfwm4,500,0,117
78661,os_spy,500,2,103
76230,VizCompositorTh,500,0,106
3863,Xorg,500,0,61
78661,os_spy,2,500,70
3863,Xorg,500,0,59
76167,code,0,500,11
2899,prometheus-node,286,27,500
2900,prometheus-node,285,30,500
810,prometheus-node,281,14,500
```
```
TGID,Kmem Count,Vmem Count,Slab Count
76306,6,1000,129
76490,319,190,1000
76167,97,1000,89
76208,52,1000,50
76076,2,1000,25
78661,1000,19,98
3863,1000,3,151
3863,1000,1,252
4033,1000,0,246
78661,1000,2,103
3863,1000,1,122
78661,2,1000,148
3863,1000,1,122
76167,0,1000,12
723,362,170,1000
704,1000,84,482
78661,1000,0,93
3863,1000,1,112
3863,1000,1,115
```

## oom事件记录
- 挂载点
  - 挂载到 kprobe/oom_kill_process，捕获系统触发 OOM 事件时的详细信息
- 数据结构
  - OOM 事件的数据通过以下结构体传递到用户态
```c
struct oom_event {
    u32 trigger_id;         // 触发 OOM 的进程 PID
    u32 killed_id;          // 被 OOM 杀死的进程 PID
    char comm[TASK_COMM_LEN]; // 被杀死进程的命令名
    u64 kill_time;          // OOM 发生的时间戳
};
```
精确记录 OOM 事件的触发与受害者，便于快速分析内存不足的原因，结合内存分配频率数据，可以深入定位异常任务或进程

数据在本地的[这里](visualize/run/oom_event.csv)




## 实验


