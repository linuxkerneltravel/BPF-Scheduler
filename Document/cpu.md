## 挂载的程序和相关钩子
这里把前面部分和cpu部分无关的输出删除了，只显示cpu的部分
```shell
root@ne0-System:~# bpftool prog show
1097: raw_tracepoint  name handle_sched_wakeup  tag 09665ce5a1061f80  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 1208B  jited 730B  memlock 4096B  map_ids 527,536,544
	btf_id 438
1099: raw_tracepoint  name handle_sched_wakeup_new  tag 09665ce5a1061f80  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 1208B  jited 730B  memlock 4096B  map_ids 527,536,544
	btf_id 438
1100: tracepoint  name handle_task_create  tag efc6aaf5cb501cf1  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 464B  jited 276B  memlock 4096B  map_ids 527,544
	btf_id 438
1101: tracepoint  name handle_task_exit  tag bbd5266b129ac1f5  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 536B  jited 316B  memlock 4096B  map_ids 527,536,531,533,537,544
	btf_id 438
1102: tracepoint  name record_task_switch  tag 84f5ae70e9eae07c  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 6648B  jited 4141B  memlock 8192B  map_ids 528,529,527,531,539,544,533,542,530,536,537,540
	btf_id 438
1103: tracepoint  name record_backtrace  tag 609e86149c8868ed  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 968B  jited 556B  memlock 4096B  map_ids 531,532,544,533,527
	btf_id 438
1104: tracepoint  name record_cpu_idle  tag da0312df36e18d94  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 584B  jited 312B  memlock 4096B  map_ids 528,529,544
	btf_id 438
1105: tracepoint  name trace_sys_enter  tag b321ae7b2ce4198b  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 1160B  jited 660B  memlock 4096B  map_ids 527,536,544
	btf_id 438
1106: tracepoint  name trace_sys_exit  tag ab90f585a0514ff8  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 1152B  jited 653B  memlock 4096B  map_ids 527,536,544
	btf_id 438
1107: tracepoint  name trace_cpu_softirq_entry  tag 54c4d1a106cfa8a9  gpl recursion_misses 13
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 712B  jited 403B  memlock 4096B  map_ids 528,529,544
	btf_id 438
1108: tracepoint  name trace_cpu_softirq_exit  tag 3d80b7c8e918ee61  gpl recursion_misses 13
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 632B  jited 357B  memlock 4096B  map_ids 528,529,544
	btf_id 438
1109: tracepoint  name trace_cpu_irq_entry  tag eba63ed6afd29a18  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 712B  jited 403B  memlock 4096B  map_ids 528,529,544
	btf_id 438
1110: tracepoint  name trace_cpu_irq_exit  tag 9626ba411786b4fa  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 632B  jited 357B  memlock 4096B  map_ids 528,529,544
	btf_id 438
1111: perf_event  name handle_cpu_event  tag 47b18a86e41937b8  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 2000B  jited 1318B  memlock 4096B  map_ids 545,534,544,529,528,538
	btf_id 438
1112: perf_event  name handle_sys_latency_event  tag 865cfeaa4297ac99  gpl
	loaded_at 2024-12-22T14:14:47+0800  uid 0
	xlated 1280B  jited 654B  memlock 4096B  map_ids 541,544,530
	btf_id 438
```
```shell
root@ne0-System:~# bpftool link show
1: tracing  prog 2  
	prog_type tracing  attach_type modify_return  
	target_obj_id 1  target_btf_id 35400  
408: raw_tracepoint  prog 1120  
	tp 'sched_wakeup'  
409: raw_tracepoint  prog 1122  
	tp 'sched_wakeup_new'  
410: perf_event  prog 1123  
	tracepoint sched_process_fork  
411: perf_event  prog 1124  
	tracepoint sched_process_exit  
412: perf_event  prog 1125  
	tracepoint sched_switch  
413: perf_event  prog 1126  
	tracepoint sched_switch  
414: perf_event  prog 1127  
	tracepoint cpu_idle  
415: perf_event  prog 1128  
	tracepoint sys_enter  
416: perf_event  prog 1129  
	tracepoint sys_exit  
417: perf_event  prog 1130  
	tracepoint softirq_entry  
418: perf_event  prog 1131  
	tracepoint softirq_exit  
419: perf_event  prog 1132  
	tracepoint irq_handler_entry  
420: perf_event  prog 1133  
	tracepoint irq_handler_exit  
421: perf_event  prog 1134  
	event 6 :0  
422: perf_event  prog 1135  
	event 6 :0  
```

挂载了14个ebpf程序，raw_tracepoint 2个，tracepoint 10 个，perf_event 2 个

## cpu使用情况
通过挂载在在sched_switch、cpu_idle、sys_enter、sys_exit、softirq_entry、softirq_exit、
irq_handler_entry、irq_handler_exit等节点实现对于cpu不同的功能的使用率的统计

本地文件保存在`visualize/run/cpu_usage.csv`中，格式如下
```
CPU ID,User Time,Kernel Time,Idle Time,IRQ Time,SoftIRQ Time
0,0.000000,0.050000,0.920000,0.000000,0.000000
1,0.000000,0.010000,0.940000,0.000000,0.000000
2,0.000000,0.020000,0.900000,0.000000,0.000000
3,0.000000,0.020000,0.960000,0.000000,0.000000
4,0.000000,0.050000,0.940000,0.000000,0.000000
5,0.000000,0.140000,0.840000,0.000000,0.000000
6,0.000000,0.050000,0.930000,0.000000,0.000000
7,0.000000,0.100000,0.840000,0.000000,0.000000
8,0.000000,0.010000,0.970000,0.000000,0.000000
9,0.000000,0.040000,0.860000,0.000000,0.000000
10,0.000000,0.020000,0.950000,0.000000,0.000000
11,0.030000,0.590000,0.290000,0.000000,0.000000
```
每500ms用perf事件输出一次

## cpu占用率高的线程的情况
对于所有的task都有个`struct task_cpu_usage`存储它的cpu使用情况，记录在task_cpu_usage_map中，
同时有个`task_concerned_update(struct task_cpu_usage *task_usage, u32 threshold)`函数，
来判断同时把占用率高于阈值的task移入`thread_occupied_map`同时perf输出。

对于这边的perf输出有个注意点就是，对于这里占用率的更新也是500ms清理一次，为了保证提前超过阈值的task不会重复输出，
我这里设置了参数来确保这个，同时对于提前到达阈值的task，根据提前的比例对占用率进行线性增长，具体来说算法如下
```c
u64 delta = (HALF_SECOND + task_usage->last_clear_time - now )*10 / HALF_SECOND;
```

输出保存在`visualize/run/task_usage.csv`
```
PID,Name,Total Percent,Kernel Percent,User Percent
76167,code,51.000000,1.000000,0.000000
76318,cpptools,185.000000,1.000000,0.000000
77306,xrdp,21.000000,1.000000,0.000000
3863,Xorg,10.000000,1.000000,0.000000
76167,code,42.000000,1.000000,0.000000
3863,Xorg,41.000000,1.000000,0.000000
77306,xrdp,53.000000,1.000000,0.000000
3863,Xorg,30.000000,1.000000,0.000000
77306,xrdp,37.000000,1.000000,0.000000
```

## cpu占用率高的进程的情况
和task统计的思路差不多，就是把统计的身份从pid改为了tgid，由`process_map`来存储所有的进程的cpu占用情况，
由`process_concerned_update(struct process_struct *ps, u32 threshold)`来对占用率高的进程记录和输出，
具体是用`process_occupied_map`记录和perf输出

输出保存在`visualize/run/process_stat.csv`
```
TGID,Kids Length,Total Percent
77306,1,68.000000
3863,1,51.000000
76167,9,60.000000
76167,11,65.000000
77306,1,53.000000
77620,1,150.000000
```



## 调度延迟
参考自runqlat功能，主要用于监控和分析系统中任务等待 CPU 调度的时间分布，即运行队列等待时间

简单来说我建立了一个`runqlat_map`，分为8索引，从输出来看更清楚，本地文件是在`visualize/run/runqlat`
```
1us,4us,16us,64us,256us,1ms,4ms,4ms+
4384,570,252,36,0,0,0,0
4764,1019,514,68,0,0,2,0
5144,1376,818,101,0,1,3,1
5336,1611,1067,125,1,1,3,1
5403,1680,1167,176,2,3,3,1
5415,1719,1221,234,2,3,3,1
5426,1746,1262,280,2,4,3,1
5432,1773,1296,319,2,4,3,1
5515,1842,1357,366,3,5,3,1
5728,1951,1413,391,3,5,3,1
6423,2338,1563,434,6,8,3,1
6498,2424,1626,483,6,8,3,1
6732,2567,1702,521,10,9,3,1
6975,2688,1783,568,10,9,3,1
6986,2737,1827,626,10,9,3,1
7192,2821,1874,659,11,9,3,1
```
具体来说分为了8个区间，分别代表了在队列等待的时间，数据记载的是累计值，从ebpf程序运行开始，
每500ms输出一次，记录到当前位置，任务调度延迟在某个区间的累计值，从中反映出当前系统的cpu压力情况，
当存在异常任务占用大量cpu，那么后面几个区间的值就会增长更快


## 实验



















