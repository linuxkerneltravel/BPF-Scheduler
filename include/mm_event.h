#ifndef MM_EVENT_H
#define MM_EVENT_H

#include "sys_event.h"

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






#endif //CPU_EVENT_H