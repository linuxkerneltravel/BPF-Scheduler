// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

// #include "sys_event.h"

// // 由于task和process使用的广泛性，为了便于创建这些记录，这里建立2个map来记录
// // 其他的bpf文件均可以根据这里的数据来更新各自的map，避免在钩子节点重复挂载和初始化

// DEFINE_BPF_MAP(global_task_map,BPF_MAP_TYPE_HASH,MAX_ENTRIES,u32,struct task_public_info);
// DEFINE_BPF_MAP(global_process_map,BPF_MAP_TYPE_HASH,MAX_PROCESS_ENTRIES,u32,struct process_public_info);


