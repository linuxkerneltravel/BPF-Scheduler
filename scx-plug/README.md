## scx-plug 可热插拔的调度器
关于这部分程序的原理性解析请看 https://gitlab.eduxiji.net/T202410701994230/project2608126-270009 的scx分支，
在里面的 scx-nest部分有过详细的解析，这里只介绍scx-plug用法

scx-plug部分的环境配置和scx分支的环境配置相同

本项目调度器的架构参考自 https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/45-scx-nest ，
整体逻辑设计和本项目的scx分支设计差不多，同时在此基础上加入了一些和用户态交互的部分

```
concerned/                          # 关注的文件目录
├── comm_attention.txt              # 需要抑制的任务名
├── comm_ignore.txt                 # 需要保护的任务名，避免受策略影响
├── id_attention.txt                # 需要抑制的任务id，根据设置可同时表示pid和tgid
└── id_ignore.txt                   # 需要保护的任务id，根据设置可同时表示pid和tgid
```
支持在调度器运行之后写入，在调度器运行其间，可以同时运行任何其他系统监测程序，把问题线程的名字或id写入上述文件，
这个scx-plug可以视为一个即插即用的插件

## 基于此的二次开发
在主程序中，我留出了一个部分方便需要的人来进行二次开发，在`scx_plug.c`中，在`static int attach_scx_skel()`部分，
可以看到我注释了一部分示例的代码，
```c
    // 下面这里是演示，对于别的满足filter_inner_map 格式的map都能放入fliter_map，
    // 你可以很轻松的把你的代码融合在我这里，把要处理的pid整合整个我这个格式的map，然后像下面这样传进来

    // struct filter_inner_map {
	// __uint(type, BPF_MAP_TYPE_HASH);
	// __uint(max_entries, 102400);
	// __type(key, u32);
	// __type(value, u32);
    // } template_map SEC(".maps");

    // int cpu_fd = bpf_map__fd(cpu_skel->maps.thread_occupied_map);
    // if(cpu_fd < 0){
    //     fprintf(stderr, "Failed to get thread_occupied_map map fd\n");
    //     return -1;
    // }
    // int scx_fd;
    // struct bpf_map *map = bpf_object__find_map_by_name(scx_skel->obj, "fliter_map");
    // if (!map) {
    //     fprintf(stderr, "Failed to find fliter_map\n");
    //     return -1;
    // }
    // scx_fd = bpf_map__fd(map);
    // if(scx_fd < 0){
    //     fprintf(stderr, "Failed to get fliter_map fd\n");
    //     return -1;
    // }

    // int ret = bpf_map_update_elem(scx_fd, &zero, &cpu_fd, BPF_ANY);
    // if(ret < 0){
    //     fprintf(stderr, "Failed to update cpu_filter_ids map\n");
    //     return -1;
    // }
```
对于任何满足filter_inner_map类型的ebpf_map，可以直接插入到我预留好的fliter_map中，实现自动化的监控抑制，
插入方式就在上面的示例中

