#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/select.h>
#include <unistd.h> 
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <asm/unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <assert.h>


#include "mm_event.h"

#include "mm_stats.skel.h"
#include "mm_leak.skel.h"
#include "blazesym.h"

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
	do { \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, \
				.func_name = #sym_name, \
				.retprobe = is_retprobe); \
		skel->links.prog_name = bpf_program__attach_uprobe_opts( \
				skel->progs.prog_name, \
				trace_pid, /* No specific PID */ \
				"/lib/x86_64-linux-gnu/libc.so.6", /* No specific object */ \
				0, \
				&uprobe_opts); \
	} while (false)

#define __CHECK_PROGRAM(skel, prog_name) \
	do { \
		if (!skel->links.prog_name) { \
			perror("no program attached for " #prog_name); \
			return -errno; \
		} \
	} while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
	do { \
		__ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe); \
		__CHECK_PROGRAM(skel, prog_name); \
	} while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)
#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

static u32 zero = 0;
static u32 one = 1;

/*-----------------------这些都是内存的-------------------------------------*/
static u64 trace_pid = 0;
int leak_allocs_fd;
int leak_stack_traces_fd;

static struct blaze_symbolizer *mm_symbolizer;
static struct allocation *allocs;
struct ring_buffer *rb_oom, *rb_task_mm, *rb_process_mm;

static u64 *stack;

static int attach_leak_uprobes(struct mm_leak_bpf *skel);
static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd);
static int print_stack_frames(struct allocation *allocs, u64 nr_allocs, int stack_traces_fd);

static int handle_oom_event(void *ctx,void *data, size_t data_sz);
static int handle_task_mm_stats_event(void *ctx,void *data, size_t data_sz);
static int handle_process_mm_stats_event(void *ctx,void *data, size_t data_sz);


static int attach_leak_skel(struct mm_leak_bpf *skel);
static int attach_mm_stats_skel(struct mm_stats_bpf *skel);
static int mm_ring_buffer_poll();
void ring_buffer_destroy();

int main(){
    int ret = 0;
    struct mm_leak_bpf *leak_skel = NULL;
	struct mm_stats_bpf *mm_skel = NULL;

    leak_skel = mm_leak_bpf__open();
    if(!leak_skel){
        fprintf(stderr, "failed to open mm_leak skel\n");
		ret = 1;

		goto cleanup;
    }

	mm_skel = mm_stats_bpf__open();
	if(!mm_skel){
		fprintf(stderr, "failed to open mm_stats skel\n");
		ret = 1;

		goto cleanup;
	}

	ret = attach_leak_skel(leak_skel);
	if(ret != 0)
		goto cleanup;
	
	ret = attach_mm_stats_skel(mm_skel);
	if(ret != 0)
		goto cleanup;

    while(1){
        print_outstanding_allocs(leak_allocs_fd,leak_stack_traces_fd);
        //sleep(1);
		ret = mm_ring_buffer_poll();
		if(ret < 0)
			break;
    }

cleanup:
	ring_buffer_destroy();

    blaze_symbolizer_free(mm_symbolizer);
    mm_leak_bpf__destroy(leak_skel);
	mm_stats_bpf__destroy(mm_skel);

    return ret;
}

void ring_buffer_destroy(){
	if(rb_oom)
		ring_buffer__free(rb_oom);
	if(rb_task_mm)
		ring_buffer__free(rb_task_mm);
	if(rb_process_mm)
		ring_buffer__free(rb_process_mm);
}

static int handle_oom_event(void *ctx,void *data, size_t data_sz){
	struct oom_event *event = (struct oom_event *)data;

	// 将时间戳转换为可读格式
    time_t kill_time_sec = event->kill_time / 1000000000;
    long kill_time_nsec = event->kill_time % 1000000000;

	struct tm *tm_info = localtime(&kill_time_sec);
    char time_buffer[64];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

	printf("[%s.%09ld] OOM Event:\n", time_buffer, kill_time_nsec);
    printf("  Trigger PID: %u\n", event->trigger_id);
    printf("  Killed PID: %u\n", event->killed_id);
    printf("  Command: %s\n", event->comm);
    printf("  Kill Time: %llu ns\n\n", event->kill_time);

    return 0;
}

static int handle_task_mm_stats_event(void *ctx,void *data, size_t data_sz){
	struct task_mm_stats *event = (struct task_mm_stats *)data;

    printf("  PID: %u\n", event->info.pid);
    printf("  Command: %s\n", event->info.comm);
    printf("  kmem_count: %u\n", event->kmem_count);
    printf("  vmem_count: %u\n", event->vmem_count);
    printf("  slab_count: %u\n\n", event->slab_count);

    return 0;
}

static int handle_process_mm_stats_event(void *ctx,void *data, size_t data_sz){
	struct process_mm_stats *event = (struct process_mm_stats *)data;

    printf("  process tgid: %u\n", event->tgid);
    printf("  kmem_count: %u\n", event->kmem_count);
    printf("  vmem_count: %u\n", event->vmem_count);
    printf("  slab_count: %u\n\n", event->slab_count);

    return 0;
}

static int attach_leak_skel(struct mm_leak_bpf *skel){
	int ret;

	allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));
    if (!allocs) {
		fprintf(stderr, "failed to allocate array\n");
		ret = -ENOMEM;

		return ret;
	}

    stack = calloc(PERF_MAX_STACK_DEPTH, sizeof(*stack));
	if (!stack) {
		fprintf(stderr, "failed to allocate stack array\n");
		ret = -ENOMEM;

		return ret;
	}

	ret = mm_leak_bpf__load(skel);
    if(ret){
        fprintf(stderr, "failed to load mm_leak skel\n");

		return -1;
    }

	leak_allocs_fd = bpf_map__fd(skel->maps.allocs);
    leak_stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);

	ret = attach_leak_uprobes(skel);
    if(ret){
        fprintf(stderr, "failed to attach mm_leak uprobes\n");

		return -1;
    }


    ret = mm_leak_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "failed to attach bpf program(s)\n");

		return -1;
	}

    mm_symbolizer = blaze_symbolizer_new();
    if(!mm_symbolizer){
        printf("Failed to initialize symbolizer\n");
        ret = -1;

        return ret;
    }

	return 0;
}

static int attach_mm_stats_skel(struct mm_stats_bpf *skel){
	int ret,map_fd;

	ret = mm_stats_bpf__load(skel);
	if(ret){
		fprintf(stderr, "failed to load mm_leak skel\n");
		return -1;
	}

	ret = mm_stats_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "failed to attach mm_stats bpf program(s)\n");

		return -1;
	}

	rb_oom = ring_buffer__new(bpf_map__fd(skel->maps.oom_event_buffer),handle_oom_event,NULL,NULL);
	if(!rb_oom){
		fprintf(stderr, "Failed to create oom ring buffer\n");
		return -1;
	}

	rb_task_mm = ring_buffer__new(bpf_map__fd(skel->maps.task_mm_stats_buffer),handle_task_mm_stats_event,NULL,NULL);
	if(!rb_task_mm){
		fprintf(stderr, "Failed to create task mm stats ring buffer\n");
		return -1;
	}

	rb_process_mm = ring_buffer__new(bpf_map__fd(skel->maps.process_mm_stats_buffer),handle_process_mm_stats_event,NULL,NULL);
	if(!rb_process_mm){
		fprintf(stderr, "Failed to create task mm stats ring buffer\n");
		return -1;
	}

	struct mm_threhold threhold_task = {
		.kmem_threhold = 500,
		.slab_threhold = 500,
		.vmem_threhold = 500,
		.time_window = MSEC * 1000 // 1秒
	};

	struct mm_threhold threhold_process = {
		.kmem_threhold = 1000,
		.slab_threhold = 1000,
		.vmem_threhold = 1000,
		.time_window = MSEC * 1000 // 1秒
	};

	map_fd = bpf_map__fd(skel->maps.threhold_map);
	if(bpf_map_update_elem(map_fd,&zero,&threhold_task,BPF_ANY) != 0){
		perror("Failed to update mm_threhold map\n");
		return -1;
	}

	if(bpf_map_update_elem(map_fd,&one,&threhold_process,BPF_ANY) != 0){
		perror("Failed to update mm_threhold map\n");
		return -1;
	}

	return 0;
}

static int mm_ring_buffer_poll(){
	int err;

	err = ring_buffer__poll(rb_oom,500);
	if(err < 0)
	{
		fprintf(stderr, "Error polling oom ring buffer: %d\n", err);
		return err;
	}

	err = ring_buffer__poll(rb_task_mm,500);
	if(err < 0)
	{
		fprintf(stderr, "Error polling task mm stats ring buffer: %d\n", err);
		return err;
	}

	err = ring_buffer__poll(rb_process_mm,500);
	if(err < 0)
	{
		fprintf(stderr, "Error polling process mm stats ring buffer: %d\n", err);
		return err;
	}

	return 0;
}

int print_outstanding_combined_allocs(u64 combined_allocs_fd, u64 stack_traces_fd){

	for (u64 prev_key = 0, curr_key = 0;; prev_key = curr_key){
		if (bpf_map_get_next_key(combined_allocs_fd,&prev_key,&curr_key))
		{
			if (errno == ENOENT)
			{
				break; // no more keys, done!
			}
			perror("map get next key failed!");

			return -errno;
		}

		union combined_alloc_info cinfo;
		memset(&cinfo, 0, sizeof(cinfo));

		if (bpf_map_lookup_elem(combined_allocs_fd,&curr_key,&cinfo))
		{
			if (errno == ENOENT)
			{
				continue;
			}

			perror("map lookup failed!");
			return -errno;
		}

		if (bpf_map_lookup_elem(stack_traces_fd,&curr_key,stack))
		{
			perror("failed to lookup stack traces!");
			return -errno;
		}

		printf("stack_id=0x%llx with outstanding allocations: total_size=%llu nr_allocs=%llu\n",
			   curr_key, (u64)cinfo.total_size, (u64)cinfo.number_of_allocs);

		int stack_sz = 0;
		for (int i = 0; i < 128; i++)
		{
			if (stack[i] == 0)
			{
				break;
			}
			stack_sz++;
			// printf("[%3d] 0x%llx\n", i, g_stacks[i]);
		}

		print_stack_frames_by_blazesym(stack,stack_sz);
	}
	return 0;
}


int alloc_size_compare(const void *a, const void *b)
{
	const struct allocation *x = (struct allocation *)a;
	const struct allocation *y = (struct allocation *)b;

	// descending order

	if (x->size > y->size)
		return -1;

	if (x->size < y->size)
		return 1;

	return 0;
}

static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd){
    //const u64 allocs_key_size = bpf_map__key_size(skel->maps.allocs);

    u64 t = time(NULL);
    struct tm *tm = localtime(&t);// 获取当前时间，用于输出时的时间戳
    u64 nr_allocs = 0;// 计数器用来记录找到的分配信息的数量

    //遍历 allocs map,prev_key 和 curr_key 用来在 BPF map 中迭代查找元素
    for (u64 prev_key = 0, curr_key = 0;; prev_key = curr_key)
    {
        struct alloc_info alloc_info = {};
        memset(&alloc_info, 0, sizeof(alloc_info));
        // 获取下一个 allocs map 中的键，直到遍历完所有键，如果返回 ENOENT 错误，表示没有更多的键，可以退出循环
        if (bpf_map_get_next_key(allocs_fd,&prev_key,&curr_key))
		{
			if (errno == ENOENT)
			{
				break; // no more keys, done
			}

			perror("map get next key error");

			return -errno;
		}
    
        // 使用 bpf_map__lookup_elem() 查找当前键对应的值,如果发生 ENOENT 错误，表示当前键没有对应值，跳过该键
        if (bpf_map_lookup_elem(allocs_fd,&curr_key,&alloc_info))
		{
			if (errno == ENOENT)
				continue;

			perror("map lookup error");

			return -errno;
		}

        // 过滤掉无效的栈
        if (alloc_info.stack_id < 0)
		    {   
			    continue;
		    }

        bool stack_exists = false;

        // 遍历已存储的 allocs 数组（内存分配信息的集合）并查找相同的 stack_id
        // 如果找到了相同的堆栈 ID（意味着同一个堆栈进行了多次分配），就将 alloc_info.size 累加到已存在的分配中，且将 count 增加 1

        for (u64 i = 0; !stack_exists && i < nr_allocs; ++i)
		    {
			    struct allocation *alloc = &allocs[i];

			    if (alloc->stack_id == alloc_info.stack_id)
			    {
				    alloc->size += alloc_info.size;
				    alloc->count++;

				    stack_exists = true;
				    break;
			    }
		    }


        if (stack_exists)
			continue;

        // 如果没有找到相同的堆栈 ID，说明这是一个新的堆栈分配，创建一个新的 allocation 结构体，并将其添加到 allocs 数组中
        struct allocation alloc = {
			.stack_id = alloc_info.stack_id ,
			.size = alloc_info.size,
			.count = 1,
		};
        
        // 将新创建的 allocation 结构体复制到 allocs 数组中，并增加 nr_allocs
        memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
		nr_allocs++;
    }

    // 使用 qsort() 函数按内存大小降序排列 allocs 数组
    //qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);
    if (nr_allocs > 0) {
        qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);
    }

    printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs);
    
    for (size_t i = 0; i < nr_allocs; i++)
	{
		if (bpf_map_lookup_elem(stack_traces_fd,&allocs[i].stack_id,stack))
		{
			perror("failed to lookup stack traces!");
			return -errno;
		}
	}
    
    print_stack_frames(allocs, nr_allocs, stack_traces_fd);
    for (size_t i = 0; i < nr_allocs; i++) {
        allocs[i].stack_id = 0;
    }

	return 0;
}

void print_stack_frames_by_blazesym(u64 *stack, int stack_sz)
{
    struct blaze_syms *result;
    struct blaze_sym *sym;
    
    if(trace_pid == 0){
		struct blaze_symbolize_src_kernel src = {
        	.type_size = sizeof(src)
    	};
		result = blaze_symbolize_kernel_abs_addrs(mm_symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}
	else{
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = trace_pid,
		};
		result = blaze_symbolize_process_abs_addrs(mm_symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}
    
    // 获取符号信息
    //printf("Stack depth: %d\n", stack_sz);

    if (!result) {
        perror("Failed to symbolize stack addresses");
        return;
    }

    // 打印栈回溯信息
    for (size_t j = 0; j < result->cnt; ++j) {
        //printf("inlined count: %d\n", result->syms[j].inlined_cnt);

        const uint64_t addr = stack[j];

        if (addr == 0)
            break;

        sym = &result->syms[j];

        if (sym->name == NULL) {
            printf("No symbol found for address <0x%lx>\n", addr);
            continue;
        }

        // 打印每个栈帧的函数名和地址
        printf("\t%zu [<%016lx>] %s + 0x%lx\n", j, addr, sym->name, sym->offset);

        // 打印源代码位置（文件、行号等）
        if (sym->code_info.file != NULL) {
            printf("\t\tSource: %s:%d:%d\n", sym->code_info.file, sym->code_info.line, sym->code_info.column);
        }

        // 如果存在内联函数，打印内联函数信息
        if (sym->inlined_cnt > 0) {
            for (size_t k = 0; k < sym->inlined_cnt; ++k) {
                const struct blaze_symbolize_inlined_fn *inlined = &sym->inlined[k];
                printf("\t\tInlined function: %s\n", inlined->name);
                if (inlined->code_info.file != NULL) {
                    printf("\t\t\tSource: %s:%d:%d\n", inlined->code_info.file, inlined->code_info.line, inlined->code_info.column);
                }
            }
        }
    }

    blaze_syms_free(result);
}

int print_stack_frames(struct allocation *allocs, u64 nr_allocs, int stack_traces_fd)
{
    for (u64 i = 0; i < nr_allocs; ++i){
        const struct allocation *alloc = &allocs[i];
        printf("%zu bytes in %zu allocations from stack\n", alloc->size, alloc->count);

        if (bpf_map_lookup_elem(stack_traces_fd, &alloc->stack_id, stack)) {
			if (errno == ENOENT)
				continue;

			perror("failed to lookup stack trace");

			return -errno;
		}

        print_stack_frames_by_blazesym(stack,nr_allocs);
    }
}


static void print_frame(const char *name, u64 input_addr, u64 addr, u64 offset, const blaze_symbolize_code_info *code_info)
{
	// If we have an input address  we have a new symbol.
	if (input_addr != 0)
	{
		printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL)
		{
			printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
		}
		else if (code_info != NULL && code_info->file != NULL)
		{
			printf(" %s:%u\n", code_info->file, code_info->line);
		}
		else
		{
			printf("\n");
		}
	}
	else
	{
		printf("%16s  %s", "", name);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL)
		{
			printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
		}
		else if (code_info != NULL && code_info->file != NULL)
		{
			printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
		}
		else
		{
			printf("[inlined]\n");
		}
	}
}


static int attach_leak_uprobes(struct mm_leak_bpf *skel){
    ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);

	ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

	ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

	ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
	ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);

	ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);

	ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

	ATTACH_UPROBE_CHECKED(skel, free, free_enter);
	ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

	// the following probes are intentinally allowed to fail attachment

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, valloc, valloc_enter);
	ATTACH_URETPROBE(skel, valloc, valloc_exit);

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
	ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

	// added in C11
	ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
	ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);

	return 0;
}

// void print_stack_frame_by_blazesym(size_t frame, uint64_t addr, const blaze_sym_info *sym)
// {
//     if (!sym)
//         printf("\t%zu [<%016lx>] <%s>\n", frame, addr, "null sym");
//     else if (sym->obj_file_name && strlen(sym->obj_file_name))
//         printf("\t%zu [<%016lx>] %s+0x%lx %s\n", frame, addr, sym->name, addr - sym->addr, sym->obj_file_name);
//     else
//         printf("\t%zu [<%016lx>] %s+0x%lx\n", frame, addr, sym->name, addr - sym->addr);
// }

// void disable_kernel_tracepoints(struct mm_leak_bpf *skel)
// {
// 	bpf_program__set_autoload(skel->progs.memleak__kmalloc, false);
// 	bpf_program__set_autoload(skel->progs.memleak__kfree, false);
// 	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
// 	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_free, false);
// 	bpf_program__set_autoload(skel->progs.memleak__mm_page_alloc, false);
// 	bpf_program__set_autoload(skel->progs.memleak__mm_page_free, false);
// 	bpf_program__set_autoload(skel->progs.memleak__percpu_alloc_percpu, false);
// 	bpf_program__set_autoload(skel->progs.memleak__percpu_free_percpu, false);
// }