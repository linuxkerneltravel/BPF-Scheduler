#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mm_event.h"

const volatile u64 sample_rate = 2;
const volatile size_t page_size = 4096;

const volatile u64 stack_flags = 0;


char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 每个task分配的内存大小，pid——size
DEFINE_BPF_MAP(sizes,BPF_MAP_TYPE_HASH,10240,u32,u64);
// 分配的内存块的信息，address——info
DEFINE_BPF_MAP(allocs,BPF_MAP_TYPE_HASH,100000,u64,struct alloc_info);
// 
DEFINE_BPF_MAP(combined_allocs,BPF_MAP_TYPE_HASH,10240,u64,union combined_alloc_info);
// task的用户态指针变量
DEFINE_BPF_MAP(memptrs,BPF_MAP_TYPE_HASH,10240,u64,u64);
// 栈回溯信息
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
    __type(value, 128 * sizeof(u64));
    __uint(max_entries,10240);
} stack_traces SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
// 	__type(key, u32);
//     __type(value, 128 * sizeof(u64));
//     __uint(max_entries,10240);
// } stack_traces_usr SEC(".maps");

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	long err;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	if (err && err < 0)
		return 0;

	return bpf_map_lookup_elem(map, key);
}

static union combined_alloc_info initial_cinfo;

// 当发生内存分配时，通过增加堆栈对应的内存分配信息（内存大小和分配次数）
static void update_statistics_add(u64 stack_id, u64 sz)
{
    // 查找或初始化一个联合体 combined_alloc_info 结构体
    // 该结构体包含总内存大小 (total_size) 和分配次数 (number_of_allocs)
    // 如果 stack_id 对应的记录不存在，则初始化为 initial_cinfo
    union combined_alloc_info *existing_cinfo;
    existing_cinfo = bpf_map_lookup_or_try_init(&combined_allocs, &stack_id, &initial_cinfo);
    
    if (!existing_cinfo)
        return;
    
    // 这里的增加和下面的减少，这样的构建个union之后操作都是为了保证原子操作和安全性

    // 构建一个增量的 combined_alloc_info 结构体
    // 增量的 total_size 为当前分配的内存大小 (sz)，
    // 增量的 number_of_allocs 为 1，表示本次分配
    const union combined_alloc_info incremental_cinfo = {
        .total_size = sz,       // 增量内存大小
        .number_of_allocs = 1   // 增量内存分配次数
    };

    // 这里使用 __sync_fetch_and_add 来保证多线程环境中的原子操作
    __sync_fetch_and_add(&existing_cinfo->bits, incremental_cinfo.bits);
}

// 当发生内存释放时，通过减少堆栈对应的内存分配信息（内存大小和分配次数）
static void update_statistics_del(u64 stack_id, u64 sz)
{
    // 查找 stack_id 对应的记录
    union combined_alloc_info *existing_cinfo;
    existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);

    if (!existing_cinfo) {
        bpf_printk("failed to lookup combined allocs\n");
        return;
    }

    // 构建一个减少的 combined_alloc_info 结构体
    // 减少的 total_size 为当前释放的内存大小 (sz)，
    // 减少的 number_of_allocs 为 1，表示本次释放
    const union combined_alloc_info decremental_cinfo = {
        .total_size = sz,        // 减少内存大小
        .number_of_allocs = 1    // 减少内存分配次数
    };

    // 使用 __sync_fetch_and_sub 来进行原子减法操作
    __sync_fetch_and_sub(&existing_cinfo->bits, decremental_cinfo.bits);
}

// 在内存分配进入时被调用，记录当前task分配的内存大小
static int gen_alloc_enter(u64 size)
{
    if (sample_rate > 1) {
		if (bpf_ktime_get_ns() % sample_rate != 0)
			return 0;
	}

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&sizes,&pid,&size,BPF_ANY);

    return 0;
}

// 在内存分配退出时被调用，记录被分配的内存本身的信息，比如对应的堆栈id，大小，分配时间
static int gen_alloc_exit2(void *ctx, u64 address)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct alloc_info info;

	u64* size = bpf_map_lookup_elem(&sizes, &pid);
	if (!size)
		return 0; // missed alloc entry

	__builtin_memset(&info, 0, sizeof(info));

	info.size = *size;
	bpf_map_delete_elem(&sizes, &pid);

	if (address != 0) {
		info.timestamp_ns = bpf_ktime_get_ns();

		//info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);
		// info.stack_id = bpf_get_stackid(ctx, &stack_traces, 0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);
		info.stack_id = bpf_get_stackid(ctx, &stack_traces, 0 | BPF_F_FAST_STACK_CMP);

		int res = bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);
        if(res != 0)
        {
            bpf_printk("allocs update failed, error code is %i\n",res);
        }

		update_statistics_add(info.stack_id, info.size);
        //update_statistics_add(info.stack_id_usr,info.size);
	}

	return 0;
}

static int gen_alloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

// 内存释放时候清理相关的内存块的记录
static int gen_free_enter(const void *address)
{
	const u64 addr = (u64)address;

	const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
	if (!info)
		return 0;

	bpf_map_delete_elem(&allocs, &addr);
	update_statistics_del(info->stack_id, info->size);

	return 0;
}

SEC("uprobe")
int BPF_KPROBE(malloc_enter, u64 size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_KPROBE(calloc_enter, u64 nmemb, u64 size)
{
	return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_KRETPROBE(calloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, u64 size)
{
	gen_free_enter(ptr);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(realloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(mmap_enter, void *address, u64 size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(mmap_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(munmap_enter, void *address)
{
	return gen_free_enter(address);
}

// 记录用户态内存分配信息
SEC("uprobe")
int BPF_KPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size)
{
    // 将传入的 memptr（指向内存的指针）转换为 64 位无符号整数类型
	const u64 memptr64 = (u64)(size_t)memptr;
	const u64 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(posix_memalign_exit)
{
	const u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 *memptr64;
	void *addr;

    // 清理用户态的内存信息
	memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &pid);

	if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
		return 0;

	const u64 addr64 = (u64)(size_t)addr;

	return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe")
int BPF_KPROBE(aligned_alloc_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(aligned_alloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(valloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(valloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(memalign_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(memalign_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(pvalloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(pvalloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("tracepoint/kmem/kmalloc")
int memleak__kmalloc(struct trace_event_raw_kmalloc *ctx){
    const void *ptr = BPF_CORE_READ(ctx, ptr);
    u64 bytes_alloc = BPF_CORE_READ(ctx, bytes_alloc);

    gen_alloc_enter(bytes_alloc);

    return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kfree")
int memleak__kfree(struct trace_event_raw_kfree *ctx){
    const void *ptr = BPF_CORE_READ(ctx, ptr);

    return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int memleak__kmem_cache_alloc_node(struct trace_event_raw_kmem_cache_alloc *ctx){
    const void *ptr = BPF_CORE_READ(ctx, ptr);
    u64 bytes_alloc = BPF_CORE_READ(ctx, bytes_alloc);

    gen_alloc_enter(bytes_alloc);

    return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmem_cache_free")
int memleak__kmem_cache_free(struct trace_event_raw_kmem_cache_free *ctx){
    const void *ptr = BPF_CORE_READ(ctx, ptr);

    return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int memleak__mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx){
    gen_alloc_enter(page_size << ctx->order);

	return gen_alloc_exit2(ctx, ctx->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int memleak__mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	return gen_free_enter((void *)ctx->pfn);
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int memleak__percpu_alloc_percpu(struct trace_event_raw_percpu_alloc_percpu *ctx)
{
	gen_alloc_enter(ctx->bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
}

SEC("tracepoint/percpu/percpu_free_percpu")
int memleak__percpu_free_percpu(struct trace_event_raw_percpu_free_percpu *ctx)
{
	return gen_free_enter(ctx->ptr);
}