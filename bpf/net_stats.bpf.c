#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "net_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static u32 target_tgid = 0;

const u32 zero = 0;

static u64 tcptop_send_threhold = 5 * 1024;// 5kB
static u64 tcptop_recv_threhold = 10 * 1024;// 10kB

static u32 filiter_id = 0;

DEFINE_BPF_MAP(net_latency_start,BPF_MAP_TYPE_HASH,4096,struct sock *,struct task_public_info);
DEFINE_BPF_MAP(tcprtt_map,BPF_MAP_TYPE_ARRAY,1,u32,struct tcprtt_perf_data);

// tcp_top的map
DEFINE_BPF_MAP(ipv4_top_map,BPF_MAP_TYPE_HASH,1024,struct ipv4_key_t,struct recv_send_bytes);
DEFINE_BPF_MAP(ipv6_top_map,BPF_MAP_TYPE_HASH,1024,struct ipv6_key_t,struct recv_send_bytes);
DEFINE_BPF_MAP(top_sock_store,BPF_MAP_TYPE_HASH,1024,u32,struct sock *);

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  
} net_latency_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);  
} tcprtt_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  
} tcptop_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  
} tcpretrans_buffer SEC(".maps");

static int net_trace_connect(struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid & 0xFFFFFFFF;  
    u32 tgid = pid_tgid >> 32; 
    u64 now = bpf_ktime_get_ns();

    // if(tgid == 0 || tgid != target_tgid)
    //     return 0;
    
    if(tgid == 0)
        return 0;

    struct task_public_info info = {
        .pid = pid,
        .tgid = tgid,
        .time = now
    };
    bpf_get_current_comm(&info.comm,sizeof(info.comm));

    bpf_map_update_elem(&net_latency_start,&sk,&info,BPF_ANY);
    return 0;
}

static int handle_tcp_rcv_state_process(struct sock *sk)
{
    struct task_public_info *info;
    struct tcp_net_latency *latency;
    u64 delta;
    u64 now;

    if(BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
        return 0;
    
    info = bpf_map_lookup_elem(&net_latency_start,&sk);
    if(!info)
        return 0;
    
    now = bpf_ktime_get_ns();
    delta = now - info->time;

    latency = bpf_ringbuf_reserve(&net_latency_buffer,sizeof(struct tcp_net_latency),0);
    if(!latency){
        bpf_printk("the net latency buffer is full\n");
        return 0;
    }
    memset(latency,0,sizeof(struct tcp_net_latency));
    latency->delta = delta;
    latency->tgid = info->pid;
    bpf_probe_read_kernel_str(latency->comm,sizeof(info->comm),info->comm);
    latency->ts = now;
    latency->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    latency->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    latency->af = BPF_CORE_READ(sk, __sk_common.skc_family);

    if(latency->af == AF_INET){
        latency->src_addr.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        latency->dst_addr.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    }
    else{
        BPF_CORE_READ_INTO(&latency->src_addr.saddr_v6,sk,__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&latency->dst_addr.daddr_v6,sk,__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }
    bpf_ringbuf_submit(latency,0);

    return 0;
}

static int tcp_top_ringbuff_send(struct recv_send_bytes *bytes,struct ipv4_key_t *ip4, struct ipv6_key_t *ip6){
    if(!ip4 && !ip6 || !bytes)
        return 0;
    
    u64 now = bpf_ktime_get_ns();
    if((now - bytes->last_output) < 1000 * MSEC)
        return 0;
    u64 send = bytes->send;
    u64 recv = bytes->recv;
    if(send < tcptop_send_threhold && recv < tcptop_recv_threhold)
        return 0;

    struct tcp_top_perf_data *buff = bpf_ringbuf_reserve(&tcptop_buffer,sizeof(struct tcp_top_perf_data),0);
    if(!buff){
        bpf_printk("the tcptop buffer is full\n");
        return 0;
    }
    memset(buff,0,sizeof(struct tcp_top_perf_data));
    buff->send = send;
    buff->recv = recv;
    if(ip4 != NULL){
        bpf_probe_read_str(buff->comm,sizeof(buff->comm),ip4->comm);
        buff->af = AF_INET;
        buff->pid = ip4->pid;
        buff->dport = ip4->dport;
        buff->lport = ip4->lport;
        buff->dst_addr.daddr_v4 = ip4->daddr;
        buff->src_addr.saddr_v4 = ip4->saddr;
        bpf_ringbuf_submit(buff,0);

        bytes->last_output = now;
        bpf_map_update_elem(&ipv4_top_map,ip4,bytes,BPF_ANY);
    }
    else if(ip6 != NULL){
        bpf_probe_read_str(buff->comm,sizeof(buff->comm),ip6->comm);
        buff->af = AF_INET6;
        buff->pid = ip6->pid;
        buff->dport = ip6->dport;
        buff->lport = ip6->lport;
        bpf_probe_read(&buff->dst_addr.daddr_v6, sizeof(buff->dst_addr.daddr_v6), &ip6->daddr);
        bpf_probe_read(&buff->src_addr.saddr_v6, sizeof(buff->src_addr.saddr_v6), &ip6->saddr);

        bpf_ringbuf_submit(buff,0);

        bytes->last_output = now;
        bpf_map_update_elem(&ipv6_top_map,ip6,bytes,BPF_ANY);
    }
    return 0;
}

static int tcp_top_sendstat(struct sock *sk, int size) {
    //u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; 
    u16 family = 0, dport = 0;
    u64 now = bpf_ktime_get_ns();

    BPF_CORE_READ_INTO(&family,sk,__sk_common.skc_family);

    if (family == AF_INET){
        struct ipv4_key_t key;
        memset(&key,0,sizeof(struct ipv4_key_t));
        key.pid = pid;
        bpf_get_current_comm(&key.comm,sizeof(key.comm));
        BPF_CORE_READ_INTO(&key.saddr,sk,__sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&key.daddr,sk,__sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&key.lport,sk,__sk_common.skc_num);
        BPF_CORE_READ_INTO(&dport,sk,__sk_common.skc_dport);
        key.dport = bpf_ntohs(dport);

        struct recv_send_bytes *by = bpf_map_lookup_elem(&ipv4_top_map,&key);
        if(!by){
            struct recv_send_bytes init = {
                .send = size,
                .recv = 0,
                .last_output = now
            };
            bpf_map_update_elem(&ipv4_top_map,&key,&init,BPF_ANY);

            tcp_top_ringbuff_send(&init,&key,NULL);
        }
        else{
            by->send += size;
            bpf_map_update_elem(&ipv4_top_map,&key,by,BPF_ANY);

            tcp_top_ringbuff_send(by,&key,NULL);
        }
    }
    else if(family == AF_INET6){
        struct ipv6_key_t key;
        memset(&key,0,sizeof(struct ipv6_key_t));
        key.pid = pid;
        bpf_get_current_comm(&key.comm,sizeof(key.comm));
        BPF_CORE_READ_INTO(&key.saddr,sk,__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&key.daddr,sk,__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&key.lport,sk,__sk_common.skc_num);
        BPF_CORE_READ_INTO(&dport,sk,__sk_common.skc_dport);
        key.dport = bpf_ntohs(dport);

        struct recv_send_bytes *by = bpf_map_lookup_elem(&ipv6_top_map,&key);
        if(!by){
            struct recv_send_bytes init = {
                .send = size,
                .recv = 0,
                .last_output = now
            };
            bpf_map_update_elem(&ipv6_top_map,&key,&init,BPF_ANY);

            tcp_top_ringbuff_send(&init,NULL,&key);
        }
        else{
            by->send += size;
            bpf_map_update_elem(&ipv6_top_map,&key,by,BPF_ANY);

            tcp_top_ringbuff_send(by,NULL,&key);
        }
    }
    return 0;
}

static int tcp_kprobe_retrans_event(struct sock *sk, struct sk_buff *skb, u32 type){
    if(!sk)
        return 0;

    //u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; 
    if(pid == filiter_id)
        return 0;

    u64 now = bpf_ktime_get_ns();
    // struct tcp_skb_cb *tcb = (struct tcp_skb_cb *)skb->cb;
    // u32 seq = skb ? tcb->seq : 0;
    u32 seq;
    struct tcp_skb_cb tcb;
    if (skb) {
        bpf_probe_read_kernel(&tcb, sizeof(tcb), skb->cb);
        seq = tcb.seq;
    } else {
        seq = 0;
    }
    // u16 family = sk->__sk_common.skc_family;
    // u16 lport = sk->__sk_common.skc_num;
    // u16 dport = bpf_ntohs(sk->__sk_common.skc_dport);
    // u8 state = sk->__sk_common.skc_state;
    u16 family,lport,dport;
    u8 state;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    bpf_probe_read_kernel(&lport, sizeof(lport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&state, sizeof(state), &sk->__sk_common.skc_state);

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    if(family != AF_INET && family != AF_INET6)
        return 0;
    struct tcp_resubmit *buff = bpf_ringbuf_reserve(&tcpretrans_buffer,sizeof(struct tcp_resubmit),0);
    if(!buff){
        bpf_printk("the tcp_retrans buffer is full\n");
        return 0;
    }
    memset(buff,0,sizeof(struct tcp_resubmit));
    buff->pid = pid;
    buff->dport = dport;
    buff->lport = lport;
    buff->seq = seq;
    buff->state = state;
    buff->type = type;
    buff->occur = now;
    bpf_probe_read_str(buff->comm,sizeof(comm),comm);

    switch(family){
        case AF_INET:{
            buff->af = AF_INET;
            u32 daddr,saddr;
            bpf_probe_read_kernel(&daddr,sizeof(daddr),&sk->__sk_common.skc_daddr);
            bpf_probe_read_kernel(&saddr,sizeof(saddr),&sk->__sk_common.skc_rcv_saddr);
            buff->src_addr.saddr_v4 = saddr;
            buff->dst_addr.daddr_v4 = daddr;
            // buff->dst_addr.daddr_v4 = sk->__sk_common.skc_daddr;
            // buff->src_addr.saddr_v4 = sk->__sk_common.skc_rcv_saddr;
            bpf_ringbuf_submit(buff,0);
            break;
        }
        case AF_INET6:{
            buff->af = AF_INET6;
            bpf_probe_read_kernel(&buff->src_addr.saddr_v6, sizeof(buff->src_addr.saddr_v6), &sk->__sk_common.skc_v6_rcv_saddr);
            bpf_probe_read_kernel(&buff->dst_addr.daddr_v6,sizeof(buff->dst_addr.daddr_v6),&sk->__sk_common.skc_v6_daddr);
            bpf_ringbuf_submit(buff,0);
            break;
        }
        default:
            bpf_ringbuf_discard(buff, 0);
            return 0;
    }

    return 0;
}


// 重传事件追踪
SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_retransmit(struct tcp_retransmit_skb_event *ctx) {
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    struct sock *sk = (struct sock *)ctx->skaddr;
    return tcp_kprobe_retrans_event(sk,skb,RETRANSMIT);
}

// // TLP 事件追踪
// SEC("kprobe/tcp_send_loss_probe")
// int trace_tlp(struct pt_regs *ctx, struct sock *sk) {
//     return tcp_kprobe_retrans_event(sk,NULL,TLP);
// }

// 下面俩处理tcptop
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(top_tcp_send_entry, struct sock *sk){
    //u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; 
    bpf_map_update_elem(&top_sock_store,&pid,&sk,BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(top_tcp_send_ret, int ret){
    //u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; 
    struct sock **sockpp = bpf_map_lookup_elem(&top_sock_store, &pid);
    if (!sockpp)
        return 0;

    struct sock *sk = *sockpp;
    if (ret > 0) {
        tcp_top_sendstat(sk, ret);
    }

    bpf_map_delete_elem(&top_sock_store, &pid);

    return 0;
}

// SEC("kprobe/tcp_sendpage")
// int BPF_KPROBE(top_tcp_sendpage_entry, struct sock *sk, struct page *page, int offset, size_t size) 
// {
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_map_update_elem(&top_sock_store,&pid,&sk,BPF_ANY);
//     return 0;
// }

// SEC("kretprobe/tcp_sendpage")
// int BPF_KRETPROBE(top_tcp_sendpage_ret, int ret){
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     struct sock **sockpp = bpf_map_lookup_elem(&top_sock_store, &pid);
//     if (!sockpp)
//         return 0;

//     struct sock *sk = *sockpp;
//     if (ret > 0) {
//         tcp_top_sendstat(sk, ret);
//     }

//     bpf_map_delete_elem(&top_sock_store, &pid);

//     return 0;
// }

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(top_tcp_recv_entry, struct sock *sk, int copied){
    if (copied <= 0)
        return 0;
    
    //u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; 
    u16 family = 0, dport = 0;
    u64 now = bpf_ktime_get_ns();

    BPF_CORE_READ_INTO(&family,sk,__sk_common.skc_family);

    if (family == AF_INET){
        struct ipv4_key_t key;
        memset(&key,0,sizeof(struct ipv4_key_t));
        key.pid = pid;
        bpf_get_current_comm(&key.comm,sizeof(key.comm));
        BPF_CORE_READ_INTO(&key.saddr,sk,__sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&key.daddr,sk,__sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&key.lport,sk,__sk_common.skc_num);
        BPF_CORE_READ_INTO(&dport,sk,__sk_common.skc_dport);
        key.dport = bpf_ntohs(dport);

        struct recv_send_bytes *by = bpf_map_lookup_elem(&ipv4_top_map,&key);
        if(!by){
            struct recv_send_bytes init = {
                .send = 0,
                .recv = copied,
                .last_output = now
            };
            bpf_map_update_elem(&ipv4_top_map,&key,&init,BPF_ANY);

            tcp_top_ringbuff_send(&init,&key,NULL);
        }
        else{
            by->recv += copied;
            bpf_map_update_elem(&ipv4_top_map,&key,by,BPF_ANY);

            tcp_top_ringbuff_send(by,&key,NULL);
        }
    }
    else if(family == AF_INET6){
        struct ipv6_key_t key;
        memset(&key,0,sizeof(struct ipv6_key_t));
        key.pid = pid;
        bpf_get_current_comm(&key.comm,sizeof(key.comm));
        BPF_CORE_READ_INTO(&key.saddr,sk,__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&key.daddr,sk,__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&key.lport,sk,__sk_common.skc_num);
        BPF_CORE_READ_INTO(&dport,sk,__sk_common.skc_dport);
        key.dport = bpf_ntohs(dport);

        struct recv_send_bytes *by = bpf_map_lookup_elem(&ipv6_top_map,&key);
        if(!by){
            struct recv_send_bytes init = {
                .send = 0,
                .recv = copied,
                .last_output = now
            };
            bpf_map_update_elem(&ipv6_top_map,&key,&init,BPF_ANY);

            tcp_top_ringbuff_send(&init,NULL,&key);
        }
        else{
            by->recv += copied;
            bpf_map_update_elem(&ipv6_top_map,&key,by,BPF_ANY);

            tcp_top_ringbuff_send(by,NULL,&key);
        }
    }
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
    return net_trace_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
    return net_trace_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk)
{
    return handle_tcp_rcv_state_process(sk);
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk)
{
    return net_trace_connect(sk);
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk)
{
    return net_trace_connect(sk);
}

SEC("fentry/tcp_rcv_state_process")
int BPF_PROG(fentry_tcp_rcv_state_process, struct sock *sk)
{
    return handle_tcp_rcv_state_process(sk);
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcprtt,struct sock *sk)
{
    const struct inet_sock *inet = (struct inet_sock *)(sk);
	struct tcp_sock *ts;
    u32 srtt;

    struct tcprtt_perf_data *data = bpf_map_lookup_elem(&tcprtt_map,&zero);
    if(!data){
        // bpf_printk("the tcprtt map not init\n");
        // return 0;
        struct tcprtt_perf_data init;
        memset(&init,0,sizeof(struct tcprtt_perf_data));
        bpf_map_update_elem(&tcprtt_map,&zero,&init,BPF_ANY);

        data = bpf_map_lookup_elem(&tcprtt_map,&zero);
        if(!data)
            return 0;
    }
    ts = (struct tcp_sock *)(sk);
    srtt = BPF_CORE_READ(ts, srtt_us) >> 3; // 将 srtt 从纳秒转换为微秒

    srtt /= 1000; // 转ms

    u32 index;
    if(srtt <= 0)
        index = 0;
    else if(srtt < 5)
        index = 1;
    else if(srtt < 17)
        index = 2;
    else if(srtt < 33)
        index = 3;
    else if(srtt < 65)
        index = 4;
    else if(srtt < 129)
        index = 5;
    else if(srtt < 257)
        index = 6;
    else 
        index = 7;
    
    data->data[index] += 1;
    bpf_map_update_elem(&tcprtt_map,&zero,data,BPF_ANY);

    return 0;
}

SEC("perf_event")
int handle_tcprtt_event(struct bpf_perf_event_data *ctx){
    struct tcprtt_perf_data *src = bpf_map_lookup_elem(&tcprtt_map,&zero);
    if(!src){
        bpf_printk("the tcprtt map is not init\n");
        return 0;
    }

    struct tcprtt_perf_data *buff = bpf_ringbuf_reserve(&tcprtt_buffer,sizeof(struct tcprtt_perf_data),0);
    if(!buff){
        bpf_printk("the tcprtt buffer is full\n");
        return 0;
    }
    memset(buff,0,sizeof(struct tcprtt_perf_data));

    for(int i = 0;i<8;i++){
        buff->data[i] = src->data[i];
    }
    bpf_ringbuf_submit(buff, 0);

    return 0;
}