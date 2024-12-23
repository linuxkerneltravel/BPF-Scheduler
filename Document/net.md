## 挂载的程序和相关钩子
```shell
root@ne0-System:~# bpftool prog show
1486: tracepoint  name trace_retransmit  tag 3626250b7905d155  gpl
	loaded_at 2024-12-22T22:05:26+0800  uid 0
	xlated 1160B  jited 639B  memlock 4096B  map_ids 763,765
	btf_id 556
1488: kprobe  name top_tcp_send_entry  tag a7ce508aab49e47f  gpl
	loaded_at 2024-12-22T22:05:26+0800  uid 0
	xlated 112B  jited 70B  memlock 4096B  map_ids 760,765
	btf_id 556
1489: kprobe  name top_tcp_send_ret  tag d9c91fb97919a059  gpl
	loaded_at 2024-12-22T22:05:26+0800  uid 0
	xlated 3680B  jited 1984B  memlock 4096B  map_ids 760,758,762,765,759
	btf_id 556
1490: kprobe  name top_tcp_recv_entry  tag 3db6d55e406884b9  gpl
	loaded_at 2024-12-22T22:05:26+0800  uid 0
	xlated 3552B  jited 1910B  memlock 4096B  map_ids 758,762,765,759
	btf_id 556
1491: kprobe  name tcp_v4_connect  tag b03fb14003ec8076  gpl
	loaded_at 2024-12-22T22:05:26+0800  uid 0
	xlated 224B  jited 126B  memlock 4096B  map_ids 757,765
	btf_id 556
1492: kprobe  name tcp_v6_connect  tag b03fb14003ec8076  gpl
	loaded_at 2024-12-22T22:05:26+0800  uid 0
	xlated 224B  jited 126B  memlock 4096B  map_ids 757,765
	btf_id 556
1493: kprobe  name tcp_rcv_state_process  tag e94e0aad43db0596  gpl
	loaded_at 2024-12-22T22:05:26+0800  uid 0
	xlated 1008B  jited 561B  memlock 4096B  map_ids 757,761,765
	btf_id 556
1494: tracing  name tcprtt  tag e11fbd522e358eb5  gpl
	loaded_at 2024-12-22T22:05:26+0800  uid 0
	xlated 680B  jited 387B  memlock 4096B  map_ids 755,765
	btf_id 556
1495: perf_event  name handle_tcprtt_event  tag 2a56ebe47815a31d  gpl
	loaded_at 2024-12-22T22:05:26+0800  uid 0
	xlated 472B  jited 244B  memlock 4096B  map_ids 755,765,756
	btf_id 556
```
```shell
root@ne0-System:~# bpftool link show
568: perf_event  prog 1486  
	tracepoint tcp_retransmit_skb  
569: perf_event  prog 1488  
	kprobe ffffffffa85b3020 tcp_sendmsg  
570: perf_event  prog 1489  
	kretprobe ffffffffa85b3020 tcp_sendmsg  
571: perf_event  prog 1490  
	kprobe ffffffffa85b3170 tcp_cleanup_rbuf  
572: perf_event  prog 1491  
	kprobe ffffffffa85d3b70 tcp_v4_connect  
573: perf_event  prog 1492  
	kprobe ffffffffa86ac640 tcp_v6_connect  
574: perf_event  prog 1493  
	kprobe ffffffffa85c6290 tcp_rcv_state_process  
575: tracing  prog 1494  
	prog_type tracing  attach_type trace_fentry  
	target_obj_id 1  target_btf_id 55882  
576: perf_event  prog 1495  
	event 6 :0  
```
挂载的程序数量9个，tracepoint 1个，kprobe/kretprobe 6 个


## 系统整体的网络接口统计信息
首先还是先从proc中直接系统的整体性数据
```
Interface,Bytes Received,Packets Received,Errs Rcv,Drops Rcv,Bytes Sent,Packets Sent,Errs Sent,Drops Sent
lo,357168131,258560,0,0,357168131,258560,0,0
enp5s0,3269952491,3791526,0,18932,12237168071,9750198,0,0
docker0,0,0,0,0,0,0,0,0

lo,357168131,258560,0,0,357168131,258560,0,0
enp5s0,3269951654,3791513,0,18932,12237124409,9750158,0,0
docker0,0,0,0,0,0,0,0,0
```
- Interface：网络接口的名称，例如 lo（本地回环）、enp5s0（以太网接口）、docker0（Docker 桥接接口）
- Bytes Received：接收到的总字节数
- Packets Received：接收到的数据包总数
- Errs Rcv：接收时发生的错误数量（例如校验错误或帧错误）
- Drops Rcv：接收时丢弃的数据包数量，可能因为队列溢出或其他原因
- Bytes Sent：发送的总字节数
- Packets Sent：发送的数据包总数
- Errs Sent：发送时发生的错误数量
- Drops Sent：发送时丢弃的数据包数量

从这些信息得到系统整体的网络接口的流量统计数据表本地数据在[这里](visualize/proc/net.csv)

## tcptop
tcptop 用于显示系统中基于 TCP 协议的网络流量统计信息，包括每个进程的发送和接收流量
- 实现方式
  - 挂载在以下内核节点
    - kprobe/tcp_sendmsg 和 kretprobe/tcp_sendmsg：获取任务的发送字节数
    - kprobe/tcp_cleanup_rbuf：获取任务的接收字节数
- 功能特点
  - 实时统计每个进程的网络发送和接收流量
  - 帮助快速定位高流量的任务或进程，便于分析系统的网络行为


```
Timestamp,PID,Comm,Sent_Bytes,Received_Bytes
2024-12-22 22:05:27,79852,xrdp,76064,1976
2024-12-22 22:05:28,79852,xrdp,629012,4251
2024-12-22 22:05:29,79852,xrdp,930864,5628
2024-12-22 22:05:30,79852,xrdp,1094929,5723
2024-12-22 22:05:31,79852,xrdp,1186351,5749
2024-12-22 22:05:32,79852,xrdp,1492384,5795
2024-12-22 22:05:33,79852,xrdp,1651137,7911
2024-12-22 22:18:21,79852,xrdp,872722,3271
2024-12-22 22:18:22,79852,xrdp,1999434,8459
2024-12-22 22:18:23,79852,xrdp,2662462,12991
2024-12-22 22:18:24,79852,xrdp,3010331,14944
2024-12-22 22:18:25,79852,xrdp,3014084,14966
2024-12-22 22:18:26,79852,xrdp,3014392,15182
2024-12-22 22:18:27,79852,xrdp,3014776,15254
2024-12-22 22:18:28,79852,xrdp,3014978,15254
2024-12-22 22:18:29,915,prometheus,11867,0
```
运行的本地结果存储在[这里](visualize/run/tcptop.csv)


## tcprtt
tcprtt 用于显示系统中基于 TCP 连接的往返时间（Round-Trip Time, RTT）分布情况
- 实现方式
  - 挂载在 fentry/tcp_rcv_established 节点
  - 获取 sock 中的 srtt_us 字段，提取往返时间
- 功能特点
  - 每秒通过 perf 输出统计数据，展示不同 RTT 区间的网络请求分布
  - 帮助分析系统网络延迟情况，评估网络性能


```
1ms,4ms,16ms,32ms,64ms,128ms,256ms,256ms+
0,0,8,10,10,0,0,0
0,0,139,10,10,0,0,0
0,0,303,11,10,0,0,0
3,0,333,30,47,0,0,0
3,0,387,32,47,0,0,0
3,31,422,32,47,0,0,0
3,31,520,34,47,1,0,0
6,33,522,37,47,1,0,0
6,33,524,40,47,1,0,0
6,33,525,40,47,1,0,0
6,33,525,48,47,1,0,0
6,33,525,58,47,1,0,0
6,33,525,66,50,1,0,0
12,33,525,75,50,1,0,0
12,33,525,75,54,1,0,0
12,33,525,75,56,1,0,0
12,33,525,75,58,1,0,0
15,35,525,75,60,1,0,0
15,35,525,75,63,1,0,0
15,35,525,75,66,1,0,0
15,35,525,75,70,1,0,0
15,35,525,75,82,1,0,0
15,35,525,75,94,1,0,0
15,35,525,101,102,1,0,0
15,35,525,102,103,1,0,0
```
运行的本地结果存储在[这里](visualize/run/tcprtt.csv)


## tcpretrans
tcpretrans 用于显示系统中发生的 TCP 重传事件，定位具体的任务和连接
- 实现方式
  - 挂载在 tracepoint/tcp/tcp_retransmit_skb 节点
  - 捕获每次 TCP 数据包重传事件
- 功能特点
  - 精确记录发生重传的任务信息，包括 PID、源 IP 和目标 IP 等
  - 帮助分析网络抖动、丢包等问题，优化系统网络传输性能

网络这部分的数据都是通过`visualize/net_with_delay.sh`这个来模拟的，这个脚本会加入给系统加入一定的延迟和掉包率，运行60s
```
Timestamp,PID,Comm,State,Event_Type,Source_IP,Source_Port,Destination_IP,Destination_Port
2024-12-22 22:18:31.175572385,81508,python3,ESTABLISHED,1,::ffff:10.193.121.196,15629,::ffff:10.196.79.194,61794
2024-12-22 22:18:35.664009094,81510,python3,ESTABLISHED,1,10.193.121.196,1764,98.85.100.80,443
2024-12-22 22:18:36.030003791,81514,python3,ESTABLISHED,1,::ffff:10.193.121.196,15629,::ffff:10.196.79.194,61794
2024-12-22 22:18:36.030738760,81514,python3,ESTABLISHED,1,::ffff:10.193.121.196,15629,::ffff:10.196.79.194,61794
2024-12-22 22:18:39.633488507,81510,python3,ESTABLISHED,1,10.193.121.196,2692,98.85.100.80,443
2024-12-22 22:18:39.636941928,81510,python3,ESTABLISHED,1,10.193.121.196,2692,98.85.100.80,443
2024-12-22 22:18:41.211002518,81508,python3,ESTABLISHED,1,::ffff:10.193.121.196,15629,::ffff:10.196.79.194,61794
2024-12-22 22:18:41.211005083,81508,python3,ESTABLISHED,1,::ffff:10.193.121.196,15629,::ffff:10.196.79.194,61794
2024-12-22 22:18:43.497009470,81512,python3,ESTABLISHED,1,10.193.121.196,6788,98.85.100.80,443
2024-12-22 22:18:48.290008285,81512,python3,ESTABLISHED,1,10.193.121.196,17028,98.85.100.80,443
2024-12-22 22:18:48.547011250,81506,python3,ESTABLISHED,1,10.193.121.196,11918,34.226.108.155,443
2024-12-22 22:18:48.797912580,81505,python3,ESTABLISHED,1,10.193.121.196,37504,34.226.108.155,443
2024-12-22 22:18:48.798215136,81505,python3,ESTABLISHED,1,10.193.121.196,37504,34.226.108.155,443
2024-12-22 22:18:48.798589181,81505,python3,ESTABLISHED,1,10.193.121.196,37504,34.226.108.155,443
2024-12-22 22:18:48.799707180,81505,python3,ESTABLISHED,1,10.193.121.196,37504,34.226.108.155,443
2024-12-22 22:18:49.708015183,81223,C1 CompilerThre,ESTABLISHED,1,10.193.121.196,13454,34.226.108.155,443
```
运行的本地结果存储在[这里](visualize/run/tcpretrans.csv)


## tcp连接延迟
用于监控 TCP 连接建立过程中的延迟情况
- 实现方式
  - 挂载在以下内核节点
    - tcp_v4_connect 和 tcp_v6_connect：捕获 IPv4 和 IPv6 的 TCP 连接请求
    - tcp_rcv_state_process：捕获 TCP 状态处理事件
- 功能特点
  - 记录从连接请求到完成的时间间隔，精确评估 TCP 连接延迟
  - 帮助发现可能导致连接延迟的网络或系统问题



```
Timestamp,PID,Comm,Delay_us
2024-12-22 22:05:27.675840321,76241,code,278458368
2024-12-22 22:18:31.565844370,81505,python3,247682805
2024-12-22 22:18:31.569318272,81508,python3,251836536
2024-12-22 22:18:31.570976574,81506,python3,239246101
2024-12-22 22:18:31.571226255,81510,python3,239484962
2024-12-22 22:18:31.571479964,81507,python3,239863430
2024-12-22 22:18:31.573810751,81515,python3,242115724
2024-12-22 22:18:31.574551499,81512,python3,242965114
2024-12-22 22:18:31.576232680,81509,python3,244483253
```
运行的本地结果存储在[这里](visualize/run/net_latency.csv)



## 实验
