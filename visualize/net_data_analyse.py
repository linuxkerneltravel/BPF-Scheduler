import os
import time
import pandas as pd
from prometheus_client import CollectorRegistry, Counter, Gauge, push_to_gateway
import threading

def monitor_and_push(csv_file, update_function, check_interval=0.5, gateway="http://localhost:9091"):
    last_size = 0  # 上次处理的行数

    while True:
        try:
            # 检查文件是否存在
            if not os.path.exists(csv_file):
                print(f"File {csv_file} does not exist. Retrying...")
                time.sleep(check_interval)
                continue

            # 获取当前文件的总行数
            current_size = sum(1 for _ in open(csv_file))
            print(f"Monitoring {csv_file}: last_size={last_size}, current_size={current_size}")

            # 如果有新增数据行
            if current_size > last_size:
                new_rows = current_size - last_size
                print(f"New data detected in {csv_file}: {new_rows} new rows.")

                # 读取新增的部分
                new_data = pd.read_csv(
                    csv_file,
                    skiprows=range(1, last_size + 1),  # 跳过前 `last_size` 行
                    header=0  # 第一行为标题行
                )

                # 调用更新函数
                update_function(new_data, gateway)

                # 更新记录的行数
                last_size = current_size

            time.sleep(check_interval)

        except Exception as e:
            print(f"Error while monitoring {csv_file}: {type(e).__name__}, {e}")
            time.sleep(check_interval)

def update_delay_data(new_data, gateway):
    """
    更新网络延迟数据到 Prometheus。
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus 指标
    network_delay = Gauge(
        "network_delay_microseconds",
        "Network delay in microseconds",
        ["pid", "comm"],
        registry=registry
    )

    # 遍历新增数据并更新指标
    for _, row in new_data.iterrows():
        try:
            # 从行中获取数据
            pid = str(row["PID"])  # 确保按列名访问
            comm = row["Comm"]
            delay_us = row["Delay_us"]

            # 设置指标值
            network_delay.labels(pid=pid, comm=comm).set(delay_us)

        except KeyError as ke:
            print(f"KeyError while processing delay data: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="network_delay", registry=registry)
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")

def update_state_data(new_data, gateway):
    """
    更新网络状态变化数据到 Prometheus。
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus Counter 指标
    network_state_changes = Counter(
        "network_state_changes",
        "Count of network state changes",
        [
            "pid", "comm", "state", "event_type",
            "source_ip", "source_port",
            "destination_ip", "destination_port"
        ],
        registry=registry
    )

    # 遍历新增数据并更新指标
    for _, row in new_data.iterrows():
        try:
            # 从行中获取数据
            pid = str(row["PID"])  # 转为字符串类型
            comm = row["Comm"]
            state = row["State"]
            event_type = str(row["Event_Type"])  # 转为字符串类型
            source_ip = row["Source_IP"]
            source_port = str(row["Source_Port"])  # 转为字符串类型
            destination_ip = row["Destination_IP"]
            destination_port = str(row["Destination_Port"])  # 转为字符串类型

            # 更新 Prometheus 指标
            network_state_changes.labels(
                pid=pid,
                comm=comm,
                state=state,
                event_type=event_type,
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=destination_ip,
                destination_port=destination_port
            ).inc()

        except KeyError as ke:
            print(f"KeyError while processing state data: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="network_state_changes", registry=registry)
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")



def update_traffic_data(new_data, gateway):
    """
    更新网络流量数据到 Prometheus。
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus Counter 指标
    sent_bytes = Counter(
        "network_sent_bytes",
        "Total bytes sent over the network",
        ["pid", "comm"],  # 根据实际数据调整标签
        registry=registry
    )

    received_bytes = Counter(
        "network_received_bytes",
        "Total bytes received over the network",
        ["pid", "comm"],  # 根据实际数据调整标签
        registry=registry
    )

    # 遍历新增数据并更新指标
    for _, row in new_data.iterrows():
        try:
            pid = str(row["PID"])  # 从列名访问数据
            comm = row["Comm"]
            sent = row["Sent_Bytes"]
            received = row["Received_Bytes"]

            # 更新发送字节指标
            sent_bytes.labels(pid=pid, comm=comm).inc(sent)

            # 更新接收字节指标
            received_bytes.labels(pid=pid, comm=comm).inc(received)

        except KeyError as ke:
            print(f"KeyError while processing traffic data: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送数据到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="network_traffic", registry=registry)
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")


threading.Thread(target=monitor_and_push, args=("run/net_latency.csv", update_delay_data ,0.5)).start()
threading.Thread(target=monitor_and_push, args=("run/tcptop.csv", update_traffic_data,0.2)).start()
threading.Thread(target=monitor_and_push, args=("run/tcpretrans.csv",update_state_data , 1.0)).start()

