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


def update_task_mm_data(new_data, gateway):
    """
    更新任务的内存分配频率数据到 Prometheus。
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus 指标
    kmem_count = Gauge(
        "task_kmem_count",
        "Kernel memory allocation count",
        ["pid", "command"],
        registry=registry
    )
    vmem_count = Gauge(
        "task_vmem_count",
        "Virtual memory allocation count",
        ["pid", "command"],
        registry=registry
    )
    slab_count = Gauge(
        "task_slab_count",
        "Slab memory allocation count",
        ["pid", "command"],
        registry=registry
    )

    # 遍历新增数据并更新指标
    for _, row in new_data.iterrows():
        try:
            # 获取数据行内容
            pid = str(row["PID"])  # 确保按列名访问
            command = row["Command"]
            kmem = row["Kmem Count"]
            vmem = row["Vmem Count"]
            slab = row["Slab Count"]

            # 设置指标值
            kmem_count.labels(pid=pid, command=command).set(kmem)
            vmem_count.labels(pid=pid, command=command).set(vmem)
            slab_count.labels(pid=pid, command=command).set(slab)

        except KeyError as ke:
            print(f"KeyError while processing task memory data: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="task_memory_stats", registry=registry)
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")


def update_process_mm_data(new_data, gateway):
    """
    更新进程的内存分配频率数据到 Prometheus。
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus 指标
    kmem_count = Gauge(
        "process_kmem_count",
        "Kernel memory allocation count for processes",
        ["tgid"],  # 使用 TGID 作为标签
        registry=registry
    )
    vmem_count = Gauge(
        "process_vmem_count",
        "Virtual memory allocation count for processes",
        ["tgid"],  # 使用 TGID 作为标签
        registry=registry
    )
    slab_count = Gauge(
        "process_slab_count",
        "Slab memory allocation count for processes",
        ["tgid"],  # 使用 TGID 作为标签
        registry=registry
    )

    # 遍历新增数据并更新指标
    for _, row in new_data.iterrows():
        try:
            # 获取数据行内容
            tgid = str(row["TGID"])  # 确保 TGID 为字符串
            kmem = row["Kmem Count"]
            vmem = row["Vmem Count"]
            slab = row["Slab Count"]

            # 设置指标值
            kmem_count.labels(tgid=tgid).set(kmem)
            vmem_count.labels(tgid=tgid).set(vmem)
            slab_count.labels(tgid=tgid).set(slab)

        except KeyError as ke:
            print(f"KeyError while processing process memory data: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="process_memory_stats", registry=registry)
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")


threading.Thread(target=monitor_and_push, args=("run/task_mm_stats.csv", update_task_mm_data ,1)).start()
threading.Thread(target=monitor_and_push, args=("run/process_mm_stats.csv", update_process_mm_data,1)).start()