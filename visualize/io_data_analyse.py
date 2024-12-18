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


def update_io_task_stats(new_data, gateway):
    """
    更新 IO 任务统计数据到 Prometheus。

    参数:
    - new_data: pandas DataFrame，包含字段 ["PID", "Command", "Read Count", "Write Count"]
    - gateway: Pushgateway 的 URL
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus 指标
    io_read_count = Gauge(
        "io_task_read_count",
        "I/O task read count",
        ["pid", "command"],
        registry=registry
    )

    io_write_count = Gauge(
        "io_task_write_count",
        "I/O task write count",
        ["pid", "command"],
        registry=registry
    )

    # 遍历新增数据并更新指标
    for _, row in new_data.iterrows():
        try:
            # 从行中获取数据
            pid = str(row["PID"])  # 确保为字符串
            command = row["Command"]
            read_count = row["Read Count"]
            write_count = row["Write Count"]

            # 更新指标值
            io_read_count.labels(pid=pid, command=command).set(read_count)
            io_write_count.labels(pid=pid, command=command).set(write_count)

        except KeyError as ke:
            print(f"KeyError while processing IO task stats: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="io_task_stats", registry=registry)
        print("IO task stats successfully pushed to Prometheus.")
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")


def update_io_process_stats(new_data, gateway):
    """
    更新 IO 进程统计数据到 Prometheus。

    参数:
    - new_data: pandas DataFrame，包含字段 ["TGID", "Read Count", "Write Count"]
    - gateway: Pushgateway 的 URL
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus 指标
    io_process_read_count = Gauge(
        "io_process_read_count",
        "I/O process read count",
        ["tgid"],
        registry=registry
    )

    io_process_write_count = Gauge(
        "io_process_write_count",
        "I/O process write count",
        ["tgid"],
        registry=registry
    )

    # 遍历数据行并更新指标
    for _, row in new_data.iterrows():
        try:
            # 从行中提取数据
            tgid = str(row["TGID"])  # 确保 TGID 为字符串
            read_count = row["Read Count"]
            write_count = row["Write Count"]

            # 设置指标值
            io_process_read_count.labels(tgid=tgid).set(read_count)
            io_process_write_count.labels(tgid=tgid).set(write_count)

        except KeyError as ke:
            print(f"KeyError while processing IO process stats: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送数据到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="io_process_stats", registry=registry)
        print("IO process stats successfully pushed to Prometheus.")
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")

def update_iowait(new_data, gateway):
    """
    更新 IO 等待分布数据到 Prometheus。

    参数:
    - new_data: pandas DataFrame，包含各时间段的等待数据列。
    - gateway: Pushgateway 的 URL。
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus 指标
    iowait_distribution = Gauge(
        "iowait_distribution",
        "I/O wait distribution across different time ranges",
        ["range"],
        registry=registry
    )

    # 定义时间范围标签（列名）
    time_ranges = ["1us", "4us", "16us", "64us", "256us", "1ms", "4ms", "4ms+"]

    # 遍历数据行并更新指标
    for _, row in new_data.iterrows():
        try:
            # 遍历每个时间范围，并设置对应的指标
            for time_range in time_ranges:
                iowait_distribution.labels(range=time_range).set(row[time_range])
        except KeyError as ke:
            print(f"KeyError while processing IO wait stats: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送数据到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="iowait_stats", registry=registry)
        print("IO wait stats successfully pushed to Prometheus.")
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")

threading.Thread(target=monitor_and_push, args=("run/io_task.csv", update_io_task_stats ,0.5)).start()
threading.Thread(target=monitor_and_push, args=("run/io_process.csv", update_io_process_stats,0.8)).start()
threading.Thread(target=monitor_and_push, args=("run/iowait.csv",update_iowait , 1.0)).start()