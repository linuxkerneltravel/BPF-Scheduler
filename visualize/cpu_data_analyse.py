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


def update_cpu_usage(new_data, gateway):
    """
    更新 CPU 使用数据到 Prometheus。

    参数:
    - new_data: pandas DataFrame，包含字段 ["CPU ID", "User Time", "Kernel Time", "Idle Time", "IRQ Time", "SoftIRQ Time"]
    - gateway: Pushgateway 的 URL
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus 指标
    cpu_user_time = Gauge(
        "cpu_user_time_seconds",
        "CPU time spent in user mode",
        ["cpu_id"],
        registry=registry
    )

    cpu_kernel_time = Gauge(
        "cpu_kernel_time_seconds",
        "CPU time spent in kernel mode",
        ["cpu_id"],
        registry=registry
    )

    cpu_idle_time = Gauge(
        "cpu_idle_time_seconds",
        "CPU time spent idle",
        ["cpu_id"],
        registry=registry
    )

    cpu_irq_time = Gauge(
        "cpu_irq_time_seconds",
        "CPU time spent servicing IRQs",
        ["cpu_id"],
        registry=registry
    )

    cpu_softirq_time = Gauge(
        "cpu_softirq_time_seconds",
        "CPU time spent servicing soft IRQs",
        ["cpu_id"],
        registry=registry
    )

    # 遍历数据行并更新指标
    for _, row in new_data.iterrows():
        try:
            # 获取 CPU ID 和各个时间段的数据
            cpu_id = str(row["CPU ID"])  # CPU ID 转为字符串
            user_time = row["User Time"]
            kernel_time = row["Kernel Time"]
            idle_time = row["Idle Time"]
            irq_time = row["IRQ Time"]
            softirq_time = row["SoftIRQ Time"]

            # 设置 Prometheus 指标值
            cpu_user_time.labels(cpu_id=cpu_id).set(user_time)
            cpu_kernel_time.labels(cpu_id=cpu_id).set(kernel_time)
            cpu_idle_time.labels(cpu_id=cpu_id).set(idle_time)
            cpu_irq_time.labels(cpu_id=cpu_id).set(irq_time)
            cpu_softirq_time.labels(cpu_id=cpu_id).set(softirq_time)

        except KeyError as ke:
            print(f"KeyError while processing CPU usage data: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送数据到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="cpu_usage_stats", registry=registry)
        print("CPU usage stats successfully pushed to Prometheus.")
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")

def update_task_usage(new_data, gateway):
    """
    更新任务 CPU 使用情况数据到 Prometheus。

    参数:
    - new_data: pandas DataFrame，包含 ["PID", "Name", "Total Percent", "Kernel Percent", "User Percent"]
    - gateway: Pushgateway 的 URL。
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus 指标
    total_usage = Gauge(
        "task_total_cpu_usage_percent",
        "Total CPU usage percent for tasks",
        ["pid", "name"],
        registry=registry
    )

    kernel_usage = Gauge(
        "task_kernel_cpu_usage_percent",
        "CPU usage percent in kernel mode for tasks",
        ["pid", "name"],
        registry=registry
    )

    user_usage = Gauge(
        "task_user_cpu_usage_percent",
        "CPU usage percent in user mode for tasks",
        ["pid", "name"],
        registry=registry
    )

    # 遍历数据行并更新指标
    for _, row in new_data.iterrows():
        try:
            # 提取数据
            pid = str(row["PID"])
            name = row["Name"]
            total_percent = row["Total Percent"]
            kernel_percent = row["Kernel Percent"]
            user_percent = row["User Percent"]

            # 设置指标值
            total_usage.labels(pid=pid, name=name).set(total_percent)
            kernel_usage.labels(pid=pid, name=name).set(kernel_percent)
            user_usage.labels(pid=pid, name=name).set(user_percent)

        except KeyError as ke:
            print(f"KeyError while processing task usage data: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送数据到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="task_usage_stats", registry=registry)
        print("Task usage stats successfully pushed to Prometheus.")
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")

def update_process_stat(new_data, gateway):
    """
    更新进程统计数据到 Prometheus。

    参数:
    - new_data: pandas DataFrame，包含 ["TGID", "Kids Length", "Total Percent"]
    - gateway: Pushgateway 的 URL。
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus 指标
    process_kids_length = Gauge(
        "process_kids_length",
        "Number of child processes (Kids Length)",
        ["tgid"],
        registry=registry
    )

    process_total_percent = Gauge(
        "process_total_cpu_percent",
        "Total CPU usage percentage for process",
        ["tgid"],
        registry=registry
    )

    # 遍历数据行并更新指标
    for _, row in new_data.iterrows():
        try:
            # 提取数据
            tgid = str(row["TGID"])  # TGID 转为字符串
            kids_length = row["Kids Length"]
            total_percent = row["Total Percent"]

            # 设置 Prometheus 指标值
            process_kids_length.labels(tgid=tgid).set(kids_length)
            process_total_percent.labels(tgid=tgid).set(total_percent)

        except KeyError as ke:
            print(f"KeyError while processing process stats: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送数据到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="process_stats", registry=registry)
        print("Process stats successfully pushed to Prometheus.")
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")



def update_runqlat(new_data, gateway):
    """
    更新运行队列延迟数据到 Prometheus。

    参数:
    - new_data: pandas DataFrame，包含 ["1us", "4us", "16us", "64us", "256us", "1ms", "4ms", "4ms+"]
    - gateway: Pushgateway 的 URL。
    """
    # 初始化 Prometheus 注册表
    registry = CollectorRegistry()

    # 定义 Prometheus 指标
    runqlat_gauge = Gauge(
        "runqlat_distribution",
        "Run queue latency distribution",
        ["time_range", "row_index"],
        registry=registry
    )

    # 定义时间范围标签（列名）
    time_ranges = ["1us", "4us", "16us", "64us", "256us", "1ms", "4ms", "4ms+"]

    # 遍历数据行和时间范围，更新指标
    for row_index, row in new_data.iterrows():
        try:
            for time_range in time_ranges:
                # 设置 Prometheus 指标值
                runqlat_gauge.labels(time_range=time_range, row_index=str(row_index)).set(row[time_range])
        except KeyError as ke:
            print(f"KeyError while processing runqlat data: {ke}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    # 推送数据到 Prometheus Pushgateway
    try:
        push_to_gateway(gateway, job="runqlat_stats", registry=registry)
        print("Run queue latency stats successfully pushed to Prometheus.")
    except Exception as e:
        print(f"Error while pushing to Prometheus: {e}")

threading.Thread(target=monitor_and_push, args=("run/cpu_usage.csv", update_cpu_usage ,0.8)).start()
threading.Thread(target=monitor_and_push, args=("run/task_usage.csv", update_task_usage,0.5)).start()
threading.Thread(target=monitor_and_push, args=("run/process_stat.csv",update_process_stat , 1.0)).start()
threading.Thread(target=monitor_and_push, args=("run/runqlat.csv", update_runqlat ,0.5)).start()