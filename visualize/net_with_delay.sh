#!/bin/bash

DEV=enp5s0  # 网络接口名称，可根据需要修改
DELAY_MEAN=10  # 平均延迟（毫秒）
DELAY_JITTER=10  # 延迟波动范围（毫秒）
DELAY_DISTRIBUTION="normal"  # 延迟分布类型（normal, uniform, pareto, paretonormal）
LOSS_RATE=5  # 丢包率百分比（例如，5表示5%）

# 添加网络延迟和丢包
add_network_delay() {
    echo "Adding network delay and packet loss to $DEV"
    echo "Mean delay: $DELAY_MEAN ms, Jitter: $DELAY_JITTER ms, Distribution: $DELAY_DISTRIBUTION, Loss rate: $LOSS_RATE%"
    sudo tc qdisc add dev $DEV root netem delay ${DELAY_MEAN}ms ${DELAY_JITTER}ms distribution $DELAY_DISTRIBUTION loss ${LOSS_RATE}%
}

# 移除网络延迟和丢包
remove_network_delay() {
    echo "Removing network delay and packet loss from $DEV"
    sudo tc qdisc del dev $DEV root
}

# 启动网络延迟并运行 Python 脚本
run_with_delay() {
    add_network_delay
    echo "Starting Python script..."
    python3 net_test.py
    echo "Python script finished. Removing delay..."
    remove_network_delay
}

# 处理用户中断信号
trap "remove_network_delay; echo 'Network delay and packet loss removed. Exiting.'; exit 0" SIGINT SIGTERM

# 主函数
run_with_delay
