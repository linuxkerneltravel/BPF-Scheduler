#!/bin/bash

# 获取初始 CPU 时间
get_cpu_stat() {
    awk '/^cpu / {print $2, $3, $4, $5, $6, $7, $8}' /proc/stat
}

# 获取每个 CPU 核的时间
get_per_core_stat() {
    awk '/^cpu[0-9]+ / {print $1, $2, $3, $4, $5, $6, $7, $8}' /proc/stat
}

# 计算 CPU 使用率
calculate_cpu_usage() {
    local prev=($1)  # 表示第一个参数
    local curr=($2)  # 表示第二个参数,函数调用时传入的第一个值就会成为 $1，第二个值成为 $2
    local total_prev=0
    local total_curr=0
    local total_diff=0
    local idle_diff=0

    # 计算总时间
    for value in "${prev[@]}"; do
        total_prev=$((total_prev + value))
    done
    for value in "${curr[@]}"; do
        total_curr=$((total_curr + value))
    done

    # 计算差值
    total_diff=$((total_curr - total_prev))
    idle_diff=$((curr[3] - prev[3]))  # Idle 时间差

    # 使用率计算
    local usage=$((100 * (total_diff - idle_diff) / total_diff))
    echo "$usage"
}

# 初始数据
PREV_STATS=$(get_cpu_stat)

# 定时收集数据
while true; do
    sleep 5  # 每5秒采样一次

    # 获取当前数据
    CURR_STATS=$(get_cpu_stat)

    # 计算 CPU 使用率
    CPU_USAGE=$(calculate_cpu_usage "$PREV_STATS" "$CURR_STATS")

    # 输出总 CPU 使用率
    echo "Total CPU Usage: $CPU_USAGE%"

    # 获取每个 CPU 核的统计数据
    PER_CORE_STATS=$(get_per_core_stat)

    # 处理每个 CPU 核的使用率
    echo "Per Core CPU Usage:"
    while read -r line; do
        core_name=$(echo $line | awk '{print $1}')
        prev_core=(${PREV_CORE_STATS[$core_name]})
        curr_core=($(echo $line | awk '{print $2, $3, $4, $5, $6, $7, $8}'))

        if [ ! -z "$prev_core" ]; then
            core_usage=$(calculate_cpu_usage "${prev_core[*]}" "${curr_core[*]}")
            echo "$core_name Usage: $core_usage%"
        fi

        # 更新当前的统计数据
        PREV_CORE_STATS[$core_name]="${curr_core[*]}"
    done <<< "$PER_CORE_STATS"

    # 更新为当前数据
    PREV_STATS=$CURR_STATS

    echo "------------------------------------------------------"
done
