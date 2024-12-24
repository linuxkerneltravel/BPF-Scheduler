#!/bin/bash

# 定义需要运行的 Python 脚本
SCRIPTS=("cpu_data_analyse.py" "io_data_analyse.py" "mm_data_analyse.py" "net_data_analyse.py")

# 用于存储进程的 PID
PIDS=()

# 启动每个脚本
for SCRIPT in "${SCRIPTS[@]}"; do
    echo "Starting $SCRIPT..."
    python3 $SCRIPT &  # 后台运行脚本
    PIDS+=($!)         # 保存进程的 PID
done

# 捕获终止信号 (Ctrl+C) 并终止所有子进程
trap "echo 'Terminating all scripts...'; for PID in \"\${PIDS[@]}\"; do kill \$PID 2>/dev/null; done; exit 0" SIGINT SIGTERM

# 保持脚本运行直到手动终止
echo "All scripts are running. Press Ctrl+C to stop."
while true; do
    sleep 1
done













