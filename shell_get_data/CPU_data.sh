#!/bin/bash

# 获取当前时间戳
# date 命令用于获取当前日期和时间，+ 后面的部分定义了时间的格式
# $(...): 将命令的输出结果赋值给变量 TIMESTAMP
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

# 提取 CPU 总体使用信息
# awk '/^cpu / {...}': 这个 awk 命令用于匹配以 cpu 开头的行（注意空格），并输出各项统计数据
# {print "User:", $2, ...}: 打印 CPU 的各个状态的值，如用户态时间 (User)、优先级较低的用户态时间 (Nice)、
# 系统态时间 (System)、空闲时间 (Idle)、等待 I/O 时间 (IOWait)、硬中断时间 (IRQ)、软中断时间 (SoftIRQ)
# /proc/stat: 该文件包含关于 CPU 使用的统计信息
CPU_STAT=$(awk '/^cpu / {print "User:", $2, "Nice:", $3, "System:", $4, "Idle:", $5, "IOWait:", $6, "IRQ:", $7, "SoftIRQ:", $8}' /proc/stat)

# 提取每个 CPU 核的使用信息
# /^cpu[0-9]+ /: 匹配每个 CPU 核心的信息行
# {print "CPU"$1, ...}: 打印每个 CPU 核心的编号及其各项使用状态的值
CPU_CORES_STAT=$(awk '/^cpu[0-9]+ / {print "CPU"$1, "User:", $2, "Nice:", $3, "System:", $4, "Idle:", $5, "IOWait:", $6, "IRQ:", $7, "SoftIRQ:", $8}' /proc/stat)

# 输出到命令行
echo "$TIMESTAMP - Overall CPU: $CPU_STAT"
echo "$TIMESTAMP - Per Core CPU Usage:"
echo "$CPU_CORES_STAT"
echo "------------------------------------------------------"
