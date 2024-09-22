#!/bin/bash

# Function to collect CPU statistics for all cores and the system
collect_cpu_info() {
    # Extract current CPU statistics from /proc/stat for total CPU
    total_cpu_data=($(awk '/^cpu / {print $2, $3, $4, $5, $6, $7, $8, $9, $10, $11}' /proc/stat))

    # Extract CPU core data for each core
    for ((i=0; i<=cpu_cores; i++)); do
        cpu_core_data[$i]=$(awk -v core="cpu$i" '$1 == core {print $2, $3, $4, $5, $6, $7, $8, $9, $10, $11}' /proc/stat)
    done

    # Extract system load averages from /proc/loadavg
    loadavg=($(cat /proc/loadavg))
    loadavg_1min=${loadavg[0]}
    loadavg_5min=${loadavg[1]}
    loadavg_15min=${loadavg[2]}
    running_processes=$(echo ${loadavg[3]} | cut -d'/' -f1)
    total_processes=$(echo ${loadavg[3]} | cut -d'/' -f2)

    # Extract context switches and interrupts from /proc/stat
    ctxt=$(awk '/^ctxt/ {print $2}' /proc/stat)
    intr=$(awk '/^intr/ {print $2}' /proc/stat)

    # Get system uptime from /proc/uptime (first value)
    uptime=$(awk '{print $1}' /proc/uptime)
}

# Function to calculate CPU usage percentage for total and each core
calculate_usage() {
    # Calculate the differences between current and previous total CPU data
    prev_total_cpu_data=(${previous_total_cpu_data[@]})

    total_user_diff=$(( ${total_cpu_data[0]:-0} - ${prev_total_cpu_data[0]:-0} ))
    total_nice_diff=$(( ${total_cpu_data[1]:-0} - ${prev_total_cpu_data[1]:-0} ))
    total_system_diff=$(( ${total_cpu_data[2]:-0} - ${prev_total_cpu_data[2]:-0} ))
    total_idle_diff=$(( ${total_cpu_data[3]:-0} - ${prev_total_cpu_data[3]:-0} ))
    total_iowait_diff=$(( ${total_cpu_data[4]:-0} - ${prev_total_cpu_data[4]:-0} ))
    total_irq_diff=$(( ${total_cpu_data[5]:-0} - ${prev_total_cpu_data[5]:-0} ))
    total_softirq_diff=$(( ${total_cpu_data[6]:-0} - ${prev_total_cpu_data[6]:-0} ))
    total_steal_diff=$(( ${total_cpu_data[7]:-0} - ${prev_total_cpu_data[7]:-0} ))
    total_guest_diff=$(( ${total_cpu_data[8]:-0} - ${prev_total_cpu_data[8]:-0} ))
    total_guest_nice_diff=$(( ${total_cpu_data[9]:-0} - ${prev_total_cpu_data[9]:-0} ))

    total_time_diff=$(( total_user_diff + total_nice_diff + total_system_diff + total_idle_diff + total_iowait_diff + total_irq_diff + total_softirq_diff + total_steal_diff + total_guest_diff + total_guest_nice_diff ))
    total_idle_time_diff=$(( total_idle_diff + total_iowait_diff ))

    if [ $total_time_diff -gt 0 ]; then
        total_cpu_usage=$(( 100 * (total_time_diff - total_idle_time_diff) / total_time_diff ))
        total_user_cpu_usage=$(( 100 * (total_user_diff + total_nice_diff) / total_time_diff ))
        total_system_cpu_usage=$(( 100 * total_system_diff / total_time_diff ))
        total_iowait_cpu_usage=$(( 100 * total_iowait_diff / total_time_diff ))
        total_irq_cpu_usage=$(( 100 * total_irq_diff / total_time_diff ))
        total_softirq_cpu_usage=$(( 100 * total_softirq_diff / total_time_diff ))
    else
        total_cpu_usage=0
        total_user_cpu_usage=0
        total_system_cpu_usage=0
        total_iowait_cpu_usage=0
        total_irq_cpu_usage=0
        total_softirq_cpu_usage=0
    fi

    # Calculate the differences between current and previous CPU core data
    for ((i=0; i<=cpu_cores; i++)); do
        core_data=(${cpu_core_data[$i]})
        prev_core_data=(${previous_cpu_data[$i]})

        # Initialize all variables to avoid empty values
        core_user_diff=$(( ${core_data[0]:-0} - ${prev_core_data[0]:-0} ))
        core_nice_diff=$(( ${core_data[1]:-0} - ${prev_core_data[1]:-0} ))
        core_system_diff=$(( ${core_data[2]:-0} - ${prev_core_data[2]:-0} ))
        core_idle_diff=$(( ${core_data[3]:-0} - ${prev_core_data[3]:-0} ))
        core_iowait_diff=$(( ${core_data[4]:-0} - ${prev_core_data[4]:-0} ))
        core_irq_diff=$(( ${core_data[5]:-0} - ${prev_core_data[5]:-0} ))
        core_softirq_diff=$(( ${core_data[6]:-0} - ${prev_core_data[6]:-0} ))
        core_steal_diff=$(( ${core_data[7]:-0} - ${prev_core_data[7]:-0} ))
        core_guest_diff=$(( ${core_data[8]:-0} - ${prev_core_data[8]:-0} ))
        core_guest_nice_diff=$(( ${core_data[9]:-0} - ${prev_core_data[9]:-0} ))

        core_total_diff=$(( core_user_diff + core_nice_diff + core_system_diff + core_idle_diff + core_iowait_diff + core_irq_diff + core_softirq_diff + core_steal_diff + core_guest_diff + core_guest_nice_diff ))
        core_idle_total_diff=$(( core_idle_diff + core_iowait_diff ))

        if [ $core_total_diff -gt 0 ]; then
            core_usage[$i]=$(( 100 * (core_total_diff - core_idle_total_diff) / core_total_diff ))
            core_user_usage[$i]=$(( 100 * (core_user_diff + core_nice_diff) / core_total_diff ))
            core_system_usage[$i]=$(( 100 * core_system_diff / core_total_diff ))
            core_iowait_usage[$i]=$(( 100 * core_iowait_diff / core_total_diff ))
            core_irq_usage[$i]=$(( 100 * core_irq_diff / core_total_diff ))
            core_softirq_usage[$i]=$(( 100 * core_softirq_diff / core_total_diff ))
        else
            core_usage[$i]=0
            core_user_usage[$i]=0
            core_system_usage[$i]=0
            core_iowait_usage[$i]=0
            core_irq_usage[$i]=0
            core_softirq_usage[$i]=0
        fi
    done
}

# Function to display all CPU metrics
display_info() {
    echo "---------------------------------------------"
    echo "System Load Averages (1min, 5min, 15min): ${loadavg_1min}, ${loadavg_5min}, ${loadavg_15min}"
    echo "Running/Total Processes: ${running_processes}/${total_processes}"
    echo "Context Switches: ${ctxt}"
    echo "Interrupts: ${intr}"
    echo "System Uptime: ${uptime} seconds"
    echo "---------------------------------------------"

    # Display total CPU usage
    echo "Total CPU Usage: ${total_cpu_usage}%"
    echo "  - User CPU Usage: ${total_user_cpu_usage}%"
    echo "  - System CPU Usage: ${total_system_cpu_usage}%"
    echo "  - I/O Wait Usage: ${total_iowait_cpu_usage}%"
    echo "  - IRQ Usage: ${total_irq_cpu_usage}%"
    echo "  - SoftIRQ Usage: ${total_softirq_cpu_usage}%"
    echo "---------------------------------------------"

    # Display each core's detailed CPU usage
    for ((i=0; i<=cpu_cores; i++)); do
        echo "CPU${i} Usage: ${core_usage[$i]}%"
        echo "  - User CPU Usage: ${core_user_usage[$i]}%"
        echo "  - System CPU Usage: ${core_system_usage[$i]}%"
        echo "  - I/O Wait Usage: ${core_iowait_usage[$i]}%"
        echo "  - IRQ Usage: ${core_irq_usage[$i]}%"
        echo "  - SoftIRQ Usage: ${core_softirq_usage[$i]}%"
    done
    echo "---------------------------------------------"
}

# Infinite loop to collect and display information every 5 seconds
cpu_cores=$(grep -c '^cpu[0-9]' /proc/stat)  # Get the number of CPU cores
declare -a previous_total_cpu_data
declare -a total_cpu_data
declare -a previous_cpu_data
declare -a cpu_core_data
declare -a core_usage
declare -a core_user_usage
declare -a core_system_usage
declare -a core_iowait_usage
declare -a core_irq_usage
declare -a core_softirq_usage

# Initial collection of CPU data
collect_cpu_info
previous_total_cpu_data=("${total_cpu_data[@]}")
previous_cpu_data=("${cpu_core_data[@]}")

# Loop to calculate and display CPU usage every 5 seconds
while true; do
    sleep 5

    # Collect new CPU data
    collect_cpu_info

    # Calculate CPU usage
    calculate_usage

    # Display all collected metrics
    display_info

    # Save current data as previous for next iteration
    previous_total_cpu_data=("${total_cpu_data[@]}")
    previous_cpu_data=("${cpu_core_data[@]}")
done
