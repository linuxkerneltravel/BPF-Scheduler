#!/bin/bash

# Function to collect and calculate memory usage and cache hit ratio
collect_memory_info() {
    # Extract MemTotal, MemAvailable, and MemFree from /proc/meminfo
    mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    mem_available=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
    mem_free=$(awk '/MemFree/ {print $2}' /proc/meminfo)

    # Extract Cached from /proc/meminfo (for file system caching)
    cached=$(awk '/^Cached:/ {print $2}' /proc/meminfo)

    # Extract SwapTotal and SwapFree from /proc/meminfo
    swap_total=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
    swap_free=$(awk '/SwapFree/ {print $2}' /proc/meminfo)

    # Extract page faults and major page faults from /proc/vmstat
    page_faults=$(awk '/pgfault/ {print $2}' /proc/vmstat)
    major_page_faults=$(awk '/pgmajfault/ {print $2}' /proc/vmstat)

    # Calculate memory usage percentage
    mem_used=$((mem_total - mem_available))
    mem_usage_percent=$((mem_used * 100 / mem_total))

    # Calculate swap usage percentage
    swap_used=$((swap_total - swap_free))
    if [ $swap_total -gt 0 ]; then
        swap_usage_percent=$((swap_used * 100 / swap_total))
    else
        swap_usage_percent=0
    fi

    # Calculate cache hit ratio
    if [ $page_faults -gt 0 ]; then
        cache_hit_ratio=$(( (page_faults - major_page_faults) * 100 / page_faults ))
    else
        cache_hit_ratio=0
    fi

    # Output the collected data with percentages
    echo "Memory Information:"
    echo "-------------------"
    echo "Total Memory: ${mem_total} kB"
    echo "Available Memory: ${mem_available} kB"
    echo "Memory Usage: ${mem_used} kB (${mem_usage_percent}%)"
    echo "Cached Memory: ${cached} kB"
    echo "-------------------"
    echo "Total Swap: ${swap_total} kB"
    echo "Free Swap: ${swap_free} kB"
    echo "Swap Usage: ${swap_used} kB (${swap_usage_percent}%)"
    echo "-------------------"
    echo "Page Faults: ${page_faults}"
    echo "Major Page Faults: ${major_page_faults}"
    echo "Cache Hit Ratio: ${cache_hit_ratio}%"
    echo "-------------------"
}

# Main loop to collect data every 5 seconds
while true; do
    collect_memory_info
    sleep 5  # Sleep for 5 seconds before collecting data again
done

