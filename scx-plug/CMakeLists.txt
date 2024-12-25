# cmake_minimum_required(VERSION 3.10)
# project(cpu_watcher VERSION 1.0)
# set(CMAKE_C_STANDARD 11)
# set(CMAKE_C_FLAGS "-g -Wall")

# include_directories(
#     -I.output
#     -I../../../libbpf/include/uapi
#     -I../vmlinux/x86/
#     -I/home/ne0/sys_competition/start/blazesym/include
#     -I./include
# )

# set(SOURCE_FILES
#     controller.c
#     cpu_watcher.c
# )

# add_executable(cpu_watcher $\{SOURCE_FILES\})
# target_link_libraries(cpu_watcher  -lelf -lz -lstdc++)
cmake_minimum_required(VERSION 3.10)
project(cpu_watcher VERSION 1.0)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-g -Wall")

# 使用 target_include_directories 而不是 include_directories
include_directories(
    ${CMAKE_SOURCE_DIR}/.output
    ${CMAKE_SOURCE_DIR}/../../../libbpf/include/uapi
    ${CMAKE_SOURCE_DIR}/../vmlinux/x86/
    ${CMAKE_SOURCE_DIR}/home/ne0/sys_competition/start/blazesym/include
    ${CMAKE_SOURCE_DIR}/./include
)

set(SOURCE_FILES
    sys_spy.c
)

# 添加目标文件
add_executable(cpu_watcher ${SOURCE_FILES})

# 确保链接所需的库，且包含 libblazesym 的路径
target_link_libraries(cpu_watcher
    -lelf
    -lz
    -lstdc++
    ${CMAKE_SOURCE_DIR}/../blazesym/target/release/libblazesym.a
)