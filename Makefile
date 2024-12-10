## Copyright 2023 The LMP Authors.
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
## https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##
## author: zhangziheng0525@163.com
##
## compile the current folder code
#
## SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#OUTPUT := .output
#CLANG ?= clang
#LIBBPF_SRC := $(abspath ../libbpf/src)
#BPFTOOL_SRC := $(abspath ../bpftool/src)
#LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
#BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
#BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
#LIBBLAZESYM_SRC := $(abspath ../blazesym/)
#LIBBLAZESYM_INC := $(abspath $(LIBBLAZESYM_SRC)/include)
#LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym.a)
#ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
#			 | sed 's/arm.*/arm/' \
#			 | sed 's/aarch64/arm64/' \
#			 | sed 's/ppc64le/powerpc/' \
#			 | sed 's/mips.*/mips/' \
#			 | sed 's/riscv64/riscv/' \
#			 | sed 's/loongarch64/loongarch/')
#VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h
## Use our own libbpf API headers and Linux UAPI headers distributed with
## libbpf to avoid dependency on system-wide headers, which could be missing or
## outdated
#INCLUDES := -I$(OUTPUT) -I../../../libbpf/include/uapi -I$(dir $(VMLINUX)) -I$(LIBBLAZESYM_INC) -I./include
#CFLAGS := -g -Wall
#ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
#
#APPS =cpu_stats
#TARGETS=sys_spy
#CONTROLLER := cpu_controller
#
#SRC_DIR = ./include
#
## Get Clang's default includes on this system. We'll explicitly add these dirs
## to the includes list when compiling with `-target bpf` because otherwise some
## architecture-specific dirs will be "missing" on some architectures/distros -
## headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
## sys/cdefs.h etc. might be missing.
##
## Use '-idirafter': Don't interfere with include mechanics except where the
## build would have failed anyways.
#CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
#	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
#
#ifeq ($(V),1)
#	Q =
#	msg =
#else
#	Q = @
#	msg = @printf '  %-8s %s%s\n'					\
#		      "$(1)"						\
#		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
#		      "$(if $(3), $(3))";
#	MAKEFLAGS += --no-print-directory
#endif
#
#define allow-override
#  $(if $(or $(findstring environment,$(origin $(1))),\
#            $(findstring command line,$(origin $(1)))),,\
#    $(eval $(1) = $(2)))
#endef
#
#$(call allow-override,CC,$(CROSS_COMPILE)cc)
#$(call allow-override,LD,$(CROSS_COMPILE)ld)
#
#.PHONY: all
#all: $(CONTROLLER) $(TARGETS)
#
#.PHONY: clean
#clean:
#	$(call msg,CLEAN)
#	$(Q)rm -rf $(OUTPUT) $(TARGETS) $(CONTROLLER)
#
#$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
#	$(call msg,MKDIR,$@)
#	$(Q)mkdir -p $@
#
## Build libbpf
#$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
#	$(call msg,LIB,$@)
#	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
#		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
#		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
#		    install
#
## Build bpftool
#$(BPFTOOL): | $(BPFTOOL_OUTPUT)
#	$(call msg,BPFTOOL,$@)
#	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap
#
#
#$(LIBBLAZESYM_SRC)/target/release/libblazesym.a::
#	$(Q)cd $(LIBBLAZESYM_SRC) && $(CARGO) build --release
#
#$(LIBBLAZESYM_OBJ): $(LIBBLAZESYM_SRC)/target/release/libblazesym.a | $(OUTPUT)
#	$(call msg,LIB, $@)
#	$(Q)cp $(LIBBLAZESYM_SRC)/target/release/libblazesym.a $@
#
## Build BPF code
#$(OUTPUT)/%.bpf.o: bpf/%.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
#	$(call msg,BPF,$@)
#	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
#		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
#		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
#	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
#
## Generate BPF skeletons
#.PHONY: $(APPS)
#$(APPS): %: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
#	$(call msg,GEN-SKEL,$@)
#	$(Q)$(BPFTOOL) gen skeleton $< > $(OUTPUT)/$@.skel.h
#
## Build user-space code
#$(OUTPUT)/%.o: $(SRC_DIR)/%.c | $(OUTPUT)
#	$(call msg,CC,$@)
#	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@
#
#$(OUTPUT)/%.o: $(CONTROLLER).c | $(OUTPUT)
#	$(call msg,CC,$@)
#	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@
#
#$(OUTPUT)/$(TARGETS).o: $(TARGETS).c $(APPS) | $(OUTPUT)
#	$(call msg,CC,$@)
#	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@
#
## Build application binary
#$(CONTROLLER): %: $(OUTPUT)/%.o $(COMMON_OBJ) $(LIBBPF_OBJ) | $(OUTPUT)
#	$(call msg,BINARY,$@)
#	$(Q)$(CC) $^ $(ALL_LDFLAGS) -lstdc++ -lelf -lz -o $@
#
#$(TARGETS): %: $(OUTPUT)/%.o $(COMMON_OBJ) $(LIBBPF_OBJ) | $(OUTPUT)
#	$(call msg,BINARY,$@)
#	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lstdc++ -lelf -lz -o $@
#
#SUCCESS_MESSAGE:
#	@echo "\e[38;2;255;0;0m                                      __       __             \e[0m"
#	@echo "\e[38;2;255;128;0m  _________  __  __   _      ______ _/ /______/ /_  ___  _____\e[0m"
#	@echo "\e[38;2;255;255;0m / ___/ __ \/ / / /  | | /| / / __  / __/ ___/ __ \/ _ \/ ___/\e[0m"
#	@echo "\e[38;2;128;255;0m/ /__/ /_/ / /_/ /   | |/ |/ / /_/ / /_/ /__/ / / /  __/ /    \e[0m"
#	@echo "\e[38;2;0;255;0m\___/ .___/\__,_/    |__/|__/\__,_/\__/\___/_/ /_/\___/_/     \e[0m"
#	@echo "\e[38;2;0;255;128m   /_/                                                       \e[0m"
#	@echo "\e[38;2;0;255;255mSuccessful to compile cpu_watcher tools:                      \e[0m"
#	@echo "\e[38;2;0;255;255mPlease start your use ~                                      \e[0m"
#
#
#all: $(TARGETS) SUCCESS_MESSAGE
#
#
## delete failed targets
#.DELETE_ON_ERROR:
#
## keep intermediate (.skel.h, .bpf.o, etc) targets
#.SECONDARY:
#
#.PHONY: generate_cmake
#generate_cmake:
#	@echo "cmake_minimum_required(VERSION 3.10)" > CMakeLists.txt
#	@echo "project(cpu_watcher VERSION 1.0)" >> CMakeLists.txt
#	@echo "set(CMAKE_C_STANDARD 11)" >> CMakeLists.txt
#	@echo "set(CMAKE_C_FLAGS \"$(CFLAGS)\")" >> CMakeLists.txt
#	@echo "" >> CMakeLists.txt
#
#	# 包含目录
#	@echo "include_directories(" >> CMakeLists.txt
#	@for dir in $(INCLUDES); do \
#		echo "    $$dir" >> CMakeLists.txt; \
#	done
#	@echo ")" >> CMakeLists.txt
#	@echo "" >> CMakeLists.txt
#
#	# 源文件
#	@echo "set(SOURCE_FILES" >> CMakeLists.txt
#	@for src in $(wildcard *.c src/*.c); do \
#		echo "    $$src" >> CMakeLists.txt; \
#	done
#	@echo ")" >> CMakeLists.txt
#	@echo "" >> CMakeLists.txt
#
#	# 可执行文件和链接库
#	@echo "add_executable(cpu_watcher \$$\{SOURCE_FILES\})" >> CMakeLists.txt
#	@echo "target_link_libraries(cpu_watcher ${LIBS} -lelf -lz -lstdc++)" >> CMakeLists.txt
#	@echo "CMakeLists.txt generated successfully."


OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBLAZESYM_SRC := $(abspath ../blazesym/)
LIBBLAZESYM_INC := $(abspath $(LIBBLAZESYM_SRC)/include)
LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym_c.a)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h

INCLUDES := -I$(OUTPUT) -I../../../libbpf/include/uapi -I$(dir $(VMLINUX)) -I$(LIBBLAZESYM_INC) -I./include
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = cpu_stats mm_stats mm_leak io_stats net_stats
TARGETS = net_spy
CONTROLLER := cpu_controller

SRC_DIR = ./include

CARGO := cargo

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(CONTROLLER) $(TARGETS) SUCCESS_MESSAGE

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(TARGETS) $(CONTROLLER)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build libblazesym
$(LIBBLAZESYM_SRC)/target/release/libblazesym_c.a::
	$(Q)echo "Building blazesym in $(LIBBLAZESYM_SRC)"
	$(Q)cd $(LIBBLAZESYM_SRC) && $(CARGO) build --release

$(LIBBLAZESYM_OBJ): $(LIBBLAZESYM_SRC)/target/release/libblazesym_c.a | $(OUTPUT)
	$(call msg,LIB, $@)
	$(Q)cp $(LIBBLAZESYM_SRC)/target/release/libblazesym_c.a $@

# Build BPF code
$(OUTPUT)/%.bpf.o: bpf/%.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# $(OUTPUT)/%.bpf.o: bpf/%.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
# 	$(call msg,BPF,$@)
# 	$(Q)$(CLANG) -g -O1 -target bpf -D__TARGET_ARCH_$(ARCH) \
# 		         $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
# 		         -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
# 	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)



# Generate BPF skeletons
.PHONY: $(APPS)
$(APPS): %: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $(OUTPUT)/$@.skel.h

# Build user-space code
$(OUTPUT)/%.o: $(SRC_DIR)/%.c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/%.o: $(CONTROLLER).c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/$(TARGETS).o: $(TARGETS).c $(APPS) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(CONTROLLER): %: $(OUTPUT)/%.o $(COMMON_OBJ) $(LIBBPF_OBJ) $(LIBBLAZESYM_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $^ $(ALL_LDFLGS) -lstdc++ -lelf -lz -o $@

$(TARGETS): %: $(OUTPUT)/%.o $(COMMON_OBJ) $(LIBBPF_OBJ) $(LIBBLAZESYM_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lstdc++ -lelf -lz -o $@

SUCCESS_MESSAGE:
	@echo "\033[38;2;255;255;0m   ______                __    _           __  ___                \033[0m"
	@echo "\033[38;2;255;128;0m  / ____/______  _______/ /_  (_)____     /  |/  /_  ______ _____ \033[0m"
	@echo "\033[38;2;255;255;0m / /   / ___/ / / / ___/ __ \/ / ___/    / /|_/ / / / / __  / __ \ \033[0m"
	@echo "\033[38;2;128;255;0m/ /___/ /  / /_/ / /__/ / / / / /__     / /  / / /_/ / /_/ / /_/ / \033[0m"
	@echo "\033[38;2;0;255;0m\____/_/   \__, /\___/_/ /_/_/\___/____/_/  /_/\__, /\__, /\____/ \033[0m"
	@echo "\033[38;2;0;255;128m          /____/                 /_____/      /____//____/      \033[0m"
	@echo "\033[38;2;0;255;255mSuccessful to compile cpu_watcher tools:                      \033[0m"
	@echo "\033[38;2;0;255;255mPlease start your use ~                                      \033[0m"

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

.PHONY: generate_cmake
generate_cmake:
	@echo "cmake_minimum_required(VERSION 3.10)" > CMakeLists.txt
	@echo "project(cpu_watcher VERSION 1.0)" >> CMakeLists.txt
	@echo "set(CMAKE_C_STANDARD 11)" >> CMakeLists.txt
	@echo "set(CMAKE_C_FLAGS \"$(CFLAGS)\")" >> CMakeLists.txt
	@echo "" >> CMakeLists.txt

	# 包含目录
	@echo "include_directories(" >> CMakeLists.txt
	@for dir in $(INCLUDES); do \
		echo "    $$dir" >> CMakeLists.txt; \
	done
	@echo ")" >> CMakeLists.txt
	@echo "" >> CMakeLists.txt

	# 源文件
	@echo "set(SOURCE_FILES" >> CMakeLists.txt
	@for src in $(wildcard *.c src/*.c); do \
		echo "    $$src" >> CMakeLists.txt; \
	done
	@echo ")" >> CMakeLists.txt
	@echo "" >> CMakeLists.txt

	# 可执行文件和链接库
	@echo "add_executable(cpu_watcher \$$\{SOURCE_FILES\})" >> CMakeLists.txt
#	@echo "target_link_libraries(cpu_watcher ${LIBS} -lelf -lz -lstdc++)" >> CMakeLists.txt
	@echo "target_link_libraries(cpu_watcher ${LIBS} -lelf -lz -lstdc++ -L$(LIBBLAZESYM_SRC)/target/release -lblazesym_c)" >> CMakeLists.txt
	@echo "CMakeLists.txt generated successfully."
