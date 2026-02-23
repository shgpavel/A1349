# sched_latency perf tool - standalone build
#
# Usage:
#   make                    (builds in ./build/)
#   make O=/tmp/out         (out-of-source build)
#   sudo ./build/sched_latency [-d 10] [-i 1] [-p PID] [-c]

SRC_DIR  ?= $(CURDIR)
OBJ_DIR  ?= $(CURDIR)/build

BPF_CLANG  ?= clang
BPFTOOL    ?= bpftool
CC         ?= gcc

TARGET_ARCH := x86
ENDIAN      ?= $(shell printf '\1\0' | od -An -t x2 | awk '{print ($$1=="0001"?"little":"big")}')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf)

SCHED_INC := $(SRC_DIR)/../impl/s3/scheds

BPF_CFLAGS := -g -O2 -Wall -Wno-compare-distinct-pointer-types \
	-D__TARGET_ARCH_$(TARGET_ARCH) -mcpu=v3 -m$(ENDIAN)-endian

BPF_INCLUDES := -I$(SCHED_INC)/include \
	-I$(SCHED_INC)/include/bpf-compat \
	-I$(SCHED_INC)/vmlinux \
	-I$(SCHED_INC)/vmlinux/arch/$(TARGET_ARCH) \
	$(LIBBPF_CFLAGS)

CFLAGS := -std=gnu11 -O2 -Wall \
	-I$(SCHED_INC)/include \
	-I$(SCHED_INC)/vmlinux \
	-I$(OBJ_DIR) \
	$(LIBBPF_CFLAGS)

LDFLAGS := $(LIBBPF_LIBS) -lelf -lz -lzstd

TOOLS := sched_latency

ALL := $(addprefix $(OBJ_DIR)/,$(TOOLS))

all: $(ALL)

$(OBJ_DIR):
	@mkdir -p $@

$(OBJ_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c | $(OBJ_DIR)
	@echo "  BPF     $<"
	$(BPF_CLANG) $(BPF_CFLAGS) -target bpf $(BPF_INCLUDES) -c $< -o $@

$(OBJ_DIR)/%.bpf.skel.h: $(OBJ_DIR)/%.bpf.o
	@echo "  SKEL    $@"
	$(BPFTOOL) gen skeleton $< name $(basename $(basename $(notdir $<))) > $@

$(OBJ_DIR)/%: $(SRC_DIR)/%.c $(OBJ_DIR)/%.bpf.skel.h
	@echo "  CC      $@"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR)

.PHONY: all clean
