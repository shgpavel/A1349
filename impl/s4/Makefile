# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2025 Pavel Shago
#
# Top-level Makefile for s4 (VCG auction scheduler).
# Mirrors the s3+ build system; delegates out-of-source build to ./build/.

C_SCHEDS := scx_auction

ifeq ("$(origin O)", "command line")
  KBUILD_OUTPUT := $(abspath $(O))
else
  KBUILD_OUTPUT := $(CURDIR)/build
endif

ifneq ($(KBUILD_OUTPUT), $(CURDIR))
ifeq ($(ROOT_SRC_DIR),)

PHONY += _all $(MAKECMDGOALS) sub-make

$(filter-out _all sub-make,$(MAKECMDGOALS)) _all: sub-make
	@:

sub-make:
	+@mkdir -p $(KBUILD_OUTPUT)
	@$(MAKE) --no-print-directory -C $(KBUILD_OUTPUT) -f $(CURDIR)/Makefile \
		ROOT_SRC_DIR=$(CURDIR) \
		LIB_OBJ_DIR=$(KBUILD_OUTPUT)/lib \
		SCHED_OBJ_DIR=$(KBUILD_OUTPUT)/scheds/c \
		$(MAKECMDGOALS)

.PHONY: $(PHONY)

skip-makefile := 1
endif
endif

ifeq ($(skip-makefile),)

export BPF_CLANG ?= clang
export BPFTOOL   ?= bpftool

TARGET_ARCH ?= x86
ARCH        ?= $(TARGET_ARCH)
ENDIAN      ?= $(shell printf '\1\0' | od -An -t x2 | awk '{print ($$1=="0001"?"little":"big")}')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf)

export BPF_CFLAGS := -g -O2 -Wall -Wno-compare-distinct-pointer-types \
	-D__TARGET_ARCH_$(TARGET_ARCH) -mcpu=v3 -m$(ENDIAN)-endian

export ROOT_SRC_DIR ?= $(CURDIR)
export BPF_INCLUDES := -I$(ROOT_SRC_DIR)/scheds/include \
	-I$(ROOT_SRC_DIR)/scheds/include/bpf-compat \
	-I$(ROOT_SRC_DIR)/scheds/include/lib \
	-I$(ROOT_SRC_DIR)/scheds/vmlinux \
	-I$(ROOT_SRC_DIR)/scheds/vmlinux/arch/$(TARGET_ARCH) \
	$(LIBBPF_CFLAGS)

export CFLAGS := -std=gnu11 \
	-I$(ROOT_SRC_DIR)/scheds/include \
	-I$(ROOT_SRC_DIR)/scheds/vmlinux \
	-I$(SCHED_OBJ_DIR) \
	$(LIBBPF_CFLAGS)

export LIBBPF_DEPS := $(LIBBPF_LIBS) -lelf -lz -lzstd
export THREAD_DEPS := -lpthread

export OBJ_DIR := $(CURDIR)
ifeq ($(SCHED_OBJ_DIR),)
  export SCHED_OBJ_DIR := $(ROOT_SRC_DIR)/scheds/c
endif

KVER          := $(shell uname -r)
VMLINUX_SRC   := /lib/modules/$(KVER)/build/vmlinux.h
VMLINUX_LINK  := $(ROOT_SRC_DIR)/scheds/vmlinux/vmlinux.h

all: vmlinux-link scheds-c

vmlinux-link:
	@ln -sfn $(VMLINUX_SRC) $(VMLINUX_LINK)

$(C_SCHEDS):
	@mkdir -p $(SCHED_OBJ_DIR)
	@$(MAKE) -C $(ROOT_SRC_DIR)/scheds/c SRC_DIR=$(ROOT_SRC_DIR)/scheds/c $@

$(SCHED_OBJ_DIR):
	@mkdir -p $@

scheds-c:
	@mkdir -p $(SCHED_OBJ_DIR)
	@$(MAKE) -C $(ROOT_SRC_DIR)/scheds/c SRC_DIR=$(ROOT_SRC_DIR)/scheds/c

clean:
	$(MAKE) -C $(ROOT_SRC_DIR)/scheds/c clean

install: all
	$(MAKE) -C $(ROOT_SRC_DIR)/scheds/c install

.PHONY: all vmlinux-link scheds-c clean install $(C_SCHEDS)

endif
