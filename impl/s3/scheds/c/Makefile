# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
# Copyright (c) 2025 Pavel Shago

# Handle out-of-source builds
SRC_DIR ?= $(CURDIR)
ifneq ($(SCHED_OBJ_DIR),)
  OBJ_DIR := $(SCHED_OBJ_DIR)
else
  OBJ_DIR := $(CURDIR)
endif

C_SCHEDS := scx_eevdf

ALL_SCHEDS := $(addprefix $(OBJ_DIR)/,$(C_SCHEDS))

INSTALL_DIR ?= /usr/local/bin

all: $(ALL_SCHEDS)

# Convenience targets for individual schedulers (old names without path)
$(C_SCHEDS): %: $(OBJ_DIR)/% ;

# Disable built-in implicit rule for C compilation to prevent conflicts
%: %.c

# Build regular schedulers (no library dependency) - from source to output dir
$(addprefix $(OBJ_DIR)/,$(C_SCHEDS)): $(OBJ_DIR)/%: $(SRC_DIR)/%.c $(OBJ_DIR)/%.bpf.skel.h
	@echo "Building scheduler: $@"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -o $@ $(LIBBPF_DEPS) $(THREAD_DEPS)

$(OBJ_DIR)/%.bpf.skel.h: $(OBJ_DIR)/%.bpf.o
	@echo "Generating skeleton: $@"
	@mkdir -p $(dir $@)
	$(BPFTOOL) gen skeleton $< name $(basename $(basename $(notdir $<))) > $@

$(OBJ_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c
	@echo "Compiling BPF: $< -> $@"
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -target bpf $(BPF_INCLUDES) -c $< -o $@

install: $(ALL_SCHEDS)
	@echo "Installing schedulers to $(INSTALL_DIR)"
	@mkdir -p $(INSTALL_DIR)
	@for sched in $(ALL_SCHEDS); do \
		echo "Installing $$sched"; \
		cp $$sched $(INSTALL_DIR)/; \
	done

clean:
	rm -f $(OBJ_DIR)/*.bpf.o $(OBJ_DIR)/*.bpf.skel.h $(ALL_SCHEDS)

.PHONY: all install clean
