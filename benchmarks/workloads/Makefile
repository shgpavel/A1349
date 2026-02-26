# benchmarks/workloads - fairness test harness

CC      ?= gcc
CFLAGS  := -std=gnu11 -O2 -Wall
OBJ_DIR ?= $(CURDIR)/build

TARGETS := fairness_harness
ALL     := $(addprefix $(OBJ_DIR)/,$(TARGETS))

all: $(ALL)

$(OBJ_DIR):
	@mkdir -p $@

$(OBJ_DIR)/%: %.c | $(OBJ_DIR)
	@echo "  CC      $@"
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJ_DIR)

.PHONY: all clean
