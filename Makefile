# SPDX-License-Identifier: GPL-2.0

IMPL_DIRS := impl/s3 impl/s3+ impl/s4
BENCHMARK_DIR := benchmarks
PYTHON ?= python3
SCX_DIR ?= ../scx
SCX_CARGO ?= cargo
SCX_LAVD_BIN ?= $(abspath $(SCX_DIR)/target/release/scx_lavd)
BENCH_INTERVAL ?= 1
BENCH_RESULTS_DIR ?= results
BENCH_PLOTS_DIR ?= plots

all: $(IMPL_DIRS)

clean: $(addsuffix -clean,$(IMPL_DIRS)) benchmarks-clean

install: $(addsuffix -install,$(IMPL_DIRS))

benchmarks-build: all scx-lavd-build schbench-build
	$(MAKE) -C $(BENCHMARK_DIR) all

schbench-build:
	@# `git submodule status` prefixes uninitialized entries with '-'.
	@# Covers: never-initialized, partially-initialized, or externally deleted.
	@status=$$(git submodule status $(BENCHMARK_DIR)/third_party/schbench 2>/dev/null); \
	case "$$status" in \
		-*) git submodule update --init --recursive $(BENCHMARK_DIR)/third_party/schbench ;; \
	esac
	@if [ ! -f $(BENCHMARK_DIR)/third_party/schbench/Makefile ]; then \
		echo "schbench submodule missing Makefile even after init"; exit 1; \
	fi
	$(MAKE) -C $(BENCHMARK_DIR)/third_party/schbench

benchmarks: benchmarks-build
	$(MAKE) benchmarks-run

benchmarks-run:
	$(PYTHON) $(BENCHMARK_DIR)/run_suite.py \
		--interval $(BENCH_INTERVAL) \
		--lavd-bin $(SCX_LAVD_BIN) \
		--results-root $(BENCH_RESULTS_DIR) \
		--plots-root $(BENCH_PLOTS_DIR)

scx-lavd-build:
	$(SCX_CARGO) build --manifest-path $(SCX_DIR)/Cargo.toml --release -p scx_lavd

benchmarks-clean:
	$(MAKE) -C $(BENCHMARK_DIR) clean

$(IMPL_DIRS):
	$(MAKE) -C $@ all

$(addsuffix -clean,$(IMPL_DIRS)):
	$(MAKE) -C $(patsubst %-clean,%,$@) clean

$(addsuffix -install,$(IMPL_DIRS)):
	$(MAKE) -C $(patsubst %-install,%,$@) install

.PHONY: all clean install benchmarks benchmarks-build benchmarks-run benchmarks-clean scx-lavd-build schbench-build $(IMPL_DIRS) $(addsuffix -clean,$(IMPL_DIRS)) $(addsuffix -install,$(IMPL_DIRS))
