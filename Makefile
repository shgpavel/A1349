# SPDX-License-Identifier: GPL-2.0

IMPL_DIRS := impl/s3 impl/s3+
BENCHMARK_DIR := benchmarks
PYTHON ?= python3
BENCH_DURATION ?= 60
BENCH_INTERVAL ?= 1
BENCH_RESULTS_DIR ?= results
BENCH_PLOTS_DIR ?= plots

all: $(IMPL_DIRS)

clean: $(addsuffix -clean,$(IMPL_DIRS)) benchmarks-clean

install: $(addsuffix -install,$(IMPL_DIRS))

benchmarks-build: all
	$(MAKE) -C $(BENCHMARK_DIR) all

benchmarks: benchmarks-build
	$(MAKE) benchmarks-run

benchmarks-run:
	$(PYTHON) $(BENCHMARK_DIR)/run_suite.py \
		--duration $(BENCH_DURATION) \
		--interval $(BENCH_INTERVAL) \
		--results-root $(BENCH_RESULTS_DIR) \
		--plots-root $(BENCH_PLOTS_DIR)

benchmarks-clean:
	$(MAKE) -C $(BENCHMARK_DIR) clean

$(IMPL_DIRS):
	$(MAKE) -C $@ all

$(addsuffix -clean,$(IMPL_DIRS)):
	$(MAKE) -C $(patsubst %-clean,%,$@) clean

$(addsuffix -install,$(IMPL_DIRS)):
	$(MAKE) -C $(patsubst %-install,%,$@) install

.PHONY: all clean install benchmarks benchmarks-build benchmarks-run benchmarks-clean $(IMPL_DIRS) $(addsuffix -clean,$(IMPL_DIRS)) $(addsuffix -install,$(IMPL_DIRS))
