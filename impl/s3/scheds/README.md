SCHED_EXT SCHEDULERS
====================

# Introduction

This directory contains the repo's schedulers.

Some of these schedulers are simply examples of different types of schedulers
that can be built using `sched_ext`. They can be loaded and used to schedule on
your system, but their primary purpose is to illustrate how various features of
`sched_ext` can be used.

Other schedulers are actually performant, production-ready schedulers. That is,
for the correct workload and with the correct tuning, they may be deployed in a
production environment with acceptable or possibly even improved performance.
Some of the examples could be improved to become production schedulers.

This baseline tree contains the schedulers implemented in this repository:

- `c/scx_eevdf.c` and `c/scx_eevdf.bpf.c` implement the baseline EEVDF
  scheduler.

There are no Rust schedulers or per-language README files in this tree.

## Note on syncing

Note that there is a [`sync-to-kernel.sh`](sync-to-kernel.sh) script in this
directory. This is used to sync scheduler changes with the Linux kernel tree.
If you've made changes to a scheduler here, use the script to synchronize with
the `sched_ext` Linux kernel tree:

```shell
$ ./sync-to-kernel.sh /path/to/kernel/tree
```
