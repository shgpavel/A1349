/* SPDX-License-Identifier: GPL-2.0
 *
 * Definitions shared between scx_A1349.bpf.c and the scx_A1349 loader.
 * Anything both sides must agree on (map value layouts, table sizes,
 * fixed-point scales, stat slots) lives here so the two cannot drift.
 */
#ifndef __SCX_A1349_H
#define __SCX_A1349_H

/*
 * Contract length cap (theory §2.4: L upper-bounds l_i).  Size of the δ^m
 * lookup table populated by userspace.  m ∈ [0, MAX_CONTRACT_LENGTH−1].
 */
#define MAX_CONTRACT_LENGTH 32u

/* Fixed-point scale for δ^m and \bar W_κ: delta_table[m] = round(δ^m · DELTA_SCALE). */
#define DELTA_SHIFT         20
#define DELTA_SCALE         (1ULL << DELTA_SHIFT)

/* Default per-quantum P-core cost c_P. */
#define COST_P_DEF          1024u

#define SLICE_P_US_DEF          20000u
#define SLICE_E_PCT_DEF         150u
#define BUDGET_MUL_DEF          16u
#define REPLENISH_DIV_DEF       6000000u
#define STARVE_FLOOR_PCT_DEF    10u
#define STARVED_WAIT_SLICES_DEF 5u
#define CLUSTER_WAIT_SLICES_DEF 25u
#define W_BAR_EWMA_DEN_DEF      16u

enum idle_pick_mode {
	IDLE_PICK_PSCAN,
	IDLE_PICK_CORE,
};

/*
 * Userspace-owned configuration (RO from BPF).  Refreshed periodically by
 * the loader.  No estimator state lives here.
 */
struct auction_ctx {
	__u32 max_capacity;          /* η_P (max cpu_capacity)  */
	__u32 min_capacity;          /* η_E (min cpu_capacity)  */
	__u32 cost_p;                /* c_P                     */
	__u32 cost_e;                /* c_E                     */
	__u32 p_core_count;          /* K_P                     */
	__u32 e_core_count;          /* K_E                     */
};

/* Per-CPU event counters (stats map), summed by the loader. */
enum auction_stat {
	STAT_ENQ_P,          /* enqueued on AUCTION_DSQ_P               */
	STAT_ENQ_E,          /* enqueued on AUCTION_DSQ_E               */
	STAT_ENQ_STARVED,    /* budget floor hit at enqueue             */
	STAT_SPILL,          /* P→E spill                               */
	STAT_PIN,            /* wake-up pinned to idle prev_cpu         */
	STAT_DIRECT_IDLE,    /* select_cpu direct dispatch to idle CPU  */
	STAT_AUCTION_WIN,    /* auction winner dispatched               */
	STAT_EXILE,          /* auction winner could not pay → STARVED  */
	STAT_KEEP_PREV,      /* incumbent won against the queue head    */
	STAT_STEAL,          /* cross-cluster steal                     */
	STAT_STARVED_AGED,   /* STARVED head served by the age bound    */
	STAT_STARVED_IDLE,   /* STARVED served because clusters empty   */
	STAT_DEMOTE,         /* cluster DSQ wait bound hit → STARVED    */
	STAT_NO_CTX,         /* enqueue without task ctx → global DSQ   */
	STAT_NR,
};

#endif /* __SCX_A1349_H */
