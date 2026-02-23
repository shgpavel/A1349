#pragma once
#include <stdint.h>

#define SCX_VCG_MAX_CPUS   64
#define SCX_VCG_MAX_TASKS  1024

// HZ=1000 => tick = 1ms
#define SCX_VCG_K          20   // окно T=20ms по умолчанию (можно менять из userspace)
#define SCX_VCG_R_MS       2    // rolling horizon каждые 2ms

// Типы "классов" (для MVP: от marks/hints или дефолт)
enum vcg_class {
    VCG_CLASS_DEFAULT = 0,
    VCG_CLASS_LAT     = 1,
    VCG_CLASS_BATCH   = 2,
};

// Параметры задачи (в тиках)
struct task_params {
    uint32_t pid;

    uint32_t v;        // value
    uint32_t lambda;   // lateness penalty per tick
    uint16_t L;        // block length in ticks
    uint16_t D;        // soft deadline in ticks (within window)
    uint16_t r;        // release tick (within current planning epoch), MVP: 0

    uint8_t  cls;      // vcg_class
    uint8_t  _pad[3];
};

// План: на каждый cpu массив pid на тиках [0..K-1]
struct plan {
    uint32_t epoch;
    uint16_t K;
    uint16_t _pad;

    // dense representation for MVP
    uint32_t slot[SCX_VCG_MAX_CPUS][SCX_VCG_K];
};

// per-cpu quality (alpha scaled by 1024)
struct cpu_q {
    uint32_t alpha_q10; // alpha * 1024
};

