#pragma once

#include <stdint.h>
#include <stddef.h>
#include "esp_private/esp_clk.h"
#include "esp_cpu.h"

typedef enum {
    BENCH_PHASE1_MLKEM = 1,
    BENCH_PHASE2_MLKEM_DUAL = 2,
    BENCH_PHASE3_HQC = 3,
    BENCH_PHASE4_X25519_SEQ = 4,
    BENCH_PHASE5_HYBRID_DUAL = 5,
    BENCH_PHASE6_HQC_HYBRID = 6,
    BENCH_PHASE7_MLKEM_PARALLEL = 7,
    BENCH_PHASE8_HQC_PARALLEL = 8,
} bench_phase_t;

typedef enum {
    BENCH_METRIC_MEDIAN = 0,
    BENCH_METRIC_AVERAGE = 1,
} bench_metric_t;

typedef struct bench_config_s {
    bench_phase_t phase;
    uint16_t trials;   // number of timed trials
    bench_metric_t metric;
} bench_config_t;

// Cycle counter helpers shared across benches
static inline uint32_t bench_cycles_now(void)
{
    return esp_cpu_get_cycle_count();
}

static inline float bench_cycles_to_ms(uint32_t cycles)
{
    const uint32_t freq_hz = (uint32_t)esp_clk_cpu_freq();
    if (freq_hz == 0) return 0.0f;
    return (cycles / (float)freq_hz) * 1000.0f;
}

// Stats helpers (implemented in bench_common.c)
void bench_compute_median_u32(uint32_t *arr, size_t n, uint32_t *out);
void bench_compute_avg_u32(const uint32_t *arr, size_t n, uint32_t *out);
void bench_compute_stddev_u32(const uint32_t *arr, size_t n, uint32_t avg, uint32_t *out);
void bench_compute_percentile_u32(uint32_t *arr, size_t n, uint8_t percentile, uint32_t *out);
