#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "bench_common.h"
#include "bench_mlkem.h"
#include "bench_hqc.h"
#include "bench_hybrid_hqc.h"
#include "bench_hybrid_mlkem.h"
#include "bench_parallel_mlkem.h"
#include "bench_parallel_hqc.h"

static const char *TAG = "app";

// Simple compile-time toggles
//
// Select default benchmark phase (set BENCH_DEFAULT_PHASE to one of):
// - BENCH_PHASE1_MLKEM          : Phase 1 — ML-KEM-512 baseline
// - BENCH_PHASE3_HQC            : Phase 3 — HQC-128 baseline
// - BENCH_PHASE4_X25519_SEQ     : Phase 4 — ML-KEM-512 + X25519 hybrid (sequential)
// - BENCH_PHASE6_HQC_HYBRID     : Phase 6 — HQC-128 + X25519 hybrid (sequential)
// - BENCH_PHASE7_MLKEM_PARALLEL : Phase 7 — ML-KEM-512 + X25519 hybrid (dual-core parallel)
// - BENCH_PHASE8_HQC_PARALLEL   : Phase 8 — HQC-128 + X25519 hybrid (dual-core parallel)
//
// Reserved (not used here):
// - BENCH_PHASE2_MLKEM_DUAL     : ML-KEM dual-core scheduling (planned)
// - BENCH_PHASE5_HYBRID_DUAL    : Hybrid parallel (planned)
#ifndef BENCH_DEFAULT_PHASE
#define BENCH_DEFAULT_PHASE BENCH_PHASE1_MLKEM
#endif
#ifndef BENCH_DEFAULT_TRIALS
#define BENCH_DEFAULT_TRIALS 100
#endif
#ifndef BENCH_DEFAULT_METRIC
#define BENCH_DEFAULT_METRIC BENCH_METRIC_MEDIAN
#endif

void app_main(void)
{
    ESP_LOGI(TAG, "ML-KEM measurement app");
    const bench_config_t cfg = {
        .phase = (bench_phase_t)BENCH_DEFAULT_PHASE,
        .trials = (uint16_t)BENCH_DEFAULT_TRIALS,
        .metric = (bench_metric_t)BENCH_DEFAULT_METRIC,
    };

    switch (cfg.phase) {
        case BENCH_PHASE1_MLKEM:
        default:
            ESP_LOGI(TAG, "Starting Phase 1 benchmark (ML-KEM single-core)");
            bench_mlkem_start(&cfg);
            break;
        case BENCH_PHASE4_X25519_SEQ:
            ESP_LOGI(TAG, "Starting Phase 4 benchmark (ML-KEM-512 + X25519 Hybrid)");
            bench_hybrid_mlkem_start(&cfg);
            break;
        case BENCH_PHASE3_HQC:
            ESP_LOGI(TAG, "Starting Phase 3 benchmark (HQC-128 single-core)");
            bench_hqc_start(&cfg);
            break;
        case BENCH_PHASE6_HQC_HYBRID:
            ESP_LOGI(TAG, "Starting Phase 6 benchmark (HQC-128 + X25519 Hybrid)");
            bench_hybrid_hqc_start(&cfg);
            break;
        case BENCH_PHASE7_MLKEM_PARALLEL:
            ESP_LOGI(TAG, "Starting Phase 7 benchmark (ML-KEM-512 + X25519 Parallel)");
            bench_parallel_mlkem_start(&cfg);
            break;
        case BENCH_PHASE8_HQC_PARALLEL:
            ESP_LOGI(TAG, "Starting Phase 8 benchmark (HQC-128 + X25519 Parallel)");
            bench_parallel_hqc_start(&cfg);
            break;
    }
}
