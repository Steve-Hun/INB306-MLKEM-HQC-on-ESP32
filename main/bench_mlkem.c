#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_private/esp_clk.h"
#include "esp_cpu.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "driver/gpio.h"

#include "bench_common.h"
#include "bench_mlkem.h"
#include "mlkem_randombytes.h"

#define MLK_CONFIG_PARAMETER_SET 512
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem
#define MLK_CONFIG_API_PARAMETER_SET MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_API_NAMESPACE_PREFIX MLK_CONFIG_NAMESPACE_PREFIX
#include "mlkem/mlkem_native.h"

static const char *TAG = "mlkem_phase1";

// Stack depth for the benchmark task in FreeRTOS words (4 bytes each).
// Keep this reasonable to avoid starving the heap.
#ifndef BENCH_TASK_STACK_WORDS
// Default to 32,768 words (≈128 KB) for extra safety margin
#define BENCH_TASK_STACK_WORDS 32768
#endif

// Cooperative yield controls (outside timed windows)
// Set BENCH_YIELD_TICKS=0 to disable delay-based yield.
#ifndef BENCH_YIELD_TICKS
#define BENCH_YIELD_TICKS 1
#endif
// Yield every N trials (1 = yield each trial, 0 = disable)
#ifndef BENCH_YIELD_EVERY
#define BENCH_YIELD_EVERY 1
#endif
// LED progress indicator: blink every N trials (0 = disable)
// Uses GPIO toggle - negligible overhead (~15 cycles) without cache pollution
#ifndef BENCH_LED_BLINK_EVERY
#define BENCH_LED_BLINK_EVERY 25
#endif
#ifndef BENCH_LED_GPIO
#define BENCH_LED_GPIO 2  // ESP32 built-in LED
#endif

static void log_result(const char *label, uint32_t cycles, int rc)
{
    const float ms = bench_cycles_to_ms(cycles);
    ESP_LOGI(TAG, "%s: cycles=%u (~%.3f ms) rc=%d", label, cycles, ms, rc);
}

static void log_hex16(const char *label, const uint8_t *buf)
{
    char out[16 * 2 + 1];
    for (size_t i = 0; i < 16; ++i) {
        sprintf(&out[i * 2], "%02x", buf[i]);
    }
    out[sizeof(out) - 1] = '\0';
    ESP_LOGI(TAG, "%s: %s", label, out);
}

static void init_progress_led(void)
{
#if BENCH_LED_BLINK_EVERY > 0
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << BENCH_LED_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
    gpio_set_level(BENCH_LED_GPIO, 0);
#endif
}

static inline void toggle_progress_led(void)
{
#if BENCH_LED_BLINK_EVERY > 0
    static uint8_t led_state = 0;
    led_state ^= 1;
    gpio_set_level(BENCH_LED_GPIO, led_state);
#endif
}

static void mlkem_bench_task(void *arg)
{
    bench_config_t local_cfg = {
        .phase = BENCH_PHASE1_MLKEM,
        .trials = 25,
        .metric = BENCH_METRIC_MEDIAN,
    };
    if (arg) {
        local_cfg = *(const bench_config_t *)arg;
        free(arg);
    }

    mlkem_randombytes_use_trng();
    init_progress_led();

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    ESP_LOGI(TAG, "Phase 1: ML-KEM single-core baseline");
    ESP_LOGI(TAG, "Parameter set: %d", MLK_CONFIG_PARAMETER_SET);
    ESP_LOGI(TAG, "Sizes: pk=%d sk=%d ct=%d shared=%d", CRYPTO_PUBLICKEYBYTES,
             CRYPTO_SECRETKEYBYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_BYTES);

    // Warm-up (untimed): pay lazy inits and fill caches
    {
        int rc;
        ESP_LOGI(TAG, "Warm-up: keypair...");
        rc = crypto_kem_keypair(pk, sk);
        if (rc != 0) { ESP_LOGE(TAG, "Warm-up keypair failed"); goto end_task; }
        vTaskDelay(1);
        ESP_LOGI(TAG, "Warm-up: encaps...");
        rc = crypto_kem_enc(ct, key_b, pk);
        if (rc != 0) { ESP_LOGE(TAG, "Warm-up encaps failed"); goto end_task; }
        vTaskDelay(1);
        ESP_LOGI(TAG, "Warm-up: decaps...");
        rc = crypto_kem_dec(key_a, ct, sk);
        if (rc != 0) { ESP_LOGE(TAG, "Warm-up decaps failed"); goto end_task; }
        ESP_LOGI(TAG, "Warm-up: done");
    }

    // Timed trials with chosen metric
    const size_t trials = local_cfg.trials;
    uint32_t *keygen_cyc = NULL;
    uint32_t *enc_cyc    = NULL;
    uint32_t *dec_cyc    = NULL;
    // Heap diagnostics before allocations
    size_t free_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t largest_before = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    ESP_LOGI(TAG, "Heap before alloc: free=%u bytes, largest=%u bytes",
             (unsigned)free_before, (unsigned)largest_before);
    keygen_cyc = (uint32_t *)malloc(trials * sizeof(uint32_t));
    enc_cyc    = (uint32_t *)malloc(trials * sizeof(uint32_t));
    dec_cyc    = (uint32_t *)malloc(trials * sizeof(uint32_t));
    if (!keygen_cyc || !enc_cyc || !dec_cyc) {
        ESP_LOGE(TAG, "Allocation failed for cycle arrays");
        goto end_task;
    }
    ESP_LOGI(TAG, "Allocated cycle arrays for %u trials", (unsigned)trials);
    ESP_LOGI(TAG, "Starting %u trials (silent loop, LED blinks for progress)...", (unsigned)trials);

    for (size_t i = 0; i < trials; ++i) {
        uint32_t start, end;
        int rc;

        start = bench_cycles_now();
        rc = crypto_kem_keypair(pk, sk);
        end = bench_cycles_now();
        keygen_cyc[i] = end - start;
        if (rc != 0) { ESP_LOGE(TAG, "Keypair failed"); goto end_task; }

        start = bench_cycles_now();
        rc = crypto_kem_enc(ct, key_b, pk);
        end = bench_cycles_now();
        enc_cyc[i] = end - start;
        if (rc != 0) { ESP_LOGE(TAG, "Encaps failed"); goto end_task; }

        start = bench_cycles_now();
        rc = crypto_kem_dec(key_a, ct, sk);
        end = bench_cycles_now();
        dec_cyc[i] = end - start;
        if (rc != 0) { ESP_LOGE(TAG, "Decaps failed"); goto end_task; }

        // LED progress indicator (minimal overhead, no cache pollution)
#if BENCH_LED_BLINK_EVERY > 0
        if (((i + 1) % BENCH_LED_BLINK_EVERY) == 0) {
            toggle_progress_led();
        }
#endif

        // Yield to allow idle and system tasks to run and feed watchdogs.
        // Keeps the system responsive during long benchmarking loops.
#if BENCH_YIELD_EVERY > 0
        if (((i + 1) % BENCH_YIELD_EVERY) == 0) {
#  if BENCH_YIELD_TICKS > 0
            vTaskDelay(BENCH_YIELD_TICKS);
#  else
            taskYIELD();
#  endif
        }
#endif
    }
    
    ESP_LOGI(TAG, "Completed %u trials", (unsigned)trials);
    ESP_LOGI(TAG, "Computing statistics...");

    // Compute both median and average for complete statistical picture
    uint32_t keygen_median = 0, enc_median = 0, dec_median = 0;
    uint32_t keygen_avg = 0, enc_avg = 0, dec_avg = 0;

    bench_compute_median_u32(keygen_cyc, trials, &keygen_median);
    bench_compute_median_u32(enc_cyc, trials, &enc_median);
    bench_compute_median_u32(dec_cyc, trials, &dec_median);

    bench_compute_avg_u32(keygen_cyc, trials, &keygen_avg);
    bench_compute_avg_u32(enc_cyc, trials, &enc_avg);
    bench_compute_avg_u32(dec_cyc, trials, &dec_avg);

    // Primary results: show both median and mean
    log_result("keypair[median]", keygen_median, 0);
    log_result("keypair[mean]", keygen_avg, 0);
    log_result("encaps[median]", enc_median, 0);
    log_result("encaps[mean]", enc_avg, 0);
    log_result("decaps[median]", dec_median, 0);
    log_result("decaps[mean]", dec_avg, 0);

    // Publication-grade statistics: stddev and percentiles (always computed)
    if (trials >= 10) {
        uint32_t keygen_std, enc_std, dec_std;
        bench_compute_stddev_u32(keygen_cyc, trials, keygen_avg, &keygen_std);
        bench_compute_stddev_u32(enc_cyc, trials, enc_avg, &enc_std);
        bench_compute_stddev_u32(dec_cyc, trials, dec_avg, &dec_std);

        uint32_t keygen_p5, keygen_p95, enc_p5, enc_p95, dec_p5, dec_p95;
        bench_compute_percentile_u32(keygen_cyc, trials, 5, &keygen_p5);
        bench_compute_percentile_u32(keygen_cyc, trials, 95, &keygen_p95);
        bench_compute_percentile_u32(enc_cyc, trials, 5, &enc_p5);
        bench_compute_percentile_u32(enc_cyc, trials, 95, &enc_p95);
        bench_compute_percentile_u32(dec_cyc, trials, 5, &dec_p5);
        bench_compute_percentile_u32(dec_cyc, trials, 95, &dec_p95);

        ESP_LOGI(TAG, "keypair: median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
                 keygen_median, keygen_avg, keygen_std, keygen_p5, keygen_p95);
        ESP_LOGI(TAG, "encaps:  median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
                 enc_median, enc_avg, enc_std, enc_p5, enc_p95);
        ESP_LOGI(TAG, "decaps:  median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
                 dec_median, dec_avg, dec_std, dec_p5, dec_p95);
    }

    const bool match = (memcmp(key_a, key_b, sizeof(key_a)) == 0);
    ESP_LOGI(TAG, "Shared secret match (last trial): %s", match ? "yes" : "no");
    log_hex16("Alice ss[0:16] (last)", key_a);
    log_hex16("Bob   ss[0:16] (last)", key_b);

end_task:
    UBaseType_t watermark = uxTaskGetStackHighWaterMark(NULL);
    ESP_LOGI(TAG, "Stack high-water mark: %u words", (unsigned)watermark);
    ESP_LOGI(TAG, "Done.");
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    if (keygen_cyc) free(keygen_cyc);
    if (enc_cyc) free(enc_cyc);
    if (dec_cyc) free(dec_cyc);
    #pragma GCC diagnostic pop
    vTaskDelete(NULL);
}

void bench_mlkem_start(const bench_config_t *cfg)
{
    ESP_LOGI(TAG, "Creating bench task with stack=%u words (~%u KB)",
             (unsigned)BENCH_TASK_STACK_WORDS,
             (unsigned)(BENCH_TASK_STACK_WORDS * 4 / 1024));

    bench_config_t *cfg_copy = malloc(sizeof(*cfg_copy));
    if (!cfg_copy) {
        ESP_LOGE(TAG, "Failed to alloc bench config");
        return;
    }
    if (cfg) {
        *cfg_copy = *cfg;
    } else {
        cfg_copy->phase = BENCH_PHASE1_MLKEM;
        cfg_copy->trials = 25;
        cfg_copy->metric = BENCH_METRIC_MEDIAN;
    }

    const BaseType_t ok = xTaskCreatePinnedToCore(mlkem_bench_task, "mlkem_bench",
                                                  BENCH_TASK_STACK_WORDS, (void *)cfg_copy,
                                                  tskIDLE_PRIORITY + 1, NULL, 0);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "Failed to create benchmark task");
        free(cfg_copy);
    }
}
