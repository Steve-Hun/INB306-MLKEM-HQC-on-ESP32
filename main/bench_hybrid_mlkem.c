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
#include "bench_hybrid_mlkem.h"
#include "mlkem_randombytes.h"

#define MLK_CONFIG_PARAMETER_SET 512
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem
#define MLK_CONFIG_API_PARAMETER_SET MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_API_NAMESPACE_PREFIX MLK_CONFIG_NAMESPACE_PREFIX
#include "mlkem/mlkem_native.h"

// Include mbedTLS for X25519 (using general ECP implementation, mirroring Phase 6)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"

static const char *TAG = "mlkem_hybrid_phase4";

// ML-KEM-512 uses significantly less stack than HQC; 128 KB is sufficient
#ifndef BENCH_TASK_STACK_WORDS
#define BENCH_TASK_STACK_WORDS 32768  // 128 KB for ML-KEM
#endif

// Cooperative yield controls (outside timed windows)
#ifndef BENCH_YIELD_TICKS
#define BENCH_YIELD_TICKS 1
#endif
#ifndef BENCH_YIELD_EVERY
#define BENCH_YIELD_EVERY 1
#endif
// LED progress indicator
#ifndef BENCH_LED_BLINK_EVERY
#define BENCH_LED_BLINK_EVERY 25
#endif
#ifndef BENCH_LED_GPIO
#define BENCH_LED_GPIO 2
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

static void hybrid_mlkem_bench_task(void *arg)
{
    bench_config_t local_cfg = {
        .phase = BENCH_PHASE4_X25519_SEQ,
        .trials = 25,
        .metric = BENCH_METRIC_MEDIAN,
    };
    if (arg) {
        local_cfg = *(const bench_config_t *)arg;
        free(arg);
    }

    // Ensure ML-KEM uses TRNG for randomness
    mlkem_randombytes_use_trng();
    init_progress_led();

    // ML-KEM buffers
    uint8_t mlkem_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t mlkem_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t mlkem_ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t mlkem_ss_alice[CRYPTO_BYTES];
    uint8_t mlkem_ss_bob[CRYPTO_BYTES];

    // X25519 using lower-level ECP API (stateless; same as Phase 6)
    mbedtls_ecp_group grp;
    mbedtls_mpi alice_d, bob_d;         // Private keys (scalars)
    mbedtls_ecp_point alice_Q, bob_Q;   // Public keys (points)
    mbedtls_mpi shared_alice, shared_bob; // Shared secrets
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // X25519 shared secrets (final output)
    uint8_t x25519_ss_alice[32];
    uint8_t x25519_ss_bob[32];

    ESP_LOGI(TAG, "Phase 4: ML-KEM-512 + X25519 Hybrid (primitives only, no HKDF)");
    ESP_LOGI(TAG, "Algorithm: ML-KEM-512 + X25519");
    ESP_LOGI(TAG, "ML-KEM sizes: pk=%d sk=%d ct=%d shared=%d", CRYPTO_PUBLICKEYBYTES,
             CRYPTO_SECRETKEYBYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_BYTES);
    ESP_LOGI(TAG, "X25519: 32-byte keys and shared secret");

    // Initialize mbedTLS
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&alice_d);
    mbedtls_mpi_init(&bob_d);
    mbedtls_ecp_point_init(&alice_Q);
    mbedtls_ecp_point_init(&bob_Q);
    mbedtls_mpi_init(&shared_alice);
    mbedtls_mpi_init(&shared_bob);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "mlkem_hybrid_bench";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: %d", ret);
        goto end_task;
    }

    // Load Curve25519 group
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load Curve25519: %d", ret);
        goto end_task;
    }

    // Warm-up (untimed): pay lazy inits and fill caches
    {
        int rc;
        ESP_LOGI(TAG, "Warm-up: ML-KEM keypair...");
        rc = crypto_kem_keypair(mlkem_pk, mlkem_sk);
        if (rc != 0) { ESP_LOGE(TAG, "Warm-up ML-KEM keypair failed"); goto end_task; }

        ESP_LOGI(TAG, "Warm-up: X25519 setup...");
        ret = mbedtls_ecdh_gen_public(&grp, &alice_d, &alice_Q,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) { ESP_LOGE(TAG, "Warm-up X25519 gen_public failed"); goto end_task; }

        ESP_LOGI(TAG, "Warm-up: ML-KEM encaps...");
        rc = crypto_kem_enc(mlkem_ct, mlkem_ss_bob, mlkem_pk);
        if (rc != 0) { ESP_LOGE(TAG, "Warm-up ML-KEM encaps failed"); goto end_task; }

        ESP_LOGI(TAG, "Warm-up: ML-KEM decaps...");
        rc = crypto_kem_dec(mlkem_ss_alice, mlkem_ct, mlkem_sk);
        if (rc != 0) { ESP_LOGE(TAG, "Warm-up ML-KEM decaps failed"); goto end_task; }

        ESP_LOGI(TAG, "Warm-up: done");
    }

    // Timed trials with chosen metric
    const size_t trials = local_cfg.trials;
    uint32_t *alice_keygen_cyc = NULL;
    uint32_t *alice_decaps_cyc = NULL;
    uint32_t *bob_encaps_cyc   = NULL;
    uint32_t *bob_dh_cyc       = NULL;

    // Heap diagnostics before allocations
    size_t free_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t largest_before = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    ESP_LOGI(TAG, "Heap before alloc: free=%u bytes, largest=%u bytes",
             (unsigned)free_before, (unsigned)largest_before);

    alice_keygen_cyc = (uint32_t *)malloc(trials * sizeof(uint32_t));
    alice_decaps_cyc = (uint32_t *)malloc(trials * sizeof(uint32_t));
    bob_encaps_cyc   = (uint32_t *)malloc(trials * sizeof(uint32_t));
    bob_dh_cyc       = (uint32_t *)malloc(trials * sizeof(uint32_t));
    if (!alice_keygen_cyc || !alice_decaps_cyc || !bob_encaps_cyc || !bob_dh_cyc) {
        ESP_LOGE(TAG, "Allocation failed for cycle arrays");
        goto end_task;
    }
    ESP_LOGI(TAG, "Allocated cycle arrays for %u trials", (unsigned)trials);
    ESP_LOGI(TAG, "Starting %u trials (silent loop, LED blinks for progress)...", (unsigned)trials);

    for (size_t i = 0; i < trials; ++i) {
        uint32_t start, end;
        int rc;

        // ===== Alice's operations =====

        // Alice measurement 1: ML-KEM keygen + X25519 keygen
        start = bench_cycles_now();
        rc = crypto_kem_keypair(mlkem_pk, mlkem_sk);
        ret = mbedtls_ecdh_gen_public(&grp, &alice_d, &alice_Q,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        end = bench_cycles_now();
        alice_keygen_cyc[i] = end - start;
        if (rc != 0 || ret != 0) { ESP_LOGE(TAG, "Alice keygen failed (rc=%d, ret=%d)", rc, ret); goto end_task; }

        // Bob does encaps (needed for Alice's decaps later)
        ret = mbedtls_ecdh_gen_public(&grp, &bob_d, &bob_Q,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) { ESP_LOGE(TAG, "Bob gen_public failed"); goto end_task; }

        rc = crypto_kem_enc(mlkem_ct, mlkem_ss_bob, mlkem_pk);
        if (rc != 0) { ESP_LOGE(TAG, "Bob encaps failed"); goto end_task; }

        // Alice measurement 2: ML-KEM decaps + X25519 DH
        start = bench_cycles_now();
        rc = crypto_kem_dec(mlkem_ss_alice, mlkem_ct, mlkem_sk);
        ret = mbedtls_ecdh_compute_shared(&grp, &shared_alice, &bob_Q, &alice_d,
                                           mbedtls_ctr_drbg_random, &ctr_drbg);
        end = bench_cycles_now();
        alice_decaps_cyc[i] = end - start;
        if (rc != 0 || ret != 0) { ESP_LOGE(TAG, "Alice decaps+DH failed (rc=%d, ret=%d)", rc, ret); goto end_task; }

        // ===== Bob's operations (fresh run for fair measurement) =====

        // Reset: Alice creates keys again for Bob's measurement
        ret = mbedtls_ecdh_gen_public(&grp, &alice_d, &alice_Q,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) { ESP_LOGE(TAG, "Alice re-gen_public failed"); goto end_task; }

        rc = crypto_kem_keypair(mlkem_pk, mlkem_sk);
        if (rc != 0) { ESP_LOGE(TAG, "Alice re-keygen failed"); goto end_task; }

        // Bob measurement 1: X25519 keygen + ML-KEM encaps
        start = bench_cycles_now();
        ret = mbedtls_ecdh_gen_public(&grp, &bob_d, &bob_Q,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        rc = crypto_kem_enc(mlkem_ct, mlkem_ss_bob, mlkem_pk);
        end = bench_cycles_now();
        bob_encaps_cyc[i] = end - start;
        if (rc != 0 || ret != 0) { ESP_LOGE(TAG, "Bob encaps failed (rc=%d, ret=%d)", rc, ret); goto end_task; }

        // Bob measurement 2: X25519 DH
        start = bench_cycles_now();
        ret = mbedtls_ecdh_compute_shared(&grp, &shared_bob, &alice_Q, &bob_d,
                                           mbedtls_ctr_drbg_random, &ctr_drbg);
        end = bench_cycles_now();
        bob_dh_cyc[i] = end - start;
        if (ret != 0) { ESP_LOGE(TAG, "Bob DH failed (ret=%d)", ret); goto end_task; }

        // LED progress indicator (minimal overhead, no cache pollution)
#if BENCH_LED_BLINK_EVERY > 0
        if (((i + 1) % BENCH_LED_BLINK_EVERY) == 0) {
            toggle_progress_led();
        }
#endif

        // Yield to allow idle and system tasks to run and feed watchdogs.
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
    uint32_t alice_keygen_median = 0, alice_decaps_median = 0;
    uint32_t bob_encaps_median = 0, bob_dh_median = 0;
    uint32_t alice_keygen_avg = 0, alice_decaps_avg = 0;
    uint32_t bob_encaps_avg = 0, bob_dh_avg = 0;

    bench_compute_median_u32(alice_keygen_cyc, trials, &alice_keygen_median);
    bench_compute_median_u32(alice_decaps_cyc, trials, &alice_decaps_median);
    bench_compute_median_u32(bob_encaps_cyc, trials, &bob_encaps_median);
    bench_compute_median_u32(bob_dh_cyc, trials, &bob_dh_median);

    bench_compute_avg_u32(alice_keygen_cyc, trials, &alice_keygen_avg);
    bench_compute_avg_u32(alice_decaps_cyc, trials, &alice_decaps_avg);
    bench_compute_avg_u32(bob_encaps_cyc, trials, &bob_encaps_avg);
    bench_compute_avg_u32(bob_dh_cyc, trials, &bob_dh_avg);

    // Primary results: show both median and mean
    log_result("Alice keygen[median]", alice_keygen_median, 0);
    log_result("Alice keygen[mean]", alice_keygen_avg, 0);
    log_result("Alice decaps+DH[median]", alice_decaps_median, 0);
    log_result("Alice decaps+DH[mean]", alice_decaps_avg, 0);
    log_result("Bob encaps[median]", bob_encaps_median, 0);
    log_result("Bob encaps[mean]", bob_encaps_avg, 0);
    log_result("Bob DH[median]", bob_dh_median, 0);
    log_result("Bob DH[mean]", bob_dh_avg, 0);

    // Publication-grade statistics: stddev and percentiles (always computed using actual mean)
    if (trials >= 10) {
        uint32_t alice_keygen_sd, alice_decaps_sd, bob_encaps_sd, bob_dh_sd;
        bench_compute_stddev_u32(alice_keygen_cyc, trials, alice_keygen_avg, &alice_keygen_sd);
        bench_compute_stddev_u32(alice_decaps_cyc, trials, alice_decaps_avg, &alice_decaps_sd);
        bench_compute_stddev_u32(bob_encaps_cyc, trials, bob_encaps_avg, &bob_encaps_sd);
        bench_compute_stddev_u32(bob_dh_cyc, trials, bob_dh_avg, &bob_dh_sd);

        uint32_t alice_keygen_p5, alice_keygen_p95;
        uint32_t alice_decaps_p5, alice_decaps_p95;
        uint32_t bob_encaps_p5, bob_encaps_p95;
        uint32_t bob_dh_p5, bob_dh_p95;

        bench_compute_percentile_u32(alice_keygen_cyc, trials, 5, &alice_keygen_p5);
        bench_compute_percentile_u32(alice_keygen_cyc, trials, 95, &alice_keygen_p95);
        bench_compute_percentile_u32(alice_decaps_cyc, trials, 5, &alice_decaps_p5);
        bench_compute_percentile_u32(alice_decaps_cyc, trials, 95, &alice_decaps_p95);
        bench_compute_percentile_u32(bob_encaps_cyc, trials, 5, &bob_encaps_p5);
        bench_compute_percentile_u32(bob_encaps_cyc, trials, 95, &bob_encaps_p95);
        bench_compute_percentile_u32(bob_dh_cyc, trials, 5, &bob_dh_p5);
        bench_compute_percentile_u32(bob_dh_cyc, trials, 95, &bob_dh_p95);

        ESP_LOGI(TAG, "Alice keygen: median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
                 alice_keygen_median, alice_keygen_avg, alice_keygen_sd, alice_keygen_p5, alice_keygen_p95);
        ESP_LOGI(TAG, "Alice decaps+DH: median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
                 alice_decaps_median, alice_decaps_avg, alice_decaps_sd, alice_decaps_p5, alice_decaps_p95);
        ESP_LOGI(TAG, "Bob encaps: median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
                 bob_encaps_median, bob_encaps_avg, bob_encaps_sd, bob_encaps_p5, bob_encaps_p95);
        ESP_LOGI(TAG, "Bob DH: median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
                 bob_dh_median, bob_dh_avg, bob_dh_sd, bob_dh_p5, bob_dh_p95);
    }

    // Total costs (using median values)
    uint32_t alice_total_median = alice_keygen_median + alice_decaps_median;
    uint32_t bob_total_median = bob_encaps_median + bob_dh_median;
    uint32_t alice_total_mean = alice_keygen_avg + alice_decaps_avg;
    uint32_t bob_total_mean = bob_encaps_avg + bob_dh_avg;

    ESP_LOGI(TAG, "=== Phase 4 Summary ===");
    ESP_LOGI(TAG, "Alice total (median): %u cycles (~%.1f ms)",
             alice_total_median, bench_cycles_to_ms(alice_total_median));
    ESP_LOGI(TAG, "Alice total (mean): %u cycles (~%.1f ms)",
             alice_total_mean, bench_cycles_to_ms(alice_total_mean));
    ESP_LOGI(TAG, "Bob total (median): %u cycles (~%.1f ms)",
             bob_total_median, bench_cycles_to_ms(bob_total_median));
    ESP_LOGI(TAG, "Bob total (mean): %u cycles (~%.1f ms)",
             bob_total_mean, bench_cycles_to_ms(bob_total_mean));

    // Correctness check - convert MPI to bytes
    ret = mbedtls_mpi_write_binary(&shared_alice, x25519_ss_alice, 32);
    ret |= mbedtls_mpi_write_binary(&shared_bob, x25519_ss_bob, 32);

    bool mlkem_match = (memcmp(mlkem_ss_alice, mlkem_ss_bob, CRYPTO_BYTES) == 0);
    bool x25519_match = (memcmp(x25519_ss_alice, x25519_ss_bob, 32) == 0);
    ESP_LOGI(TAG, "ML-KEM shared secret match (last trial): %s", mlkem_match ? "yes" : "NO");
    ESP_LOGI(TAG, "X25519 shared secret match (last trial): %s", x25519_match ? "yes" : "NO");

    if (mlkem_match) {
        log_hex16("ML-KEM ss[0:16] (last)", mlkem_ss_alice);
    }
    if (x25519_match) {
        log_hex16("X25519 ss[0:16] (last)", x25519_ss_alice);
    }

    // Stack high-water mark
    UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
    ESP_LOGI(TAG, "Stack high-water mark: %u words", (unsigned)hwm);
    ESP_LOGI(TAG, "Done.");

end_task:
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    if (alice_keygen_cyc) free(alice_keygen_cyc);
    if (alice_decaps_cyc) free(alice_decaps_cyc);
    if (bob_encaps_cyc) free(bob_encaps_cyc);
    if (bob_dh_cyc) free(bob_dh_cyc);
    #pragma GCC diagnostic pop
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&alice_d);
    mbedtls_mpi_free(&bob_d);
    mbedtls_ecp_point_free(&alice_Q);
    mbedtls_ecp_point_free(&bob_Q);
    mbedtls_mpi_free(&shared_alice);
    mbedtls_mpi_free(&shared_bob);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    vTaskDelete(NULL);
}

void bench_hybrid_mlkem_start(const bench_config_t *cfg)
{
    bench_config_t *task_cfg = (bench_config_t *)malloc(sizeof(bench_config_t));
    if (!task_cfg) {
        ESP_LOGE(TAG, "Failed to allocate config");
        return;
    }
    *task_cfg = *cfg;

    xTaskCreate(hybrid_mlkem_bench_task, "hybrid_mlkem_bench", BENCH_TASK_STACK_WORDS,
                task_cfg, 5, NULL);
}

