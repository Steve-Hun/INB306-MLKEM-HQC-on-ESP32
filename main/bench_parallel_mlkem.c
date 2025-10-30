#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_private/esp_clk.h"
#include "esp_cpu.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "driver/gpio.h"

#include "bench_common.h"
#include "bench_parallel_mlkem.h"
#include "mlkem_randombytes.h"

#define MLK_CONFIG_PARAMETER_SET 512
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem
#define MLK_CONFIG_API_PARAMETER_SET MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_API_NAMESPACE_PREFIX MLK_CONFIG_NAMESPACE_PREFIX
#include "mlkem/mlkem_native.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"

static const char *TAG = "mlkem_parallel_phase7";

// Parallel-only stack sizing (expressed in FreeRTOS words for consistency with sequential phases)
// Note: This task allocates multiple crypto contexts and buffers on the stack.
// A larger stack helps avoid subtle corruption that can manifest during logging.
#ifndef BENCH_TASK_STACK_WORDS
#define BENCH_TASK_STACK_WORDS 32768   // 128 KB orchestrator (matches sequential phases)
#endif
#ifndef MLK_WORKER_STACK_WORDS
#define MLK_WORKER_STACK_WORDS 131072  // 512 KB ML-KEM worker (131,072 words × 4 bytes)
#endif
#ifndef X25519_WORKER_STACK_WORDS
#define X25519_WORKER_STACK_WORDS 24576 // 96 KB X25519 worker (24,576 words × 4 bytes)
#endif

// All stack sizes and diagnostics below are expressed in FreeRTOS words

#ifndef BENCH_YIELD_TICKS
#define BENCH_YIELD_TICKS 1
#endif
#ifndef BENCH_YIELD_EVERY
#define BENCH_YIELD_EVERY 1
#endif
#ifndef BENCH_LED_BLINK_EVERY
#define BENCH_LED_BLINK_EVERY 25
#endif
#ifndef BENCH_LED_GPIO
#define BENCH_LED_GPIO 2
#endif

// Parallel worker infrastructure
typedef enum {
    MLK_OP_NONE = 0,
    MLK_OP_KEYGEN,
    MLK_OP_DECAPS,
    MLK_OP_ENCAPS,
} mlk_op_t;

typedef enum {
    X_OP_NONE = 0,
    X_OP_KEYGEN,
    X_OP_DH,
} x25519_op_t;

typedef struct {
    // sync
    SemaphoreHandle_t start_sem;
    SemaphoreHandle_t done_sem;
    volatile mlk_op_t op;
    volatile uint32_t cycles;
    volatile int rc;
    // ML-KEM buffers
    uint8_t *pk;
    uint8_t *sk;
    uint8_t *ct;
    uint8_t *ss;
} mlk_worker_t;

typedef struct {
    // sync
    SemaphoreHandle_t start_sem;
    SemaphoreHandle_t done_sem;
    volatile x25519_op_t op;
    volatile uint32_t cycles;
    volatile int rc;
    // X25519 contexts/pointers
    mbedtls_ecp_group *grp;
    mbedtls_ctr_drbg_context *ctr;
    mbedtls_mpi *d_priv;                // for KEYGEN/DH
    mbedtls_ecp_point *Q_pub;           // for KEYGEN
    const mbedtls_ecp_point *Q_peer;    // for DH
    mbedtls_mpi *shared_out;            // for DH
} x25519_worker_t;

static void mlk_worker_task(void *arg)
{
    mlk_worker_t *w = (mlk_worker_t *)arg;
    for (;;) {
        xSemaphoreTake(w->start_sem, portMAX_DELAY);
        uint32_t s = bench_cycles_now();
        int rc = 0;
        switch (w->op) {
            case MLK_OP_KEYGEN:
                rc = crypto_kem_keypair(w->pk, w->sk);
                break;
            case MLK_OP_DECAPS:
                rc = crypto_kem_dec(w->ss, w->ct, w->sk);
                break;
            case MLK_OP_ENCAPS:
                rc = crypto_kem_enc(w->ct, w->ss, w->pk);
                break;
            default:
                rc = 0;
                break;
        }
        uint32_t e = bench_cycles_now();
        w->cycles = e - s;
        w->rc = rc;
        xSemaphoreGive(w->done_sem);
    }
}

static void x25519_worker_task(void *arg)
{
    x25519_worker_t *w = (x25519_worker_t *)arg;
    for (;;) {
        xSemaphoreTake(w->start_sem, portMAX_DELAY);
        uint32_t s = bench_cycles_now();
        int rc = 0;
        switch (w->op) {
            case X_OP_KEYGEN:
                rc = mbedtls_ecdh_gen_public(w->grp, w->d_priv, w->Q_pub,
                                            mbedtls_ctr_drbg_random, w->ctr);
                break;
            case X_OP_DH:
                rc = mbedtls_ecdh_compute_shared(w->grp, w->shared_out, w->Q_peer, w->d_priv,
                                                 mbedtls_ctr_drbg_random, w->ctr);
                break;
            default:
                rc = 0;
                break;
        }
        uint32_t e = bench_cycles_now();
        w->cycles = e - s;
        w->rc = rc;
        xSemaphoreGive(w->done_sem);
    }
}

static void log_result(const char *label, uint32_t cycles, int rc)
{
    const float ms = bench_cycles_to_ms(cycles);
    ESP_LOGI(TAG, "%s: cycles=%u (~%.3f ms) rc=%d", label, cycles, ms, rc);
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

static void parallel_mlkem_bench_task(void *arg)
{
    bench_config_t local_cfg = {
        .phase = BENCH_PHASE7_MLKEM_PARALLEL,
        .trials = 25,
        .metric = BENCH_METRIC_MEDIAN,
    };
    if (arg) {
        local_cfg = *(const bench_config_t *)arg;
        free(arg);
    }

    mlkem_randombytes_use_trng();
    init_progress_led();

    ESP_LOGI(TAG, "Phase 7: ML-KEM-512 + X25519 Hybrid (Parallel overlap only)");
    ESP_LOGI(TAG, "Dual-core workers (Core0=ML-KEM, Core1=X25519); segment wall-time = max(worker cycles)");
    ESP_LOGI(TAG, "Configured stack sizes (words): orchestrator=%u, ML-KEM worker=%u, X25519 worker=%u",
             (unsigned)BENCH_TASK_STACK_WORDS,
             (unsigned)MLK_WORKER_STACK_WORDS,
             (unsigned)X25519_WORKER_STACK_WORDS);
#if CONFIG_FREERTOS_UNICORE
    ESP_LOGW(TAG, "Single-core configuration detected — parallel overlap requires dual-core for intended results");
#endif
    ESP_LOGI(TAG, "X25519: ~27-30M cycles vs ML-KEM: ~1-1.4M cycles");

    // Declare cycle arrays early (before any goto)
    uint32_t *alice_seg_a_wall = NULL;
    uint32_t *alice_seg_b_wall = NULL;
    uint32_t *bob_seg_a_wall = NULL;
    uint32_t *bob_dh_cyc = NULL;

    // ML-KEM buffers
    uint8_t mlkem_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t mlkem_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t mlkem_ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t mlkem_ss_alice[CRYPTO_BYTES];
    uint8_t mlkem_ss_bob[CRYPTO_BYTES];

    // X25519 contexts
    mbedtls_ecp_group grp;
    mbedtls_mpi alice_d, bob_d;
    mbedtls_ecp_point alice_Q, bob_Q;
    mbedtls_mpi shared_alice, shared_bob;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

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

    const char *pers = "parallel_mlkem_bench";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: %d", ret);
        goto end_task;
    }

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load Curve25519: %d", ret);
        goto end_task;
    }

    // Warm-up
    {
        ESP_LOGI(TAG, "Warm-up: ML-KEM keypair...");
        int rc = crypto_kem_keypair(mlkem_pk, mlkem_sk);
        if (rc != 0) { ESP_LOGE(TAG, "Warm-up ML-KEM keypair failed"); goto end_task; }

        ESP_LOGI(TAG, "Warm-up: X25519 keygen...");
        ret = mbedtls_ecdh_gen_public(&grp, &alice_d, &alice_Q,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) { ESP_LOGE(TAG, "Warm-up X25519 failed"); goto end_task; }

        ESP_LOGI(TAG, "Warm-up: done");
    }

    const size_t trials = local_cfg.trials;

    size_t free_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t largest_before = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    ESP_LOGI(TAG, "Heap before alloc: free=%u bytes, largest=%u bytes",
             (unsigned)free_before, (unsigned)largest_before);

    alice_seg_a_wall = (uint32_t *)malloc(trials * sizeof(uint32_t));
    alice_seg_b_wall = (uint32_t *)malloc(trials * sizeof(uint32_t));
    bob_seg_a_wall = (uint32_t *)malloc(trials * sizeof(uint32_t));
    bob_dh_cyc = (uint32_t *)malloc(trials * sizeof(uint32_t));
    
    if (!alice_seg_a_wall || !alice_seg_b_wall || !bob_seg_a_wall || !bob_dh_cyc) {
        ESP_LOGE(TAG, "Allocation failed for cycle arrays");
        goto end_task;
    }

    ESP_LOGI(TAG, "Allocated cycle arrays for %u trials", (unsigned)trials);
    ESP_LOGI(TAG, "Starting %u trials...", (unsigned)trials);

    // Parallel workers setup
    mlk_worker_t mlk_w = {0};
    x25519_worker_t x_w = {0};
    mlk_w.start_sem = xSemaphoreCreateBinary();
    mlk_w.done_sem  = xSemaphoreCreateBinary();
    x_w.start_sem   = xSemaphoreCreateBinary();
    x_w.done_sem    = xSemaphoreCreateBinary();
    x_w.grp = &grp;
    x_w.ctr = &ctr_drbg;
    if (!mlk_w.start_sem || !mlk_w.done_sem || !x_w.start_sem || !x_w.done_sem) {
        ESP_LOGE(TAG, "Failed to create semaphores");
        goto end_task;
    }
    TaskHandle_t mlk_th = NULL, x_th = NULL;
    if (xTaskCreatePinnedToCore(mlk_worker_task, "parallel_mlkem_", MLK_WORKER_STACK_WORDS, &mlk_w, 5, &mlk_th, 0) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create ML-KEM worker");
        goto end_task;
    }
    if (xTaskCreatePinnedToCore(x25519_worker_task, "parallel_x25519", X25519_WORKER_STACK_WORDS, &x_w, 5, &x_th, 1) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create X25519 worker");
        goto end_task;
    }

    for (size_t i = 0; i < trials; ++i) {
        int rc;
        
        // ===== Alice Segment A: ML-KEM keygen || X25519 keygen =====
        mlk_w.op = MLK_OP_KEYGEN;
        mlk_w.pk = mlkem_pk; mlk_w.sk = mlkem_sk;
        x_w.op = X_OP_KEYGEN;
        x_w.d_priv = &alice_d; x_w.Q_pub = &alice_Q; x_w.Q_peer = NULL; x_w.shared_out = NULL;
        xSemaphoreGive(mlk_w.start_sem);
        xSemaphoreGive(x_w.start_sem);
        xSemaphoreTake(mlk_w.done_sem, portMAX_DELAY);
        xSemaphoreTake(x_w.done_sem, portMAX_DELAY);
        if (mlk_w.rc != 0 || x_w.rc != 0) { ESP_LOGE(TAG, "Alice segment A failed"); goto end_task; }
        alice_seg_a_wall[i] = (mlk_w.cycles > x_w.cycles) ? mlk_w.cycles : x_w.cycles;

        // Bob needs Alice's PK for encaps
        ret = mbedtls_ecdh_gen_public(&grp, &bob_d, &bob_Q,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        rc = crypto_kem_enc(mlkem_ct, mlkem_ss_bob, mlkem_pk);
        if (ret != 0 || rc != 0) {
            ESP_LOGE(TAG, "Bob setup failed"); goto end_task;
        }

        // ===== Alice Segment B: ML-KEM decaps || X25519 DH =====
        mlk_w.op = MLK_OP_DECAPS;
        mlk_w.ct = mlkem_ct; mlk_w.sk = mlkem_sk; mlk_w.ss = mlkem_ss_alice;
        x_w.op = X_OP_DH;
        x_w.d_priv = &alice_d; x_w.Q_peer = &bob_Q; x_w.shared_out = &shared_alice;
        xSemaphoreGive(mlk_w.start_sem);
        xSemaphoreGive(x_w.start_sem);
        xSemaphoreTake(mlk_w.done_sem, portMAX_DELAY);
        xSemaphoreTake(x_w.done_sem, portMAX_DELAY);
        if (mlk_w.rc != 0 || x_w.rc != 0) { ESP_LOGE(TAG, "Alice segment B failed"); goto end_task; }
        alice_seg_b_wall[i] = (mlk_w.cycles > x_w.cycles) ? mlk_w.cycles : x_w.cycles;

        // ===== Bob measurements (fresh run) =====
        // Alice creates keys again
        ret = mbedtls_ecdh_gen_public(&grp, &alice_d, &alice_Q,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        rc = crypto_kem_keypair(mlkem_pk, mlkem_sk);
        if (ret != 0 || rc != 0) {
            ESP_LOGE(TAG, "Alice re-keygen failed"); goto end_task;
        }

        // Bob Segment A: X25519 keygen || ML-KEM encaps
        mlk_w.op = MLK_OP_ENCAPS;
        mlk_w.pk = mlkem_pk; mlk_w.ct = mlkem_ct; mlk_w.ss = mlkem_ss_bob;
        x_w.op = X_OP_KEYGEN;
        x_w.d_priv = &bob_d; x_w.Q_pub = &bob_Q; x_w.Q_peer = NULL; x_w.shared_out = NULL;
        xSemaphoreGive(mlk_w.start_sem);
        xSemaphoreGive(x_w.start_sem);
        xSemaphoreTake(mlk_w.done_sem, portMAX_DELAY);
        xSemaphoreTake(x_w.done_sem, portMAX_DELAY);
        if (mlk_w.rc != 0 || x_w.rc != 0) { ESP_LOGE(TAG, "Bob segment A failed"); goto end_task; }
        bob_seg_a_wall[i] = (mlk_w.cycles > x_w.cycles) ? mlk_w.cycles : x_w.cycles;

        // Bob DH standalone
        x_w.op = X_OP_DH;
        x_w.d_priv = &bob_d; x_w.Q_peer = &alice_Q; x_w.shared_out = &shared_bob;
        xSemaphoreGive(x_w.start_sem);
        xSemaphoreTake(x_w.done_sem, portMAX_DELAY);
        if (x_w.rc != 0) { ESP_LOGE(TAG, "Bob DH failed"); goto end_task; }
        bob_dh_cyc[i] = x_w.cycles;

#if BENCH_LED_BLINK_EVERY > 0
        if (((i + 1) % BENCH_LED_BLINK_EVERY) == 0) {
            toggle_progress_led();
        }
#endif

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
    uint32_t alice_seg_a_median = 0, alice_seg_b_median = 0;
    uint32_t bob_seg_a_median = 0, bob_dh_median = 0;
    uint32_t alice_seg_a_avg = 0, alice_seg_b_avg = 0;
    uint32_t bob_seg_a_avg = 0, bob_dh_avg = 0;

    bench_compute_median_u32(alice_seg_a_wall, trials, &alice_seg_a_median);
    bench_compute_median_u32(alice_seg_b_wall, trials, &alice_seg_b_median);
    bench_compute_median_u32(bob_seg_a_wall, trials, &bob_seg_a_median);
    bench_compute_median_u32(bob_dh_cyc, trials, &bob_dh_median);

    bench_compute_avg_u32(alice_seg_a_wall, trials, &alice_seg_a_avg);
    bench_compute_avg_u32(alice_seg_b_wall, trials, &alice_seg_b_avg);
    bench_compute_avg_u32(bob_seg_a_wall, trials, &bob_seg_a_avg);
    bench_compute_avg_u32(bob_dh_cyc, trials, &bob_dh_avg);

    // Report results: show both median and mean
    ESP_LOGI(TAG, "=== Phase 7 Results (ML-KEM-512 + X25519 Parallel Overlap) ===");
    log_result("Alice Segment A[median]", alice_seg_a_median, 0);
    log_result("Alice Segment A[mean]", alice_seg_a_avg, 0);
    log_result("Alice Segment B[median]", alice_seg_b_median, 0);
    log_result("Alice Segment B[mean]", alice_seg_b_avg, 0);

    uint32_t alice_total_median = alice_seg_a_median + alice_seg_b_median;
    uint32_t alice_total_avg = alice_seg_a_avg + alice_seg_b_avg;
    log_result("Alice TOTAL[median]", alice_total_median, 0);
    log_result("Alice TOTAL[mean]", alice_total_avg, 0);

    log_result("Bob Segment A[median]", bob_seg_a_median, 0);
    log_result("Bob Segment A[mean]", bob_seg_a_avg, 0);
    log_result("Bob DH[median]", bob_dh_median, 0);
    log_result("Bob DH[mean]", bob_dh_avg, 0);

    uint32_t bob_total_median = bob_seg_a_median + bob_dh_median;
    uint32_t bob_total_avg = bob_seg_a_avg + bob_dh_avg;
    log_result("Bob TOTAL[median]", bob_total_median, 0);
    log_result("Bob TOTAL[mean]", bob_total_avg, 0);

    // Compute stddev and percentiles (always using actual mean, never median)
    uint32_t alice_seg_a_stddev = 0, alice_seg_b_stddev = 0;
    uint32_t alice_seg_a_p5 = 0, alice_seg_a_p95 = 0;
    uint32_t alice_seg_b_p5 = 0, alice_seg_b_p95 = 0;

    bench_compute_stddev_u32(alice_seg_a_wall, trials, alice_seg_a_avg, &alice_seg_a_stddev);
    bench_compute_stddev_u32(alice_seg_b_wall, trials, alice_seg_b_avg, &alice_seg_b_stddev);
    bench_compute_percentile_u32(alice_seg_a_wall, trials, 5, &alice_seg_a_p5);
    bench_compute_percentile_u32(alice_seg_a_wall, trials, 95, &alice_seg_a_p95);
    bench_compute_percentile_u32(alice_seg_b_wall, trials, 5, &alice_seg_b_p5);
    bench_compute_percentile_u32(alice_seg_b_wall, trials, 95, &alice_seg_b_p95);

    ESP_LOGI(TAG, "Alice Segment A: median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
             alice_seg_a_median, alice_seg_a_avg, alice_seg_a_stddev, alice_seg_a_p5, alice_seg_a_p95);
    ESP_LOGI(TAG, "Alice Segment B: median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
             alice_seg_b_median, alice_seg_b_avg, alice_seg_b_stddev, alice_seg_b_p5, alice_seg_b_p95);

    uint32_t bob_seg_a_stddev = 0, bob_dh_stddev = 0;
    uint32_t bob_seg_a_p5 = 0, bob_seg_a_p95 = 0;
    uint32_t bob_dh_p5 = 0, bob_dh_p95 = 0;

    bench_compute_stddev_u32(bob_seg_a_wall, trials, bob_seg_a_avg, &bob_seg_a_stddev);
    bench_compute_stddev_u32(bob_dh_cyc, trials, bob_dh_avg, &bob_dh_stddev);
    bench_compute_percentile_u32(bob_seg_a_wall, trials, 5, &bob_seg_a_p5);
    bench_compute_percentile_u32(bob_seg_a_wall, trials, 95, &bob_seg_a_p95);
    bench_compute_percentile_u32(bob_dh_cyc, trials, 5, &bob_dh_p5);
    bench_compute_percentile_u32(bob_dh_cyc, trials, 95, &bob_dh_p95);

    ESP_LOGI(TAG, "Bob Segment A: median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
             bob_seg_a_median, bob_seg_a_avg, bob_seg_a_stddev, bob_seg_a_p5, bob_seg_a_p95);
    ESP_LOGI(TAG, "Bob DH: median=%u mean=%u σ=%u p5=%u p95=%u (cycles)",
             bob_dh_median, bob_dh_avg, bob_dh_stddev, bob_dh_p5, bob_dh_p95);

    ESP_LOGI(TAG, "=== Benchmark Complete ===");

end_task:
    // Report stack high-water marks (in words) before cleaning up
    {
        UBaseType_t orch_hwm = uxTaskGetStackHighWaterMark(NULL);
        UBaseType_t mlk_hwm = (mlk_th) ? uxTaskGetStackHighWaterMark(mlk_th) : 0;
        UBaseType_t x_hwm   = (x_th)   ? uxTaskGetStackHighWaterMark(x_th)   : 0;
        ESP_LOGI(TAG, "Stack high-water marks (words): orchestrator=%u, ML-KEM worker=%u, X25519 worker=%u",
                 (unsigned)orch_hwm, (unsigned)mlk_hwm, (unsigned)x_hwm);
    }

    if (alice_seg_a_wall) free(alice_seg_a_wall);
    if (alice_seg_b_wall) free(alice_seg_b_wall);
    if (bob_seg_a_wall) free(bob_seg_a_wall);
    if (bob_dh_cyc) free(bob_dh_cyc);

    // Clean up worker tasks and semaphores
    if (mlk_th) {
        vTaskDelete(mlk_th);
    }
    if (x_th) {
        vTaskDelete(x_th);
    }
    if (mlk_w.start_sem) vSemaphoreDelete(mlk_w.start_sem);
    if (mlk_w.done_sem) vSemaphoreDelete(mlk_w.done_sem);
    if (x_w.start_sem) vSemaphoreDelete(x_w.start_sem);
    if (x_w.done_sem) vSemaphoreDelete(x_w.done_sem);

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

void bench_parallel_mlkem_start(const bench_config_t *cfg)
{
    bench_config_t *arg = (bench_config_t *)malloc(sizeof(bench_config_t));
    if (arg) {
        *arg = *cfg;
    }
    
    xTaskCreate(parallel_mlkem_bench_task, "parallel_mlkem_bench",
                BENCH_TASK_STACK_WORDS, arg, 5, NULL);
}
