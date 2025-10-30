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
#include "bench_parallel_hqc.h"

// HQC via PQClean
#include "api.h"
#include "randombytes.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"

static const char *TAG = "hqc_parallel_phase8";

// Stack sizing (expressed in FreeRTOS words for consistency)
// HQC requires large stack due to deep Karatsuba recursion in warm-up and worker
#ifndef BENCH_TASK_STACK_WORDS
#define BENCH_TASK_STACK_WORDS 65536   // 256 KB orchestrator (HQC warm-up needs Karatsuba recursion)
#endif
#ifndef HQC_WORKER_STACK_WORDS
#define HQC_WORKER_STACK_WORDS 65536   // 256 KB HQC worker (deep Karatsuba recursion)
#endif
#ifndef X25519_WORKER_STACK_WORDS
#define X25519_WORKER_STACK_WORDS 6144 // 24 KB X25519 worker
#endif

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
    HQC_OP_NONE = 0,
    HQC_OP_KEYGEN,
    HQC_OP_DECAPS,
    HQC_OP_ENCAPS,
} hqc_op_t;

typedef enum {
    X_OP_NONE = 0,
    X_OP_KEYGEN,
    X_OP_DH,
} x25519_op_t;

typedef struct {
    // sync
    SemaphoreHandle_t start_sem;
    SemaphoreHandle_t done_sem;
    volatile hqc_op_t op;
    volatile uint32_t cycles;
    volatile int rc;
    // HQC buffers
    uint8_t *pk;
    uint8_t *sk;
    uint8_t *ct;
    uint8_t *ss;
} hqc_worker_t;

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

static void hqc_worker_task(void *arg)
{
    hqc_worker_t *w = (hqc_worker_t *)arg;
    for (;;) {
        xSemaphoreTake(w->start_sem, portMAX_DELAY);
        uint32_t s = bench_cycles_now();
        int rc = 0;
        switch (w->op) {
            case HQC_OP_KEYGEN:
                rc = PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(w->pk, w->sk);
                break;
            case HQC_OP_DECAPS:
                rc = PQCLEAN_HQC128_CLEAN_crypto_kem_dec(w->ss, w->ct, w->sk);
                break;
            case HQC_OP_ENCAPS:
                rc = PQCLEAN_HQC128_CLEAN_crypto_kem_enc(w->ct, w->ss, w->pk);
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

static void parallel_hqc_bench_task(void *arg)
{
    bench_config_t local_cfg = {
        .phase = BENCH_PHASE8_HQC_PARALLEL,
        .trials = 25,
        .metric = BENCH_METRIC_MEDIAN,
    };
    if (arg) {
        local_cfg = *(const bench_config_t *)arg;
        free(arg);
    }

    init_progress_led();

    ESP_LOGI(TAG, "Phase 8: HQC-128 + X25519 Hybrid (Parallel overlap only)");
    ESP_LOGI(TAG, "Dual-core workers (Core0=HQC, Core1=X25519); segment wall-time = max(worker cycles)");
    ESP_LOGI(TAG, "Configured stack sizes (words): orchestrator=%u, HQC worker=%u, X25519 worker=%u",
             (unsigned)BENCH_TASK_STACK_WORDS,
             (unsigned)HQC_WORKER_STACK_WORDS,
             (unsigned)X25519_WORKER_STACK_WORDS);
#if CONFIG_FREERTOS_UNICORE
    ESP_LOGW(TAG, "Single-core configuration detected — parallel overlap requires dual-core for intended results");
#endif
    ESP_LOGI(TAG, "HQC: ~500M-2B cycles vs X25519: ~27-30M cycles");

    // Declare cycle arrays early (before any goto)
    uint32_t *alice_seg_a_wall = NULL;
    uint32_t *alice_seg_b_wall = NULL;
    uint32_t *bob_seg_a_wall = NULL;
    uint32_t *bob_dh_cyc = NULL;

    // HQC buffers
    uint8_t hqc_pk[PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t hqc_sk[PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t hqc_ct[PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t hqc_ss_alice[PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES];
    uint8_t hqc_ss_bob[PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES];

    // X25519 contexts
    mbedtls_ecp_group grp;
    mbedtls_mpi alice_d, bob_d;
    mbedtls_ecp_point alice_Q, bob_Q;
    mbedtls_mpi shared_alice, shared_bob;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    ESP_LOGI(TAG, "HQC sizes: pk=%d sk=%d ct=%d shared=%d",
             PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES,
             PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES,
             PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
             PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES);
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

    const char *pers = "parallel_hqc_bench";
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

    // Create parallel workers before warm-up so heavy HQC ops run on worker stack
    hqc_worker_t hqc_w = {0};
    x25519_worker_t x_w = {0};
    hqc_w.start_sem = xSemaphoreCreateBinary();
    hqc_w.done_sem  = xSemaphoreCreateBinary();
    x_w.start_sem   = xSemaphoreCreateBinary();
    x_w.done_sem    = xSemaphoreCreateBinary();
    x_w.grp = &grp;
    x_w.ctr = &ctr_drbg;
    if (!hqc_w.start_sem || !hqc_w.done_sem || !x_w.start_sem || !x_w.done_sem) {
        ESP_LOGE(TAG, "Failed to create semaphores");
        goto end_task;
    }
    TaskHandle_t hqc_th = NULL, x_th = NULL;
    if (xTaskCreatePinnedToCore(hqc_worker_task, "parallel_hqc_", HQC_WORKER_STACK_WORDS, &hqc_w, 0, &hqc_th, 0) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create HQC worker");
        goto end_task;
    }
    if (xTaskCreatePinnedToCore(x25519_worker_task, "parallel_x25519", X25519_WORKER_STACK_WORDS, &x_w, 0, &x_th, 1) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create X25519 worker");
        goto end_task;
    }

    // DIAGNOSTIC TEST: HQC directly in orchestrator (before worker warm-up)
    // This isolates whether the issue is with worker threading or HQC library itself
    {
        static uint8_t diag_pk[PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES];
        static uint8_t diag_sk[PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES];
        static uint8_t diag_ct[PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        static uint8_t diag_ss_enc[PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES];
        static uint8_t diag_ss_dec[PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES];

        ESP_LOGI(TAG, "=== DIAGNOSTIC: Direct HQC test (no workers) ===");
        int rc_kg = PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(diag_pk, diag_sk);
        ESP_LOGI(TAG, "Direct keygen: rc=%d", rc_kg);
        if (rc_kg != 0) {
            ESP_LOGE(TAG, "DIAG: Direct keygen FAILED");
            goto end_task;
        }

        int rc_enc = PQCLEAN_HQC128_CLEAN_crypto_kem_enc(diag_ct, diag_ss_enc, diag_pk);
        ESP_LOGI(TAG, "Direct encaps: rc=%d, ss[0:4]=%02x%02x%02x%02x",
                 rc_enc, diag_ss_enc[0], diag_ss_enc[1], diag_ss_enc[2], diag_ss_enc[3]);
        if (rc_enc != 0) {
            ESP_LOGE(TAG, "DIAG: Direct encaps FAILED");
            goto end_task;
        }

        int rc_dec = PQCLEAN_HQC128_CLEAN_crypto_kem_dec(diag_ss_dec, diag_ct, diag_sk);
        ESP_LOGI(TAG, "Direct decaps: rc=%d, ss[0:4]=%02x%02x%02x%02x",
                 rc_dec, diag_ss_dec[0], diag_ss_dec[1], diag_ss_dec[2], diag_ss_dec[3]);
        if (rc_dec != 0) {
            ESP_LOGE(TAG, "DIAG: Direct decaps FAILED with rc=%d — HQC library issue (not worker-related)", rc_dec);
            goto end_task;
        }

        // Verify shared secret agreement
        if (memcmp(diag_ss_enc, diag_ss_dec, PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES) != 0) {
            ESP_LOGW(TAG, "DIAG: Direct shared secret MISMATCH");
            goto end_task;
        }

        ESP_LOGI(TAG, "✓ DIAGNOSTIC PASSED: Direct HQC works fine — Worker issue is likely");
        ESP_LOGI(TAG, "=== END DIAGNOSTIC ===");
    }

    // Warm-up: Exercise all hot paths to avoid first-iteration anomalies
    {
        static uint8_t warm_ct[PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        static uint8_t warm_ss[PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES];

        ESP_LOGI(TAG, "Warm-up: HQC keypair...");
        hqc_w.op = HQC_OP_KEYGEN;
        hqc_w.pk = hqc_pk; hqc_w.sk = hqc_sk;
        xSemaphoreGive(hqc_w.start_sem);
        xSemaphoreTake(hqc_w.done_sem, portMAX_DELAY);
        if (hqc_w.rc != 0) {
            ESP_LOGE(TAG, "Warm-up HQC keypair failed: rc=%d", hqc_w.rc);
            goto end_task;
        }

        static uint8_t warm_ss_enc[PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES];  // separate buffer to detect mismatch
        static uint8_t warm_ct_saved[PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES];  // save ct to detect corruption

        ESP_LOGI(TAG, "Warm-up: HQC encaps...");
        memset(warm_ct, 0, sizeof(warm_ct));
        memset(warm_ss, 0, sizeof(warm_ss));
        memset(warm_ss_enc, 0, sizeof(warm_ss_enc));
        // Run encaps on the HQC worker to ensure identical stack/ctx as decaps
        hqc_w.op = HQC_OP_ENCAPS;
        hqc_w.pk = hqc_pk; hqc_w.ct = warm_ct; hqc_w.ss = warm_ss_enc;
        xSemaphoreGive(hqc_w.start_sem);
        xSemaphoreTake(hqc_w.done_sem, portMAX_DELAY);
        if (hqc_w.rc != 0) {
            ESP_LOGE(TAG, "Warm-up HQC encaps failed: rc=%d", hqc_w.rc);
            goto end_task;
        }
        ESP_LOGI(TAG, "  encaps OK: ss[0:4]=%02x%02x%02x%02x",
                 warm_ss_enc[0], warm_ss_enc[1], warm_ss_enc[2], warm_ss_enc[3]);
        ESP_LOGI(TAG, "  ct[0:8]=%02x%02x%02x%02x%02x%02x%02x%02x (after encaps)",
                 warm_ct[0], warm_ct[1], warm_ct[2], warm_ct[3],
                 warm_ct[4], warm_ct[5], warm_ct[6], warm_ct[7]);

        // Save ciphertext before decaps to detect if it gets corrupted
        memcpy(warm_ct_saved, warm_ct, sizeof(warm_ct));

        ESP_LOGI(TAG, "Warm-up: HQC decaps...");
        hqc_w.op = HQC_OP_DECAPS;
        hqc_w.sk = hqc_sk; hqc_w.ct = warm_ct; hqc_w.ss = warm_ss;
        xSemaphoreGive(hqc_w.start_sem);
        xSemaphoreTake(hqc_w.done_sem, portMAX_DELAY);

        // Check if ciphertext was corrupted during decaps
        if (memcmp(warm_ct_saved, warm_ct, sizeof(warm_ct)) != 0) {
            ESP_LOGW(TAG, "  ⚠ CIPHERTEXT CORRUPTED during decaps!");
            ESP_LOGW(TAG, "  ct[0:8] before: %02x%02x%02x%02x%02x%02x%02x%02x",
                     warm_ct_saved[0], warm_ct_saved[1], warm_ct_saved[2], warm_ct_saved[3],
                     warm_ct_saved[4], warm_ct_saved[5], warm_ct_saved[6], warm_ct_saved[7]);
            ESP_LOGW(TAG, "  ct[0:8] after:  %02x%02x%02x%02x%02x%02x%02x%02x",
                     warm_ct[0], warm_ct[1], warm_ct[2], warm_ct[3],
                     warm_ct[4], warm_ct[5], warm_ct[6], warm_ct[7]);
        }

        if (hqc_w.rc != 0) {
            ESP_LOGE(TAG, "Warm-up HQC decaps FAILED: rc=%d", hqc_w.rc);
            ESP_LOGE(TAG, "  buffer sizes: pk=%u sk=%u ct=%u ss=%u",
                     PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES,
                     PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES,
                     PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                     PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES);
            ESP_LOGE(TAG, "  encaps ss[0:4]=%02x%02x%02x%02x (pre-decaps)",
                     warm_ss_enc[0], warm_ss_enc[1], warm_ss_enc[2], warm_ss_enc[3]);
            goto end_task;
        }
        ESP_LOGI(TAG, "  decaps OK: ss[0:4]=%02x%02x%02x%02x",
                 warm_ss[0], warm_ss[1], warm_ss[2], warm_ss[3]);

        // Verify agreement
        if (memcmp(warm_ss_enc, warm_ss, PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES) != 0) {
            ESP_LOGW(TAG, "  ⚠ Shared secret MISMATCH! encaps≠decaps");
            goto end_task;
        }

        ESP_LOGI(TAG, "Warm-up: X25519 keygen...");
        x_w.op = X_OP_KEYGEN;
        x_w.d_priv = &alice_d; x_w.Q_pub = &alice_Q; x_w.Q_peer = NULL; x_w.shared_out = NULL;
        xSemaphoreGive(x_w.start_sem);
        xSemaphoreTake(x_w.done_sem, portMAX_DELAY);
        if (x_w.rc != 0) { ESP_LOGE(TAG, "Warm-up X25519 failed"); goto end_task; }

        // TEST: Try encaps/decaps directly in orchestrator (not via worker) to isolate issue
        ESP_LOGI(TAG, "Warm-up: Testing direct encaps/decaps (orchestrator, no worker)...");
        {
            static uint8_t test_pk[PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES];
            static uint8_t test_sk[PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES];
            static uint8_t test_ct[PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            static uint8_t test_ss_enc[PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES];
            static uint8_t test_ss_dec[PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES];

            int rc1 = PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(test_pk, test_sk);
            int rc2 = PQCLEAN_HQC128_CLEAN_crypto_kem_enc(test_ct, test_ss_enc, test_pk);
            int rc3 = PQCLEAN_HQC128_CLEAN_crypto_kem_dec(test_ss_dec, test_ct, test_sk);

            ESP_LOGI(TAG, "  direct test: keygen=%d encaps=%d decaps=%d", rc1, rc2, rc3);
            if (rc3 == 0 && memcmp(test_ss_enc, test_ss_dec, PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES) == 0) {
                ESP_LOGI(TAG, "  direct test PASSED (no worker needed)");
            } else {
                ESP_LOGE(TAG, "  direct test FAILED: rc3=%d, ss_match=%d",
                         rc3, memcmp(test_ss_enc, test_ss_dec, PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES) == 0 ? 1 : 0);
            }
        }

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

    // Workers already created above for warm-up

    ESP_LOGI(TAG, "Starting %u trials...", (unsigned)trials);

    for (size_t i = 0; i < trials; ++i) {
        int rc;

        // Clear all HQC buffers before each trial
        memset(hqc_pk, 0, sizeof(hqc_pk));
        memset(hqc_sk, 0, sizeof(hqc_sk));
        memset(hqc_ct, 0, sizeof(hqc_ct));
        memset(hqc_ss_alice, 0, sizeof(hqc_ss_alice));
        memset(hqc_ss_bob, 0, sizeof(hqc_ss_bob));

        // ===== Alice Segment A: HQC keygen || X25519 keygen =====
        hqc_w.op = HQC_OP_KEYGEN;
        hqc_w.pk = hqc_pk; hqc_w.sk = hqc_sk;
        x_w.op = X_OP_KEYGEN;
        x_w.d_priv = &alice_d; x_w.Q_pub = &alice_Q; x_w.Q_peer = NULL; x_w.shared_out = NULL;
        xSemaphoreGive(hqc_w.start_sem);
        xSemaphoreGive(x_w.start_sem);
        xSemaphoreTake(hqc_w.done_sem, portMAX_DELAY);
        xSemaphoreTake(x_w.done_sem, portMAX_DELAY);
        if (hqc_w.rc != 0 || x_w.rc != 0) { ESP_LOGE(TAG, "Alice segment A failed"); goto end_task; }
        alice_seg_a_wall[i] = (hqc_w.cycles > x_w.cycles) ? hqc_w.cycles : x_w.cycles;

        // Bob needs Alice's PK for encaps
        ret = mbedtls_ecdh_gen_public(&grp, &bob_d, &bob_Q,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        rc = PQCLEAN_HQC128_CLEAN_crypto_kem_enc(hqc_ct, hqc_ss_bob, hqc_pk);
        if (ret != 0 || rc != 0) {
            ESP_LOGE(TAG, "Bob setup failed"); goto end_task;
        }

        // ===== Alice Segment B: HQC decaps || X25519 DH =====
        ESP_LOGD(TAG, "Trial %u: Alice Segment B starting, using ct_size=%u, sk_size=%u", 
                 (unsigned)i, PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES);
        hqc_w.op = HQC_OP_DECAPS;
        hqc_w.ct = hqc_ct; hqc_w.sk = hqc_sk; hqc_w.ss = hqc_ss_alice;
        x_w.op = X_OP_DH;
        x_w.d_priv = &alice_d; x_w.Q_peer = &bob_Q; x_w.shared_out = &shared_alice;
        xSemaphoreGive(hqc_w.start_sem);
        xSemaphoreGive(x_w.start_sem);
        xSemaphoreTake(hqc_w.done_sem, portMAX_DELAY);
        xSemaphoreTake(x_w.done_sem, portMAX_DELAY);
        if (hqc_w.rc != 0 || x_w.rc != 0) {
            ESP_LOGE(TAG, "Alice segment B failed on trial %u: HQC decaps rc=%d, X25519 DH rc=%d", 
                     (unsigned)i, hqc_w.rc, x_w.rc);
            goto end_task;
        }

        // Sanity check: Compare shared secrets (outside timing window)
        int ss_mismatch = memcmp(hqc_ss_alice, hqc_ss_bob, PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES);
        if (ss_mismatch != 0) {
            ESP_LOGE(TAG, "Trial %u: Shared secret mismatch! Alice/Bob decapsulation agreement failed",
                     (unsigned)i);
            goto end_task;
        }

        alice_seg_b_wall[i] = (hqc_w.cycles > x_w.cycles) ? hqc_w.cycles : x_w.cycles;

        // ===== Bob measurements (fresh run) =====
        // Alice creates keys again
        ret = mbedtls_ecdh_gen_public(&grp, &alice_d, &alice_Q,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        rc = PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(hqc_pk, hqc_sk);
        if (ret != 0 || rc != 0) {
            ESP_LOGE(TAG, "Alice re-keygen failed"); goto end_task;
        }

        // Bob Segment A: X25519 keygen || HQC encaps
        hqc_w.op = HQC_OP_ENCAPS;
        hqc_w.pk = hqc_pk; hqc_w.ct = hqc_ct; hqc_w.ss = hqc_ss_bob;
        x_w.op = X_OP_KEYGEN;
        x_w.d_priv = &bob_d; x_w.Q_pub = &bob_Q; x_w.Q_peer = NULL; x_w.shared_out = NULL;
        xSemaphoreGive(hqc_w.start_sem);
        xSemaphoreGive(x_w.start_sem);
        xSemaphoreTake(hqc_w.done_sem, portMAX_DELAY);
        xSemaphoreTake(x_w.done_sem, portMAX_DELAY);
        if (hqc_w.rc != 0 || x_w.rc != 0) { ESP_LOGE(TAG, "Bob segment A failed"); goto end_task; }
        bob_seg_a_wall[i] = (hqc_w.cycles > x_w.cycles) ? hqc_w.cycles : x_w.cycles;

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
    ESP_LOGI(TAG, "=== Phase 8 Results (HQC-128 + X25519 Parallel Overlap) ===");
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
        UBaseType_t hqc_hwm = (hqc_th) ? uxTaskGetStackHighWaterMark(hqc_th) : 0;
        UBaseType_t x_hwm   = (x_th)   ? uxTaskGetStackHighWaterMark(x_th)   : 0;
        ESP_LOGI(TAG, "Stack high-water marks (words): orchestrator=%u, HQC worker=%u, X25519 worker=%u",
                 (unsigned)orch_hwm, (unsigned)hqc_hwm, (unsigned)x_hwm);
    }

    if (alice_seg_a_wall) free(alice_seg_a_wall);
    if (alice_seg_b_wall) free(alice_seg_b_wall);
    if (bob_seg_a_wall) free(bob_seg_a_wall);
    if (bob_dh_cyc) free(bob_dh_cyc);

    // Clean up worker tasks and semaphores
    if (hqc_th) {
        vTaskDelete(hqc_th);
    }
    if (x_th) {
        vTaskDelete(x_th);
    }
    if (hqc_w.start_sem) vSemaphoreDelete(hqc_w.start_sem);
    if (hqc_w.done_sem) vSemaphoreDelete(hqc_w.done_sem);
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

void bench_parallel_hqc_start(const bench_config_t *cfg)
{
    bench_config_t *arg = (bench_config_t *)malloc(sizeof(bench_config_t));
    if (arg) {
        *arg = *cfg;
    }
    
    xTaskCreate(parallel_hqc_bench_task, "parallel_hqc_bench",
                BENCH_TASK_STACK_WORDS, arg, 0, NULL);
}
