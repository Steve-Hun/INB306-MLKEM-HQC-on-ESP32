# ML-KEM & HQC Benchmarking on ESP32

Benchmarks for post-quantum cryptographic KEMs on ESP32-WROOM-32 @ 240 MHz. Measures ML-KEM-512, HQC-128, and hybrid combinations with X25519.

---

## Quick Start

### Prerequisites

- ESP32-WROOM-32 development board
- ESP-IDF v5.0+ ([installation guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html))
- Git

### Setup

Clone external dependencies at the same level as this project:

```bash
mkdir -p pq-crypto && cd pq-crypto

git clone https://github.com/pq-code-package/mlkem-native.git
git clone https://github.com/PQClean/PQClean.git
git clone https://github.com/Mbed-TLS/mbedtls.git

# Directory structure:
# pq-crypto/
# ├── mlkem-native/
# ├── PQClean/
# ├── mbedtls/
# └── mlkem_primitives/  (this repo)
```

### Build & Flash

```bash
cd mlkem_primitives

idf.py set-target esp32
idf.py build

# Adjust port for your system
idf.py -p /dev/tty.usbserial-0001 flash monitor
```

---

## Configuration

Edit `main/app_main.c` to change settings:

```c
#define BENCH_DEFAULT_PHASE BENCH_PHASE1_MLKEM  // Phase to run
#define BENCH_DEFAULT_TRIALS 100                 // 10-100 trials
#define BENCH_DEFAULT_METRIC BENCH_METRIC_MEDIAN // Median/mean
```

**Phases:**
- `BENCH_PHASE1_MLKEM` – ML-KEM-512 baseline
- `BENCH_PHASE3_HQC` – HQC-128 baseline
- `BENCH_PHASE4_X25519_SEQ` – ML-KEM + X25519 (sequential)
- `BENCH_PHASE6_HQC_HYBRID` – HQC + X25519 (sequential)
- `BENCH_PHASE7_MLKEM_PARALLEL` – ML-KEM + X25519 (parallel)
- `BENCH_PHASE8_HQC_PARALLEL` – HQC + X25519 (parallel)

**Trial counts:**
- 10 trials: ~30 seconds
- 100 trials: ~5–10 minutes 

---

## Troubleshooting

**Build fails (missing dependencies):** Ensure all three repos (mlkem-native, PQClean, mbedtls) are cloned at the same level. Run from the project root, not a subdirectory.

**Flash fails:** Check your USB port:
- Linux: `ls /dev/ttyUSB*` (may need `sudo usermod -a -G dialout $USER`)
- macOS: `ls /dev/tty.usb*`
- Windows: Check Device Manager for COM port

**HQC crashes/timeout:** HQC is ~150× slower than ML-KEM. Increase watchdog timeout in `sdkconfig.defaults`:
```
CONFIG_ESP_TASK_WDT_TIMEOUT_S=60
```

**Stack overflow:** Edit `main/bench_*.h`:
```c
#define BENCH_TASK_STACK_WORDS (384 * 1024 / sizeof(StackType_t))
```

---

## Project Structure

```
main/
├── app_main.c              // Phase selection
├── bench_mlkem.c / .h      // ML-KEM benchmarks
├── bench_hqc.c / .h        // HQC benchmarks
├── bench_hybrid_*.c / .h   // Hybrid benchmarks
├── bench_parallel_*.c / .h // Parallel benchmarks
└── bench_common.c / .h     // Shared utilities

components/
├── mlkem_native_port/      // ML-KEM integration
└── hqc_port/               // HQC integration
```

---

## Hardware

| Spec | Details |
|------|---------|
| MCU | ESP32-WROOM-32 (dual-core, 240 MHz) |
| RAM | 520 KB SRAM + 4 MB PSRAM |
| RNG | Hardware TRNG (`esp_fill_random()`) |

---

## Dependencies

- [mlkem-native](https://github.com/pq-code-package/mlkem-native) – ML-KEM-512 (Apache 2.0 / MIT)
- [PQClean](https://github.com/PQClean/PQClean) – HQC-128 (CC0)
- [mbedtls](https://github.com/Mbed-TLS/mbedtls) – X25519 (Apache 2.0)
- [ESP-IDF](https://github.com/espressif/esp-idf) – IoT framework (Apache 2.0)

---

## Performance (reference)

| Algorithm | Cycles | Latency |
|-----------|--------|---------|
| ML-KEM-512 | ~3.46M | ~14.4 ms |
| HQC-128 | ~519M | ~2,163 ms |

**Verdict:** ML-KEM is ~150× faster—practical for embedded systems than HQC.

---

## References

- [NIST FIPS 203 – ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST PQC Round 4 – HQC](https://csrc.nist.gov/projects/post-quantum-cryptography/round-4-submissions)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography/)

---
