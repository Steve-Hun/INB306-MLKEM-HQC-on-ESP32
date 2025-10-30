#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Use ESP32 TRNG for mlkem-native randomness (default).
 */
void mlkem_randombytes_use_trng(void);

/**
 * @brief Use a deterministic PRNG seeded with the provided 64-bit seed.
 *        Useful for reproducing KAT results. Calling this switches the
 *        generator away from TRNG until mlkem_randombytes_use_trng() is called.
 */
void mlkem_randombytes_use_fixed_seed(uint64_t seed);

#ifdef __cplusplus
}
#endif
