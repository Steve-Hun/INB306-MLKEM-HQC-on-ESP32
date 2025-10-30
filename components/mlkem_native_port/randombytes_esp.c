#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "esp_random.h"
#include "esp_system.h"

#include "mlkem_randombytes.h"

/*
 * Runtime-selectable randomness source for mlkem-native.
 * Default: use ESP32 TRNG via esp_fill_random().
 * Optional: deterministic Xoshiro256** PRNG seeded via mlkem_randombytes_use_fixed_seed().
 */

static bool s_use_fixed_seed = false;
static uint64_t s_state[4] = {0};

static uint64_t splitmix64(uint64_t *x)
{
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static uint64_t xoshiro256ss(void)
{
    const uint64_t result = (s_state[1] * 5ULL);
    const uint64_t rot = ((result << 7) | (result >> (64 - 7))) * 9ULL;

    const uint64_t t = s_state[1] << 17;

    s_state[2] ^= s_state[0];
    s_state[3] ^= s_state[1];
    s_state[1] ^= s_state[2];
    s_state[0] ^= s_state[3];

    s_state[2] ^= t;
    s_state[3] = (s_state[3] << 45) | (s_state[3] >> (64 - 45));

    return rot;
}

void mlkem_randombytes_use_trng(void)
{
    s_use_fixed_seed = false;
}

void mlkem_randombytes_use_fixed_seed(uint64_t seed)
{
    s_use_fixed_seed = true;
    uint64_t x = seed;
    for (size_t i = 0; i < 4; ++i) {
        s_state[i] = splitmix64(&x);
    }
    /* Avoid all-zero state */
    if (s_state[0] == 0 && s_state[1] == 0 && s_state[2] == 0 && s_state[3] == 0) {
        s_state[0] = 1;
    }
}

void randombytes(uint8_t *out, size_t outlen)
{
    if (!s_use_fixed_seed) {
        esp_fill_random(out, outlen);
        return;
    }

    while (outlen > 0) {
        uint64_t r = xoshiro256ss();
        size_t chunk = (outlen < sizeof(r)) ? outlen : sizeof(r);
        memcpy(out, &r, chunk);
        out += chunk;
        outlen -= chunk;
    }
}
