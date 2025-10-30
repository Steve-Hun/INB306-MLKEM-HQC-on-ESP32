/**
 * @file randombytes_esp.c
 * @brief ESP32 TRNG adapter for PQClean's randombytes() interface
 */

#include "randombytes.h"
#include "esp_random.h"

int randombytes(uint8_t *out, size_t outlen) {
    esp_fill_random(out, outlen);
    return 0;
}
