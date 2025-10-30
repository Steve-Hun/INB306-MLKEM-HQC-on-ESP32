#include <stdlib.h>
#include <math.h>
#include "bench_common.h"

static int cmp_u32_qsort(const void *a, const void *b)
{
    uint32_t ua = *(const uint32_t *)a;
    uint32_t ub = *(const uint32_t *)b;
    return (ua > ub) - (ua < ub);
}

void bench_compute_median_u32(uint32_t *arr, size_t n, uint32_t *out)
{
    if (!arr || n == 0 || !out) return;
    qsort(arr, n, sizeof(uint32_t), cmp_u32_qsort);
    *out = arr[n/2];
}

void bench_compute_avg_u32(const uint32_t *arr, size_t n, uint32_t *out)
{
    if (!arr || n == 0 || !out) return;
    uint64_t sum = 0;
    for (size_t i = 0; i < n; ++i) sum += arr[i];
    *out = (uint32_t)(sum / n);
}

void bench_compute_stddev_u32(const uint32_t *arr, size_t n, uint32_t avg, uint32_t *out)
{
    if (!arr || n == 0 || !out) return;
    uint64_t sum_sq_diff = 0;
    for (size_t i = 0; i < n; ++i) {
        int64_t diff = (int64_t)arr[i] - (int64_t)avg;
        sum_sq_diff += (uint64_t)(diff * diff);
    }
    double variance = (double)sum_sq_diff / (double)n;
    *out = (uint32_t)sqrt(variance);
}

void bench_compute_percentile_u32(uint32_t *arr, size_t n, uint8_t percentile, uint32_t *out)
{
    if (!arr || n == 0 || !out || percentile > 100) return;
    qsort(arr, n, sizeof(uint32_t), cmp_u32_qsort);
    size_t idx = (size_t)((percentile / 100.0) * (n - 1));
    *out = arr[idx];
}
