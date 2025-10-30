idf_component_register(
    SRCS
        "app_main.c"
        "bench_common.c"
        "bench_mlkem.c"
        "bench_hqc.c"
        "bench_hybrid_hqc.c"
        "bench_hybrid_mlkem.c"
        "bench_parallel_mlkem.c"
        "bench_parallel_hqc.c"
    INCLUDE_DIRS "."
    REQUIRES mlkem_native_port hqc_port mbedtls
    PRIV_REQUIRES esp_hw_support esp_driver_gpio)
