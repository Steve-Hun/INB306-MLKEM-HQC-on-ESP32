# Path to external PQClean repository
set(PQCLEAN_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../PQClean")
set(HQC_CLEAN_DIR "${PQCLEAN_DIR}/crypto_kem/hqc-128/clean")

# List all HQC-128 source files from PQClean
set(HQC_SRCS
    ${HQC_CLEAN_DIR}/code.c
    ${HQC_CLEAN_DIR}/fft.c
    ${HQC_CLEAN_DIR}/gf.c
    ${HQC_CLEAN_DIR}/gf2x.c
    ${HQC_CLEAN_DIR}/hqc.c
    ${HQC_CLEAN_DIR}/kem.c
    ${HQC_CLEAN_DIR}/parsing.c
    ${HQC_CLEAN_DIR}/reed_muller.c
    ${HQC_CLEAN_DIR}/reed_solomon.c
    ${HQC_CLEAN_DIR}/shake_ds.c
    ${HQC_CLEAN_DIR}/shake_prng.c
    ${HQC_CLEAN_DIR}/vector.c
    # SHAKE-256 from PQClean common
    ${PQCLEAN_DIR}/common/fips202.c
)

idf_component_register(
    SRCS
        "randombytes_esp.c"  # Our ESP32 adapter
        ${HQC_SRCS}          # External PQClean sources
    INCLUDE_DIRS
        "include"
        "${HQC_CLEAN_DIR}"   # HQC headers
        "${PQCLEAN_DIR}/common"  # fips202.h, randombytes.h
    REQUIRES
        esp_system  # for esp_random.h
)
