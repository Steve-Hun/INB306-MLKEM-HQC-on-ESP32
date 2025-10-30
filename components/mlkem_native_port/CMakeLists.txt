set(MLKEM_NATIVE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../mlkem-native")

set(MLKEM_NATIVE_SRCS
    ${MLKEM_NATIVE_DIR}/mlkem/src/compress.c
    ${MLKEM_NATIVE_DIR}/mlkem/src/debug.c
    ${MLKEM_NATIVE_DIR}/mlkem/src/indcpa.c
    ${MLKEM_NATIVE_DIR}/mlkem/src/kem.c
    ${MLKEM_NATIVE_DIR}/mlkem/src/poly.c
    ${MLKEM_NATIVE_DIR}/mlkem/src/poly_k.c
    ${MLKEM_NATIVE_DIR}/mlkem/src/sampling.c
    ${MLKEM_NATIVE_DIR}/mlkem/src/verify.c
    ${MLKEM_NATIVE_DIR}/mlkem/src/fips202/fips202.c
    ${MLKEM_NATIVE_DIR}/mlkem/src/fips202/fips202x4.c
    ${MLKEM_NATIVE_DIR}/mlkem/src/fips202/keccakf1600.c)

idf_component_register(
    SRCS
        "randombytes_esp.c"
        ${MLKEM_NATIVE_SRCS}
    INCLUDE_DIRS
        "include"
        "${MLKEM_NATIVE_DIR}"
        "${MLKEM_NATIVE_DIR}/mlkem"
    PRIV_INCLUDE_DIRS
        "${MLKEM_NATIVE_DIR}/mlkem/src"
    REQUIRES
        esp_system)

# Force portable C implementation and parameter set selection
# Shared between library sources and application includes.
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    MLK_CONFIG_PARAMETER_SET=512
    MLK_CONFIG_NAMESPACE_PREFIX=mlkem)

# Ensure we use the portable C backends explicitly.
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    MLK_CONFIG_USE_NATIVE_BACKEND_ARITH=0
    MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202=0)
