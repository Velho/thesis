
# Include some utilities from cmake modules.
include (${CMAKE_SOURCE_DIR}/cmake/functions.cmake)

# Configuration for the test suite.
set (TARGET_NAME test_tls_tlse)

set (TEST_SUITE_TLS_SOURCES
    test_tlse.c
    test_tls_init.c
)

add_executable (${TARGET_NAME}
    ${TEST_SUITE_TLS_SOURCES}
)

find_package(Threads REQUIRED) # Work around: Fix to DSO missing with libcheck

# TODO : Are these defined already? Or can be added through the main target?
set (MG_DEFINITIONS
    # MG_ARCH=${MG_ARCH}
        MG_ENABLE_TLSE
        MG_ENABLE_CUSTOM_TLS)

target_compile_definitions (test_tls_tlse
    PUBLIC
    ${MG_DEFINITIONS})

target_link_libraries (test_tls_tlse
    PUBLIC
        Threads::Threads
        pthread
        check
        thesis-tls
        tlse
        mongoose
)

target_include_directories (test_tls_tlse
    PUBLIC
    ${CMAKE_BINARY_DIR}/deps/check/src
    ${CMAKE_BINARY_DIR}/deps/check
    ${PROJECT_SOURCE_DIR}/deps/check/src
    ${PROJECT_SOURCE_DIR}/deps/mongoose/src
    ${PROJECT_SOURCE_DIR}/deps/tlse
    ${PROJECT_SOURCE_DIR}/src
)

add_test (NAME test_tls_tlse COMMAND test_tls_tlse)

set (TEST_SERVER_FILES
    #     "certs/root.pem"
    #     "certs/server.pem"
    #     "certs/ss_ca.pem"
    #     "certs/ss_server.pem"
    #     "certs/fullchain.pem"
    #     "certs/privkey.pem"
    "certs/ca.pem"
    "certs/cert-2048.pem"
    "certs/pk-rsa-2048.pem"
    # FIXME : testing out the ecc alg
    # can be disabled and used only with rsa keys.
    "certs/ecsda/cert.pem"
    "certs/ecsda/private-key.pem"
    # FIXME : better filenames for the ecc keys
    # "certs/ecsda/MYCSR.csr"
    # "certs/ecsda/PRIVATEKEY.key"
)

# Include some utilities from cmake modules.
include (certificates)
# Copy the testing files over to build folder.
thesis_copy_certificates(${TARGET_NAME})
