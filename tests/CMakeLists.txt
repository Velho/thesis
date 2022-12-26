
# Include some utilities from cmake modules.
include (${CMAKE_SOURCE_DIR}/cmake/functions.cmake)

# Configuration for the test suite.
set (TARGET_NAME test_tls_tlse)

set (TEST_SUITE_TLS_SOURCES
    test_tls.c
)

add_executable (${TARGET_NAME}
    ${TEST_SUITE_TLS_SOURCES}
)

find_package(Threads REQUIRED) # Work around: Fix to DSO missing with libcheck

# TODO : Are these defined already?
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
    "root.pem"
    "server.pem"
    "ss_ca.pem"
    "ss_server.pem"
)

# Copy the testing files over to build folder.
thesis_copy_build (${TARGET_NAME} "${TEST_SERVER_FILES}")

