set (TEST_SUITE_TLS_SOURCES
    test_tls.c
)

add_executable (test_tls_tlse 
    ${TEST_SUITE_TLS_SOURCES}
)

find_package(Threads REQUIRED) # Fix to DSO missing with libcheck

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

message ("${CMAKE_BINARY_DIR}")
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
add_custom_command(
    TARGET test_tls_tlse POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/root.pem
        ${CMAKE_BINARY_DIR})

