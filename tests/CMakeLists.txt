
add_executable (test_tls_tlse
    test_tls_tlse_check.c)

find_package(Threads REQUIRED) # Fix to DSO missing with libcheck

target_link_libraries (test_tls_tlse
    PUBLIC
    Threads::Threads
    check
    
    # thesis-tls
    # mongoose
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

