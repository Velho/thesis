# Include the cutest module.

add_executable (test_tls_tlse
    test_tls_tlse_check.c)

# target_compile_options(test_tls_tlse
#     PUBLIC "-pthread"
# )

target_link_libraries (test_tls_tlse
    PRIVATE
    thesis-tls
    mongoose
    check
)

message ("${CMAKE_BINARY_DIR}")
target_include_directories (test_tls_tlse
    PUBLIC
    # $<INSTALL_INTERFACE:deps/check/src>
    ${PROJECT_SOURCE_DIR}/deps/check/src
    ${CMAKE_BINARY_DIR}/deps/check/src
    ${CMAKE_BINARY_DIR}/deps/check
    ${PROJECT_SOURCE_DIR}/deps/mongoose/src
    ${PROJECT_SOURCE_DIR}/deps/tlse
    ${PROJECT_SOURCE_DIR}/src
)

add_test (NAME test_tls_tlse COMMAND test_tls_tlse)

