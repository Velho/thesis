
# Include the cutest module.
include (cutest)

add_executable (test_tls_tlse
    test_tls_tlse.c)

message ("tests/CMakeLists.txt : cutest headers = ${CUTEST_HEADERS}")

target_include_directories (test_tls_tlse
    PRIVATE
        ${CUTEST_HEADERS})

target_link_libraries (test_tls_tlse
    PRIVATE
        cutest)

add_test (NAME test_tls_tlse COMMAND test_tls_tlse)


set (failRegex "!!!FAILURES!!!")

set_property (TEST test_tls_tlse
    PROPERTY FAIL_REGULAR_EXPRESSION "${failRegex}")

