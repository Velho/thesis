
message ("cutest -module")

set (CUTEST_SOURCES
    ${PROJECT_SOURCE_DIR}/deps/cutest/CuTest.h
    ${PROJECT_SOURCE_DIR}/deps/cutest/CuTest.c)

add_library (cutest ${CUTEST_SOURCES})

target_include_directories (cutest
    PUBLIC
    <BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/deps/cutest>)

set (CUTEST_HEADERS
    "${PROJECT_SOURCE_DIR}/deps/cutest")

