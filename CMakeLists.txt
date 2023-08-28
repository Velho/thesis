cmake_minimum_required (VERSION 3.12)
project (thesis)

# project options, used to control separate actions in the build configuration
option (THESIS_BUILD_EXAMPLES "Build examples for the project." OFF)
option (THESIS_TLSE_UNIT_TESTS "Build unit tests for the project." ON)
option (THESIS_BUILD_MONGOOSE "Enable or Disable thesis to build mongoose." OFF)
option (THESIS_BUILD_AS_LIBRARY "Build library without linking against mongoose." OFF)

set (THESIS_COMPILE_DEFINITONS "" CACHE STRING "Custom compile definitions")

# build_mongoose and build_as_library is the same?
# build_as_lib is meant as parameter to disable any linkage to
# mongoose for example. perhaps it's easier to understand if
# user wants to link against

if (THESIS_BUILD_AS_LIBRARY)
    set (THESIS_BUILD_MONGOOSE OFF)
endif ()

message ("Thesis building mongoose : ${THESIS_BUILD_MONGOOSE}")

list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

set (THESIS_MG_ARCH "1") # 1 == LINUX, immediate value, set from var instead?

set (THESIS_MG_DEFINITIONS
    MG_ARCH=${THESIS_MG_ARCH})

set (THESIS_TLS_SOURCES
    src/tls_tlse.h
    src/tls_tlse.c)

add_subdirectory (deps)

# thesis-tls includes the tls implementation for mongoose.
# crypto functionalities provided by tomcrypt.
add_library (thesis-tls ${THESIS_TLS_SOURCES})

# add includes for the libtlse, mongoose and tlse from deps folder.
target_include_directories(thesis-tls
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose/src
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tlse)

target_compile_definitions(thesis-tls
    PUBLIC
        ${THESIS_MG_DEFINITIONS}
        ${THESIS_COMPILE_DEFINITONS})

target_link_libraries(thesis-tls
    PRIVATE
        tlse)

target_link_libraries (thesis-tls
    PRIVATE mongoose)

# enable testing, including the dependencies.
if (THESIS_TLSE_UNIT_TESTS)
    enable_testing()

    add_subdirectory (deps/check)
    add_subdirectory (tests)
endif ()

if (THESIS_TLSE_EXAMPLES)
    add_subdirectory (examples)
endif ()

