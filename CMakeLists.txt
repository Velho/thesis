cmake_minimum_required (VERSION 3.12)
project (thesis)

# project options, used to control separate actions in the build configuration
option (THESIS_BUILD_EXAMPLES      FALSE "Build examples for the project.")
option (THESIS_BUILD_UNIT_TESTS    FALSE "Build unit tests for the project.")
option (THESIS_BUILD_AS_LIBRARY    FALSE "Build library without linking against mongoose.")
option (THESIS_BUILD_MONGOOSE      FALSE "Enable or Disable thesis to build mongoose.")
option (THESIS_TLSE_DEBUG          FALSE "Enable debugging for tlse.")

# build_mongoose and build_as_library is the same?
# build_as_lib is meant as parameter to disable any linkage to
# mongoose for example. perhaps it's easier to understand if
# user wants to link against

message ("Thesis building mongoose : ${THESIS_BUILD_MONGOOSE}")
message ("Thesis building examples : ${THESIS_BUILD_EXAMPLES}")

list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 1 == LINUX, immediate value, set from var instead?
set (THESIS_MG_ARCH "1") 
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
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/tlse>)

target_compile_definitions(thesis-tls
    PUBLIC
        ${THESIS_MG_DEFINITIONS}
        ${THESIS_COMPILE_DEFINITONS})

if (CMAKE_BUILD_TYPE EQUAL "Debug" AND THESIS_TLSE_DEBUG)
    target_compile_definitions (tlse PRIVATE ${THESIS_COMPILE_DEFINITONS})
endif ()

target_link_libraries(thesis-tls     PUBLIC tlse)

# skip link if mg built outside
if (THESIS_BUILD_MONGOOSE)
    target_link_libraries (thesis-tls PRIVATE mongoose)
endif ()
# enable testing, including the dependencies.
if (THESIS_BUILD_UNIT_TESTS)
    message ("Enabling testing..")
    enable_testing()

    add_subdirectory (deps/check)
    add_subdirectory (tests)
endif ()

if (THESIS_BUILD_EXAMPLES)
    message ("Including subdirectory examples/")
    add_subdirectory (examples)
endif ()

