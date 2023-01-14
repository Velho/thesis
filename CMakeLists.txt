cmake_minimum_required (VERSION 3.12)
project (thesis)

list (APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

set (THESIS_TLS_SOURCES
    src/tls_tlse.h
    src/tls_tlse.c)


add_subdirectory (deps)

# thesis-tls includes the tls implementation for mongoose.
# crypto functionalities provided by tomcrypt.
add_library (thesis-tls ${THESIS_TLS_SOURCES})


# Add includes for the libtlse, mongoose and tlse from deps folder.
target_include_directories(thesis-tls
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/tlse>)

# Definitions required to compile against custom tls implementation.
set (MG_DEFINITIONS
        MG_ARCH=${MG_ARCH}
        MG_ENABLE_TLSE
        MG_ENABLE_CUSTOM_TLS)

target_compile_definitions(thesis-tls
    PUBLIC
    ${MG_DEFINITIONS})

target_link_libraries(thesis-tls
    PRIVATE
        tlse)

# Build the examples
set (THESIS_TLSE_EXAMPLES   TRUE)
set (THESIS_TLSE_UNIT_TESTS TRUE)

# Enable testing, including the dependencies.
if (THESIS_TLSE_UNIT_TESTS)
    enable_testing()

    add_subdirectory (deps/check)
    add_subdirectory (tests)
endif ()

if (THESIS_TLSE_EXAMPLES)
    add_subdirectory (examples)
endif ()

