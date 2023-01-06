cmake_minimum_required (VERSION 3.12)
project (thesis)

list (APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Define the build definitions.
# MG_ARCH Initialized with a value
# MG_ENABLE_CUSTOM_TLS
# MG_ENABLE_TLSE

set (MG_ARCH "MG_ARCH_UNIX") # -DMG_ARCH=MG_ARCH_UNIX is this correct ?


file (GLOB MONGOOSE_SOURCES
    deps/mongoose/src/*.h
    deps/mongoose/src/*.c)

# set (MONGOOSE_SOURCES
#     deps/mongoose/mongoose.h
#     deps/mongoose/mongoose.c)

set (TLSE_SOURCES
    deps/tlse/curve25519.c
    deps/tlse/libtomcrypt.c
    deps/tlse/tlse.h
    deps/tlse/tlse.c)


set (THESIS_TLS_SOURCES
    src/tls_tlse.h
    src/tls_tlse.c)

# thesis-tls includes the tls implementation for mongoose.
# crypto functionalities provided by tomcrypt.
add_library (thesis-tls ${THESIS_TLS_SOURCES})
add_library (tlse       ${TLSE_SOURCES})
add_library (mongoose   ${MONGOOSE_SOURCES})

# Add includes for the libtlse, mongoose and tlse from deps folder.
target_include_directories(thesis-tls
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/tlse>)

target_include_directories(mongoose
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Definitions required to compile against custom tls implementation.
set (MG_DEFINITIONS
        MG_ARCH=${MG_ARCH}
        MG_ENABLE_TLSE
        MG_ENABLE_CUSTOM_TLS)


target_compile_definitions(mongoose
    PUBLIC
    ${MG_DEFINITIONS})

target_compile_definitions(thesis-tls
    PUBLIC
    ${MG_DEFINITIONS})


target_compile_definitions(tlse
    PUBLIC
        TLS_AMALGAMATION
        DEBUG)

target_link_libraries(thesis-tls
    PRIVATE
        tlse)

target_link_libraries(mongoose
    PRIVATE
        thesis-tls)

# Build the examples
set (THESIS_TLSE_EXAMPLES   TRUE)

# TODO : Add some config var to enable/disable testing.
enable_testing()

add_subdirectory (deps/check)
add_subdirectory (tests)


if (THESIS_TLSE_EXAMPLES)
    add_subdirectory (examples)
endif ()

