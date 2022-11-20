cmake_minimum_required (VERSION 3.12)
project (thesis)

# Define the build definitions.
# MG_ARCH Initialized with a value
# MG_ENABLE_CUSTOM_TLS
# MG_ENABLE_TLSE

set (MG_ARCH 1) # MG_ARCH_UNIX

set (MONGOOSE_SOURCES
    deps/mongoose/mongoose.h
    deps/mongoose/mongoose.c)

set (TLSE_SOURCES
    deps/tlse/curve25519.c
    deps/tlse/libtomcrypt.c
    deps/tlse/tlse.h
    deps/tlse/tlse.c)


set (THESIS_TLS_SOURCES
    include/tls.h
    src/tls_tlse.h
    src/tls_tlse.c)


add_library (thesis-tls ${THESIS_TLS_SOURCES})
add_library (tlse       ${TLSE_SOURCES})
add_library (mongoose   ${MONGOOSE_SOURCES})

# Add includes for the libtlse, mongoose and tlse from deps folder.
target_include_directories(thesis-tls
    PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose/src>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/tlse>)


set (MG_DEFINITIONS
        MG_ARCH=${MG_ARCH}
        MG_ENABLE_TLSE
        MG_ENABLE_CUSTOM_TLS)


target_compile_definitions(thesis-tls
    PUBLIC
    ${MG_DEFINITIONS})

target_compile_definitions(tlse
    PUBLIC
        TLS_AMALGAMATION)

target_link_libraries(thesis-tls
    PRIVATE
        tlse)

target_link_libraries(mongoose
    PRIVATE 
        thesis-tls)

