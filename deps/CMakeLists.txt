# Define the build definitions.
# MG_ARCH Initialized with a value
# MG_ENABLE_CUSTOM_TLS
# MG_ENABLE_TLSE
set (MG_ARCH "MG_ARCH_UNIX" PARENT_SCOPE) # -DMG_ARCH=MG_ARCH_UNIX is this correct ?

file (GLOB MONGOOSE_SOURCES
    mongoose/src/*.h
    mongoose/src/*.c)


set (TLSE_SOURCES
    tlse/curve25519.c
    tlse/libtomcrypt.c
    tlse/tlse.h
    tlse/tlse.c)

add_library (tlse       ${TLSE_SOURCES})
add_library (mongoose   ${MONGOOSE_SOURCES})

target_include_directories(mongoose
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_definitions(mongoose
    PUBLIC
    ${MG_DEFINITIONS})

target_compile_definitions(tlse
    PUBLIC
        TLS_AMALGAMATION
        DEBUG)

target_link_libraries(mongoose
    PRIVATE
        thesis-tls)
