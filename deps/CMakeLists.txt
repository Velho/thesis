# Define the build definitions.
# MG_ARCH Initialized with a value
# MG_ENABLE_CUSTOM_TLS
# MG_ENABLE_TLSE

set (MG_ARCH_CUSTOM "0")
set (MG_ARCH_UNIX "1")
set (MG_ARCH_WIN32 "2")
set (MG_ARCH ${MG_ARCH_UNIX} PARENT_SCOPE) #

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

set (BUILD_TLSE_EXAMPLES TRUE)

if (${BUILD_TLSE_EXAMPLES})
    include (certificates)

    set (TLSE_EXAMPLE_HW_SOURCES tlse/examples/tlshelloworld.c)

    add_executable (tls-helloworld ${TLSE_EXAMPLE_HW_SOURCES})
    target_link_libraries (tls-helloworld
        PRIVATE
            tlse)

    target_compile_definitions (tls-helloworld
        PRIVATE
            DEBUG)

    thesis_copy_certificates ("tls-helloworld")
endif ()