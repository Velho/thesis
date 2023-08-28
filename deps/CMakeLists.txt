# CMake configuration for the dependencies.
# Dependencies include, tlse, mongoose, check, tomcrypt.
# Velho

# set (BUILD_TLSE_EXAMPLES TRUE)

# Define the build definitions.
# MG_ARCH Initialized with a value
# MG_ENABLE_CUSTOM_TLS
# MG_ENABLE_TLSE

if (THESIS_BUILD_MONGOOSE)
    message ("Building thesis as part of thesis library.")

    file (GLOB MONGOOSE_SOURCES
        mongoose/src/*.h
        mongoose/src/*.c)

    add_library (mongoose   ${MONGOOSE_SOURCES})

    target_include_directories(mongoose
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/src)

    target_compile_definitions(mongoose
        PUBLIC
            ${THESIS_MG_DEFINITIONS})


    set (MONGOOSE_INCLUDE_DIR
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/mongoose/src>
        PARENT_SCOPE)

    target_link_libraries(mongoose
        PRIVATE
            thesis-tls)
endif ()

set (TLSE_SOURCES
    tlse/curve25519.c
    tlse/libtomcrypt.c
    tlse/tlse.h
    tlse/tlse.c)

add_library (tlse       ${TLSE_SOURCES})

target_compile_definitions(tlse
    PUBLIC
        TLS_AMALGAMATION
        DEBUG)


if (THESIS_TLSE_EXAMPLES EQUAL TRUE)
    include (certificates)

    set (TLSE_EXAMPLE_HW_SOURCES tlse/examples/tlshelloworld.c)

    add_executable (tls-helloworld ${TLSE_EXAMPLE_HW_SOURCES})
    target_link_libraries (tls-helloworld
        PRIVATE
            tlse)

    target_compile_definitions (tls-helloworld
        PRIVATE
            DEBUG)

    thesis_copy_certificates (tls-helloworld)
endif ()
