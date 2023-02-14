# CMake configuration for the dependencies.
# Dependencies include, tlse, mongoose, check, tomcrypt.
# Velho

# set (BUILD_TLSE_EXAMPLES TRUE)

# Define the build definitions.
# MG_ARCH Initialized with a value
# MG_ENABLE_CUSTOM_TLS
# MG_ENABLE_TLSE

if (${THESIS_BUILD_MONGOOSE})
    message ("Building thesis as part of thesis library.")

    # set_property is not supported in cmake 2.8
    list(APPEND CMAKE_C_FLAGS "-std=gnu99")

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

message ("Current source dir : ${CMAKE_CURRENT_SOURCE_DIR}")
# configure the sources for target tlse
set (TLSE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/tlse/curve25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tlse/libtomcrypt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tlse/tlse.h
    ${CMAKE_CURRENT_SOURCE_DIR}/tlse/tlse.c)

add_library (tlse       ${TLSE_SOURCES})

set_property (TARGET tlse     PROPERTY C_STANDRD 99)

# target_include_directories (tlse
#     PUBLIC
#         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/libtomcrypt/src/headers>
# )

target_compile_definitions (tlse
    PRIVATE
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

