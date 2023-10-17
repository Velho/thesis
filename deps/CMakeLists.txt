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
    set_property (TARGET mongoose PROPERTY C_STANDARD 99)

    target_include_directories(mongoose
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/mongoose/
            ${CMAKE_CURRENT_SOURCE_DIR}/mongoose/src)

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

# if set to false, build tomcrypt separately
set (TLSE_TOMCRYPT_AMALG FALSE CACHE BOOL "Build using tomcrypt amalgamation.")

if (NOT TLSE_TOMCRYPT_AMALG)
    message ("Building tomcrypt & tommath.")
    list(APPEND LTM_CFLAGS "-DUSE_LTM -DLTM_DESC -DLTC_SOURCE -DLTM_ALL")
    add_subdirectory (libtommath)

    message ("Building libtomcrypt.")
    include (${CMAKE_CURRENT_SOURCE_DIR}/tomcrypt_sources.cmake)

    set (TOMCRYPT_DEFS
        "USE_LTM"
        "LTM_DESC"
        "LTC_NO_ASM" # FIXME enable asm for each arch properly
        "LTC_SOURCE"
    )

    set (TOMCRYPT_SOURCES_HEADERS
        ${TOMCRYPT_SOURCES} ${TOMCRYPT_PUBLIC_HEADERS})

    add_library (tomcrypt ${TOMCRYPT_SOURCES_HEADERS})
    set_property (TARGET tomcrypt PROPERTY C_STANDARD 99)

    target_link_libraries (tomcrypt PUBLIC tommath)
    target_include_directories (tomcrypt PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/libtomcrypt/src/headers>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/libtommath>)
    target_compile_definitions (tomcrypt
        PRIVATE ${TOMCRYPT_DEFS})
endif ()

# configure the sources for target tlse
set (TLSE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/tlse/curve25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tlse/tlse.h
    # ${CMAKE_CURRENT_SOURCE_DIR}/tlse/libtomcrypt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tlse/tlse.c)

if (TLSE_TOMCRYPT_AMALG EQUAL TRUE)
    list (APPEND TLSE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tlse/libtomcrypt.c)
endif ()

add_library (tlse       ${TLSE_SOURCES})

set_property (TARGET tlse     PROPERTY C_STANDRD 99)
target_include_directories (tlse 
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        tomcrypt tommath
)

target_compile_definitions (tlse
    PRIVATE
        ${TOMCRYPT_DEFS}
        ${THESIS_COMPILE_DEFINITIONS}
)

# print out libtommath compile defs as debug
get_target_property (tommath_defs tommath COMPILE_DEFINITIONS)
message ("tommath_defs: ${tommath_defs}")

if (NOT TLSE_TOMCRYPT_AMALG)
    message ("Linking tomcrypt to tlse")
    target_compile_definitions (tlse
        PUBLIC 
        #"TLS_AMALGAMATION"
        tomcrypt)
    target_link_libraries (tlse PRIVATE tomcrypt tommath)
    target_include_directories (tlse
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/libtomcrypt/src/headers>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/libtommath/src>
    )
endif ()

if (THESIS_TLSE_EXAMPLES STREQUAL TRUE)
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
