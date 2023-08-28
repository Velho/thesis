message ("Configuring thesis examples.")

set (THESIS_EX1 "thesis-server")
set (THESIS_TLS_SERVER_SRC
    tls_server.c
)

add_executable (${THESIS_EX1}
    ${THESIS_TLS_SERVER_SRC})

# Link against thesis-tls, (required to link against mongoose as well??)
target_link_libraries (${THESIS_EX1}
    PRIVATE
        thesis-tls tlse tomcrypt mongoose)

# Add include headers for the mongoose target
target_include_directories (${THESIS_EX1}
    PRIVATE
        thesis-tls tomcrypt mongoose)

target_include_directories (${THESIS_EX1}
    PRIVATE
    ${CMAKE_SOURCE_DIR}/deps/libtomcrypt/src/headers)

set (TARGET_NAME ${THESIS_EX1})
include (certificates)

thesis_copy_certificates(${TARGET_NAME})
