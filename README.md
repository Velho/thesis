
** TLSE Can tlse lib be integrated into mongoose without any modifications?
    Just by accepting the mongoose interface and initializing the tlse application
    correctly.

    - Mongoose TLS interface implements the following functions
        - mg_tls_init ( struct mg_connection *, const struct mg_tls_opts * )
        - mg_tls_free ( .. )
        - mg_tls_send ( struct mg_connection *, const void *buf, size_t len )
        - mg_tls_recv ( struct mg_connection *, void *buf, size_t len) )
        - mg_tls_handshake ( .. )
        - mg_tls_pending ( struct mg_connection * )

    TLSE can be adapted (supposed) directly into the mongoose webserver.
    
