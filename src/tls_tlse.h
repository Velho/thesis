#pragma once

#if MG_ENABLE_TLSE

#include <tlse.h>

// Define the TLS version to 1.3, TODO : Make this compiler opt.
#define MG_TLSE_VERSION TLS_V13

struct mg_tls {
    struct TLSContext* ctx;     /* SSL context. */
};

#endif

