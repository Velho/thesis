#pragma once

#if MG_ENABLE_TLSE

#include <tlse.h>

struct mg_tls {
    struct TLSContext* ctx;   // SSL context.
};

#endif

