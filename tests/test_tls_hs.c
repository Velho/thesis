#include "test_tls_hs.h"

#include <mongoose.h>
#include <tlse.c>

/* TARGET */
// #include "tls_tlse.c"


TCase* tls_tlse_hs_init_tcase(void)
{
    TCase* tc = tcase_create("mg-tls - tlse handshake");

    return tc;
}
