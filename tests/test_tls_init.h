#ifndef _TEST_TLS_INIT_H_
#define _TEST_TLS_INIT_H_

#include <stdlib.h>
#include <string.h>

#include <check.h>

/**
 * Defines the test cases for tls_init functionality.
 * \return Pointer to the TCase structure, containing the test cases,
 *  Tests added to the TCase* :
 *      - test_tlse_init_alloc
 *      - test_tlse_init_context
 *      - test_tlse_init_ca_root
 *      - test_tlse_init_pk
 *      - test_tlse_init_pk_ecdha
 *      - test_tlse_init_success
 */
TCase* tls_tlse_init_tcase(void);

#endif

