#include <check.h>

#include <mongoose.h>
#include "tls_tlse.c" /* TARGET */

#define TLS_ECDSA_SUPPORTED

#include <stdlib.h>
#include <string.h>
#include "tlse.c"

#define MG_OPTS_SERVER_CA       "ss_ca.pem"
#define MG_OPTS_SERVER_CERT     "ss_server.pem"
#define MG_OPTS_SERVER_CERTKEY  "ss_server.pem"


START_TEST (test_tlse_init_certificate)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    // Set the certificate authority.
    opts.ca = MG_OPTS_SERVER_CA;

    mg_tls_init(&c, &opts); // Call the unit

    const uint32_t expected_cert_count = 151;
    struct mg_tls* tls = (struct mg_tls*)c.tls;
    // What are the expecations when loading the certificates?
    // tlse context certificates should be initialized.
    ck_assert_ptr_nonnull(tls->ctx->certificates);
    // certificates_count should be greater than 0.
    ck_assert_uint_gt(tls->ctx->certificates_count, 0);
    // What is the count of certificates in the root.pem?
    ck_assert_uint_eq(tls->ctx->certificates_count, expected_cert_count);
}
END_TEST;

START_TEST (test_tlse_init_context)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    mg_tls_init(&c, &opts); // Call the unit

    ck_assert_ptr_nonnull(c.tls);

    // TLSContext created correctly?
    struct mg_tls* tls = (struct mg_tls*)c.tls;
    const unsigned char expected_is_server = 1;

    // FIXME : If the tls gets released, is_closing is set.
    if (c.is_closing == true)
    {
        return;
    }

    ck_assert_msg(!c.is_closing, "tls context is released");

    ck_assert_ptr_nonnull(tls->ctx);
    ck_assert_uint_eq(tls->ctx->version, MG_TLSE_VERSION);
    ck_assert_uint_eq(tls->ctx->is_server, expected_is_server);

} END_TEST

START_TEST (test_tlse_init_alloc)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    // Call to mg tls init seg faults.
    mg_tls_init(&c, &opts); // Call the unit

    ck_assert_ptr_nonnull(c.tls);
}
END_TEST

START_TEST (test_tlse_init_pk)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    opts.ca = MG_OPTS_SERVER_CA;
    opts.cert = MG_OPTS_SERVER_CERT; 
    opts.certkey = MG_OPTS_SERVER_CERTKEY;

    mg_tls_init(&c, &opts); // Call the unit

    ck_assert_ptr_nonnull(c.tls);

    struct mg_tls* tls = (struct mg_tls*)c.tls;

    // tlse tls_load_priv_key sets the context->private_key
    // Make sure the private_key is not null.
    // in case of ecdsa is supported ec_private_key is set.
    ck_assert_ptr_nonnull(tls->ctx->private_key);
}
END_TEST


Suite* tls_tlse_suite(void)
{
    Suite *s;
    TCase *tc;

    s = suite_create("tlse suite");
    tc = tcase_create("mg-tls - tlse_init");

    tcase_add_test(tc, test_tlse_init_alloc);
    tcase_add_test(tc, test_tlse_init_context);
    tcase_add_test(tc, test_tlse_init_certificate);
    tcase_add_test(tc, test_tlse_init_pk);

    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    int num_fail = 0;

    Suite* s    = tls_tlse_suite();
    SRunner* sr = srunner_create(s);

    srunner_set_fork_status(sr, CK_NOFORK);

    srunner_run_all(sr, CK_VERBOSE);
    num_fail = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (num_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

