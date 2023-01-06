#include <check.h>

// #include <tls_tlse.h>
#include <mongoose.h>

#include <tls_tlse.h>

/* Include the TLSE library. */
#include <tlse.c>

// #include "tls_tlse.c" /* TARGET */

#define TLS_ECDSA_SUPPORTED


#define TLSE_MG_OPT_CA      "certs/ca.pem"
#define TLSE_MG_OPT_CERT    "certs/cert-2048.pem"
#define TLSE_MG_OPT_KEY     "certs/pk-rsa-2048.pem"

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

// TODO : These certificate setup is done the same for all these tests,
// this could be simplified by having a separate function to initialize
// the mg_tls_opts struct.

struct mg_tls_opts setup_mg_opts()
{
    struct mg_tls_opts opts = { 0 };

    opts.ca = TLSE_MG_OPT_CA;
    opts.cert = TLSE_MG_OPT_CERT;
    opts.certkey = TLSE_MG_OPT_KEY;

    return opts;
}

START_TEST (test_tlse_init_ca_root)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    // Set the certificate authority.
    opts = setup_mg_opts();

    mg_tls_init(&c, &opts); // Call the unit

    const uint32_t expected_cert_count = 151;
    struct mg_tls* tls = (struct mg_tls*)c.tls;
    // What are the expecations when loading the certificates?
    // tlse context certificates should be initialized.
    ck_assert_ptr_nonnull(tls->ctx->root_certificates);
    // certificates_count should be greater than 0.
    ck_assert_uint_gt(tls->ctx->root_count, 0);
    // What is the count of certificates in the root.pem?
    ck_assert_uint_eq(tls->ctx->root_count, expected_cert_count);
}
END_TEST;

START_TEST (test_tlse_init_pk)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    // Set the certificate authority and private keys.
    opts = setup_mg_opts();

    mg_tls_init(&c, &opts); // Call the unit

    ck_assert_ptr_nonnull(c.tls);

    struct mg_tls* tls = (struct mg_tls*)c.tls;

    // tlse tls_load_priv_key sets the context->private_key
    // Make sure the private_key is not null.
    // in case of ecdsa is supported ec_private_key is set.
    ck_assert_ptr_nonnull(tls->ctx->private_key);
}
END_TEST

// FIXME
// Do we do failure condition for the separate operations
// aka, init_pk_failure, init_cert_failure and so on,
// or we take just one and see that the cleanup is done
// correctly.


// if cert is NULl or [0] is \0, the function should
// return an error code and clear the tls context.
START_TEST (test_tlse_init_cert_failure)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    // FIXME : Properly set the failure.
    opts.ca = TLSE_MG_OPT_CA;
    opts.cert = TLSE_MG_OPT_CERT;
    opts.certkey = TLSE_MG_OPT_KEY;

    mg_tls_init(&c, &opts); // Call the unit

    ck_assert_ptr_null(c.tls);

    struct mg_tls* tls = (struct mg_tls*)c.tls;
}
END_TEST

START_TEST (test_tlse_init_pk_failure)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    opts.ca = TLSE_MG_OPT_CA;
    opts.cert = TLSE_MG_OPT_CERT;
    opts.certkey = TLSE_MG_OPT_KEY;

    mg_tls_init(&c, &opts); // Call the unit

    unsigned expected_is_closing = 1;
    ck_assert_ptr_null(c.tls);
    ck_assert_uint_eq(c.is_closing, expected_is_closing);

    struct mg_tls* tls = (struct mg_tls*)c.tls;
}
END_TEST

START_TEST (test_tlse_init_pk_ecdha)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    opts.ca = TLSE_MG_OPT_CA;
    opts.cert = "certs/ecsda/cert.pem";
    opts.certkey = "certs/ecsda/private-key.pem";

    mg_tls_init(&c, &opts); // Call the unit

    ck_assert_ptr_null(c.tls);

    struct mg_tls* tls = (struct mg_tls*)c.tls;
}
END_TEST



START_TEST (test_tlse_init_success)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    opts.ca = TLSE_MG_OPT_CA;
    opts.cert = TLSE_MG_OPT_CERT;
    opts.certkey = TLSE_MG_OPT_KEY;

    mg_tls_init(&c, &opts); // Call the unit

    ck_assert_ptr_nonnull(c.tls);

    struct mg_tls* tls = (struct mg_tls*)c.tls;

    ck_assert_ptr_nonnull(tls->ctx->private_key);

    // mg_connection
    // is_tls and is_tls_hs should be set with a successfull initialization.

}
END_TEST


/**
 * Test-cases added to the TCase struct.
 * Returning it with the tests to be added
 * into the global suite.
 */
TCase* tls_tlse_init_tcase(void)
{
    TCase *tc;
    tc = tcase_create("mg-tls - tlse init");

    tcase_add_test(tc, test_tlse_init_alloc);
    tcase_add_test(tc, test_tlse_init_context);
    tcase_add_test(tc, test_tlse_init_ca_root);
    tcase_add_test(tc, test_tlse_init_pk);
    // tcase_add_test(tc, test_tlse_init_pk_ecdha);
    tcase_add_test(tc, test_tlse_init_success);

    return tc;
}


