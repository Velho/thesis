#include <stdlib.h>
#include <check.h>

#include <mongoose.h>
#include "tls_tlse.c" /* TARGET */

#include "tlse.c"

START_TEST (test_tlse_certificate)
{
}
END_TEST;

START_TEST (test_tlse_init_context)
{
    // Define the inputs and set the members to 0.
    struct mg_connection c = { 0 };
    struct mg_tls_opts opts = { 0 };

    // Call to mg tls init seg faults.
    mg_tls_init(&c, &opts); // Call the unit

    ck_assert_ptr_nonnull(c.tls);

    // TLSContext created correctly?
    struct mg_tls* tls = (struct mg_tls*)c.tls;

    ck_assert_ptr_nonnull(tls->ctx);
    ck_assert_uint_eq(tls->ctx->version, MG_TLSE_VERSION);
    // ck_assert_int_eq(((struct TLSContext*)tls->ctx)->version, MG_TLSE_VERSION);
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



Suite* tls_tlse_suite(void)
{
    Suite *s;
    TCase *tc;

    s = suite_create("tlse suite");
    tc = tcase_create("mg-tls - tlse_init");

    // tcase_add_test(tc, test_tlse_loadfile);
    // tcase_add_test(tc, test_tlse_certificate);
    tcase_add_test(tc, test_tlse_init_alloc);
    tcase_add_test(tc, test_tlse_init_context);

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

