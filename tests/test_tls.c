#include <stdlib.h>
#include <check.h>

#include "tls_tlse.c" /* TARGET */

START_TEST (TLS_LoadFile)
{
    ck_assert_int_eq(4, 2);
}
END_TEST

Suite * tls_tlse_suite(void)
{
    Suite *s;
    TCase *tc;

    s = suite_create("Mg TLS Tlse");
    tc = tcase_create("TLS Load File");

    tcase_add_test(tc, TLS_LoadFile);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    int num_fail = 0;
    Suite *s;
    SRunner *sr;

    s = tls_tlse_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    num_fail = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (num_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

