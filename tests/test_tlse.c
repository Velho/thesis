
#include "test_tls_init.h"

Suite* tls_tlse_suite(void)
{
    Suite* s;
    s = suite_create("tlse suite");

    suite_add_tcase(s, tls_tlse_init_tcase());

    return s;
}

int main(void)
{
    int num_fail = 0;

    // FIXME : One big test suite which would contain
    // multiple test cases.
    Suite* s    = tls_tlse_suite();
    SRunner* sr = srunner_create(s);

    // set the process fork status no NOFORK in case of
    // debug build. It is easier to execute under dbg.
#ifndef NDEBUG
    srunner_set_fork_status(sr, CK_NOFORK);
#endif

    srunner_run_all(sr, CK_VERBOSE);
    num_fail = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (num_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

