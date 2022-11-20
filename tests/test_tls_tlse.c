#include <stdio.h>
#include <CuTest.h>


void TestTlsTlseInit(CuTest* tc)
{
    CuAssertTrue(tc, 0 == 0);
}

void TestTlsTlseFail(CuTest* tc)
{
    CuAssert(tc, "test should fail", 1 == 1 + 1);
}

CuSuite* CuGetSuite(void)
{
    CuSuite* suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, TestTlsTlseInit);
    SUITE_ADD_TEST(suite, TestTlsTlseFail);

    return suite;
}

void RunAllTests(void)
{
	CuString *output = CuStringNew();
	CuSuite* suite = CuSuiteNew();

	CuSuiteAddSuite(suite, CuGetSuite());

	CuSuiteRun(suite);
	CuSuiteSummary(suite, output);
	CuSuiteDetails(suite, output);
	printf("%s\n", output->buffer);

    CuStringDelete(output);
    CuSuiteDelete(suite);
}

int main(void)
{
	RunAllTests();
}
