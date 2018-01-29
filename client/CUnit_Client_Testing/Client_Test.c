#include "CUnit/CUnit.h"
#include "CUnit/Basic.h"
#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int init_suite(void) { return 0; }
int clean_suite(void) { return 0; }

void test_case_sample(void)
{
	CU_ASSERT(CU_TRUE);
	CU_ASSERT_NOT_EQUAL(2, -1);
	CU_ASSERT_STRING_NOT_EQUAL("string #1", "string #1");
	CU_ASSERT_STRING_EQUAL("string #1", "string #2");

	CU_ASSERT(CU_TRUE);
	CU_ASSERT_NOT_EQUAL(2, 3);
	CU_ASSERT_STRING_NOT_EQUAL("string #1", "string #1");
	CU_ASSERT_STRING_EQUAL("string #1", "string #2");
}

void login_test(void) {
	CU_ASSERT_EQUAL( brute_5(1, 'v'), 0x63);
	CU_ASSERT_EQUAL( brute_5(5, 'i'), 0x17);
	CU_ASSERT_EQUAL( brute_5(7, 'i'), 0x17);
}

void password_test(void) {
	CU_ASSERT_EQUAL( pass_pol("fail"), 0x17);
	CU_ASSERT_EQUAL( pass_pol("testpass"), 0x63
);
}


int main(void)
{
	CU_pSuite pSuite = NULL;
	if (CUE_SUCCESS != CU_initialize_registry() )
		return CU_get_error();

	pSuite = CU_add_suite( "server_test_suite", init_suite, clean_suite );
	if ( NULL == pSuite ) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if ( (NULL == CU_add_test(pSuite, "login_test", login_test)) ||
	     (NULL == CU_add_test(pSuite, "password_test", password_test))
	)
	{
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	printf("\n");
	CU_basic_show_failures(CU_get_failure_list());
	printf("\n\n");

	CU_cleanup_registry();
	return CU_get_error();
}
