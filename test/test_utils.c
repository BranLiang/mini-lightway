#ifdef TEST

#include "unity.h"

#include "utils.h"

void setUp(void)
{
}

void tearDown(void)
{
}

void test_utils_return_code_name(void)
{
    TEST_ASSERT_EQUAL_STRING("HE_SUCCESS", he_return_code_name(HE_SUCCESS));
    TEST_ASSERT_EQUAL_STRING("HE_ERR_UNKNOWN", he_return_code_name(1));
}

void test_utils_client_state_name(void)
{
    TEST_ASSERT_EQUAL_STRING("HE_STATE_NONE", he_client_state_name(HE_STATE_NONE));
    TEST_ASSERT_EQUAL_STRING("HE_STATE_UNKNOWN", he_client_state_name(-1));
}

#endif // TEST
