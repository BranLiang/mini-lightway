#ifdef TEST

#include "unity.h"

#include "config.h"

void setUp(void)
{
}

void tearDown(void)
{
}

void test_config_length_is_ok(void)
{
    // len = 50
    char *max_string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    TEST_ASSERT_TRUE(he_internal_config_is_string_length_ok(max_string));
    // len = 51
    char *too_long_string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    TEST_ASSERT_FALSE(he_internal_config_is_string_length_ok(too_long_string));
}

#endif // TEST
