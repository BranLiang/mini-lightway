#ifdef TEST

#include "unity.h"

#include "config.h"

void setUp(void)
{
}

void tearDown(void)
{
}

void test_config_length_is_okay(void)
{
    // len = 50
    char *max_string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    TEST_ASSERT_TRUE(he_internal_config_is_string_length_okay(max_string));
    // len = 51
    char *too_long_string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    TEST_ASSERT_FALSE(he_internal_config_is_string_length_okay(too_long_string));
}

void test_config_is_empty_string(void)
{
    char *empty_string = "";
    TEST_ASSERT_TRUE(he_internal_config_is_empty_string(empty_string));
    char *not_empty_string = "not empty";
    TEST_ASSERT_FALSE(he_internal_config_is_empty_string(not_empty_string));
}

#endif // TEST
