#ifdef TEST

#include "unity.h"

#include "config.h"

void test_config_length_is_okay(void)
{
    // len = 50
    char *max_string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    TEST_ASSERT_TRUE(he_internal_config_is_string_length_okay(max_string));
    TEST_ASSERT_FALSE(he_internal_config_is_string_too_long(max_string));
    // len = 51
    char *too_long_string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    TEST_ASSERT_FALSE(he_internal_config_is_string_length_okay(too_long_string));
    TEST_ASSERT_TRUE(he_internal_config_is_string_too_long(too_long_string));
}

void test_config_is_empty_string(void)
{
    char *empty_string = "";
    TEST_ASSERT_TRUE(he_internal_config_is_empty_string(empty_string));
    char *not_empty_string = "not empty";
    TEST_ASSERT_FALSE(he_internal_config_is_empty_string(not_empty_string));
}

void test_config_set_string(void)
{
    char field[HE_CONFIG_TEXT_FIELD_LENGTH];
    char *value = "test";
    TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_set_config_string(field, value));
    TEST_ASSERT_EQUAL_STRING(value, field);
    value = "";
    TEST_ASSERT_EQUAL(HE_ERR_EMPTY_STRING, he_internal_set_config_string(field, value));
    value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    TEST_ASSERT_EQUAL(HE_ERR_STRING_TOO_LONG, he_internal_set_config_string(field, value));
    value = NULL;
    TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, he_internal_set_config_string(field, value));
}

#endif // TEST
