#include "config.h"

bool he_internal_config_is_string_length_okay(const char *string)
{
    size_t len = strnlen(string, HE_CONFIG_TEXT_FIELD_LENGTH + 1);

    if (len > HE_CONFIG_TEXT_FIELD_LENGTH)
    {
        return false;
    }

    return true;
}

bool he_internal_config_is_empty_string(const char *string)
{
    if (string[0] == '\0')
    {
        return true;
    }

    return false;
}

bool he_internal_config_is_string_too_long(const char *string)
{
    return !he_internal_config_is_string_length_okay(string);
}

he_return_code_t he_internal_set_config_string(char *field, const char *value)
{
    if (value == NULL || field == NULL)
    {
        return HE_ERR_NULL_POINTER;
    }

    if (he_internal_config_is_empty_string(value))
    {
        return HE_ERR_EMPTY_STRING;
    }

    if (he_internal_config_is_string_too_long(value))
    {
        return HE_ERR_STRING_TOO_LONG;
    }

    // Copy the value into the field
    strncpy(field, value, HE_CONFIG_TEXT_FIELD_LENGTH);
    field[HE_CONFIG_TEXT_FIELD_LENGTH - 1] = '\0';

    return HE_SUCCESS;
}
