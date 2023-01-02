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
