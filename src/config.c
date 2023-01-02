#include "config.h"

bool he_internal_config_is_string_length_ok(const char *string)
{
    size_t len = strnlen(string, HE_CONFIG_TEXT_FIELD_LENGTH + 1);

    if (len > HE_CONFIG_TEXT_FIELD_LENGTH)
    {
        return false;
    }

    return true;
}
