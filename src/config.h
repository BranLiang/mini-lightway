#ifndef CONFIG_H
#define CONFIG_H

#include "he.h"

bool he_internal_config_is_string_length_okay(const char *string);
bool he_internal_config_is_empty_string(const char *string);
bool he_internal_config_is_string_too_long(const char *string);
he_return_code_t he_internal_set_config_string(char *field, const char *value);

#endif // CONFIG_H
