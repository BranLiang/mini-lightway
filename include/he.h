#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define HE_CONFIG_TEXT_FIELD_LENGTH 50

typedef enum he_return_code {
    // Success
    HE_SUCCESS = 0,
    // This will be returned if a string parameter is too long to be stored.
    HE_ERR_STRING_TOO_LONG = -1,
    // This will be returned if trying to set a configuration parameter to an empty string
    HE_ERR_EMPTY_STRING = -2,
    // A null pointer was passed as an argument
    HE_ERR_NULL_POINTER = -4,
} he_return_code_t;
