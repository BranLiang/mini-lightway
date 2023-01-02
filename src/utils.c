#include "utils.h"

#define DEFCASE(x) case x: return #x

const char *he_return_code_name(he_return_code_t rc)
{
    switch (rc)
    {
        DEFCASE(HE_SUCCESS);
        DEFCASE(HE_ERR_STRING_TOO_LONG);
        DEFCASE(HE_ERR_EMPTY_STRING);
        DEFCASE(HE_ERR_NULL_POINTER);
    }
    return "HE_ERR_UNKNOWN";
}
