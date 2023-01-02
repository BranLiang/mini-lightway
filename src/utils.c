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

const char *he_client_state_name(he_conn_state_t st)
{
    switch (st)
    {
        DEFCASE(HE_STATE_NONE);
        DEFCASE(HE_STATE_DISCONNECTED);
        DEFCASE(HE_STATE_CONNECTING);
        DEFCASE(HE_STATE_DISCONNECTING);
        DEFCASE(HE_STATE_AUTHENTICATING);
        DEFCASE(HE_STATE_LINK_UP);
        DEFCASE(HE_STATE_ONLINE);
        DEFCASE(HE_STATE_CONFIGURING);
    }
    return "HE_STATE_UNKNOWN";
}
