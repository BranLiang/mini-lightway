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

const char *he_client_event_name(he_conn_event_t ev)
{
    switch (ev)
    {
        DEFCASE(HE_EVENT_FIRST_MESSAGE_RECEIVED);
        DEFCASE(HE_EVENT_PONG);
        DEFCASE(HE_EVENT_REJECT_FRAGMENTED_PACKETS_SENT_BY_HOST);
        DEFCASE(HE_EVENT_SECURE_RENEGOTIATION_STARTED);
        DEFCASE(HE_EVENT_SECURE_RENEGOTIATION_COMPLETED);
        DEFCASE(HE_EVENT_PENDING_SESSION_ACKNOWLEDGED);
    }
    return "HE_EVENT_UNKNOWN";
}
