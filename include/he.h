#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define HE_CONFIG_TEXT_FIELD_LENGTH 50

typedef enum he_return_code
{
    // Success
    HE_SUCCESS = 0,
    // This will be returned if a string parameter is too long to be stored.
    HE_ERR_STRING_TOO_LONG = -1,
    // This will be returned if trying to set a configuration parameter to an empty string
    HE_ERR_EMPTY_STRING = -2,
    // A null pointer was passed as an argument
    HE_ERR_NULL_POINTER = -4,
    // Initialisation failed - this is usually an issue with the SSL layer
    HE_ERR_INIT_FAILED = -9,
    // Generic issue
    HE_ERR_FAILED = -33,
    // A plugin requested that we drop the packet without further processing
    HE_ERR_PLUGIN_DROP = -49,
} he_return_code_t;

typedef enum he_conn_state
{
    // Connection has yet to be initialised
    HE_STATE_NONE = 0,
    // Connection is in a disconnected state. Any resources used for the connection have been released.
    HE_STATE_DISCONNECTED = 1,
    // Connection is currently trying to establish a D/TLS session with the server.
    HE_STATE_CONNECTING = 2,
    // Connection is currently trying to cleanly disconnect from the server.
    HE_STATE_DISCONNECTING = 3,
    // Connection has established a D/TLS session and is attempting to authenticate
    HE_STATE_AUTHENTICATING = 4,
    // TLS link is up
    HE_STATE_LINK_UP = 5,
    // Everything is done - we're online
    HE_STATE_ONLINE = 6,
    // Configuring - config has been received and config callback will soon be made
    HE_STATE_CONFIGURING = 7,
} he_conn_state_t;

typedef enum he_conn_event
{
    // First packet / message was passed to Helium (i.e. a server response)
    HE_EVENT_FIRST_MESSAGE_RECEIVED = 0,
    // Server replied to a PING request (NAT Keepalive)
    HE_EVENT_PONG = 1,
    // Connection tried to send fragmented packets which were rejected as they are not supported by Helium
    HE_EVENT_REJECT_FRAGMENTED_PACKETS_SENT_BY_HOST = 2,
    // Helium has started a secure renegotiation
    HE_EVENT_SECURE_RENEGOTIATION_STARTED = 3,
    // Helium has completed secure renegotiation
    HE_EVENT_SECURE_RENEGOTIATION_COMPLETED = 4,
    // Pending Session Acknowledged
    HE_EVENT_PENDING_SESSION_ACKNOWLEDGED = 5,
} he_conn_event_t;

typedef enum he_plugin_return_code
{
    HE_PLUGIN_SUCCESS = 0,
    HE_PLUGIN_FAIL = -1,
    HE_PLUGIN_DROP = -2,
} he_plugin_return_code_t;

typedef he_plugin_return_code_t (*plugin_do_ingress) (
    uint8_t *packet,
    size_t *length,
    size_t capacity,
    void *data
);

typedef he_plugin_return_code_t (*plugin_do_egress) (
    uint8_t *packet,
    size_t *length,
    size_t capacity,
    void *data
);

typedef struct plugin_struct
{
    plugin_do_ingress do_ingress;
    plugin_do_egress do_egress;
    void *data;
} plugin_struct_t;

typedef struct he_plugin_chain he_plugin_chain_t;
struct he_plugin_chain
{
    plugin_struct_t *plugin;
    he_plugin_chain_t *next;
};
