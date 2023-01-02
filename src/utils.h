#ifndef UTILS_H
#define UTILS_H

#include "he.h"

const char *he_return_code_name(he_return_code_t rc);
const char *he_client_state_name(he_conn_state_t st);
const char *he_client_event_name(he_conn_event_t ev);

#endif // UTILS_H
