#ifndef CORE_H
#define CORE_H

#include "he.h"

/**
 * @brief Setup the pointers and counters for reading from a TCP stream
 */
he_return_code_t he_internal_setup_stream_state(he_conn_t *conn, uint8_t *data, size_t length);

#endif // CORE_H
