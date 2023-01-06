#include "core.h"

he_return_code_t he_internal_setup_stream_state(he_conn_t *conn, uint8_t *data, size_t length) {
  if(conn->incoming_data_left_to_read != 0) {
    // Somehow this function was called without reading all data from a previous buffer
    // This is bad
    return HE_ERR_SSL_ERROR;
  }
  // Set up the location of the buffer and its length
  conn->incoming_data = data;
  conn->incoming_data_length = length;

  // Initialise the offset pointer and data left counter
  conn->incoming_data_left_to_read = conn->incoming_data_length;
  conn->incoming_data_read_offset_ptr = conn->incoming_data;

  return HE_SUCCESS;
}
