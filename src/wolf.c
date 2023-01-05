#include "he.h"
#include "wolf.h"
#include "plugin_chain.h"

int he_wolf_dtls_read(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl; /* will not need ssl context */

  if(sz < 0) {
    // Should never ever happen but we'll just abort
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Abort if any of the IO buffers are null pointers
  if(!buf || !ctx) {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Get DTLS context
  he_conn_t *conn = (he_conn_t *)ctx;

  // This can be null if no data has been received yet, tell wolfSSL to stop asking
  if(!conn->incoming_data) {
    return WOLFSSL_CBIO_ERR_WANT_READ;
  }

  // WolfSSL will call this function any time it wants to read. As we're using libuv
  // there will only ever be one packet per callback. WolfSSL will call this function
  // any time it wants to read, it doesn't know there's only ever one, so we need to
  // check and send the equivalent of "would block" if we've already processed the
  // provided packet.
  if(conn->packet_seen) {
    // We've already processed this packet, tell WolfSSL to stop asking
    return WOLFSSL_CBIO_ERR_WANT_READ;
  }

  // Check that we have enough space to write the packet
  if(conn->incoming_data_length > sz) {
    // We can't write this packet and split it - have to drop
    conn->packet_seen = true;
    return 0;
  }

  // Copy the data out of the packet into WolfSSL's buffer
  memcpy(buf, conn->incoming_data, conn->incoming_data_length);
  // Set flag so we can ignore this packet next time
  conn->packet_seen = true;

  // The amount of data we copied into WolfSSL's buffer
  return (int)conn->incoming_data_length;
}

