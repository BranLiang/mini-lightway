#ifndef WOLF_H
#define WOLF_H

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

/**
 * @brief Callback function to handle WolfSSL read requests
 * @param ssl A pointer to the WolfSSL session that this callback relates to
 * @param buf A pointer to the buffer the callback writes data to
 * @param sz The maximum size that can be written to the buffer
 * @param ctx A pointer to the Helium context that this callback relates to
 * @return int The length of the data copied to the buffer
 * @return WOLFSSL_CBIO_ERR_WANT_READ Tells WolfSSL that there's no more data available
 *
 * Helium does not know about sockets and as such, neither can WolfSSL. Helium
 * overrides the standard socket calls with its own callback functions.
 *
 * This function simply copies data to WolfSSL's buffer and returns
 *
 * @note This function will be called twice per packet. This function will return
 * WOLFSSL_CBIO_ERR_WANT_READ on the second call.
 *
 */
int he_wolf_dtls_read(WOLFSSL *ssl, char *buf, int sz, void *ctx);

/**
 * @brief Callback function to handle WolfSSL write requests
 * @param ssl A pointer to the WolfSSL session that this callback relates to
 * @param buf A pointer to the buffer the callback reads data from
 * @param sz The size of the data to be read
 * @param ctx A pointer to the Helium context that this callback relates to
 * @return int The length of the data copied to the buffer
 *
 * Helium does not know about sockets and as such, neither can WolfSSL. Helium
 * overrides the standard socket calls with its own callback functions.
 *
 * This function simply calls the user provided write callback
 *
 * @note The buffer is only valid until this function returns. As such the user provided write
 * callback must copy the data from the buffer if it needs it to persist after that time.
 */

int he_wolf_dtls_write(WOLFSSL *ssl, char *buf, int sz, void *ctx);


#endif // WOLF_H
