#ifndef FE_UTIL_H
#define FE_UTIL_H

#include "relic.h"


/**
 * Returns the number of bytes necessary to store a rsa public or private key.
 */
int rsa_key_size_bin(const rsa_t key);

/**
 * Writes a rsa public or private key to a byte vector.
 *
 * **NO OUT OF BOUNDS CHECK**
 */
void rsa_key_write_bin(uint8_t *bin, const rsa_t key);

/**
 * Reads a rsa public or private key from a byte vector.
 *
 * **NO OUT OF BOUNDS CHECK**
 */
void rsa_key_read_bin(rsa_t key, const uint8_t *bin);


#endif /* FE_UTIL_H */
