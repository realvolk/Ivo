#ifndef IVO_PASSWORD_H
#define IVO_PASSWORD_H

#include <stdint.h>
#include <stddef.h>
#include "boot/config.h"

/* Stored password format:
 *   pbkdf2-sha256:<iterations>:<salt-hex>:<hash-hex>
 * salt is 16 bytes (32 hex chars), hash is 32 bytes (64 hex chars).
 * Structural check only: no crypto, safe to call from host tools. */
int password_hash_valid(const char *stored);

#ifndef CONFIG_HOST
int password_verify(const char *stored, const char *plaintext);
int entry_password_check(entry_t *e);
#endif

#endif