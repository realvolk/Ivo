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
/* Returns 1 on match, 0 on mismatch, -1 on malformed stored hash. */
int password_verify(const char *stored, const char *plaintext);

/* Prompt for the entry's password if it has one and hasn't been
 * proven this boot. On success sets entry->password_proven = 1.
 * Returns 0 on success (or no password set, or already proven),
 * -1 on failure. */
int entry_password_check(entry_t *e);
#endif

#endif