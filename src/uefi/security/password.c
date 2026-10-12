/* password.c — per-entry password hashes.
 *
 * A password_hash key in an entry is a string of the form
 *   pbkdf2-sha256:<iterations>:<salt-hex>:<hash-hex>
 * where salt is 16 bytes and hash is the PBKDF2-HMAC-SHA256 output,
 * 32 bytes. Structural validation is available to the host tools;
 * verification and the interactive prompt exist only in the
 * bootloader build. */

#ifdef CONFIG_HOST
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "security/password.h"
#else
#include "core.h"
#include "security/password.h"
#include "security/wipe.h"
#include "crypto/pbkdf2.h"
#endif

#define SALT_BYTES 16
#define HASH_BYTES 32

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int hex_decode(const char *s, size_t n, uint8_t *out)
{
    if (n % 2) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_val(s[i * 2]);
        int lo = hex_val(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* Parse pbkdf2-sha256:<iter>:<salt>:<hash>. Strict; nothing trailing
 * is allowed. */
static int parse_stored(const char *s, uint32_t *iter_out,
                        uint8_t salt[SALT_BYTES], uint8_t hash[HASH_BYTES])
{
    static const char prefix[] = "pbkdf2-sha256:";
    size_t plen = sizeof(prefix) - 1;
    if (!s || strncmp(s, prefix, plen) != 0) return -1;
    s += plen;

    if (*s < '0' || *s > '9') return -1;
    uint32_t iter = 0;
    while (*s >= '0' && *s <= '9') {
        iter = iter * 10 + (uint32_t)(*s - '0');
        if (iter > 10000000u) return -1;
        s++;
    }
    if (iter == 0) return -1;
    if (*s++ != ':') return -1;

    for (int i = 0; i < SALT_BYTES * 2; i++)
        if (hex_val(s[i]) < 0) return -1;
    if (hex_decode(s, SALT_BYTES * 2, salt) != 0) return -1;
    s += SALT_BYTES * 2;
    if (*s++ != ':') return -1;

    for (int i = 0; i < HASH_BYTES * 2; i++)
        if (hex_val(s[i]) < 0) return -1;
    if (hex_decode(s, HASH_BYTES * 2, hash) != 0) return -1;
    s += HASH_BYTES * 2;
    if (*s != '\0') return -1;

    *iter_out = iter;
    return 0;
}

int password_hash_valid(const char *s)
{
    uint32_t it;
    uint8_t salt[SALT_BYTES], hash[HASH_BYTES];
    return parse_stored(s, &it, salt, hash) == 0;
}

#ifndef CONFIG_HOST

int password_verify(const char *stored, const char *plaintext)
{
    uint32_t iter;
    uint8_t salt[SALT_BYTES];
    uint8_t expected[HASH_BYTES];
    uint8_t got[HASH_BYTES];

    if (!stored || !plaintext) return -1;
    if (parse_stored(stored, &iter, salt, expected) != 0) return -1;

    size_t plen = strlen(plaintext);
    if (pbkdf2_hmac_sha256((const uint8_t *)plaintext, plen,
                           salt, SALT_BYTES, iter,
                           got, HASH_BYTES) != 0) {
        ivo_wipe(got, sizeof(got));
        return -1;
    }

    uint8_t diff = 0;
    for (int i = 0; i < HASH_BYTES; i++) diff |= got[i] ^ expected[i];
    ivo_wipe(got, sizeof(got));
    return diff == 0 ? 1 : 0;
}

int entry_password_check(entry_t *e)
{
    if (!e || !e->password_hash || !e->password_hash[0]) return 0;
    if (e->password_proven) return 0;

    char pass[256];
    int n = con_read_secret("Password", pass, sizeof(pass), '*');
    con_clear();

    if (n < 0) {
        ivo_wipe(pass, sizeof(pass));
        return -1;
    }

    int rc = password_verify(e->password_hash, pass);
    ivo_wipe(pass, sizeof(pass));

    if (rc == 1) {
        e->password_proven = 1;
        return 0;
    }
    return -1;
}

#endif /* !CONFIG_HOST */