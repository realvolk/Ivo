#ifndef SECURE_BOOT_H
#define SECURE_BOOT_H

#include <stdint.h>
#include <stddef.h>

#define SB_HASH_HEX_LEN 128
#define SB_HASH_HEX_BUF 129

/* Read /ivo/config.toml into a fresh buffer. With SECURE_BOOT the
 * buffer is verified against /ivo/config.toml.sig before it is
 * returned, and the caller must parse exactly this buffer: never
 * re-read the file. Returns 0, CONFIG_ERR_READ, or
 * CONFIG_ERR_SIGNATURE (config.h). */
int sb_read_config(uint8_t **buf_out, size_t *len_out);

int sb_hash_buffer(const uint8_t *data, size_t len,
                   char hex_out[SB_HASH_HEX_BUF]);

int sb_hash_matches(const char *got_hex, const char *expected_hex);

#endif