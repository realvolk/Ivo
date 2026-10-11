/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

#ifndef KISKA_PBKDF2_H
#define KISKA_PBKDF2_H

#include <stddef.h>
#include <stdint.h>

int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations,
                       uint8_t *out, size_t out_len);

int pbkdf2_hmac_sha1(const uint8_t *password, size_t password_len,
                     const uint8_t *salt, size_t salt_len,
                     uint32_t iterations,
                     uint8_t *out, size_t out_len);

#endif