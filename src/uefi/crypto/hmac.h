/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

#ifndef KISKA_HMAC_H
#define KISKA_HMAC_H

#include <stddef.h>
#include <stdint.h>
#include "sha256.h"

struct hmac_sha256_ctx {
    struct sha256_ctx inner;
    struct sha256_ctx outer;
};

void hmac_sha256_init(struct hmac_sha256_ctx *ctx,
                      const uint8_t *key, size_t key_len);
void hmac_sha256_update(struct hmac_sha256_ctx *ctx,
                        const uint8_t *data, size_t len);
void hmac_sha256_final(struct hmac_sha256_ctx *ctx,
                       uint8_t out[SHA256_DIGEST_SIZE]);

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[SHA256_DIGEST_SIZE]);

#endif