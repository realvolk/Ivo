/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

#ifndef KISKA_SHA256_H
#define KISKA_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

struct sha256_ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[SHA256_BLOCK_SIZE];
    size_t   buflen;
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(struct sha256_ctx *ctx, uint8_t out[SHA256_DIGEST_SIZE]);

void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

#endif