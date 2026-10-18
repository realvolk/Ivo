/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

#ifndef KISKA_BLAKE2B_H
#define KISKA_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#define BLAKE2B_BLOCK_SIZE  128
#define BLAKE2B_MAX_DIGEST  64

struct blake2b_ctx {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[BLAKE2B_BLOCK_SIZE];
    size_t   buflen;
    size_t   outlen;
};

int blake2b_init(struct blake2b_ctx *ctx, size_t outlen);
int blake2b_update(struct blake2b_ctx *ctx, const uint8_t *data, size_t len);
int blake2b_final(struct blake2b_ctx *ctx, uint8_t out[BLAKE2B_MAX_DIGEST]);

int blake2b(const uint8_t *data, size_t len,
            uint8_t out[BLAKE2B_MAX_DIGEST], size_t outlen);

#endif