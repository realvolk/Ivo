/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

#ifndef KISKA_XTS_H
#define KISKA_XTS_H

#include <stddef.h>
#include <stdint.h>
#include "aes.h"

struct xts_ctx {
    struct aes_ctx data;
    struct aes_ctx tweak;
};

int  xts_init(struct xts_ctx *ctx, const uint8_t *key, size_t key_len);
void xts_clear(struct xts_ctx *ctx);

int  xts_encrypt_sector(const struct xts_ctx *ctx, uint64_t sector_num,
                        const uint8_t *in, uint8_t *out, size_t len);
int  xts_decrypt_sector(const struct xts_ctx *ctx, uint64_t sector_num,
                        const uint8_t *in, uint8_t *out, size_t len);

#endif