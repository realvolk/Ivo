/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

#ifndef KISKA_AES_H
#define KISKA_AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE  16
#define AES128_KEY_SIZE 16
#define AES256_KEY_SIZE 32

struct aes_ctx {
    uint32_t rk[60];
    int nr;
};

int  aes_init(struct aes_ctx *ctx, const uint8_t *key, size_t key_len);
void aes_encrypt_block(const struct aes_ctx *ctx,
                       const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE]);
void aes_decrypt_block(const struct aes_ctx *ctx,
                       const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE]);
void aes_clear(struct aes_ctx *ctx);

#endif