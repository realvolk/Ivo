/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

#include "xts.h"
#include "../security/wipe.h"


#include <string.h>

static void mul_alpha(uint8_t t[AES_BLOCK_SIZE]) {
    uint8_t carry = 0;
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        uint8_t next = (uint8_t)(t[i] >> 7);
        t[i] = (uint8_t)((t[i] << 1) | carry);
        carry = next;
    }
    if (carry) t[0] ^= 0x87;
}

static void make_tweak(const struct xts_ctx *ctx, uint64_t sector_num,
                       uint8_t tweak[AES_BLOCK_SIZE]) {
    memset(tweak, 0, AES_BLOCK_SIZE);
    for (int i = 0; i < 8; i++)
        tweak[i] = (uint8_t)(sector_num >> (i * 8));
    aes_encrypt_block(&ctx->tweak, tweak, tweak);
}

int xts_init(struct xts_ctx *ctx, const uint8_t *key, size_t key_len) {
    if (!ctx || !key) return -1;
    if (key_len != AES128_KEY_SIZE * 2 && key_len != AES256_KEY_SIZE * 2) {
        return -1;
    }

    size_t half = key_len / 2;

    if (aes_init(&ctx->data,  key,      half) != 0) {
        xts_clear(ctx);
        return -1;
    }
    if (aes_init(&ctx->tweak, key + half, half) != 0) {
        xts_clear(ctx);
        return -1;
    }
    return 0;
}

void xts_clear(struct xts_ctx *ctx) {
    if (!ctx) return;
    aes_clear(&ctx->data);
    aes_clear(&ctx->tweak);
}

int xts_encrypt_sector(const struct xts_ctx *ctx, uint64_t sector_num,
                       const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx || !in || !out) return -1;
    if (len == 0 || (len % AES_BLOCK_SIZE) != 0) {
        return -1;
    }

    uint8_t tweak[AES_BLOCK_SIZE];
    make_tweak(ctx, sector_num, tweak);

    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE];
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
            block[j] = in[i + j] ^ tweak[j];
        aes_encrypt_block(&ctx->data, block, block);
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
            out[i + j] = block[j] ^ tweak[j];
        mul_alpha(tweak);
    }

    ivo_wipe(tweak, sizeof(tweak));
    return 0;
}

int xts_decrypt_sector(const struct xts_ctx *ctx, uint64_t sector_num,
                       const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx || !in || !out) return -1;
    if (len == 0 || (len % AES_BLOCK_SIZE) != 0) {
        return -1;
    }

    uint8_t tweak[AES_BLOCK_SIZE];
    make_tweak(ctx, sector_num, tweak);

    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE];
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
            block[j] = in[i + j] ^ tweak[j];
        aes_decrypt_block(&ctx->data, block, block);
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
            out[i + j] = block[j] ^ tweak[j];
        mul_alpha(tweak);
    }

    ivo_wipe(tweak, sizeof(tweak));
    return 0;
}