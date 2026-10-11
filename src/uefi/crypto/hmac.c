/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */
#include "hmac.h"
#include "../security/wipe.h"

#include <string.h>

void hmac_sha256_init(struct hmac_sha256_ctx *ctx,
                      const uint8_t *key, size_t key_len) {
    uint8_t k[SHA256_BLOCK_SIZE];
    uint8_t ipad[SHA256_BLOCK_SIZE];
    uint8_t opad[SHA256_BLOCK_SIZE];

    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, k);
        memset(k + SHA256_DIGEST_SIZE, 0, SHA256_BLOCK_SIZE - SHA256_DIGEST_SIZE);
    } else {
        memcpy(k, key, key_len);
        if (key_len < SHA256_BLOCK_SIZE)
            memset(k + key_len, 0, SHA256_BLOCK_SIZE - key_len);
    }

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, ipad, SHA256_BLOCK_SIZE);

    sha256_init(&ctx->outer);
    sha256_update(&ctx->outer, opad, SHA256_BLOCK_SIZE);

    ivo_wipe(k,    sizeof(k));
    ivo_wipe(ipad, sizeof(ipad));
    ivo_wipe(opad, sizeof(opad));
}

void hmac_sha256_update(struct hmac_sha256_ctx *ctx,
                        const uint8_t *data, size_t len) {
    sha256_update(&ctx->inner, data, len);
}

void hmac_sha256_final(struct hmac_sha256_ctx *ctx,
                       uint8_t out[SHA256_DIGEST_SIZE]) {
    uint8_t inner_digest[SHA256_DIGEST_SIZE];
    sha256_final(&ctx->inner, inner_digest);
    sha256_update(&ctx->outer, inner_digest, SHA256_DIGEST_SIZE);
    sha256_final(&ctx->outer, out);
    ivo_wipe(inner_digest, sizeof(inner_digest));
}

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[SHA256_DIGEST_SIZE]) {
    struct hmac_sha256_ctx ctx;
    hmac_sha256_init(&ctx, key, key_len);
    hmac_sha256_update(&ctx, data, data_len);
    hmac_sha256_final(&ctx, out);
    ivo_wipe(&ctx, sizeof(ctx));
}