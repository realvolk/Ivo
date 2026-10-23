/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

#include "pbkdf2.h"
#include "../security/wipe.h"
#include "hmac.h"
#include "hmac_sha1.h"


#include <string.h>

int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations,
                       uint8_t *out, size_t out_len) {
    if (iterations == 0 || out_len == 0) {
        return -1;
    }

    if (out_len > (size_t)0xFFFFFFFFULL * SHA256_DIGEST_SIZE) {
        return -1;
    }

    size_t blocks = (out_len + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;

    struct hmac_sha256_ctx base;
    hmac_sha256_init(&base, password, password_len);

    for (size_t b = 0; b < blocks; b++) {
        uint8_t U[SHA256_DIGEST_SIZE];
        uint8_t T[SHA256_DIGEST_SIZE];

        struct hmac_sha256_ctx ctx;
        memcpy(&ctx, &base, sizeof(ctx));
        hmac_sha256_update(&ctx, salt, salt_len);

        uint8_t idx_be[4];
        uint32_t idx = (uint32_t)(b + 1);
        idx_be[0] = (uint8_t)(idx >> 24);
        idx_be[1] = (uint8_t)(idx >> 16);
        idx_be[2] = (uint8_t)(idx >> 8);
        idx_be[3] = (uint8_t)(idx);
        hmac_sha256_update(&ctx, idx_be, 4);
        hmac_sha256_final(&ctx, U);

        memcpy(T, U, SHA256_DIGEST_SIZE);

        for (uint32_t j = 1; j < iterations; j++) {
            memcpy(&ctx, &base, sizeof(ctx));
            hmac_sha256_update(&ctx, U, SHA256_DIGEST_SIZE);
            hmac_sha256_final(&ctx, U);
            for (int k = 0; k < SHA256_DIGEST_SIZE; k++)
                T[k] ^= U[k];
        }

        size_t copy = out_len - b * SHA256_DIGEST_SIZE;
        if (copy > SHA256_DIGEST_SIZE) copy = SHA256_DIGEST_SIZE;
        memcpy(out + b * SHA256_DIGEST_SIZE, T, copy);

        ivo_wipe(U, sizeof(U));
        ivo_wipe(T, sizeof(T));
        ivo_wipe(&ctx, sizeof(ctx));
    }

    ivo_wipe(&base, sizeof(base));
    return 0;
}

int pbkdf2_hmac_sha1(const uint8_t *password, size_t password_len,
                     const uint8_t *salt, size_t salt_len,
                     uint32_t iterations,
                     uint8_t *out, size_t out_len)
{
    if (iterations == 0 || out_len == 0) {
        return -1;
    }
    if (out_len > (size_t)0xFFFFFFFFULL * SHA1_DIGEST_SIZE) {
        return -1;
    }

    size_t blocks = (out_len + SHA1_DIGEST_SIZE - 1) / SHA1_DIGEST_SIZE;

    struct hmac_sha1_ctx base;
    hmac_sha1_init(&base, password, password_len);

    for (size_t b = 0; b < blocks; b++) {
        uint8_t U[SHA1_DIGEST_SIZE];
        uint8_t T[SHA1_DIGEST_SIZE];

        struct hmac_sha1_ctx ctx;
        memcpy(&ctx, &base, sizeof(ctx));
        hmac_sha1_update(&ctx, salt, salt_len);

        uint8_t idx_be[4];
        uint32_t idx = (uint32_t)(b + 1);
        idx_be[0] = (uint8_t)(idx >> 24);
        idx_be[1] = (uint8_t)(idx >> 16);
        idx_be[2] = (uint8_t)(idx >> 8);
        idx_be[3] = (uint8_t)(idx);
        hmac_sha1_update(&ctx, idx_be, 4);
        hmac_sha1_final(&ctx, U);

        memcpy(T, U, SHA1_DIGEST_SIZE);

        for (uint32_t j = 1; j < iterations; j++) {
            memcpy(&ctx, &base, sizeof(ctx));
            hmac_sha1_update(&ctx, U, SHA1_DIGEST_SIZE);
            hmac_sha1_final(&ctx, U);
            for (int k = 0; k < SHA1_DIGEST_SIZE; k++)
                T[k] ^= U[k];
        }

        size_t copy = out_len - b * SHA1_DIGEST_SIZE;
        if (copy > SHA1_DIGEST_SIZE) copy = SHA1_DIGEST_SIZE;
        memcpy(out + b * SHA1_DIGEST_SIZE, T, copy);

        ivo_wipe(U, sizeof(U));
        ivo_wipe(T, sizeof(T));
        ivo_wipe(&ctx, sizeof(ctx));
    }

    ivo_wipe(&base, sizeof(base));
    return 0;
}