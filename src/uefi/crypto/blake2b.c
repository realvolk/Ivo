/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */
#include "blake2b.h"
#include "../security/wipe.h"


#include <string.h>

static const uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

static const uint8_t SIGMA[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

static uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static uint64_t load64_le(const uint8_t *p) {
    return  (uint64_t)p[0]
         | ((uint64_t)p[1] <<  8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

static void store64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static void compress(struct blake2b_ctx *ctx,
                     const uint8_t block[BLAKE2B_BLOCK_SIZE]) {
    uint64_t m[16];
    uint64_t v[16];
    int i, r;

    for (i = 0; i < 16; i++)
        m[i] = load64_le(block + i * 8);

    for (i = 0; i < 8; i++)
        v[i] = ctx->h[i];
    for (i = 0; i < 8; i++)
        v[i + 8] = IV[i];

    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] ^= ctx->f[0];
    v[15] ^= ctx->f[1];

    for (r = 0; r < 12; r++) {
        const uint8_t *s = SIGMA[r];

        #define G(a, b, c, d, x, y) do { \
            v[a] = v[a] + v[b] + (x); \
            v[d] = rotr64(v[d] ^ v[a], 32); \
            v[c] = v[c] + v[d]; \
            v[b] = rotr64(v[b] ^ v[c], 24); \
            v[a] = v[a] + v[b] + (y); \
            v[d] = rotr64(v[d] ^ v[a], 16); \
            v[c] = v[c] + v[d]; \
            v[b] = rotr64(v[b] ^ v[c], 63); \
        } while (0)

        G(0, 4,  8, 12, m[s[0]],  m[s[1]]);
        G(1, 5,  9, 13, m[s[2]],  m[s[3]]);
        G(2, 6, 10, 14, m[s[4]],  m[s[5]]);
        G(3, 7, 11, 15, m[s[6]],  m[s[7]]);
        G(0, 5, 10, 15, m[s[8]],  m[s[9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7,  8, 13, m[s[12]], m[s[13]]);
        G(3, 4,  9, 14, m[s[14]], m[s[15]]);

        #undef G
    }

    for (i = 0; i < 8; i++)
        ctx->h[i] ^= v[i] ^ v[i + 8];
}

int blake2b_init(struct blake2b_ctx *ctx, size_t outlen) {
    if (outlen == 0 || outlen > BLAKE2B_MAX_DIGEST) {
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->outlen = outlen;

    for (int i = 0; i < 8; i++)
        ctx->h[i] = IV[i];

    ctx->h[0] ^= 0x01010000ULL ^ (uint64_t)outlen;

    return 0;
}

int blake2b_update(struct blake2b_ctx *ctx, const uint8_t *data, size_t len) {
    if (len == 0) return 0;

    while (len > 0) {
        size_t left = BLAKE2B_BLOCK_SIZE - ctx->buflen;
        size_t take = len < left ? len : left;

        memcpy(ctx->buf + ctx->buflen, data, take);
        ctx->buflen += take;
        data += take;
        len -= take;

        if (ctx->buflen == BLAKE2B_BLOCK_SIZE && len > 0) {
            ctx->t[0] += BLAKE2B_BLOCK_SIZE;
            if (ctx->t[0] < BLAKE2B_BLOCK_SIZE) ctx->t[1]++;
            compress(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }

    return 0;
}

int blake2b_final(struct blake2b_ctx *ctx, uint8_t out[BLAKE2B_MAX_DIGEST]) {
    uint8_t buffer[BLAKE2B_MAX_DIGEST];

    ctx->t[0] += ctx->buflen;
    if (ctx->t[0] < ctx->buflen) ctx->t[1]++;

    memset(ctx->buf + ctx->buflen, 0, BLAKE2B_BLOCK_SIZE - ctx->buflen);

    ctx->f[0] = ~(uint64_t)0;

    compress(ctx, ctx->buf);

    for (int i = 0; i < 8; i++)
        store64_le(buffer + i * 8, ctx->h[i]);

    memcpy(out, buffer, ctx->outlen);

    ivo_wipe(ctx, sizeof(*ctx));
    ivo_wipe(buffer, sizeof(buffer));

    return 0;
}

int blake2b(const uint8_t *data, size_t len,
            uint8_t out[BLAKE2B_MAX_DIGEST], size_t outlen) {
    struct blake2b_ctx ctx;
    if (blake2b_init(&ctx, outlen) != 0) return -1;
    blake2b_update(&ctx, data, len);
    return blake2b_final(&ctx, out);
}