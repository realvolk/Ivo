#include "sha1.h"
#include <string.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_zeroize(void *v, size_t n)
{
    volatile uint8_t *p = v;
    while (n--) *p++ = 0;
}

static void sha1_process_block(uint32_t state[5], const uint8_t block[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 80; i++)
        w[i] = ROTL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for (i = 0; i < 80; i++) {
        uint32_t f, k, temp;
        if (i < 20)      { f = (b & c) | ((~b) & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
        temp = ROTL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROTL(b, 30); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c;
    state[3] += d; state[4] += e;
}

void sha1_init(struct sha1_ctx *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

void sha1_update(struct sha1_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->bitlen += (uint64_t)len * 8;

    if (ctx->buflen > 0) {
        size_t need = 64 - ctx->buflen;
        size_t take = len < need ? len : need;
        memcpy(ctx->buf + ctx->buflen, data, take);
        ctx->buflen += take;
        data += take;
        len -= take;
        if (ctx->buflen == 64) {
            sha1_process_block(ctx->state, ctx->buf);
            ctx->buflen = 0;
        }
    }

    while (len >= 64) {
        sha1_process_block(ctx->state, data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buflen = len;
    }
}

void sha1_final(struct sha1_ctx *ctx, uint8_t out[SHA1_DIGEST_SIZE])
{
    uint64_t bitlen = ctx->bitlen;

    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);

    uint8_t zero = 0;
    while (ctx->buflen != 56)
        sha1_update(ctx, &zero, 1);

    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++)
        lenbuf[i] = (uint8_t)(bitlen >> (56 - i * 8));
    sha1_update(ctx, lenbuf, 8);

    for (int i = 0; i < 5; i++) {
        out[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }

    sha1_zeroize(ctx, sizeof(*ctx));
}

void sha1(const uint8_t *msg, size_t len, uint8_t out[SHA1_DIGEST_SIZE])
{
    struct sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, msg, len);
    sha1_final(&ctx, out);
}