#include "hmac_sha1.h"
#include "../security/wipe.h"
#include <string.h>

void hmac_sha1_init(struct hmac_sha1_ctx *ctx,
                    const uint8_t *key, size_t key_len)
{
    uint8_t k[SHA1_BLOCK_SIZE];
    uint8_t ipad[SHA1_BLOCK_SIZE];
    uint8_t opad[SHA1_BLOCK_SIZE];

    if (key_len > SHA1_BLOCK_SIZE) {
        sha1(key, key_len, k);
        memset(k + SHA1_DIGEST_SIZE, 0,
               SHA1_BLOCK_SIZE - SHA1_DIGEST_SIZE);
    } else {
        memcpy(k, key, key_len);
        if (key_len < SHA1_BLOCK_SIZE)
            memset(k + key_len, 0, SHA1_BLOCK_SIZE - key_len);
    }

    for (size_t i = 0; i < SHA1_BLOCK_SIZE; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    sha1_init(&ctx->inner);
    sha1_update(&ctx->inner, ipad, SHA1_BLOCK_SIZE);

    sha1_init(&ctx->outer);
    sha1_update(&ctx->outer, opad, SHA1_BLOCK_SIZE);

    ivo_wipe(k, sizeof(k));
    ivo_wipe(ipad, sizeof(ipad));
    ivo_wipe(opad, sizeof(opad));
}

void hmac_sha1_update(struct hmac_sha1_ctx *ctx,
                      const uint8_t *data, size_t len)
{
    sha1_update(&ctx->inner, data, len);
}

void hmac_sha1_final(struct hmac_sha1_ctx *ctx,
                     uint8_t out[SHA1_DIGEST_SIZE])
{
    uint8_t inner_digest[SHA1_DIGEST_SIZE];
    sha1_final(&ctx->inner, inner_digest);
    sha1_update(&ctx->outer, inner_digest, SHA1_DIGEST_SIZE);
    sha1_final(&ctx->outer, out);
    ivo_wipe(inner_digest, sizeof(inner_digest));
}

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t out[SHA1_DIGEST_SIZE])
{
    struct hmac_sha1_ctx ctx;
    hmac_sha1_init(&ctx, key, key_len);
    hmac_sha1_update(&ctx, data, data_len);
    hmac_sha1_final(&ctx, out);
    ivo_wipe(&ctx, sizeof(ctx));
}