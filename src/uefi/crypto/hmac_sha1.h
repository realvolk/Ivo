#ifndef IVO_HMAC_SHA1_H
#define IVO_HMAC_SHA1_H

#include <stddef.h>
#include <stdint.h>
#include "sha1.h"

struct hmac_sha1_ctx {
    struct sha1_ctx inner;
    struct sha1_ctx outer;
};

void hmac_sha1_init(struct hmac_sha1_ctx *ctx,
                    const uint8_t *key, size_t key_len);
void hmac_sha1_update(struct hmac_sha1_ctx *ctx,
                      const uint8_t *data, size_t len);
void hmac_sha1_final(struct hmac_sha1_ctx *ctx,
                     uint8_t out[SHA1_DIGEST_SIZE]);

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t out[SHA1_DIGEST_SIZE]);

#endif