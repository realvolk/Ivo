#ifndef IVO_SHA1_H
#define IVO_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE  64

struct sha1_ctx {
    uint32_t state[5];
    uint64_t bitlen;
    uint8_t  buf[SHA1_BLOCK_SIZE];
    size_t   buflen;
};

void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, const uint8_t *data, size_t len);
void sha1_final(struct sha1_ctx *ctx, uint8_t out[SHA1_DIGEST_SIZE]);

void sha1(const uint8_t *msg, size_t len, uint8_t out[SHA1_DIGEST_SIZE]);

#endif