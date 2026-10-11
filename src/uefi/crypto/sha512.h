#ifndef IVO_SHA512_H
#define IVO_SHA512_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t h[8];
    uint64_t len_lo;
    uint64_t len_hi;
    uint8_t  buf[128];
    size_t   buf_len;
} sha512_ctx_t;

void sha512_init(sha512_ctx_t *ctx);
void sha512_update(sha512_ctx_t *ctx, const void *data, size_t len);
void sha512_final(sha512_ctx_t *ctx, uint8_t out[64]);

#endif