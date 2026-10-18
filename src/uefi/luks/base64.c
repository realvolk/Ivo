/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Standard base64. No line breaks, no URL-safe
 * alphabet, no padding checks beyond what LUKS2 needs.
 */

#include "luks/base64.h"


static int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char *input, size_t input_len,
                  uint8_t *out, size_t *out_len) {
    size_t cap = *out_len;
    size_t written = 0;
    size_t i = 0;

    while (i + 4 <= input_len) {
        int v0 = b64_val((unsigned char)input[i]);
        int v1 = b64_val((unsigned char)input[i + 1]);
        unsigned char c2 = (unsigned char)input[i + 2];
        unsigned char c3 = (unsigned char)input[i + 3];

        if (v0 < 0 || v1 < 0) { return -1; }

        int v2 = (c2 == '=') ? 0 : b64_val(c2);
        int v3 = (c3 == '=') ? 0 : b64_val(c3);
        if (v2 < 0 || v3 < 0) { return -1; }

        if (written >= cap) { return -1; }
        out[written++] = (uint8_t)((v0 << 2) | (v1 >> 4));

        if (c2 != '=') {
            if (written >= cap) { return -1; }
            out[written++] = (uint8_t)(((v1 & 0x0F) << 4) | (v2 >> 2));

            if (c3 != '=') {
                if (written >= cap) { return -1; }
                out[written++] = (uint8_t)(((v2 & 0x03) << 6) | v3);
            }
        }

        i += 4;
    }

    if (i != input_len) { return -1; }

    *out_len = written;
    return 0;
}

static const char b64_enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t *out_len) {
    size_t cap = *out_len;
    size_t o = 0;

    for (size_t i = 0; i + 3 <= in_len; i += 3) {
        if (o + 4 > cap) { return -1; }
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[o++] = b64_enc[(v >> 18) & 0x3F];
        out[o++] = b64_enc[(v >> 12) & 0x3F];
        out[o++] = b64_enc[(v >> 6) & 0x3F];
        out[o++] = b64_enc[v & 0x3F];
    }

    size_t rem = in_len % 3;
    if (rem == 1) {
        if (o + 4 > cap) { return -1; }
        uint32_t v = (uint32_t)in[in_len - 1] << 16;
        out[o++] = b64_enc[(v >> 18) & 0x3F];
        out[o++] = b64_enc[(v >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        if (o + 4 > cap) { return -1; }
        uint32_t v = ((uint32_t)in[in_len - 2] << 16) |
                     ((uint32_t)in[in_len - 1] << 8);
        out[o++] = b64_enc[(v >> 18) & 0x3F];
        out[o++] = b64_enc[(v >> 12) & 0x3F];
        out[o++] = b64_enc[(v >> 6) & 0x3F];
        out[o++] = '=';
    }

    if (o >= cap) { return -1; }
    out[o] = '\0';
    *out_len = o;
    return 0;
}