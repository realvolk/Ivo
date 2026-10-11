/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

#ifndef KISKA_BASE64_H
#define KISKA_BASE64_H

#include <stddef.h>
#include <stdint.h>

int base64_decode(const char *input, size_t input_len,
                  uint8_t *out, size_t *out_len);

int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t *out_len);

#endif