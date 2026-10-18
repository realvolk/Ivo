/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

/* Thin wrapper: the real implementation lives in crypto/argon2.c and
 * exposes argon2id_hash. This file exists because the Ivo source
 * tree and the build wildcard reference crypto/argon2id.c. */

#include <stdint.h>
#include <stddef.h>

int argon2id_hash(const void *pwd, size_t pwd_len,
                  const void *salt, size_t salt_len,
                  uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                  void *out, size_t out_len);

int argon2id(const uint8_t *password, size_t pw_len,
             const uint8_t *salt, size_t salt_len,
             uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
             uint8_t *output, size_t output_len)
{
    return argon2id_hash(password, pw_len, salt, salt_len,
                         t_cost, m_cost, parallelism,
                         output, output_len);
}