#ifndef KISKA_ARGON2_H
#define KISKA_ARGON2_H

#include <stddef.h>
#include <stdint.h>

/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Changes:
 *   - include paths rewritten for Ivo's source tree
 */

/*
 * Argon2id implementation for kiska.
 *
 * Ported from the PHC reference implementation:
 *   Copyright 2015 Daniel Dinu, Dmitry Khovratovich,
 *   Jean-Philippe Aumasson, Samuel Neves.
 *   Licensed under CC0 1.0 / Apache 2.0.
 *   https://github.com/P-H-C/phc-winner-argon2
 *
 * Adapted to kiska's coding conventions:
 *   - single-threaded (parallelism parameter is accepted but lanes
 *     are processed sequentially)
 *   - 0/-1 return convention with errno
 *   - no encoding/decoding of the $argon2id$... string format
 *   - only the Argon2id variant is exposed
 *   - BLAKE2b comes from kiska's own implementation
 */

#define ARGON2_SYNC_POINTS  4
#define ARGON2_BLOCK_SIZE   1024
#define ARGON2_QWORDS_IN_BLOCK 128
#define ARGON2_ADDRESSES_IN_BLOCK 128
#define ARGON2_PREHASH_DIGEST_LENGTH 64
#define ARGON2_PREHASH_SEED_LENGTH   (ARGON2_PREHASH_DIGEST_LENGTH + 8)

#define ARGON2_VERSION_10  0x10
#define ARGON2_VERSION_13  0x13

#define ARGON2_MIN_OUTLEN   4
#define ARGON2_MAX_OUTLEN   0xFFFFFFFF
#define ARGON2_MIN_MEMORY   8
#define ARGON2_MAX_MEMORY   0xFFFFFFFF
#define ARGON2_MIN_TIME     1
#define ARGON2_MAX_TIME     0xFFFFFFFF
#define ARGON2_MIN_LANES    1
#define ARGON2_MAX_LANES    0xFFFFFF

/* Ivo's limits, tighter than the algorithm's. Every parameter comes
 * from an attacker-controllable LUKS2 header.
 *
 * Memory (KiB): cryptsetup's maximum is 4 GiB. 32-bit builds can't
 * address that, and memory_blocks * 1024 must stay inside size_t,
 * so it is capped at 1 GiB on them (cryptsetup's default ceiling).
 * Lanes: cryptsetup caps at 4; 64 leaves headroom. Time and total
 * work are capped so a header can't stall the boot indefinitely. */
#if SIZE_MAX > 0xFFFFFFFFu
#define ARGON2_IVO_MAX_MEMORY  (4u * 1024 * 1024)
#else
#define ARGON2_IVO_MAX_MEMORY  (1u * 1024 * 1024)
#endif
#define ARGON2_IVO_MAX_LANES   64u
#define ARGON2_IVO_MAX_TIME    (1u << 20)
#define ARGON2_IVO_MAX_WORK    (1ull << 32)
#define ARGON2_IVO_MAX_OUTLEN  1024u
#define ARGON2_IVO_MAX_SALT    1024u
#define ARGON2_IVO_MAX_PWD     4096u
#define ARGON2_MIN_SALT        8u

/* 0 if the cost parameters are within Ivo's limits, -1 otherwise. */
int argon2id_check_params(uint32_t t_cost, uint32_t m_cost,
                          uint32_t parallelism);

int argon2id_hash(const void *pwd, size_t pwd_len,
                  const void *salt, size_t salt_len,
                  uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                  void *out, size_t out_len);

#endif