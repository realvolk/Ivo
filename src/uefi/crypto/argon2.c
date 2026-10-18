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
 * Removed: threading, the $argon2id$ string API, the Argon2i and
 * Argon2d variants, user allocator callbacks, GENKAT debug output.
 * Changed: error codes are 0/-1 instead of the ARGON2_* enum,
 * includes are root-relative, BLAKE2b uses kiska's blake2b.c.
 */

#include "argon2.h"
#include "blake2b.h"
#include "argon2_internal.h"

extern int hal_sse2_available(void);

#include <stdlib.h>
#include <string.h>

#define ARGON2_GUARD_SIZE 32
#define ARGON2_GUARD_BYTE 0xA5

#ifndef CONFIG_HOST
void panic(const char *msg) __attribute__((noreturn));
#endif

#ifdef CONFIG_HOST
static void *argon2_alloc(size_t bytes) { return malloc(bytes); }
static void argon2_free(void *p, size_t bytes) { (void)bytes; free(p); }
#else
extern void *mm_alloc(size_t size);
extern void  mm_free(void *ptr);

static void *argon2_alloc(size_t bytes) { return mm_alloc(bytes); }
static void argon2_free(void *p, size_t bytes) { (void)bytes; mm_free(p); }
#endif

/* 16-byte aligned so SSE2 fill_block can use the aligned variants.
 * A plain uint64_t array only requires 8. Size is unchanged. */
typedef struct {
    uint64_t v[ARGON2_QWORDS_IN_BLOCK];
} __attribute__((aligned(16))) block;

typedef struct {
    block *memory;
    uint32_t passes;
    uint32_t memory_blocks;
    uint32_t segment_length;
    uint32_t lane_length;
    uint32_t lanes;
    uint32_t version;
} argon2_instance;

typedef struct {
    uint32_t pass;
    uint32_t lane;
    uint8_t  slice;
    uint32_t index;
} argon2_position;

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

static void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void init_block(block *b, uint8_t v) {
    memset(b->v, v, sizeof(b->v));
}

static void copy_block(block *dst, const block *src) {
    memcpy(dst->v, src->v, sizeof(dst->v));
}

static void xor_block(block *dst, const block *src) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++)
        dst->v[i] ^= src->v[i];
}

static void load_block(block *dst, const void *input) {
    const uint8_t *p = input;
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++)
        dst->v[i] = load64_le(p + i * 8);
}

static void store_block(void *output, const block *src) {
    uint8_t *p = output;
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++)
        store64_le(p + i * 8, src->v[i]);
}

static void secure_wipe(void *v, size_t n) {
    if (!v) return;
    volatile uint8_t *p = v;
    while (n--) *p++ = 0;
}

/* Variable-length hash H'. BLAKE2b keyed by the output length. */
static int argon2_hprime(const uint8_t *input, size_t input_len,
                         uint8_t *out, size_t out_len) {
    if (out_len == 0 || out_len > 0xFFFFFFFF) return -1;

    uint8_t len_le[4];
    store32_le(len_le, (uint32_t)out_len);

    if (out_len <= 64) {
        struct blake2b_ctx ctx;
        blake2b_init(&ctx, out_len);
        blake2b_update(&ctx, len_le, 4);
        blake2b_update(&ctx, input, input_len);
        return blake2b_final(&ctx, out);
    }

    uint32_t r = (uint32_t)((out_len + 31) / 32 - 2);
    uint8_t v[BLAKE2B_MAX_DIGEST];
    uint8_t digest[BLAKE2B_MAX_DIGEST];

    struct blake2b_ctx ctx;
    blake2b_init(&ctx, 64);
    blake2b_update(&ctx, len_le, 4);
    blake2b_update(&ctx, input, input_len);
    blake2b_final(&ctx, v);

    memcpy(out, v, 32);

    for (uint32_t i = 1; i < r; i++) {
        blake2b_init(&ctx, 64);
        blake2b_update(&ctx, v, 64);
        blake2b_final(&ctx, v);
        memcpy(out + 32 * i, v, 32);
    }

    size_t final_len = out_len - 32 * r;
    blake2b_init(&ctx, final_len);
    blake2b_update(&ctx, v, 64);
    blake2b_final(&ctx, digest);
    memcpy(out + 32 * r, digest, final_len);

    secure_wipe(v, sizeof(v));
    secure_wipe(digest, sizeof(digest));
    return 0;
}

static uint64_t fblamka(uint64_t x, uint64_t y) {
    const uint64_t m = 0xFFFFFFFFULL;
    const uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

static uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

#define G_RND(a, b, c, d) do { \
    a = fblamka(a, b); \
    d = rotr64(d ^ a, 32); \
    c = fblamka(c, d); \
    b = rotr64(b ^ c, 24); \
    a = fblamka(a, b); \
    d = rotr64(d ^ a, 16); \
    c = fblamka(c, d); \
    b = rotr64(b ^ c, 63); \
} while (0)

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, \
                           v8, v9, v10, v11, v12, v13, v14, v15) \
    do { \
        G_RND(v0, v4, v8,  v12); \
        G_RND(v1, v5, v9,  v13); \
        G_RND(v2, v6, v10, v14); \
        G_RND(v3, v7, v11, v15); \
        G_RND(v0, v5, v10, v15); \
        G_RND(v1, v6, v11, v12); \
        G_RND(v2, v7, v8,  v13); \
        G_RND(v3, v4, v9,  v14); \
    } while (0)

static void fill_block(const block *prev_block,
                       const block *ref_block,
                       block *next_block,
                       int with_xor) {
    if (hal_sse2_available()) {
        argon2_fill_block_sse2(prev_block, ref_block, next_block, with_xor);
        return;
    }

    block blockR, block_tmp;
    unsigned i;

    copy_block(&blockR, ref_block);
    xor_block(&blockR, prev_block);
    copy_block(&block_tmp, &blockR);
    if (with_xor) {
        xor_block(&block_tmp, next_block);
    }

    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND_NOMSG(
            blockR.v[16 * i], blockR.v[16 * i + 1], blockR.v[16 * i + 2],
            blockR.v[16 * i + 3], blockR.v[16 * i + 4], blockR.v[16 * i + 5],
            blockR.v[16 * i + 6], blockR.v[16 * i + 7], blockR.v[16 * i + 8],
            blockR.v[16 * i + 9], blockR.v[16 * i + 10], blockR.v[16 * i + 11],
            blockR.v[16 * i + 12], blockR.v[16 * i + 13], blockR.v[16 * i + 14],
            blockR.v[16 * i + 15]);
    }

    for (i = 0; i < 8; i++) {
        BLAKE2_ROUND_NOMSG(
            blockR.v[2 * i], blockR.v[2 * i + 1], blockR.v[2 * i + 16],
            blockR.v[2 * i + 17], blockR.v[2 * i + 32], blockR.v[2 * i + 33],
            blockR.v[2 * i + 48], blockR.v[2 * i + 49], blockR.v[2 * i + 64],
            blockR.v[2 * i + 65], blockR.v[2 * i + 80], blockR.v[2 * i + 81],
            blockR.v[2 * i + 96], blockR.v[2 * i + 97], blockR.v[2 * i + 112],
            blockR.v[2 * i + 113]);
    }

    copy_block(next_block, &block_tmp);
    xor_block(next_block, &blockR);
}

#undef G_RND
#undef BLAKE2_ROUND_NOMSG

static void next_addresses(block *address_block, block *input_block) {
    block zero_block, zero2_block;
    init_block(&zero_block, 0);
    init_block(&zero2_block, 0);

    input_block->v[6]++;

    fill_block(&zero_block, input_block, address_block, 0);
    fill_block(&zero2_block, address_block, address_block, 0);

    secure_wipe(&zero_block, sizeof(zero_block));
    secure_wipe(&zero2_block, sizeof(zero2_block));
}

static uint32_t index_alpha(const argon2_instance *instance,
                            const argon2_position *position,
                            uint32_t pseudo_rand, int same_lane)
{
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position, absolute_position;

    if (position->pass == 0) {
        if (position->slice == 0) {
            reference_area_size = position->index - 1;
        } else {
            if (same_lane) {
                reference_area_size =
                    position->slice * instance->segment_length +
                    position->index - 1;
            } else {
                reference_area_size =
                    position->slice * instance->segment_length +
                    ((position->index == 0) ? (uint32_t)-1 : 0);
            }
        }
    } else {
        if (same_lane) {
            reference_area_size =
                instance->lane_length - instance->segment_length +
                position->index - 1;
        } else {
            reference_area_size =
                instance->lane_length - instance->segment_length +
                ((position->index == 0) ? (uint32_t)-1 : 0);
        }
    }

    relative_position = pseudo_rand;
    relative_position = (relative_position * relative_position) >> 32;
    relative_position = reference_area_size - 1 -
                        ((reference_area_size * relative_position) >> 32);

    start_position = 0;
    if (position->pass != 0) {
        start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
                             ? 0
                             : (uint32_t)(position->slice + 1) * instance->segment_length;
    }

    /* start_position + relative_position is < 2*lane_length, so a
     * single conditional subtract is equivalent to mod lane_length.
     * Avoids __umoddi3 on i386. */
    absolute_position = start_position + (uint32_t)relative_position;
    if (absolute_position >= instance->lane_length)
        absolute_position -= instance->lane_length;
    return absolute_position;
}

static void fill_segment(const argon2_instance *instance,
                         argon2_position position) {
    block *ref_block = NULL, *curr_block = NULL;
    block address_block, input_block;
    uint64_t pseudo_rand, ref_index, ref_lane;
    uint32_t prev_offset, curr_offset;
    uint32_t starting_index, i;
    block state;

    int data_independent_addressing =
        (position.pass == 0) &&
        (position.slice < ARGON2_SYNC_POINTS / 2);

    if (data_independent_addressing) {
        init_block(&input_block, 0);
        input_block.v[0] = position.pass;
        input_block.v[1] = position.lane;
        input_block.v[2] = position.slice;
        input_block.v[3] = instance->memory_blocks;
        input_block.v[4] = instance->passes;
        input_block.v[5] = 2;   /* Argon2id type */
    }

    starting_index = 0;
    if (position.pass == 0 && position.slice == 0) {
        starting_index = 2;
        if (data_independent_addressing)
            next_addresses(&address_block, &input_block);
    }

    curr_offset = position.lane * instance->lane_length +
                  position.slice * instance->segment_length + starting_index;

    if (curr_offset % instance->lane_length == 0) {
        prev_offset = curr_offset + instance->lane_length - 1;
    } else {
        prev_offset = curr_offset - 1;
    }

    copy_block(&state, &instance->memory[prev_offset]);

    for (i = starting_index; i < instance->segment_length;
         i++, curr_offset++, prev_offset++) {

        if (curr_offset % instance->lane_length == 1)
            prev_offset = curr_offset - 1;

        if (data_independent_addressing) {
            if (i % ARGON2_ADDRESSES_IN_BLOCK == 0)
                next_addresses(&address_block, &input_block);
            pseudo_rand = address_block.v[i % ARGON2_ADDRESSES_IN_BLOCK];
        } else {
            pseudo_rand = instance->memory[prev_offset].v[0];
        }

        ref_lane = (uint32_t)(pseudo_rand >> 32) % instance->lanes;
        if (position.pass == 0 && position.slice == 0)
            ref_lane = position.lane;

        position.index = i;
        ref_index = index_alpha(instance, &position,
                                (uint32_t)(pseudo_rand & 0xFFFFFFFF),
                                ref_lane == position.lane);

        ref_block = instance->memory +
                    (uint64_t)instance->lane_length * ref_lane + ref_index;
        curr_block = instance->memory + curr_offset;

        if (position.pass == 0) {
            fill_block(&state, ref_block, curr_block, 0);
        } else {
            fill_block(&state, ref_block, curr_block, 1);
        }

        copy_block(&state, curr_block);
    }

    secure_wipe(&state, sizeof(state));
    if (data_independent_addressing) {
        secure_wipe(&address_block, sizeof(address_block));
        secure_wipe(&input_block, sizeof(input_block));
    }
}

static int initialize(argon2_instance *instance,
                      const uint8_t *pwd, size_t pwd_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t out_len) {
    uint8_t h0[ARGON2_PREHASH_DIGEST_LENGTH];
    uint8_t h0_with_idx[ARGON2_PREHASH_SEED_LENGTH];

    struct blake2b_ctx ctx;
    uint8_t le[4];

    blake2b_init(&ctx, ARGON2_PREHASH_DIGEST_LENGTH);

    store32_le(le, instance->lanes);           blake2b_update(&ctx, le, 4);
    store32_le(le, out_len);                   blake2b_update(&ctx, le, 4);
    store32_le(le, instance->memory_blocks);   blake2b_update(&ctx, le, 4);
    store32_le(le, instance->passes);          blake2b_update(&ctx, le, 4);
    store32_le(le, instance->version);         blake2b_update(&ctx, le, 4);
    store32_le(le, 2);                         blake2b_update(&ctx, le, 4);
    store32_le(le, (uint32_t)pwd_len);         blake2b_update(&ctx, le, 4);
    blake2b_update(&ctx, pwd, pwd_len);
    store32_le(le, (uint32_t)salt_len);        blake2b_update(&ctx, le, 4);
    blake2b_update(&ctx, salt, salt_len);
    store32_le(le, 0);                         blake2b_update(&ctx, le, 4);
    store32_le(le, 0);                         blake2b_update(&ctx, le, 4);

    blake2b_final(&ctx, h0);

    memcpy(h0_with_idx, h0, ARGON2_PREHASH_DIGEST_LENGTH);
    memset(h0_with_idx + ARGON2_PREHASH_DIGEST_LENGTH, 0, 8);

    for (uint32_t l = 0; l < instance->lanes; l++) {
        uint8_t buf[ARGON2_BLOCK_SIZE];

        store32_le(h0_with_idx + ARGON2_PREHASH_DIGEST_LENGTH, 0);
        store32_le(h0_with_idx + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
        argon2_hprime(h0_with_idx, ARGON2_PREHASH_SEED_LENGTH,
                      buf, ARGON2_BLOCK_SIZE);
        load_block(&instance->memory[l * instance->lane_length + 0], buf);

        store32_le(h0_with_idx + ARGON2_PREHASH_DIGEST_LENGTH, 1);
        argon2_hprime(h0_with_idx, ARGON2_PREHASH_SEED_LENGTH,
                      buf, ARGON2_BLOCK_SIZE);
        load_block(&instance->memory[l * instance->lane_length + 1], buf);

        secure_wipe(buf, sizeof(buf));
    }

    secure_wipe(h0, sizeof(h0));
    secure_wipe(h0_with_idx, sizeof(h0_with_idx));
    return 0;
}

static void finalize(const argon2_instance *instance,
                     uint8_t *out, size_t out_len) {
    block blockhash;
    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];

    copy_block(&blockhash,
               &instance->memory[instance->lane_length - 1]);

    for (uint32_t l = 1; l < instance->lanes; l++) {
        uint32_t last = l * instance->lane_length +
                        (instance->lane_length - 1);
        xor_block(&blockhash, &instance->memory[last]);
    }

    store_block(blockhash_bytes, &blockhash);
    argon2_hprime(blockhash_bytes, ARGON2_BLOCK_SIZE, out, out_len);

    secure_wipe(&blockhash, sizeof(blockhash));
    secure_wipe(blockhash_bytes, sizeof(blockhash_bytes));
}

int argon2id_check_params(uint32_t t_cost, uint32_t m_cost,
                          uint32_t parallelism) {
    if (parallelism < ARGON2_MIN_LANES) { return -1; }
    if (parallelism > ARGON2_IVO_MAX_LANES) { return -1; }
    if (t_cost < ARGON2_MIN_TIME || t_cost > ARGON2_IVO_MAX_TIME) { return -1; }
    if (m_cost < ARGON2_MIN_MEMORY) { return -1; }
    if (m_cost < 8 * parallelism) { return -1; }
    if (m_cost > ARGON2_IVO_MAX_MEMORY) { return -1; }
    /* Bound total work as well: passes * KiB. */
    if ((uint64_t)t_cost * m_cost > ARGON2_IVO_MAX_WORK) { return -1; }
    return 0;
}

int argon2id_hash(const void *pwd, size_t pwd_len,
                  const void *salt, size_t salt_len,
                  uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                  void *out, size_t out_len) {
    if (!pwd || !salt || !out) { return -1; }
    if (out_len < ARGON2_MIN_OUTLEN) { return -1; }
    if (out_len > ARGON2_IVO_MAX_OUTLEN) { return -1; }
    if (salt_len < ARGON2_MIN_SALT || salt_len > ARGON2_IVO_MAX_SALT) { return -1; }
    if (pwd_len > ARGON2_IVO_MAX_PWD) { return -1; }
    if (argon2id_check_params(t_cost, m_cost, parallelism) != 0) { return -1; }

    uint32_t memory_blocks = m_cost;
    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * parallelism)
        memory_blocks = 2 * ARGON2_SYNC_POINTS * parallelism;

    uint32_t segment_length = memory_blocks / (parallelism * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * (parallelism * ARGON2_SYNC_POINTS);

    argon2_instance instance;
    memset(&instance, 0, sizeof(instance));
    instance.passes         = t_cost;
    instance.memory_blocks  = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length    = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes          = parallelism;
    instance.version        = ARGON2_VERSION_13;

    uint64_t mem_bytes64 = (uint64_t)memory_blocks * sizeof(block);
    if (mem_bytes64 == 0 ||
        mem_bytes64 > (uint64_t)SIZE_MAX - ARGON2_GUARD_SIZE) {
        return -1;
    }
    size_t mem_bytes   = (size_t)mem_bytes64;
    size_t alloc_bytes = mem_bytes + ARGON2_GUARD_SIZE;

    uint8_t *raw = argon2_alloc(alloc_bytes);
    if (!raw) { return -1; }
    memset(raw, 0, alloc_bytes);
    instance.memory = (block *)raw;

    uint8_t *guard = raw + mem_bytes;
    memset(guard, ARGON2_GUARD_BYTE, ARGON2_GUARD_SIZE);

    if (initialize(&instance, pwd, pwd_len, salt, salt_len,
                   (uint32_t)out_len) != 0) {
        secure_wipe(raw, alloc_bytes);
        argon2_free(raw, alloc_bytes);
        return -1;
    }

    for (uint32_t r = 0; r < instance.passes; r++) {
        for (uint32_t s = 0; s < ARGON2_SYNC_POINTS; s++) {
            for (uint32_t l = 0; l < instance.lanes; l++) {
                argon2_position pos = { r, l, (uint8_t)s, 0 };
                fill_segment(&instance, pos);
            }
        }
    }

    finalize(&instance, out, out_len);

    int smashed = 0;
    for (size_t i = 0; i < ARGON2_GUARD_SIZE; i++)
        if (guard[i] != ARGON2_GUARD_BYTE) smashed = 1;

    secure_wipe(raw, alloc_bytes);
    argon2_free(raw, alloc_bytes);

#ifdef CONFIG_HOST
    return smashed ? -1 : 0;
#else
    if (smashed) panic("argon2 workspace overflow");
    return 0;
#endif
}