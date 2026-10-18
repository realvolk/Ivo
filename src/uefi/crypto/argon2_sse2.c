/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * SSE2 fill_block for Argon2id.
 *
 * Separate translation unit so it can build with -msse2 while the
 * rest of the bootloader stays at -mno-sse. Ported from the PHC
 * reference's blamka-round-opt.h, SSE2 branch.
 */

#include "argon2_internal.h"

#include <emmintrin.h>

#define ARGON2_QWORDS_IN_BLOCK 128
#define ARGON2_HALF_QWORDS     64

static __m128i fBlaMka(__m128i x, __m128i y)
{
    const __m128i z = _mm_mul_epu32(x, y);
    return _mm_add_epi64(_mm_add_epi64(x, y), _mm_add_epi64(z, z));
}

static __m128i rotr32_64(__m128i x)
{
    return _mm_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1));
}

static __m128i rotr24_64(__m128i x)
{
    return _mm_or_si128(_mm_srli_epi64(x, 24), _mm_slli_epi64(x, 40));
}

static __m128i rotr16_64(__m128i x)
{
    return _mm_or_si128(_mm_srli_epi64(x, 16), _mm_slli_epi64(x, 48));
}

static __m128i rotr63_64(__m128i x)
{
    return _mm_or_si128(_mm_srli_epi64(x, 63), _mm_slli_epi64(x, 1));
}

/* _mm_alignr_epi8(a, b, 8) without SSSE3. Result is
 * [b.hi64, a.lo64]. */
static __m128i alignr8(__m128i a, __m128i b)
{
    return _mm_unpacklo_epi64(_mm_srli_si128(b, 8), a);
}

#define G1(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        A0 = fBlaMka(A0, B0); \
        A1 = fBlaMka(A1, B1); \
        D0 = _mm_xor_si128(D0, A0); \
        D1 = _mm_xor_si128(D1, A1); \
        D0 = rotr32_64(D0); \
        D1 = rotr32_64(D1); \
        C0 = fBlaMka(C0, D0); \
        C1 = fBlaMka(C1, D1); \
        B0 = _mm_xor_si128(B0, C0); \
        B1 = _mm_xor_si128(B1, C1); \
        B0 = rotr24_64(B0); \
        B1 = rotr24_64(B1); \
    } while (0)

#define G2(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        A0 = fBlaMka(A0, B0); \
        A1 = fBlaMka(A1, B1); \
        D0 = _mm_xor_si128(D0, A0); \
        D1 = _mm_xor_si128(D1, A1); \
        D0 = rotr16_64(D0); \
        D1 = rotr16_64(D1); \
        C0 = fBlaMka(C0, D0); \
        C1 = fBlaMka(C1, D1); \
        B0 = _mm_xor_si128(B0, C0); \
        B1 = _mm_xor_si128(B1, C1); \
        B0 = rotr63_64(B0); \
        B1 = rotr63_64(B1); \
    } while (0)

#define DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        __m128i t0 = alignr8(B1, B0); \
        __m128i t1 = alignr8(B0, B1); \
        B0 = t0; \
        B1 = t1; \
        t0 = C0; \
        C0 = C1; \
        C1 = t0; \
        t0 = alignr8(D0, D1); \
        t1 = alignr8(D1, D0); \
        D0 = t0; \
        D1 = t1; \
    } while (0)

#define UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        __m128i t0 = alignr8(B0, B1); \
        __m128i t1 = alignr8(B1, B0); \
        B0 = t0; \
        B1 = t1; \
        t0 = C0; \
        C0 = C1; \
        C1 = t0; \
        t0 = alignr8(D1, D0); \
        t1 = alignr8(D0, D1); \
        D0 = t0; \
        D1 = t1; \
    } while (0)

#define BLAKE2_ROUND(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        G1(A0, B0, C0, D0, A1, B1, C1, D1); \
        G2(A0, B0, C0, D0, A1, B1, C1, D1); \
        DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1); \
        G1(A0, B0, C0, D0, A1, B1, C1, D1); \
        G2(A0, B0, C0, D0, A1, B1, C1, D1); \
        UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1); \
    } while (0)

#if defined(__i386__) && !defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void argon2_fill_block_sse2(const void *prev_p, const void *ref_p,
                            void *next_p, int with_xor)
{
    /* Cast to __m128i_u (GCC's unaligned variant) so GCC emits
     * movdqu/movups instead of movdqa/movaps. The 32-bit build doesn't
     * guarantee 16-byte alignment at the call site, and movdqa faults
     * when the caller's stack isn't aligned. */
    const __m128i_u *prev = (const __m128i_u *)prev_p;
    const __m128i_u *ref  = (const __m128i_u *)ref_p;
    __m128i_u       *next = (__m128i_u *)next_p;
    (void)prev; (void)ref; (void)next;

    __m128i block_XY[ARGON2_HALF_QWORDS];
    __m128i block_tmp[ARGON2_HALF_QWORDS];
    unsigned int i;

    for (i = 0; i < ARGON2_HALF_QWORDS; ++i) {
        block_XY[i] = _mm_xor_si128(ref[i], prev[i]);
    }

    for (i = 0; i < ARGON2_HALF_QWORDS; ++i) {
        block_tmp[i] = block_XY[i];
    }
    if (with_xor) {
        for (i = 0; i < ARGON2_HALF_QWORDS; ++i) {
            block_tmp[i] = _mm_xor_si128(block_tmp[i], next[i]);
        }
    }

    /* Row rounds: 8 iterations, 16 consecutive qwords each. */
    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(
            block_XY[8 * i + 0], block_XY[8 * i + 1],
            block_XY[8 * i + 2], block_XY[8 * i + 3],
            block_XY[8 * i + 4], block_XY[8 * i + 5],
            block_XY[8 * i + 6], block_XY[8 * i + 7]);
    }

    /* Column rounds: same 16-qword pattern, strided by 8 __m128i. */
    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(
            block_XY[i +  0], block_XY[i +  8],
            block_XY[i + 16], block_XY[i + 24],
            block_XY[i + 32], block_XY[i + 40],
            block_XY[i + 48], block_XY[i + 56]);
    }

    for (i = 0; i < ARGON2_HALF_QWORDS; ++i) {
        next[i] = _mm_xor_si128(block_tmp[i], block_XY[i]);
    }
}

#undef G1
#undef G2
#undef DIAGONALIZE
#undef UNDIAGONALIZE
#undef BLAKE2_ROUND