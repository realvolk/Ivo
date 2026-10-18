/* tools/sha512-test.c
 *
 * Test vectors for Ivo's SHA-512 (src/uefi/crypto/sha512.c).
 *
 * Published vectors: FIPS 180-4 Appendix C (empty, "abc", 448-bit) and
 * the NIST CAVP one-million-'a' case.
 *
 * Generated vectors: the three block-boundary cases at 111, 112, 127
 * bytes. Ground truth comes from tools/sha512-vendor-gen.c, which links
 * the vendored LibTomCrypt sha512. Paste its output over the
 * GEN_xxx placeholders below.
 *
 * Build: make tools
 * Run:   tools/sha512-test
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "sha512.h"

static int failures = 0;

static void to_hex(const uint8_t *b, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = h[b[i] >> 4];
        out[i * 2 + 1] = h[b[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

static void check(const char *name,
                  const uint8_t *msg, size_t len,
                  const char *expected_hex)
{
    sha512_ctx_t ctx;
    uint8_t digest[64];
    char got[129];

    sha512_init(&ctx);
    if (len > 0)
        sha512_update(&ctx, msg, len);
    sha512_final(&ctx, digest);
    to_hex(digest, 64, got);

    if (strcmp(got, expected_hex) == 0) {
        printf("PASS  %s\n", name);
    } else {
        printf("FAIL  %s\n", name);
        printf("      expected: %s\n", expected_hex);
        printf("      got:      %s\n", got);
        failures++;
    }
}

/* One million 'a', fed in 1000-byte chunks to exercise streaming. */
static void check_million_a(void)
{
    static const char *expected =
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";

    sha512_ctx_t ctx;
    uint8_t digest[64];
    char got[129];
    uint8_t chunk[1000];

    memset(chunk, 'a', sizeof(chunk));

    sha512_init(&ctx);
    for (int i = 0; i < 1000; i++)
        sha512_update(&ctx, chunk, sizeof(chunk));
    sha512_final(&ctx, digest);
    to_hex(digest, 64, got);

    if (strcmp(got, expected) == 0) {
        printf("PASS  one million 'a' (streamed in 1000-byte chunks)\n");
    } else {
        printf("FAIL  one million 'a' (streamed in 1000-byte chunks)\n");
        printf("      expected: %s\n", expected);
        printf("      got:      %s\n", got);
        failures++;
    }
}

int main(void)
{
    /* FIPS 180-4 Appendix C, example 1: empty message. */
    check("empty",
          (const uint8_t *)"", 0,
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
          "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

    /* FIPS 180-4 Appendix C, example 2: "abc". */
    check("abc",
          (const uint8_t *)"abc", 3,
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    /* FIPS 180-4 Appendix C, example 3: 112-byte string. */
    check("448-bit (112 bytes)",
          (const uint8_t *)
              "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
              "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          112,
          "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
          "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

    /* Block-boundary vectors. Ground truth from
     * tools/sha512-vendor-gen.c. Replace the GEN_xxx placeholders with
     * its output. If any of these fail while the FIPS vectors pass,
     * the bug is in sha512_final's padding path, not the compression
     * function. */
    uint8_t a[127];
    memset(a, 'a', sizeof(a));

    check("111 'a' (padding rollover)",
          a, 111,
          "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef8681819692176"
          "0b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2");

    check("112 'a' (0x80 at boundary)",
          a, 112,
          "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32"
          "bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca");

    check("127 'a' (0x80 fills block)",
          a, 127,
          "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91ba"
          "b50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502");

    check_million_a();

    printf("\n");
    if (failures == 0) {
        printf("all SHA-512 vectors passed\n");
        return 0;
    }
    printf("%d failure(s)\n", failures);
    return 1;
}