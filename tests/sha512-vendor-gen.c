/* Generator for the block-boundary SHA-512 vectors used by
 * tools/sha512-test.c. Links the vendored LibTomCrypt sha512 as
 * ground truth; paste its output into the GEN_xxx placeholders in
 * the test. */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sha512.h"

static void emit_digest(const char *comment, const uint8_t *msg, size_t len)
{
    uint8_t out[64];
    sha512(msg, len, out);

    printf("/* %s */\n", comment);
    for (int i = 0; i < 64; i += 32) {
        printf("          \"");
        for (int j = 0; j < 32; j++)
            printf("%02x", out[i + j]);
        printf("\"");
        if (i + 32 < 64)
            printf("\n");
    }
    printf("\n\n");
}

int main(void)
{
    uint8_t a[127];
    memset(a, 'a', sizeof(a));

    /* FIPS 180-4 448-bit vector, for cross-checking against the
     * published digest in the test file. */
    static const char *fips_448 =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    printf("/* Generated from LibTomCrypt sha512 (ed25519/src/sha512.c). */\n");
    printf("/* Cross-check the FIPS one against the published value. */\n\n");

    emit_digest("FIPS 180-4 448-bit: \"abcdefghbcdefghi...nopqrstu\" (112 bytes)",
                (const uint8_t *)fips_448, strlen(fips_448));

    emit_digest("111 'a' -- 0x80 at offset 111, length field rolls to next block",
                a, 111);

    emit_digest("112 'a' -- 0x80 lands exactly at offset 112",
                a, 112);

    emit_digest("127 'a' -- 0x80 fills the block exactly, compress before length",
                a, 127);

    return 0;
}