/* Host test for the LUKS2 reader.
 *
 * Reads a LUKS2 image and prints the master key. Compares against
 * `cryptsetup luksDump --dump-master-key`.
 *
 * Usage: luks2-test <image> <passphrase>
 *
 * LUKS_TEST_LBA overrides the partition offset. Default 2048 (1 MiB,
 * standard mklabel-msdos alignment). For a raw LUKS image with no
 * partition table, set LUKS_TEST_LBA=0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define LUKS_TEST_MAIN
#include "luks1-test.h"   /* common HAL shim declarations */

static FILE *g_img;
static size_t g_pass_off;

void con_puts(const char *s) { fputs(s, stderr); }
void con_putc(char c)        { fputc(c, stderr); }
void con_clear(void)         { }
void con_set_fg(uint32_t c)  { (void)c; }
void halt(void)              { exit(1); }

void *mm_alloc(size_t n) { return calloc(1, n); }
void  mm_free(void *p)   { free(p); }

int hal_read_blocks(uint64_t lba, uint32_t count, void *buf)
{
    if (!g_img) return -1;
    if (fseek(g_img, (long)(lba * 512), SEEK_SET) != 0) return -1;
    if (fread(buf, 512, count, g_img) != count) return -1;
    return 0;
}

char hal_getchar(void)
{
    if (g_pass_off >= g_pass_len) return '\n';
    return (char)g_pass[g_pass_off++];
}

int hal_sse2_available(void) { return 1; }

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s IMAGE PASSPHRASE\n", argv[0]);
        return 1;
    }

    g_img = fopen(argv[1], "rb");
    if (!g_img) { perror(argv[1]); return 1; }

    g_pass = (const uint8_t *)argv[2];
    g_pass_len = strlen(argv[2]);
    g_pass_off = 0;

    boot_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *lba_env = getenv("LUKS_TEST_LBA");
    ctx.boot_lba = lba_env ? strtoull(lba_env, NULL, 0) : 2048;

    int rc = luks2_unlock(&ctx);

    if (rc != 0) {
        fprintf(stderr, "\nluks2_unlock returned %d\n", rc);
        fclose(g_img);
        return 1;
    }

    uint8_t mk[64];
    size_t mk_len = sizeof(mk);
    if (luks_get_master_key(mk, &mk_len) != 0) {
        fprintf(stderr, "\nluks_get_master_key failed\n");
        fclose(g_img);
        return 1;
    }

    fprintf(stderr, "\nmaster key (%zu bytes):\n", mk_len);
    for (size_t i = 0; i < mk_len; i++) {
        fprintf(stderr, "%02x", mk[i]);
        if ((i & 15) == 15) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

    if (luks_test_dump() != 0) {
        fprintf(stderr, "luks_read_blocks failed\n");
        fclose(g_img);
        return 1;
    }
    fclose(g_img);
    return 0;
}