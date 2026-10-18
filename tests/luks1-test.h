#ifndef LUKS1_TEST_H
#define LUKS1_TEST_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t  drive;
    uint64_t boot_lba;
    uint32_t boot_partition_guid[4];
    void    *memory_map;
    uint64_t memory_map_size;
    void    *firmware_data;
} boot_context_t;

void  con_puts(const char *s);
void  con_putc(char c);
void  con_clear(void);
void  con_set_fg(uint32_t color);
void  halt(void);

void *mm_alloc(size_t size);
void  mm_free(void *ptr);

int   hal_read_blocks(uint64_t lba, uint32_t count, void *buf);
char  hal_getchar(void);
int   con_read_secret(const char *label, char *out, size_t max_len, char echo);

int   luks1_unlock(boot_context_t *ctx);
int   luks2_unlock(boot_context_t *ctx);
int   luks_setup_crypto(const uint8_t *mk, size_t mk_len,
                        const char *cipher_spec);
int   luks_get_master_key(uint8_t *out, size_t *len);
int   luks_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);

/* Shared by luks1-test.c and luks2-test.c. Feeds the passphrase from
 * argv in place of the keyboard, and with LUKS_TEST_DUMP=N writes the
 * first N decrypted 512-byte sectors to stdout after unlock. */
#ifdef LUKS_TEST_MAIN
#include <stdio.h>
#include <stdlib.h>

static const uint8_t *g_pass;
static size_t g_pass_len;

int con_read_secret(const char *label, char *out, size_t max_len, char echo)
{
    (void)label; (void)echo;
    size_t n = g_pass_len < max_len - 1 ? g_pass_len : max_len - 1;
    memcpy(out, g_pass, n);
    out[n] = '\0';
    return (int)n;
}

static int luks_test_dump(void)
{
    const char *e = getenv("LUKS_TEST_DUMP");
    if (!e) return 0;
    unsigned long n = strtoul(e, NULL, 0);
    /* Odd-sized chunks exercise the partial-unit path. */
    uint8_t buf[512 * 13];
    for (unsigned long lba = 0; lba < n; ) {
        uint32_t c = (uint32_t)(n - lba < 13 ? n - lba : 13);
        if (luks_read_blocks(lba, c, buf) != 0) return -1;
        fwrite(buf, 512, c, stdout);
        lba += c;
    }
    return 0;
}
#endif

#endif