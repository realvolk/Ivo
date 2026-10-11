/* Host-side glue for the bootloader code ivo-sign links: the
 * allocator config.c and iso9660.c call, stubs for the block-device
 * paths that are never reached on the host, and a small wrapper around
 * iso9660.c's memory mode.
 *
 * This file includes fs/fs.h, whose `struct stat` clashes with the
 * libc one, so it stays separate from ivo-sign.c. */

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "fs/fs.h"

void *mm_alloc(size_t n) { return malloc(n); }
void  mm_free(void *p)   { free(p); }
void  con_puts(const char *s) { (void)s; }

int hal_read_blocks(uint64_t lba, uint32_t count, void *buf)
{
    (void)lba; (void)count; (void)buf;
    return -1;
}

int iso9660_read(const char *path, uint8_t *buf, size_t *len);
int iso9660_stat(const char *path, struct stat *st);
void iso9660_umount(void);

/* Volume identifier of an ISO image in memory, trailing spaces
 * stripped — the same comparison partition_find_iso() makes. */
int ivo_iso_volume_id(const uint8_t *img, size_t size,
                      char *out, size_t out_size)
{
    const size_t pvd = 16 * 2048;
    if (out_size < 2 || size < pvd + 2048) return -1;
    const uint8_t *b = img + pvd;
    if (b[0] != 1 || memcmp(b + 1, "CD001", 5) != 0) return -1;
    size_t n = 32;
    while (n > 0 && b[40 + n - 1] == ' ') n--;
    if (n >= out_size) n = out_size - 1;
    memcpy(out, b + 40, n);
    out[n] = '\0';
    return 0;
}

/* Read `path` out of the ISO image with the bootloader's own ISO9660
 * driver, so name resolution (Rock Ridge / Joliet / plain, case
 * folding, version suffixes) is exactly what the bootloader does.
 * Returns 0 and a malloc'd buffer, or -1. */
int ivo_iso_read_file(const uint8_t *img, size_t size, const char *path,
                      uint8_t **out, size_t *out_len)
{
    if (iso9660_mount_memory(img, size) != 0) return -1;

    struct stat st;
    if (iso9660_stat(path, &st) != 0 || (st.mode & 0170000) != 0100000) {
        iso9660_umount();
        return -1;
    }
    if (st.size > size) {               /* cannot be inside the image */
        iso9660_umount();
        return -1;
    }
    size_t want = (size_t)st.size;
    uint8_t *buf = malloc(want ? want : 1);
    if (!buf) { iso9660_umount(); return -1; }
    size_t got = want;
    if (iso9660_read(path, buf, &got) != 0 || got != want) {
        free(buf);
        iso9660_umount();
        return -1;
    }
    iso9660_umount();
    *out = buf;
    *out_len = got;
    return 0;
}
