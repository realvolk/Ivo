/* Host test for the BTRFS reader.
 *
 * Links the reader without the rest of Ivo, provides shims for the
 * HAL and console functions the reader references, and reads a file
 * out of a BTRFS image. Prints the file's bytes to stdout.
 *
 * Usage: btrfs-test <image> <path>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "fs/fs.h"

extern int open(const char *path, int flags);

static int      g_fd = -1;
static uint32_t g_block_size = 512;

int hal_read_blocks(uint64_t lba, uint32_t count, void *buf) {
    off_t off = (off_t)(lba * g_block_size);
    size_t bytes = (size_t)count * g_block_size;
    ssize_t n = pread(g_fd, buf, bytes, off);
    return n == (ssize_t)bytes ? 0 : -1;
}

void con_puts(const char *s) { fputs(s, stderr); }
void con_putc(char c) { fputc(c, stderr); }

extern fs_driver_t fs_btrfs;
extern int btrfs_set_subvol(const char *path);

fs_driver_t *fs_current;
void fs_register(fs_driver_t *d) { fs_current = d; }

int fs_probe_mount(block_device_t *dev) {
    fs_driver_t *d = &fs_btrfs;
    if (d->probe(dev) != 0) return -1;
    if (d->mount(dev) != 0) return -1;
    fs_current = d;
    return 0;
}

int fs_read(const char *path, uint8_t *buf, size_t *len) {
    return fs_current->read(path, buf, len);
}

int fs_stat(const char *path, size_t *size) {
    struct stat st;
    int r = fs_current->stat(path, &st);
    if (r == 0) *size = st.size;
    return r;
}

/* The host test reads plain filesystems, never through LUKS. */
int luks_active(void) { return 0; }
int luks_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf) {
    (void)lba; (void)count; (void)buf;
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <image> <subvol|-> <path>\n", argv[0]);
        fprintf(stderr, "  subvol: a path like @ or @home, or - for default\n");
        return 2;
    }

    g_fd = open(argv[1], 0);
    if (g_fd < 0) { perror("open"); return 1; }

    block_device_t dev = {
        .lba_start  = 0,
        .lba_count  = 0,
        .block_size = g_block_size,
        .private    = NULL,
    };

    if (fs_probe_mount(&dev) != 0) {
        fprintf(stderr, "mount failed\n");
        return 1;
    }

    if (strcmp(argv[2], "-") != 0) {
        if (btrfs_set_subvol(argv[2]) != 0) {
            fprintf(stderr, "subvol %s not found\n", argv[2]);
            return 1;
        }
    }

    uint8_t *buf = malloc(64 * 1024 * 1024);
    size_t len = 64 * 1024 * 1024;

    if (fs_read(argv[3], buf, &len) != 0) {
        fprintf(stderr, "read failed\n");
        return 1;
    }

    fwrite(buf, 1, len, stdout);
    return 0;
}