/*   ivo-install --target uefi --esp /boot/efi [--efi ivo.efi] [--force]
 *   ivo-install --target usb  --device /dev/sdb --iso alpine.iso [--efi ivo.efi] [--yes]
 *
 * UEFI copies the .efi to <esp>/EFI/BOOT/BOOTX64.EFI (temp file +
 * rename). Does not touch NVRAM — the fallback path is what Ivo
 * relies on.
 *
 * USB repartitions the device, extracts the kernel and initrd from
 * the ISO onto the ESP, writes a minimal config, and copies the ISO to
 * a raw partition. Runs wipefs, sfdisk and mkfs.vfat directly (no
 * shell) and checks every exit status.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/fs.h>

#include "config.h"
#include "ivo-util.h"

#define ISO_SECTOR     2048
#define ISO_MAX_DIR    (1u << 20)    /* refuse absurd directory sizes */
#define MAX_PARTS      128

void *mm_alloc(size_t size) { return malloc(size); }

static int confirm(const char *prompt)
{
    fprintf(stderr, "%s [y/N] ", prompt);
    fflush(stderr);
    char line[16];
    if (!fgets(line, sizeof(line), stdin)) return 0;
    return (line[0] == 'y' || line[0] == 'Y') &&
           (line[1] == '\n' || line[1] == '\0');
}

static int pread_all(int fd, void *buf, size_t len, off_t off)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t r = pread(fd, p, len, off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) { errno = EIO; return -1; }
        p += r; len -= (size_t)r; off += r;
    }
    return 0;
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) { errno = EIO; return -1; }
        p += w; len -= (size_t)w;
    }
    return 0;
}

static void sleep_ms(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) { }
}

static int run_cmd(char *const argv[], const char *input, int quiet)
{
    int pfd[2] = { -1, -1 };
    if (input && pipe2(pfd, O_CLOEXEC) != 0) return -1;

    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        if (input) { close(pfd[0]); close(pfd[1]); }
        return -1;
    }
    if (pid == 0) {
        int in = input ? pfd[0] : open("/dev/null", O_RDONLY);
        if (in < 0 || dup2(in, STDIN_FILENO) < 0) _exit(127);
        if (quiet) {
            int nul = open("/dev/null", O_WRONLY);
            if (nul < 0 || dup2(nul, STDOUT_FILENO) < 0) _exit(127);
        }
        execvp(argv[0], argv);
        fprintf(stderr, "ivo-install: cannot run %s: %s\n",
                argv[0], strerror(errno));
        _exit(127);
    }

    int werr = 0;
    if (input) {
        close(pfd[0]);
        if (write_all(pfd[1], input, strlen(input)) != 0) werr = 1;
        close(pfd[1]);
    }

    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && !werr) return 0;
    if (WIFEXITED(status))
        fprintf(stderr, "ivo-install: %s exited with status %d\n",
                argv[0], WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        fprintf(stderr, "ivo-install: %s killed by signal %d\n",
                argv[0], WTERMSIG(status));
    return -1;
}

static int read_sysfs(const char *path, char *out, size_t out_size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, out_size - 1);
    close(fd);
    if (n <= 0) return -1;
    out[n] = '\0';
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' ')) out[--n] = '\0';
    return 0;
}

static int parse_devnum(const char *s, dev_t *out)
{
    unsigned ma, mi;
    char extra;
    if (sscanf(s, "%u:%u%c", &ma, &mi, &extra) != 2) return -1;
    *out = makedev(ma, mi);
    return 0;
}

typedef struct {
    char     path[PATH_MAX];
    char     name[NAME_MAX + 1];
    dev_t    rdev;
    int      is_file;
    uint64_t size;
    unsigned sector;
} disk_t;

typedef struct {
    char  name[NAME_MAX + 1];
    dev_t rdev;
    int   number;
} part_t;

static int resolve_disk(const char *arg, disk_t *d, int allow_file)
{
    memset(d, 0, sizeof(*d));
    if (!realpath(arg, d->path)) {
        fprintf(stderr, "ivo-install: %s: %s\n", arg, strerror(errno));
        return -1;
    }
    struct stat st;
    if (stat(d->path, &st) != 0) {
        fprintf(stderr, "ivo-install: %s: %s\n", d->path, strerror(errno));
        return -1;
    }
    if (S_ISREG(st.st_mode) && allow_file) {
        d->is_file = 1;
        d->size = (uint64_t)st.st_size;
        d->sector = 512;
        return 0;
    }
    if (!S_ISBLK(st.st_mode)) {
        fprintf(stderr, "ivo-install: %s: not a block device%s\n", d->path,
                allow_file ? " or image file" : "");
        return -1;
    }
    d->rdev = st.st_rdev;

    char sys[PATH_MAX], link[PATH_MAX];
    snprintf(sys, sizeof(sys), "/sys/dev/block/%u:%u",
             major(d->rdev), minor(d->rdev));
    ssize_t ln = readlink(sys, link, sizeof(link) - 1);
    if (ln <= 0) {
        fprintf(stderr, "ivo-install: %s: not found in sysfs\n", d->path);
        return -1;
    }
    link[ln] = '\0';
    const char *base = strrchr(link, '/');
    snprintf(d->name, sizeof(d->name), "%.255s", base ? base + 1 : link);

    char pfile[PATH_MAX + 16];
    snprintf(pfile, sizeof(pfile), "%s/partition", sys);
    if (access(pfile, F_OK) == 0) {
        fprintf(stderr, "ivo-install: %s is a partition; pass the whole "
                "disk\n", d->path);
        return -1;
    }

    int fd = open(d->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "ivo-install: %s: %s\n", d->path, strerror(errno));
        return -1;
    }
    int ssz = 0;
    if (ioctl(fd, BLKGETSIZE64, &d->size) != 0 ||
        ioctl(fd, BLKSSZGET, &ssz) != 0 || ssz <= 0) {
        fprintf(stderr, "ivo-install: %s: cannot query size: %s\n",
                d->path, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    d->sector = (unsigned)ssz;
    return 0;
}

static int list_parts(const disk_t *d, part_t *parts, int max)
{
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "/sys/class/block/%s", d->name);
    DIR *dh = opendir(dir);
    if (!dh) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(dh)) != NULL && n < max) {
        if (e->d_name[0] == '.') continue;
        char p[PATH_MAX + 2 * NAME_MAX], buf[64];
        snprintf(p, sizeof(p), "%s/%s/partition", dir, e->d_name);
        if (read_sysfs(p, buf, sizeof(buf)) != 0) continue;
        int num = atoi(buf);
        snprintf(p, sizeof(p), "%s/%s/dev", dir, e->d_name);
        if (read_sysfs(p, buf, sizeof(buf)) != 0) continue;
        if (parse_devnum(buf, &parts[n].rdev) != 0) continue;
        snprintf(parts[n].name, sizeof(parts[n].name), "%s", e->d_name);
        parts[n].number = num;
        n++;
    }
    closedir(dh);
    return n;
}

static int holders_nonempty(const char *name)
{
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "/sys/class/block/%s/holders", name);
    DIR *dh = opendir(dir);
    if (!dh) return 0;
    int busy = 0;
    struct dirent *e;
    while ((e = readdir(dh)) != NULL)
        if (e->d_name[0] != '.') { busy = 1; break; }
    closedir(dh);
    return busy;
}

static int table_uses(const char *table, const dev_t *devs, int ndev,
                      char *what, size_t what_size)
{
    FILE *f = fopen(table, "re");
    if (!f) return 0;
    char line[4096];
    int hit = 0;
    while (!hit && fgets(line, sizeof(line), f)) {
        char src[PATH_MAX];
        if (sscanf(line, "%4095s", src) != 1 || src[0] != '/') continue;
        char *w = src;
        for (char *r = src; *r; ) {
            if (r[0] == '\\' && r[1] >= '0' && r[1] <= '3' &&
                r[2] >= '0' && r[2] <= '7' && r[3] >= '0' && r[3] <= '7') {
                *w++ = (char)((r[1] - '0') * 64 + (r[2] - '0') * 8 + (r[3] - '0'));
                r += 4;
            } else {
                *w++ = *r++;
            }
        }
        *w = '\0';
        struct stat st;
        if (stat(src, &st) != 0 || !S_ISBLK(st.st_mode)) continue;
        for (int i = 0; i < ndev; i++) {
            if (st.st_rdev == devs[i]) {
                snprintf(what, what_size, "%s", src);
                hit = 1;
                break;
            }
        }
    }
    fclose(f);
    return hit;
}

static int disk_in_use(const disk_t *d)
{
    part_t parts[MAX_PARTS];
    int np = list_parts(d, parts, MAX_PARTS);
    if (np < 0) np = 0;

    dev_t devs[MAX_PARTS + 1];
    devs[0] = d->rdev;
    for (int i = 0; i < np; i++) devs[i + 1] = parts[i].rdev;

    char what[PATH_MAX];
    if (table_uses("/proc/self/mounts", devs, np + 1, what, sizeof(what))) {
        fprintf(stderr, "ivo-install: %s is mounted (%s); unmount it first\n",
                d->path, what);
        return 1;
    }
    if (table_uses("/proc/swaps", devs, np + 1, what, sizeof(what))) {
        fprintf(stderr, "ivo-install: %s is in use as swap (%s)\n",
                d->path, what);
        return 1;
    }
    if (holders_nonempty(d->name)) {
        fprintf(stderr, "ivo-install: %s is held by another device "
                "(dm/md/LVM)\n", d->path);
        return 1;
    }
    for (int i = 0; i < np; i++) {
        if (holders_nonempty(parts[i].name)) {
            fprintf(stderr, "ivo-install: %s is held by another device "
                    "(dm/md/LVM/LUKS)\n", parts[i].name);
            return 1;
        }
    }
    int fd = open(d->path, O_RDONLY | O_EXCL | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "ivo-install: %s: %s\n", d->path,
                errno == EBUSY ? "device is busy (in use)" : strerror(errno));
        return 1;
    }
    close(fd);
    return 0;
}

static int mkdir_p(const char *path)
{
    char tmp[PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) { errno = ENAMETOOLONG; return -1; }
    memcpy(tmp, path, len + 1);
    if (len > 0 && tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int read_efi(const char *efi, uint8_t **out, size_t *len)
{
    if (ivo_read_file(efi, 64u << 20, out, len) != 0) {
        fprintf(stderr, "ivo-install: %s: %s\n", efi, strerror(errno));
        return -1;
    }
    if (*len < 2 || (*out)[0] != 'M' || (*out)[1] != 'Z') {
        fprintf(stderr, "ivo-install: %s: not a PE/COFF image (no MZ "
                "header)\n", efi);
        free(*out);
        return -1;
    }
    return 0;
}

static int do_uefi(const char *esp, const char *efi, int force)
{
    struct stat st;
    if (stat(esp, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "ivo-install: %s: not a directory\n", esp);
        return 1;
    }

    uint8_t *src = NULL;
    size_t src_len = 0;
    if (read_efi(efi, &src, &src_len) != 0) return 1;

    char dst_dir[PATH_MAX];
    char dst[PATH_MAX];
    int n = snprintf(dst_dir, sizeof(dst_dir), "%s/EFI/BOOT", esp);
    if (n < 0 || (size_t)n >= sizeof(dst_dir) ||
        (n = snprintf(dst, sizeof(dst), "%s/BOOTX64.EFI", dst_dir)) < 0 ||
        (size_t)n >= sizeof(dst)) {
        fprintf(stderr, "ivo-install: %s: path too long\n", esp);
        free(src);
        return 1;
    }

    if (mkdir_p(dst_dir) != 0) {
        fprintf(stderr, "ivo-install: %s: cannot create: %s\n",
                dst_dir, strerror(errno));
        free(src);
        return 1;
    }

    if (ivo_write_file(dst, src, src_len, 0644,
                       force ? 0 : IVO_WRITE_NOCLOBBER) != 0) {
        if (errno == EEXIST)
            fprintf(stderr, "ivo-install: %s exists; use --force to "
                    "overwrite\n", dst);
        else
            fprintf(stderr, "ivo-install: %s: %s\n", dst, strerror(errno));
        free(src);
        return 1;
    }

    fprintf(stderr, "ivo-install: installed %s -> %s (%zu bytes)\n",
            efi, dst, src_len);
    free(src);
    return 0;
}

typedef struct {
    int      fd;
    uint64_t size;
    uint32_t root_lba;
    uint32_t root_size;
} iso_t;

typedef struct {
    char     name[256];
    int      plain;
    uint32_t lba;
    uint32_t size;
    int      is_dir;
} iso_rec_t;

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int iso_extent_ok(const iso_t *iso, uint32_t lba, uint32_t size)
{
    uint64_t end = (uint64_t)lba * ISO_SECTOR + size;
    return lba >= 16 && end <= iso->size;
}

static int iso_open(const char *path, iso_t *iso)
{
    memset(iso, 0, sizeof(*iso));
    iso->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (iso->fd < 0) return -1;
    struct stat st;
    if (fstat(iso->fd, &st) != 0 || !S_ISREG(st.st_mode)) goto fail;
    iso->size = (uint64_t)st.st_size;

    uint8_t pvd[ISO_SECTOR];
    if (iso->size < 17 * ISO_SECTOR) goto fail;
    if (pread_all(iso->fd, pvd, sizeof(pvd), 16 * ISO_SECTOR) != 0) goto fail;
    if (pvd[0] != 1 || memcmp(pvd + 1, "CD001", 5) != 0) goto fail;
    if (((uint32_t)pvd[128] | ((uint32_t)pvd[129] << 8)) != ISO_SECTOR)
        goto fail;

    const uint8_t *root = pvd + 156;
    if (root[0] < 34) goto fail;
    iso->root_lba  = le32(root + 2);
    iso->root_size = le32(root + 10);
    if (!iso_extent_ok(iso, iso->root_lba, iso->root_size)) goto fail;
    return 0;

fail:
    close(iso->fd);
    iso->fd = -1;
    return -1;
}

static void iso_close(iso_t *iso)
{
    if (iso->fd >= 0) close(iso->fd);
    iso->fd = -1;
}

static int iso_nm(const uint8_t *rec, size_t rec_len, char *out, size_t out_size)
{
    size_t su = 33 + (size_t)rec[32];
    if (su & 1) su++;
    if (su >= rec_len) return -1;

    const uint8_t *p = rec + su;
    size_t remaining = rec_len - su;
    size_t n = 0;
    int got = 0;

    while (remaining >= 4) {
        uint8_t len = p[2];
        if (len < 4 || len > remaining) break;
        if (p[0] == 'S' && p[1] == 'T') break;

        if (p[0] == 'N' && p[1] == 'M' && len >= 5) {
            uint8_t flags = p[4];
            if (flags & 0x06) return -1;
            for (size_t i = 5; i < len; i++) {
                if (n + 1 >= out_size) return -1;
                out[n++] = (char)p[i];
            }
            got = 1;
            if (!(flags & 0x01)) break;
        }
        p += len;
        remaining -= len;
    }
    if (!got || n == 0) return -1;
    out[n] = '\0';
    return 0;
}

static int iso_rec_name(const uint8_t *rec, size_t rec_len, iso_rec_t *r)
{
    size_t nl = rec[32];
    const uint8_t *id = rec + 33;
    if (nl == 1 && (id[0] == 0 || id[0] == 1)) return -1;

    if (iso_nm(rec, rec_len, r->name, sizeof(r->name)) == 0) {
        r->plain = 0;
        return 0;
    }
    size_t n = nl;
    for (size_t i = 0; i < nl; i++) if (id[i] == ';') { n = i; break; }
    if (n > 0 && id[n - 1] == '.') n--;
    if (n == 0 || n >= sizeof(r->name)) return -1;
    memcpy(r->name, id, n);
    r->name[n] = '\0';
    r->plain = 1;
    return 0;
}

typedef int (*iso_visit_fn)(const iso_rec_t *r, void *user);

static int iso_walk(const iso_t *iso, uint32_t lba, uint32_t size,
                    iso_visit_fn visit, void *user)
{
    if (size > ISO_MAX_DIR || !iso_extent_ok(iso, lba, size)) return -1;

    uint8_t buf[ISO_SECTOR];
    for (uint32_t done = 0; done < size; done += ISO_SECTOR, lba++) {
        if (pread_all(iso->fd, buf, sizeof(buf),
                      (off_t)lba * ISO_SECTOR) != 0)
            return -1;
        uint32_t off = 0;
        while (off < ISO_SECTOR) {
            uint32_t rec_len = buf[off];
            if (rec_len == 0) break;
            if (rec_len < 34 || off + rec_len > ISO_SECTOR) return -1;
            const uint8_t *rec = buf + off;
            if (33u + rec[32] > rec_len) return -1;

            iso_rec_t r;
            memset(&r, 0, sizeof(r));
            if (iso_rec_name(rec, rec_len, &r) == 0) {
                r.lba    = le32(rec + 2);
                r.size   = le32(rec + 10);
                r.is_dir = (rec[25] & 0x02) != 0;
                if (visit(&r, user)) return 1;
            }
            off += rec_len;
        }
    }
    return 0;
}

static int name_eq(const iso_rec_t *r, const char *want)
{
    return r->plain ? strcasecmp(r->name, want) == 0
                    : strcmp(r->name, want) == 0;
}

static int prefix_eq(const iso_rec_t *r, const char *prefix)
{
    size_t n = strlen(prefix);
    return r->plain ? strncasecmp(r->name, prefix, n) == 0
                    : strncmp(r->name, prefix, n) == 0;
}

struct find_dir { const char *name; iso_rec_t found; int ok; };

static int visit_find_dir(const iso_rec_t *r, void *user)
{
    struct find_dir *f = user;
    if (!r->is_dir || !name_eq(r, f->name)) return 0;
    f->found = *r;
    f->ok = 1;
    return 1;
}

struct find_boot { iso_rec_t kernel, initrd; int have_k, have_i; };

static int visit_find_boot(const iso_rec_t *r, void *user)
{
    struct find_boot *f = user;
    if (r->is_dir) return 0;
    if (!f->have_k && prefix_eq(r, "vmlinuz")) {
        f->kernel = *r; f->have_k = 1;
    } else if (!f->have_i &&
               (prefix_eq(r, "initramfs") || prefix_eq(r, "initrd"))) {
        f->initrd = *r; f->have_i = 1;
    }
    return f->have_k && f->have_i;
}

static int safe_file_name(const char *s)
{
    if (!s[0] || strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return 0;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c <= 0x20 || c >= 0x7F || c == '/' || c == '\\' ||
            c == '"' || c == '\'')
            return 0;
    }
    return 1;
}

static int iso_find_boot_files(const iso_t *iso, iso_rec_t *kernel,
                               iso_rec_t *initrd, const char *iso_path)
{
    struct find_dir fd;
    memset(&fd, 0, sizeof(fd));
    fd.name = "boot";
    if (iso_walk(iso, iso->root_lba, iso->root_size, visit_find_dir, &fd) < 0) {
        fprintf(stderr, "ivo-install: %s: malformed root directory\n", iso_path);
        return -1;
    }
    if (!fd.ok) {
        fprintf(stderr, "ivo-install: %s: no /boot directory\n", iso_path);
        return -1;
    }

    struct find_boot fb;
    memset(&fb, 0, sizeof(fb));
    if (iso_walk(iso, fd.found.lba, fd.found.size, visit_find_boot, &fb) < 0) {
        fprintf(stderr, "ivo-install: %s: malformed /boot directory\n", iso_path);
        return -1;
    }
    if (!fb.have_k || !fb.have_i) {
        fprintf(stderr, "ivo-install: %s: no kernel/initrd found in /boot\n",
                iso_path);
        return -1;
    }

    iso_rec_t *recs[2] = { &fb.kernel, &fb.initrd };
    for (int i = 0; i < 2; i++) {
        iso_rec_t *r = recs[i];
        if (r->plain)
            for (char *c = r->name; *c; c++)
                if (*c >= 'A' && *c <= 'Z') *c = (char)(*c + 32);
        if (!safe_file_name(r->name)) {
            fprintf(stderr, "ivo-install: %s: refusing file name in /boot "
                    "with quotes, spaces or control characters\n", iso_path);
            return -1;
        }
        if (!iso_extent_ok(iso, r->lba, r->size)) {
            fprintf(stderr, "ivo-install: %s: /boot/%s points outside the "
                    "image\n", iso_path, r->name);
            return -1;
        }
    }
    *kernel = fb.kernel;
    *initrd = fb.initrd;
    return 0;
}

static int copy_range(int in, off_t off, uint64_t n, int out)
{
    enum { CHUNK = 4 << 20 };
    uint8_t *buf = malloc(CHUNK);
    if (!buf) { errno = ENOMEM; return -1; }
    while (n > 0) {
        size_t want = n < CHUNK ? (size_t)n : CHUNK;
        if (pread_all(in, buf, want, off) != 0 || write_all(out, buf, want) != 0) {
            int e = errno;
            free(buf);
            errno = e;
            return -1;
        }
        off += (off_t)want;
        n -= want;
    }
    free(buf);
    return 0;
}

static int create_file(int dirfd, const char *name, const void *data,
                       size_t len, const iso_t *iso, const iso_rec_t *r)
{
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                    O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    int rc = r ? copy_range(iso->fd, (off_t)r->lba * ISO_SECTOR, r->size, fd)
               : write_all(fd, data, len);
    if (rc == 0) rc = fsync(fd);
    int e = errno;
    if (close(fd) != 0 && rc == 0) { rc = -1; e = errno; }
    errno = e;
    return rc;
}

static int mkdirs_at(int dirfd, const char *const names[], int n, int *out_fd)
{
    int cur = dup(dirfd);
    if (cur < 0) return -1;
    for (int i = 0; i < n; i++) {
        if (mkdirat(cur, names[i], 0755) != 0 && errno != EEXIST) {
            close(cur);
            return -1;
        }
        int next = openat(cur, names[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                          O_CLOEXEC);
        close(cur);
        if (next < 0) return -1;
        cur = next;
    }
    *out_fd = cur;
    return 0;
}

static int find_part_node(const disk_t *d, int number, char *out, size_t out_size,
                          uint64_t *size_bytes)
{
    for (int tries = 0; tries < 100; tries++) {
        part_t parts[MAX_PARTS];
        int np = list_parts(d, parts, MAX_PARTS);
        for (int i = 0; i < np; i++) {
            if (parts[i].number != number) continue;
            char node[PATH_MAX];
            snprintf(node, sizeof(node), "/dev/%.255s", parts[i].name);
            struct stat st;
            if (stat(node, &st) == 0 && S_ISBLK(st.st_mode) &&
                st.st_rdev == parts[i].rdev) {
                char p[PATH_MAX + NAME_MAX], buf[64];
                snprintf(p, sizeof(p), "/sys/class/block/%.255s/size", parts[i].name);
                if (read_sysfs(p, buf, sizeof(buf)) != 0) break;
                *size_bytes = strtoull(buf, NULL, 10) * 512ull;
                snprintf(out, out_size, "%s", node);
                return 0;
            }
        }
        sleep_ms(100);
    }
    fprintf(stderr, "ivo-install: partition %d of %s did not appear\n",
            number, d->path);
    return -1;
}

static int write_usb_esp(const char *mnt, const uint8_t *efi, size_t efi_len,
                         const iso_t *iso, const iso_rec_t *kernel,
                         const iso_rec_t *initrd, const char *config,
                         size_t config_len)
{
    int root = open(mnt, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) return -1;
    int rc = -1, efidir = -1, bootdir = -1, ivodir = -1;
    static const char *const efi_path[]  = { "EFI", "BOOT" };
    static const char *const boot_path[] = { "boot" };
    static const char *const ivo_path[]  = { "ivo" };

    if (mkdirs_at(root, efi_path, 2, &efidir) != 0) goto out;
    if (mkdirs_at(root, boot_path, 1, &bootdir) != 0) goto out;
    if (mkdirs_at(root, ivo_path, 1, &ivodir) != 0) goto out;

    if (create_file(efidir, "BOOTX64.EFI", efi, efi_len, NULL, NULL) != 0) {
        fprintf(stderr, "ivo-install: BOOTX64.EFI: %s\n", strerror(errno));
        goto out;
    }
    if (create_file(bootdir, kernel->name, NULL, 0, iso, kernel) != 0) {
        fprintf(stderr, "ivo-install: /boot/%s: %s\n", kernel->name, strerror(errno));
        goto out;
    }
    if (create_file(bootdir, initrd->name, NULL, 0, iso, initrd) != 0) {
        fprintf(stderr, "ivo-install: /boot/%s: %s\n", initrd->name, strerror(errno));
        goto out;
    }
    if (create_file(ivodir, "config.toml", config, config_len, NULL, NULL) != 0) {
        fprintf(stderr, "ivo-install: config.toml: %s\n", strerror(errno));
        goto out;
    }
    if (syncfs(root) != 0) goto out;
    rc = 0;
out:
    if (rc != 0 && errno) fprintf(stderr, "ivo-install: ESP: %s\n", strerror(errno));
    if (efidir >= 0) close(efidir);
    if (bootdir >= 0) close(bootdir);
    if (ivodir >= 0) close(ivodir);
    close(root);
    return rc;
}

static int do_usb(const char *device, const char *iso_path,
                  const char *efi, int yes)
{
    disk_t d;
    if (resolve_disk(device, &d, 0) != 0) return 1;
    if (disk_in_use(&d)) return 1;

    uint8_t *efi_data = NULL;
    size_t efi_len = 0;
    if (read_efi(efi, &efi_data, &efi_len) != 0) return 1;

    iso_t iso;
    if (iso_open(iso_path, &iso) != 0) {
        fprintf(stderr, "ivo-install: %s: not an ISO9660 image (2048-byte "
                "blocks)\n", iso_path);
        free(efi_data);
        return 1;
    }

    iso_rec_t kernel, initrd;
    if (iso_find_boot_files(&iso, &kernel, &initrd, iso_path) != 0) {
        iso_close(&iso); free(efi_data);
        return 1;
    }

    const uint64_t esp_bytes = 512ull << 20;
    if (d.size < esp_bytes + iso.size + (8ull << 20)) {
        fprintf(stderr, "ivo-install: %s (%llu MB) is too small for a 512 MB "
                "ESP plus the %llu MB ISO\n", d.path,
                (unsigned long long)(d.size >> 20),
                (unsigned long long)(iso.size >> 20));
        iso_close(&iso); free(efi_data);
        return 1;
    }
    if ((uint64_t)kernel.size + initrd.size + efi_len > esp_bytes - (16ull << 20)) {
        fprintf(stderr, "ivo-install: kernel + initrd do not fit the ESP\n");
        iso_close(&iso); free(efi_data);
        return 1;
    }

    ivo_buf_t cfg = {0};
    char kpath[300], ipath[300];
    snprintf(kpath, sizeof(kpath), "/boot/%s", kernel.name);
    snprintf(ipath, sizeof(ipath), "/boot/%s", initrd.name);
    ivo_buf_puts(&cfg, "timeout = 10\ndefault = \"Live\"\n\n[entries.Live]\n");
    const char *why = ivo_toml_kv(&cfg, "kernel", kpath);
    if (!why) why = ivo_toml_kv(&cfg, "initrd", ipath);
    if (!why) why = ivo_toml_kv(&cfg, "options",
                                "modules=loop,squashfs,sd-mod,usb-storage quiet");
    if (!why && cfg.failed) why = "out of memory";
    if (!why && config_parse(cfg.p, cfg.len) != 0)
        why = "generated config does not parse";
    if (why) {
        fprintf(stderr, "ivo-install: config: %s\n", why);
        ivo_buf_free(&cfg); iso_close(&iso); free(efi_data);
        return 1;
    }

    char model[256] = "";
    {
        char p[PATH_MAX];
        snprintf(p, sizeof(p), "/sys/class/block/%s/device/model", d.name);
        if (read_sysfs(p, model, sizeof(model)) != 0) model[0] = '\0';
    }
    fprintf(stderr,
        "ivo-install: about to ERASE and repartition %s%s%s%s (%llu MB)\n"
        "  ESP (FAT32, 512 MB): ivo.efi, config, kernel, initrd\n"
        "  raw ISO partition: %s\n"
        "  kernel: /boot/%s\n"
        "  initrd: /boot/%s\n",
        d.path, model[0] ? " [" : "", model, model[0] ? "]" : "",
        (unsigned long long)(d.size >> 20), iso_path, kernel.name, initrd.name);

    if (!yes && !confirm("Continue? This will erase the device.")) {
        fprintf(stderr, "aborted\n");
        ivo_buf_free(&cfg); iso_close(&iso); free(efi_data);
        return 1;
    }

    int ok = 0;
    char mnt[] = "/tmp/ivo-install.XXXXXX";
    int mounted = 0, have_mnt = 0;
    char esp_part[PATH_MAX], iso_part[PATH_MAX];
    uint64_t esp_size = 0, iso_part_size = 0;

    {
        char *wipefs[] = { "wipefs", "-a", d.path, NULL };
        if (run_cmd(wipefs, NULL, 1) != 0) {
            fprintf(stderr, "ivo-install: wipefs failed on %s\n", d.path);
            goto out;
        }
    }
    {
        char *sfdisk[] = { "sfdisk", "--quiet", "--wipe", "always", d.path, NULL };
        const char *script =
            "label: gpt\n"
            "size=512M, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=\"ESP\"\n"
            "type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=\"ISO\"\n";
        if (run_cmd(sfdisk, script, 1) != 0) {
            fprintf(stderr, "ivo-install: sfdisk failed on %s\n", d.path);
            goto out;
        }
    }
    {
        char *partx[] = { "partx", "-u", d.path, NULL };
        char *settle[] = { "udevadm", "settle", NULL };
        run_cmd(partx, NULL, 1);
        run_cmd(settle, NULL, 1);
    }

    if (find_part_node(&d, 1, esp_part, sizeof(esp_part), &esp_size) != 0 ||
        find_part_node(&d, 2, iso_part, sizeof(iso_part), &iso_part_size) != 0)
        goto out;
    if (iso_part_size < iso.size) {
        fprintf(stderr, "ivo-install: %s (%llu bytes) is smaller than the "
                "ISO\n", iso_part, (unsigned long long)iso_part_size);
        goto out;
    }

    {
        char *mkfs[] = { "mkfs.vfat", "-F", "32", "-n", "IVO", esp_part, NULL };
        if (run_cmd(mkfs, NULL, 1) != 0) {
            fprintf(stderr, "ivo-install: mkfs.vfat failed on %s\n", esp_part);
            goto out;
        }
    }

    if (!mkdtemp(mnt)) {
        fprintf(stderr, "ivo-install: mkdtemp: %s\n", strerror(errno));
        goto out;
    }
    have_mnt = 1;
    if (mount(esp_part, mnt, "vfat", MS_NOSUID | MS_NODEV | MS_NOEXEC, "") != 0) {
        fprintf(stderr, "ivo-install: mount %s: %s\n", esp_part, strerror(errno));
        goto out;
    }
    mounted = 1;

    if (write_usb_esp(mnt, efi_data, efi_len, &iso, &kernel, &initrd,
                      cfg.p, cfg.len) != 0)
        goto out;

    if (umount2(mnt, 0) != 0) {
        fprintf(stderr, "ivo-install: umount %s: %s\n", mnt, strerror(errno));
        goto out;
    }
    mounted = 0;

    fprintf(stderr, "ivo-install: writing ISO to %s (this takes a minute)\n",
            iso_part);
    {
        int out_fd = open(iso_part, O_WRONLY | O_EXCL | O_CLOEXEC);
        if (out_fd < 0) {
            fprintf(stderr, "ivo-install: %s: %s\n", iso_part, strerror(errno));
            goto out;
        }
        int rc = copy_range(iso.fd, 0, iso.size, out_fd);
        if (rc == 0) rc = fsync(out_fd);
        int e = errno;
        if (close(out_fd) != 0 && rc == 0) { rc = -1; e = errno; }
        if (rc != 0) {
            fprintf(stderr, "ivo-install: writing %s: %s\n", iso_part, strerror(e));
            goto out;
        }
    }
    ok = 1;

out:
    if (mounted && umount2(mnt, 0) != 0)
        fprintf(stderr, "ivo-install: warning: %s is still mounted\n", mnt);
    else if (have_mnt)
        rmdir(mnt);
    ivo_buf_free(&cfg);
    iso_close(&iso);
    free(efi_data);
    if (!ok) {
        fprintf(stderr, "ivo-install: USB install FAILED; %s is not usable\n",
                d.path);
        return 1;
    }
    fprintf(stderr, "ivo-install: USB is ready on %s\n", d.path);
    fprintf(stderr, "  Boot it with Secure Boot off and CSM off.\n");
    return 0;
}

int main(int argc, char **argv)
{
    const char *target = NULL;
    const char *device = NULL;
    const char *esp    = NULL;
    const char *iso    = NULL;
    const char *efi    = "ivo.efi";
    int yes   = 0;
    int force = 0;

    signal(SIGPIPE, SIG_IGN);

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target = argv[++i];
        else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) device = argv[++i];
        else if (strcmp(argv[i], "--esp")    == 0 && i + 1 < argc) esp    = argv[++i];
        else if (strcmp(argv[i], "--iso")    == 0 && i + 1 < argc) iso    = argv[++i];
        else if (strcmp(argv[i], "--efi")    == 0 && i + 1 < argc) efi    = argv[++i];
        else if (strcmp(argv[i], "--yes")    == 0) yes = 1;
        else if (strcmp(argv[i], "-y")       == 0) yes = 1;
        else if (strcmp(argv[i], "--force")  == 0) force = 1;
        else if (strcmp(argv[i], "-f")       == 0) force = 1;
        else {
            fprintf(stderr, "ivo-install: unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!target) {
        fprintf(stderr,
            "usage:\n"
            "  ivo-install --target uefi --esp /boot/efi [--efi ivo.efi] [--force]\n"
            "  ivo-install --target usb  --device /dev/sdb --iso alpine.iso [--efi ivo.efi] [--yes]\n"
            "\n"
            "UEFI copies the .efi to <esp>/EFI/BOOT/BOOTX64.EFI. USB builds\n"
            "a bootable test stick from an ISO image.\n");
        return 1;
    }

    if (strcmp(target, "uefi") == 0) {
        if (!esp) {
            fprintf(stderr, "ivo-install: --target uefi needs --esp\n");
            return 1;
        }
        return do_uefi(esp, efi, force);
    }
    if (strcmp(target, "usb") == 0) {
        if (!device || !iso) {
            fprintf(stderr,
                "ivo-install: --target usb needs --device and --iso\n");
            return 1;
        }
        return do_usb(device, iso, efi, yes);
    }

    fprintf(stderr, "ivo-install: unknown --target: %s\n", target);
    return 1;
}