/* Shared helpers for the host tools. See ivo-util.h. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ivo-util.h"
#include "sha512.h"


int ivo_read_fd(int fd, size_t max, uint8_t **out, size_t *len)
{
    size_t cap = 4096, n = 0;
    uint8_t *b = malloc(cap + 1);
    if (!b) { errno = ENOMEM; return -1; }

    for (;;) {
        if (n == cap) {
            if (cap >= max) { free(b); errno = EFBIG; return -1; }
            size_t ncap = cap * 2;
            if (ncap > max) ncap = max;
            uint8_t *nb = realloc(b, ncap + 1);
            if (!nb) { free(b); errno = ENOMEM; return -1; }
            b = nb;
            cap = ncap;
        }
        ssize_t r = read(fd, b + n, cap - n);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            free(b);
            errno = e;
            return -1;
        }
        if (r == 0) break;
        n += (size_t)r;
    }
    b[n] = 0;
    *out = b;
    *len = n;
    return 0;
}

int ivo_read_file(const char *path, size_t max, uint8_t **out, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { int e = errno; close(fd); errno = e; return -1; }
    if (!S_ISREG(st.st_mode)) { close(fd); errno = EINVAL; return -1; }
    if ((unsigned long long)st.st_size > max) { close(fd); errno = EFBIG; return -1; }
    int rc = ivo_read_fd(fd, max, out, len);
    int e = errno;
    close(fd);
    errno = e;
    return rc;
}

static int write_all_fd(int fd, const void *data, size_t len)
{
    const uint8_t *p = data;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) { errno = EIO; return -1; }
        p += w;
        len -= (size_t)w;
    }
    return 0;
}

static int fsync_parent(const char *path)
{
    char *dir = strdup(path);
    if (!dir) { errno = ENOMEM; return -1; }
    char *slash = strrchr(dir, '/');
    const char *d;
    if (!slash) d = ".";
    else if (slash == dir) { dir[1] = '\0'; d = dir; }
    else { *slash = '\0'; d = dir; }

    int fd = open(d, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) { int e = errno; free(dir); errno = e; return -1; }
    int rc = 0;
    if (fsync(fd) != 0 && errno != EINVAL && errno != EROFS) rc = -1;
    int e = errno;
    close(fd);
    free(dir);
    errno = e;
    return rc;
}

static int set_mode(int fd, mode_t mode)
{
    if (fchmod(fd, mode) == 0) return 0;
    return errno == EPERM ? 0 : -1;
}

int ivo_write_file(const char *path, const void *data, size_t len,
                   mode_t mode, int flags)
{
    struct stat st;
    int have_old = (lstat(path, &st) == 0);

    if (have_old && S_ISLNK(st.st_mode)) { errno = ELOOP; return -1; }
    if (have_old && (flags & IVO_WRITE_NOCLOBBER)) { errno = EEXIST; return -1; }
    if (have_old && !S_ISREG(st.st_mode)) { errno = EINVAL; return -1; }

    if (flags & IVO_WRITE_NOCLOBBER) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      mode & 0777);
        if (fd < 0) return -1;
        int ok = set_mode(fd, mode & 0777) == 0 &&
                 write_all_fd(fd, data, len) == 0 &&
                 fsync(fd) == 0;
        int e = errno;
        if (close(fd) != 0 && ok) { ok = 0; e = errno; }
        if (!ok) { unlink(path); errno = e; return -1; }
        return fsync_parent(path);
    }

    size_t plen = strlen(path);
    char *tmp = malloc(plen + 16);
    if (!tmp) { errno = ENOMEM; return -1; }
    memcpy(tmp, path, plen);
    memcpy(tmp + plen, ".tmp.XXXXXX", 12);

    int fd = mkostemp(tmp, O_CLOEXEC);
    if (fd < 0) { int e = errno; free(tmp); errno = e; return -1; }

    if (have_old && (flags & IVO_WRITE_KEEP_MODE)) {
        mode = st.st_mode & 07777;
        /* Best effort: only root can give a file away. */
        if (fchown(fd, st.st_uid, st.st_gid) != 0) { /* ignore */ }
    }

    int ok = set_mode(fd, mode) == 0 &&
             write_all_fd(fd, data, len) == 0 &&
             fsync(fd) == 0;
    int e = errno;
    if (close(fd) != 0 && ok) { ok = 0; e = errno; }
    if (ok && rename(tmp, path) != 0) { ok = 0; e = errno; }
    if (!ok) {
        unlink(tmp);
        free(tmp);
        errno = e;
        return -1;
    }
    free(tmp);
    return fsync_parent(path);
}

int ivo_write_stdout(const void *data, size_t len)
{
    if (len && fwrite(data, 1, len, stdout) != len) return -1;
    if (fflush(stdout) != 0 || ferror(stdout)) return -1;
    return 0;
}


const char *ivo_boot_path_problem(const char *path)
{
    if (!path || !path[0]) return "empty path";
    if (path[0] != '/') return "path must be absolute (start with '/')";
    if (strlen(path) >= 4096) return "path too long";

    const char *p = path;
    while (*p) {
        if (*p != '/') return "malformed path";
        p++;
        const char *start = p;
        while (*p && *p != '/') {
            unsigned char c = (unsigned char)*p;
            if (c < 0x20 || c == 0x7F) return "control character in path";
            p++;
        }
        size_t n = (size_t)(p - start);
        if (n == 0) return "empty path component ('//' or trailing '/')";
        if (n == 1 && start[0] == '.') return "'.' path component";
        if (n == 2 && start[0] == '.' && start[1] == '.')
            return "'..' path component";
        if (n > 255) return "path component too long";
    }
    return NULL;
}

static int walk_nofollow(int dirfd, const char *rel, int final_file,
                         char *err, size_t err_size)
{
    char comp[256];
    const char *p = rel;

    while (*p == '/') p++;
    if (!*p) {
        if (final_file) {
            close(dirfd);
            snprintf(err, err_size, "no file name");
            return -1;
        }
        return dirfd;
    }

    while (*p) {
        const char *start = p;
        while (*p && *p != '/') p++;
        size_t n = (size_t)(p - start);
        while (*p == '/') p++;
        if (n >= sizeof(comp)) {
            close(dirfd);
            snprintf(err, err_size, "path component too long");
            return -1;
        }
        memcpy(comp, start, n);
        comp[n] = '\0';
        if (strcmp(comp, ".") == 0 || strcmp(comp, "..") == 0) {
            close(dirfd);
            snprintf(err, err_size, "'%s' path component", comp);
            return -1;
        }

        int last = (*p == '\0');
        int oflags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
        if (!last || !final_file) oflags |= O_DIRECTORY;
        else oflags |= O_NONBLOCK;

        int fd = openat(dirfd, comp, oflags);
        int e = errno;
        close(dirfd);
        if (fd < 0) {
            if (e == ELOOP || e == EMLINK)
                snprintf(err, err_size,
                         "'%s' is a symlink (the bootloader does not follow "
                         "symlinks)", comp);
            else if (e == ENOTDIR && !last)
                snprintf(err, err_size, "'%s' is not a directory "
                         "(or is a symlink)", comp);
            else
                snprintf(err, err_size, "%s: %s", comp, strerror(e));
            return -1;
        }
        dirfd = fd;
    }

    if (final_file) {
        struct stat st;
        if (fstat(dirfd, &st) != 0 || !S_ISREG(st.st_mode)) {
            close(dirfd);
            snprintf(err, err_size, "not a regular file");
            return -1;
        }
        int fl = fcntl(dirfd, F_GETFL);
        if (fl >= 0) fcntl(dirfd, F_SETFL, fl & ~O_NONBLOCK);
    }
    return dirfd;
}

int ivo_open_beneath(const char *root, const char *subdir,
                     const char *path, char *err, size_t err_size)
{
    const char *why = ivo_boot_path_problem(path);
    if (why) { snprintf(err, err_size, "%s", why); return -1; }

    int fd = open(root && root[0] ? root : "/",
                  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, err_size, "%s: %s", root && root[0] ? root : "/",
                 strerror(errno));
        return -1;
    }
    if (subdir && subdir[0]) {
        fd = walk_nofollow(fd, subdir, 0, err, err_size);
        if (fd < 0) return -1;
    }
    return walk_nofollow(fd, path, 1, err, err_size);
}


static void digest_hex(const uint8_t d[64], char out[IVO_HASH_HEX_LEN + 1])
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[i * 2]     = hex[d[i] >> 4];
        out[i * 2 + 1] = hex[d[i] & 0xF];
    }
    out[IVO_HASH_HEX_LEN] = '\0';
}

void ivo_sha512_hex(const uint8_t *data, size_t len,
                    char out[IVO_HASH_HEX_LEN + 1])
{
    uint8_t digest[64];
    sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, digest);
    digest_hex(digest, out);
}

int ivo_sha512_fd(int fd, char out[IVO_HASH_HEX_LEN + 1])
{
    enum { CHUNK = 1 << 20 };
    uint8_t *buf = malloc(CHUNK);
    if (!buf) { errno = ENOMEM; return -1; }
    sha512_ctx_t ctx;
    sha512_init(&ctx);
    for (;;) {
        ssize_t r = read(fd, buf, CHUNK);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            free(buf);
            errno = e;
            return -1;
        }
        if (r == 0) break;
        sha512_update(&ctx, buf, (size_t)r);
    }
    free(buf);
    uint8_t digest[64];
    sha512_final(&ctx, digest);
    digest_hex(digest, out);
    return 0;
}


void ivo_buf_append(ivo_buf_t *b, const char *s, size_t n)
{
    if (b->failed) return;
    if (n > ((size_t)-1) / 2 - b->len) { b->failed = 1; return; }
    if (b->len + n + 1 > b->cap) {
        size_t ncap = b->cap ? b->cap : 256;
        while (ncap < b->len + n + 1) ncap *= 2;
        char *np = realloc(b->p, ncap);
        if (!np) { b->failed = 1; return; }
        b->p = np;
        b->cap = ncap;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

void ivo_buf_puts(ivo_buf_t *b, const char *s)
{
    ivo_buf_append(b, s, strlen(s));
}

void ivo_buf_printf(ivo_buf_t *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *s = NULL;
    int n = vasprintf(&s, fmt, ap);
    va_end(ap);
    if (n < 0) { b->failed = 1; return; }
    ivo_buf_append(b, s, (size_t)n);
    free(s);
}

void ivo_buf_free(ivo_buf_t *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
    b->failed = 0;
}


const char *ivo_toml_kv(ivo_buf_t *b, const char *key, const char *value)
{
    int has_dq = 0, has_sq = 0;
    for (const char *p = value; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c < 0x20 && c != '\t') || c == 0x7F)
            return "value contains a control character";
        if (c == '"')  has_dq = 1;
        if (c == '\'') has_sq = 1;
    }
    if (has_dq && has_sq)
        return "value contains both ' and \" (config.toml has no escapes)";
    char q = has_dq ? '\'' : '"';

    /* key + " = " + q + value + q */
    size_t line = strlen(key) + 3 + 1 + strlen(value) + 1;
    if (line > IVO_CFG_MAX_LINE)
        return "value too long (config.toml lines are limited to 4095 bytes)";

    ivo_buf_printf(b, "%s = %c%s%c\n", key, q, value, q);
    return NULL;
}

int ivo_entry_name(const char *in, char *out, size_t out_size)
{
    if (out_size == 0) return -1;
    size_t max = out_size - 1;
    if (max > IVO_CFG_MAX_NAME) max = IVO_CFG_MAX_NAME;
    size_t j = 0;
    for (size_t i = 0; in[i] && j < max; i++) {
        char c = in[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') ||
                 c == '.' || c == '_' || c == '+' || c == '-';
        out[j++] = ok ? c : '_';
    }
    out[j] = '\0';
    return j > 0 ? 0 : -1;
}

int ivo_parse_uint(const char *s, unsigned long max, unsigned long *out)
{
    unsigned long v = 0;
    if (!s || !*s) return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        unsigned long d = (unsigned long)(*s - '0');
        if (v > max / 10 || (v == max / 10 && d > max % 10)) return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}
