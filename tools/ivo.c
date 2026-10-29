/* Consolidated tool
 *
 *   ivo status                        report current Ivo state
 *   ivo key gen         ...           generate an Ed25519 keypair
 *   ivo key password-hash ...         hash a per-entry password
 *   ivo config hash     ...           compute + write kver/iver/cver
 *   ivo config check    ...           verify hashes without writing
 *   ivo config sign     ...           write config.toml.sig
 *   ivo config verify   ...           verify config.toml.sig
 *   ivo config generate ...           emit config.toml from a /boot scan
 *   ivo config convert  ...           convert another bootloader's config
 *   ivo install uefi    ...           install ivo.efi to an ESP
 *   ivo install usb     ...           build a bootable USB stick
 *
 * See ivo-build.c for build-time helpers (font, mkinitivo).
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <sys/random.h>
#include <linux/fs.h>

#include "config.h"
#include "ed25519.h"
#include "ge.h"
#include "wipe.h"
#include "ivo-util.h"
#include "crypto/pbkdf2.h"

void *mm_alloc(size_t size) { return malloc(size); }
void  mm_free(void *ptr)    { free(ptr); }

int  ivo_iso_volume_id(const uint8_t *img, size_t size,
                       char *out, size_t out_size);
int  ivo_iso_read_file(const uint8_t *img, size_t size, const char *path,
                       uint8_t **out, size_t *out_len);

#define CONFIG_MAX      (64 * 1024)
#define SEC_KEY_LEN     64
#define MAX_ISOS        8

typedef struct {
    const char *path;
    uint8_t    *map;
    size_t      size;
    char        label[33];
} iso_image_t;

typedef struct {
    const char *root;
    const char *subvol_root;
    iso_image_t isos[MAX_ISOS];
    int         n_isos;
    int         verbose;
    int         no_bump;
} opts_t;

typedef struct {
    char *name, *kernel, *initrd, *cmdline, *chain, *iso_label, *subvol;
    char *kver, *iver, *cver;
    int   is_chainload, is_iso, hidden, timeout;
} snap_t;

typedef struct {
    const char *key;
    const char *path;
    const char *recorded;
} file_ref_t;

static int cmd_status(int argc, char **argv);
static int cmd_key_gen(int argc, char **argv);
static int cmd_key_password_hash(int argc, char **argv);
static int cmd_config_hash(int argc, char **argv);
static int cmd_config_check(int argc, char **argv);
static int cmd_config_sign(int argc, char **argv);
static int cmd_config_verify(int argc, char **argv);
static int cmd_config_generate(int argc, char **argv);
static int cmd_config_convert(int argc, char **argv);
static int cmd_install_uefi(int argc, char **argv);
static int cmd_install_usb(int argc, char **argv);

static char *xstrdup(const char *s)
{
    if (!s) return NULL;
    char *d = strdup(s);
    if (!d) { fprintf(stderr, "ivo: out of memory\n"); exit(1); }
    return d;
}

static int str_eq(const char *a, const char *b)
{
    if (!a || !b) return a == b;
    return strcmp(a, b) == 0;
}

static int str_eq0(const char *a, const char *b)
{
    return str_eq(a && a[0] ? a : NULL, b && b[0] ? b : NULL);
}

static int read_config(const char *path, uint8_t **buf, size_t *len)
{
    if (ivo_read_file(path, CONFIG_MAX + 1, buf, len) != 0) {
        fprintf(stderr, "ivo: %s: %s\n", path,
                errno == EFBIG ? "larger than the bootloader's 64 KiB limit"
                               : strerror(errno));
        return -1;
    }
    if (*len > CONFIG_MAX || *len == 0) {
        fprintf(stderr, "ivo: %s: %s\n", path, *len ?
                "larger than the bootloader's 64 KiB limit" : "empty");
        free(*buf);
        return -1;
    }
    return 0;
}

static int parse_config(const char *path, const uint8_t *buf, size_t len)
{
    if (config_parse((const char *)buf, len) != 0) {
        int line = config_error_line();
        if (line > 0)
            fprintf(stderr, "ivo: %s:%d: parse error "
                    "(the bootloader would reject this config)\n", path, line);
        else
            fprintf(stderr, "ivo: %s: parse error: no entries, or the "
                    "last entry is incomplete\n", path);
        return -1;
    }
    return 0;
}

static snap_t *snapshot(int *count)
{
    int n = 0;
    entry_t *e = config_get_entries(&n);
    snap_t *s = calloc((size_t)(n ? n : 1), sizeof(*s));
    if (!s) { fprintf(stderr, "ivo: out of memory\n"); exit(1); }
    for (int i = 0; i < n; i++) {
        s[i].name      = xstrdup(e[i].name);
        s[i].kernel    = xstrdup(e[i].kernel_path);
        s[i].initrd    = xstrdup(e[i].initrd_path);
        s[i].cmdline   = xstrdup(e[i].cmdline);
        s[i].chain     = xstrdup(e[i].chainload_path);
        s[i].iso_label = xstrdup(e[i].iso_label);
        s[i].subvol    = xstrdup(e[i].subvol);
        s[i].kver      = xstrdup(e[i].kernel_hash);
        s[i].iver      = xstrdup(e[i].initrd_hash);
        s[i].cver      = xstrdup(e[i].chainload_hash);
        s[i].is_chainload = e[i].is_chainload;
        s[i].is_iso       = e[i].is_iso_boot;
        s[i].hidden       = e[i].hidden;
        s[i].timeout      = e[i].timeout;
    }
    *count = n;
    return s;
}

static void snapshot_free(snap_t *s, int n)
{
    for (int i = 0; i < n; i++) {
        free(s[i].name); free(s[i].kernel); free(s[i].initrd);
        free(s[i].cmdline); free(s[i].chain); free(s[i].iso_label);
        free(s[i].subvol); free(s[i].kver); free(s[i].iver); free(s[i].cver);
    }
    free(s);
}

static int entry_files(const snap_t *e, file_ref_t refs[2])
{
    if (e->is_chainload) {
        refs[0] = (file_ref_t){ "cver", e->chain, e->cver };
        return 1;
    }
    int n = 0;
    refs[n++] = (file_ref_t){ "kver", e->kernel, e->kver };
    if (e->initrd && e->initrd[0])
        refs[n++] = (file_ref_t){ "iver", e->initrd, e->iver };
    return n;
}

static int add_iso(opts_t *o, const char *path)
{
    if (o->n_isos >= MAX_ISOS) {
        fprintf(stderr, "ivo: too many --iso (max %d)\n", MAX_ISOS);
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0) {
        fprintf(stderr, "ivo: %s: %s\n", path,
                fd < 0 ? strerror(errno) : "not a regular file");
        if (fd >= 0) close(fd);
        return -1;
    }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) {
        fprintf(stderr, "ivo: %s: mmap: %s\n", path, strerror(errno));
        return -1;
    }
    iso_image_t *img = &o->isos[o->n_isos];
    img->path = path;
    img->map  = m;
    img->size = (size_t)st.st_size;
    if (ivo_iso_volume_id(img->map, img->size, img->label,
                          sizeof(img->label)) != 0) {
        fprintf(stderr, "ivo: %s: not an ISO9660 image\n", path);
        munmap(m, img->size);
        return -1;
    }
    o->n_isos++;
    return 0;
}

static int hash_ref(const opts_t *o, const snap_t *e, const char *path,
                    char hex[IVO_HASH_HEX_LEN + 1], char *err, size_t err_size)
{
    if (e->is_iso) {
        if (e->subvol && e->subvol[0]) {
            snprintf(err, err_size, "iso-boot entry with subvol: the ISO9660 "
                     "driver has no subvolumes, the bootloader cannot boot it");
            return -1;
        }
        const char *why = ivo_boot_path_problem(path);
        if (why) { snprintf(err, err_size, "%s", why); return -1; }
        for (int i = 0; i < o->n_isos; i++) {
            if (strcmp(o->isos[i].label, e->iso_label) != 0) continue;
            uint8_t *data = NULL;
            size_t len = 0;
            if (ivo_iso_read_file(o->isos[i].map, o->isos[i].size, path,
                                  &data, &len) != 0) {
                snprintf(err, err_size, "not found in %s", o->isos[i].path);
                return -1;
            }
            ivo_sha512_hex(data, len, hex);
            free(data);
            return 0;
        }
        snprintf(err, err_size, "iso-boot entry: pass --iso IMAGE for the "
                 "ISO volume labelled '%s'", e->iso_label);
        return -1;
    }

    const char *root = o->root;
    const char *sub  = NULL;
    if (e->subvol && e->subvol[0]) {
        root = o->subvol_root ? o->subvol_root : o->root;
        sub  = e->subvol;
    }
    int fd = ivo_open_beneath(root, sub, path, err, err_size);
    if (fd < 0) return -1;
    int rc = ivo_sha512_fd(fd, hex);
    if (rc != 0) snprintf(err, err_size, "read: %s", strerror(errno));
    close(fd);
    return rc;
}

static void describe(const opts_t *o, const snap_t *e, const char *path,
                     char *out, size_t out_size)
{
    if (e->is_iso)
        snprintf(out, out_size, "iso:%s:%s", e->iso_label, path);
    else if (e->subvol && e->subvol[0])
        snprintf(out, out_size, "%s/%s%s",
                 o->subvol_root ? o->subvol_root : o->root, e->subvol, path);
    else if (strcmp(o->root, "/") == 0)
        snprintf(out, out_size, "%s", path);
    else
        snprintf(out, out_size, "%s%s", o->root, path);
}

typedef struct {
    const char *start;
    size_t      len;
    size_t      full;
    int         has_nl;
    int         crlf;
    int         kind;
    int         section;
} line_t;

enum { LINE_BLANK, LINE_SECTION, LINE_KEY, LINE_HASHKEY };

static line_t *split_lines(const char *d, size_t n, int *count)
{
    size_t cap = 64;
    int cnt = 0;
    line_t *v = malloc(cap * sizeof(*v));
    if (!v) return NULL;
    int section = -1;

    size_t pos = 0;
    while (pos < n) {
        if ((size_t)cnt == cap) {
            cap *= 2;
            line_t *nv = realloc(v, cap * sizeof(*v));
            if (!nv) { free(v); return NULL; }
            v = nv;
        }
        line_t *l = &v[cnt++];
        l->start = d + pos;
        const char *nl = memchr(d + pos, '\n', n - pos);
        size_t end = nl ? (size_t)(nl - d) : n;
        l->len = end - pos;
        l->has_nl = nl != NULL;
        l->crlf = l->has_nl && l->len > 0 && l->start[l->len - 1] == '\r';
        if (l->crlf) l->len--;
        l->full = (nl ? end + 1 : end) - pos;
        pos += l->full;

        const char *p = l->start, *e = l->start + l->len;
        while (p < e && (*p == ' ' || *p == '\t')) p++;
        if (p == e || *p == '#') {
            l->kind = LINE_BLANK;
        } else if (*p == '[') {
            l->kind = LINE_SECTION;
            section++;
        } else {
            const char *k = p;
            while (p < e && *p != '=' && *p != ' ' && *p != '\t') p++;
            size_t kl = (size_t)(p - k);
            int is_hash = section >= 0 && kl == 4 &&
                (memcmp(k, "kver", 4) == 0 || memcmp(k, "iver", 4) == 0 ||
                 memcmp(k, "cver", 4) == 0);
            l->kind = is_hash ? LINE_HASHKEY : LINE_KEY;
        }
        l->section = section;
    }
    *count = cnt;
    return v;
}

static int is_version_line(const line_t *l)
{
    if (l->section != -1) return 0;
    if (l->kind != LINE_KEY) return 0;
    const char *p = l->start;
    const char *e = l->start + l->len;
    while (p < e && (*p == ' ' || *p == '\t')) p++;
    if (e - p < 7) return 0;
    if (memcmp(p, "version", 7) != 0) return 0;
    p += 7;
    while (p < e && (*p == ' ' || *p == '\t')) p++;
    return p < e && *p == '=';
}

static char *sig_path_for(const char *cfg_path)
{
    char *p = NULL;
    if (asprintf(&p, "%s.sig", cfg_path) < 0) {
        fprintf(stderr, "ivo: out of memory\n");
        exit(1);
    }
    return p;
}

static int load_secret_key(const char *path,
                           uint8_t pub[ED25519_PUBLIC_KEY_SIZE],
                           uint8_t expanded[ED25519_EXPANDED_KEY_SIZE])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "ivo: %s: %s\n", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != SEC_KEY_LEN) {
        fprintf(stderr, "ivo: %s: not a %d-byte key file\n",
                path, SEC_KEY_LEN);
        close(fd);
        return -1;
    }
    if (st.st_mode & 077)
        fprintf(stderr, "ivo: warning: %s is accessible by group/others "
                "(mode %03o); chmod 600 it\n", path, (unsigned)(st.st_mode & 0777));

    uint8_t key[SEC_KEY_LEN];
    size_t got = 0;
    while (got < sizeof(key)) {
        ssize_t r = read(fd, key + got, sizeof(key) - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got != sizeof(key)) {
        fprintf(stderr, "ivo: %s: short read\n", path);
        ivo_wipe(key, sizeof(key));
        return -1;
    }

    uint8_t derived[ED25519_PUBLIC_KEY_SIZE];
    ed25519_create_keypair(derived, expanded, key);
    if (memcmp(derived, key + 32, ED25519_PUBLIC_KEY_SIZE) == 0) {
        memcpy(pub, derived, ED25519_PUBLIC_KEY_SIZE);
        ivo_wipe(key, sizeof(key));
        return 0;
    }
    ivo_wipe(expanded, ED25519_EXPANDED_KEY_SIZE);

    int legacy = 0;
    if ((key[32] & 7) == 0 && (key[63] & 0xC0) == 0x40) {
        ge_p3 A;
        uint8_t check[32];
        ge_scalarmult_base(&A, key + 32);
        ge_p3_tobytes(check, &A);
        legacy = memcmp(check, key, 32) == 0;
        ivo_wipe(&A, sizeof(A));
    }
    ivo_wipe(key, sizeof(key));

    if (legacy) {
        fprintf(stderr,
            "ivo: %s: written by an older ivo keygen (public||scalar).\n"
            "  Treat this key as compromised and rotate it:\n"
            "    1. ivo key gen --out-prefix NEWKEY\n"
            "    2. cp NEWKEY.h src/uefi/security/secure_boot_pubkey.h\n"
            "    3. rebuild ivo.efi (make SECURE_BOOT=1 ...), sbctl sign -s\n"
            "    4. ivo config sign --key NEWKEY.sec\n"
            "    5. destroy the old .sec\n", path);
    } else {
        fprintf(stderr, "ivo: %s: public key half does not match the seed\n",
                path);
    }
    return -1;
}

static int cmd_config_hash(int argc, char **argv)
{
    const char *cfg_path = NULL;
    opts_t o;
    memset(&o, 0, sizeof(o));

    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "-v") == 0)             o.verbose = 1;
        else if (strcmp(argv[i], "--no-bump") == 0)      o.no_bump = 1;
        else if (strcmp(argv[i], "--config") == 0 && v)  cfg_path = argv[++i];
        else if (strcmp(argv[i], "--root") == 0 && v)    o.root = argv[++i];
        else if (strcmp(argv[i], "--subvol-root") == 0 && v) o.subvol_root = argv[++i];
        else if (strcmp(argv[i], "--iso") == 0 && v) {
            if (add_iso(&o, argv[++i]) != 0) return 1;
        }
        else {
            fprintf(stderr, "usage: ivo config hash --config CFG [--root DIR] "
                    "[--subvol-root DIR] [--iso IMG]... [-v] [--no-bump]\n");
            return 1;
        }
    }
    if (!cfg_path) {
        fprintf(stderr, "usage: ivo config hash --config CFG [--root DIR] "
                "[--subvol-root DIR] [--iso IMG]... [-v] [--no-bump]\n");
        return 1;
    }
    if (!o.root) o.root = "/";

    uint8_t *cfg = NULL;
    size_t cfg_len = 0;
    if (read_config(cfg_path, &cfg, &cfg_len) != 0) return 1;
    if (parse_config(cfg_path, cfg, cfg_len) != 0) { free(cfg); return 1; }

    int n = 0;
    snap_t *s = snapshot(&n);

    typedef struct { char kver[129], iver[129], cver[129]; } want_t;
    want_t *want = calloc((size_t)n, sizeof(*want));
    if (!want) { fprintf(stderr, "ivo: out of memory\n"); return 1; }

    int failed = 0;
    int changed = 0;
    for (int i = 0; i < n; i++) {
        file_ref_t refs[2];
        int nr = entry_files(&s[i], refs);
        for (int r = 0; r < nr; r++) {
            char hex[IVO_HASH_HEX_LEN + 1], err[512], where[1024];
            describe(&o, &s[i], refs[r].path, where, sizeof(where));
            if (hash_ref(&o, &s[i], refs[r].path, hex, err, sizeof(err)) != 0) {
                fprintf(stderr, "ivo: [%s] %s: %s\n",
                        s[i].name, where, err);
                failed = 1;
                continue;
            }
            char *dst = refs[r].key[0] == 'k' ? want[i].kver :
                        refs[r].key[0] == 'i' ? want[i].iver : want[i].cver;
            memcpy(dst, hex, sizeof(hex));
            if (!refs[r].recorded || strcmp(hex, refs[r].recorded) != 0)
                changed = 1;
            if (o.verbose) printf("[%s] %s = %s\n", s[i].name, refs[r].key, where);
        }
    }
    if (failed) {
        fprintf(stderr,
            "ivo: %s: not modified\n"
            "\n"
            "  One or more files referenced by the config could not be hashed.\n"
            "  The config on disk is now stale relative to the filesystem.\n"
            "  Fix by:\n"
            "\n"
            "    ivo config hash --config %s --root <root>\n"
            "\n", cfg_path, cfg_path);
        snapshot_free(s, n); free(want); free(cfg);
        return 1;
    }
    if (!changed) {
        printf("%s: unchanged (%d entr%s)\n", cfg_path, n,
               n == 1 ? "y" : "ies");
        snapshot_free(s, n); free(want); free(cfg);
        return 0;
    }

    int old_ver = config_get_version();
    int bump = 0;
    int is_initial = (old_ver < 0);
    if (!o.no_bump) {
        if (is_initial) {
            bump = 1;
        } else if (isatty(STDIN_FILENO)) {
            fprintf(stderr, "bump config version %d -> %d? [Y/n] ",
                    old_ver, old_ver + 1);
            fflush(stderr);
            char ans[8];
            if (!fgets(ans, sizeof(ans), stdin) ||
                (ans[0] != 'n' && ans[0] != 'N'))
                bump = 1;
        } else {
            bump = 1;
        }
    }

    int nl_count = 0;
    line_t *lines = split_lines((const char *)cfg, cfg_len, &nl_count);
    if (!lines) { fprintf(stderr, "ivo: out of memory\n"); return 1; }

    int *insert_after = malloc((size_t)n * sizeof(int));
    if (!insert_after) { fprintf(stderr, "ivo: out of memory\n"); return 1; }
    for (int i = 0; i < n; i++) insert_after[i] = -1;
    for (int li = 0; li < nl_count; li++) {
        int sec = lines[li].section;
        if (sec < 0 || sec >= n) continue;
        if (lines[li].kind == LINE_SECTION || lines[li].kind == LINE_KEY)
            insert_after[sec] = li;
    }

    ivo_buf_t out = {0};
    if (bump)
        ivo_buf_printf(&out, "version = %d\n", old_ver + 1);
    for (int li = 0; li < nl_count; li++) {
        const line_t *l = &lines[li];
        if (l->kind == LINE_HASHKEY) continue;
        if (bump && is_version_line(l)) continue;
        ivo_buf_append(&out, l->start, l->full);

        int sec = l->section;
        if (sec < 0 || sec >= n || insert_after[sec] != li) continue;
        const char *eol = l->crlf ? "\r\n" : "\n";
        if (!l->has_nl) ivo_buf_puts(&out, eol);
        if (s[sec].is_chainload) {
            ivo_buf_printf(&out, "cver = \"%s\"%s", want[sec].cver, eol);
        } else {
            ivo_buf_printf(&out, "kver = \"%s\"%s", want[sec].kver, eol);
            if (s[sec].initrd && s[sec].initrd[0])
                ivo_buf_printf(&out, "iver = \"%s\"%s", want[sec].iver, eol);
        }
    }
    free(lines);
    free(insert_after);
    if (out.failed) { fprintf(stderr, "ivo: out of memory\n"); return 1; }

    int ok = 1;
    if (out.len > CONFIG_MAX) {
        fprintf(stderr, "ivo: result exceeds the bootloader's 64 KiB config\n");
        ok = 0;
    } else if (config_parse(out.p, out.len) != 0) {
        fprintf(stderr, "ivo: internal error: rewritten config does not parse "
                "(line %d)\n", config_error_line());
        ok = 0;
    } else {
        int n2 = 0;
        entry_t *e = config_get_entries(&n2);
        if (bump && config_get_version() != old_ver + 1) ok = 0;
        if (n2 != n) ok = 0;
        for (int i = 0; ok && i < n; i++) {
            ok = str_eq(e[i].name, s[i].name) &&
                 str_eq(e[i].kernel_path, s[i].kernel) &&
                 str_eq(e[i].initrd_path, s[i].initrd) &&
                 str_eq(e[i].cmdline, s[i].cmdline) &&
                 str_eq(e[i].chainload_path, s[i].chain) &&
                 str_eq(e[i].iso_label, s[i].iso_label) &&
                 str_eq(e[i].subvol, s[i].subvol) &&
                 e[i].is_chainload == s[i].is_chainload &&
                 e[i].is_iso_boot == s[i].is_iso &&
                 e[i].hidden == s[i].hidden &&
                 e[i].timeout == s[i].timeout &&
                 config_entry_hashes_complete(&e[i]);
            if (!ok) break;
            if (s[i].is_chainload) {
                ok = str_eq(e[i].chainload_hash, want[i].cver) &&
                     !(e[i].kernel_hash && e[i].kernel_hash[0]);
            } else {
                ok = str_eq(e[i].kernel_hash, want[i].kver) &&
                     str_eq0(e[i].initrd_hash,
                             s[i].initrd && s[i].initrd[0] ? want[i].iver : NULL) &&
                     !(e[i].chainload_hash && e[i].chainload_hash[0]);
            }
        }
        if (!ok)
            fprintf(stderr, "ivo: internal error: rewritten config does not "
                    "carry the computed hashes\n");
    }

    int rc = 1;
    if (ok) {
        if (ivo_write_file(cfg_path, out.p, out.len, 0644,
                           IVO_WRITE_KEEP_MODE) != 0) {
            fprintf(stderr, "ivo: %s: cannot write: %s\n",
                    cfg_path, strerror(errno));
        } else {
            printf("hashed %s: %d entr%s (%zu bytes)\n", cfg_path, n,
                   n == 1 ? "y" : "ies", out.len);
            if (is_initial)
                printf("  initialized version = 0 "
                       "(rollback protection starts here)\n");
            else if (bump)
                printf("  bumped version %d -> %d\n", old_ver, old_ver + 1);
            rc = 0;
        }
    } else {
        fprintf(stderr, "ivo: %s: not modified\n", cfg_path);
    }

    ivo_buf_free(&out);
    snapshot_free(s, n);
    free(want);
    free(cfg);
    return rc;
}

static int cmd_config_check(int argc, char **argv)
{
    const char *cfg_path = NULL;
    opts_t o;
    memset(&o, 0, sizeof(o));

    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "-v") == 0)             o.verbose = 1;
        else if (strcmp(argv[i], "--config") == 0 && v)  cfg_path = argv[++i];
        else if (strcmp(argv[i], "--root") == 0 && v)    o.root = argv[++i];
        else if (strcmp(argv[i], "--subvol-root") == 0 && v) o.subvol_root = argv[++i];
        else if (strcmp(argv[i], "--iso") == 0 && v) {
            if (add_iso(&o, argv[++i]) != 0) return 1;
        }
        else {
            fprintf(stderr, "usage: ivo config check --config CFG [--root DIR] "
                    "[--subvol-root DIR] [--iso IMG]... [-v]\n");
            return 1;
        }
    }
    if (!cfg_path) {
        fprintf(stderr, "usage: ivo config check --config CFG [--root DIR] "
                "[--subvol-root DIR] [--iso IMG]... [-v]\n");
        return 1;
    }
    if (!o.root) o.root = "/";

    uint8_t *cfg = NULL;
    size_t cfg_len = 0;
    if (read_config(cfg_path, &cfg, &cfg_len) != 0) return 1;
    if (parse_config(cfg_path, cfg, cfg_len) != 0) { free(cfg); return 1; }
    free(cfg);

    int n = 0;
    snap_t *s = snapshot(&n);
    int n_ok = 0, n_bad = 0, n_missing = 0, n_nohash = 0;

    for (int i = 0; i < n; i++) {
        file_ref_t refs[2];
        int nr = entry_files(&s[i], refs);
        for (int r = 0; r < nr; r++) {
            char where[1024], hex[IVO_HASH_HEX_LEN + 1], err[512];
            describe(&o, &s[i], refs[r].path, where, sizeof(where));
            if (!refs[r].recorded || !refs[r].recorded[0]) {
                printf("[%s] %s: NO-HASH (no %s; the bootloader refuses "
                       "this entry under SECURE_BOOT)\n",
                       s[i].name, where, refs[r].key);
                n_nohash++;
                continue;
            }
            if (hash_ref(&o, &s[i], refs[r].path, hex, err, sizeof(err)) != 0) {
                printf("[%s] %s: MISSING (%s)\n", s[i].name, where, err);
                n_missing++;
                continue;
            }
            if (strcmp(hex, refs[r].recorded) != 0) {
                printf("[%s] %s: MISMATCH (%s)\n", s[i].name, where, refs[r].key);
                n_bad++;
                continue;
            }
            if (o.verbose) printf("[%s] %s: OK\n", s[i].name, where);
            n_ok++;
        }
    }
    snapshot_free(s, n);

    printf("\n%d OK, %d mismatch, %d missing, %d no-hash\n",
           n_ok, n_bad, n_missing, n_nohash);
    return (n_bad || n_missing || n_nohash) ? 1 : 0;
}

static int cmd_config_sign(int argc, char **argv)
{
    const char *cfg_path = NULL;
    const char *key_path = NULL;

    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "--config") == 0 && v) cfg_path = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && v)    key_path = argv[++i];
        else {
            fprintf(stderr, "usage: ivo config sign --config CFG --key KEY.sec\n");
            return 1;
        }
    }
    if (!cfg_path || !key_path) {
        fprintf(stderr, "usage: ivo config sign --config CFG --key KEY.sec\n");
        return 1;
    }

    uint8_t *cfg = NULL;
    size_t cfg_len = 0;
    if (read_config(cfg_path, &cfg, &cfg_len) != 0) return 1;
    if (parse_config(cfg_path, cfg, cfg_len) != 0) {
        fprintf(stderr, "ivo: refusing to sign\n");
        free(cfg);
        return 1;
    }

    int n = 0;
    entry_t *e = config_get_entries(&n);
    int incomplete = 0;
    for (int i = 0; i < n; i++) {
        if (!config_entry_hashes_complete(&e[i])) {
            fprintf(stderr, "ivo: [%s] is missing %s\n", e[i].name,
                    e[i].is_chainload ? "cver" :
                    (!e[i].kernel_hash || !e[i].kernel_hash[0]) ? "kver" : "iver");
            incomplete = 1;
        }
    }
    if (incomplete) {
        fprintf(stderr, "ivo: refusing to sign: every entry needs the "
                "hash of every file it boots (run `ivo config hash` first)\n");
        free(cfg);
        return 1;
    }

    uint8_t pub[ED25519_PUBLIC_KEY_SIZE];
    uint8_t expanded[ED25519_EXPANDED_KEY_SIZE];
    if (load_secret_key(key_path, pub, expanded) != 0) {
        free(cfg);
        return 1;
    }

    uint8_t sig[ED25519_SIGNATURE_SIZE];
    ed25519_sign(sig, cfg, cfg_len, pub, expanded);
    ivo_wipe(expanded, sizeof(expanded));

    if (!ed25519_verify(sig, cfg, cfg_len, pub)) {
        fprintf(stderr, "ivo: internal error: signature does not verify; "
                "nothing written\n");
        free(cfg);
        return 1;
    }

    char *sig_path = sig_path_for(cfg_path);
    if (ivo_write_file(sig_path, sig, sizeof(sig), 0644, 0) != 0) {
        fprintf(stderr, "ivo: %s: cannot write: %s\n",
                sig_path, strerror(errno));
        free(sig_path); free(cfg);
        return 1;
    }
    printf("signed %s -> %s\n", cfg_path, sig_path);
    free(sig_path);
    free(cfg);
    return 0;
}

static int cmd_config_verify(int argc, char **argv)
{
    const char *cfg_path = NULL;
    const char *pub_path = NULL;

    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "--config") == 0 && v) cfg_path = argv[++i];
        else if (strcmp(argv[i], "--pub") == 0 && v)    pub_path = argv[++i];
        else {
            fprintf(stderr, "usage: ivo config verify --config CFG --pub KEY.pub\n");
            return 1;
        }
    }
    if (!cfg_path || !pub_path) {
        fprintf(stderr, "usage: ivo config verify --config CFG --pub KEY.pub\n");
        return 1;
    }

    uint8_t *cfg = NULL, *pub = NULL, *sig = NULL;
    size_t cfg_len = 0, pub_len = 0, sig_len = 0;

    if (read_config(cfg_path, &cfg, &cfg_len) != 0) return 1;
    if (ivo_read_file(pub_path, 64, &pub, &pub_len) != 0 ||
        pub_len != ED25519_PUBLIC_KEY_SIZE) {
        fprintf(stderr, "ivo: %s: public key must be 32 bytes\n", pub_path);
        free(pub); free(cfg);
        return 1;
    }

    char *sig_path = sig_path_for(cfg_path);
    if (ivo_read_file(sig_path, 128, &sig, &sig_len) != 0 ||
        sig_len != ED25519_SIGNATURE_SIZE) {
        fprintf(stderr, "ivo: %s: signature must be 64 bytes\n", sig_path);
        free(sig); free(sig_path); free(cfg); free(pub);
        return 1;
    }
    free(sig_path);

    int ok = ed25519_verify(sig, cfg, cfg_len, pub);
    free(pub); free(sig);
    if (!ok) {
        free(cfg);
        printf("%s: INVALID\n", cfg_path);
        return 1;
    }

    int rc = 0;
    if (parse_config(cfg_path, cfg, cfg_len) != 0) {
        printf("%s: signature OK, but the config does not parse\n", cfg_path);
        rc = 1;
    } else {
        int n = 0;
        entry_t *e = config_get_entries(&n);
        for (int i = 0; i < n; i++)
            if (!config_entry_hashes_complete(&e[i]))
                printf("%s: warning: [%s] lacks hashes; the bootloader will "
                       "refuse it\n", cfg_path, e[i].name);
        printf("%s: OK\n", cfg_path);
    }
    free(cfg);
    return rc;
}

static int has_flag(const char *flags, const char *name)
{
    size_t nlen = strlen(name);
    const char *p = flags;
    while (*p) {
        const char *end = p;
        while (*end && *end != ' ') end++;
        size_t n = (size_t)(end - p);
        if (n == nlen && strncmp(p, name, nlen) == 0) return 1;
        while (*end == ' ') end++;
        p = end;
    }
    return 0;
}

static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int cmd_status(int argc, char **argv)
{
    const char *esp_override = NULL;
    const char *efi_override = NULL;
    const char *boot = "/boot";
    int build_host = 0;

    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "--esp") == 0 && v)  esp_override = argv[++i];
        else if (strcmp(argv[i], "--efi") == 0 && v)  efi_override = argv[++i];
        else if (strcmp(argv[i], "--boot") == 0 && v) boot = argv[++i];
        else if (strcmp(argv[i], "--build-host") == 0) build_host = 1;
        else {
            fprintf(stderr,
                "usage: ivo status [--esp DIR] [--efi PATH] [--boot DIR]\n"
                "                  [--build-host]\n"
                "\n"
                "  --esp DIR      EFI system partition mount point (default: detected)\n"
                "  --efi PATH     ivo.efi to inspect (default: <esp>/EFI/ivo/ivo.efi\n"
                "                 or <esp>/EFI/BOOT/BOOTX64.EFI)\n"
                "  --boot DIR     boot filesystem mount point for config lookup\n"
                "                 (default: /boot)\n"
                "  --build-host   suppress \"no config\" inconsistency (config will\n"
                "                 be added later; use when inspecting a prepared ESP)\n");
            return 1;
        }
    }

    char esp[PATH_MAX];
    if (esp_override) {
        snprintf(esp, sizeof(esp), "%s", esp_override);
    } else if (ivo_find_esp(esp, sizeof(esp)) != 0) {
        fprintf(stderr, "ivo: no EFI system partition found\n");
        fprintf(stderr, "  pass --esp DIR if the ESP is mounted somewhere unusual\n");
        return 1;
    }
    printf("ESP: %s\n", esp);

    char efi_path[PATH_MAX];
    int have_efi = 0;
    if (efi_override) {
        snprintf(efi_path, sizeof(efi_path), "%s", efi_override);
        have_efi = 1;
    } else {
        static const char *candidates[] = {
            "EFI/ivo/ivo.efi",
            "EFI/BOOT/BOOTX64.EFI",
        };
        for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
            int k = snprintf(efi_path, sizeof(efi_path), "%s/%s",
                             esp, candidates[i]);
            if (k < 0 || (size_t)k >= sizeof(efi_path)) continue;
            if (file_exists(efi_path)) { have_efi = 1; break; }
        }
    }
    if (!have_efi || !file_exists(efi_path)) {
        printf("ivo.efi: not found\n");
        printf("  looked at: %s/EFI/ivo/ivo.efi\n", esp);
        printf("             %s/EFI/BOOT/BOOTX64.EFI\n", esp);
        return 1;
    }
    printf("ivo.efi: %s\n", efi_path);

    char flags[256];
    if (ivo_read_efi_flags(efi_path, flags, sizeof(flags)) != 0) {
        printf("  flags: cannot read (not a build of ivo.efi?)\n");
        return 1;
    }
    if (flags[0])
        printf("  flags: %s\n", flags);
    else
        printf("  flags: (none — plain bootloader, no LUKS/TPM/SB)\n");

    int has_tpm = has_flag(flags, "TPM");
    int has_sb  = has_flag(flags, "SECURE_BOOT");

    int inconsistent = 0;

    char esp_cfg[PATH_MAX], root_cfg[PATH_MAX], boot_cfg[PATH_MAX], cfg_path[PATH_MAX] = "";
    int n = snprintf(esp_cfg, sizeof(esp_cfg), "%s/ivo/config.toml", esp);
    if (n < 0 || (size_t)n >= sizeof(esp_cfg)) {
        fprintf(stderr, "ivo: ESP path too long\n");
        return 1;
    }
    n = snprintf(root_cfg, sizeof(root_cfg), "/ivo/config.toml");
    if (n < 0 || (size_t)n >= sizeof(root_cfg)) return 1;
    n = snprintf(boot_cfg, sizeof(boot_cfg), "%s/ivo/config.toml", boot);
    if (n < 0 || (size_t)n >= sizeof(boot_cfg)) {
        fprintf(stderr, "ivo: boot path too long\n");
        return 1;
    }

    const char *cfg_where = NULL;
    if (file_exists(root_cfg)) {
        snprintf(cfg_path, sizeof(cfg_path), "%s", root_cfg);
        cfg_where = "root filesystem";
    } else if (file_exists(esp_cfg)) {
        snprintf(cfg_path, sizeof(cfg_path), "%s", esp_cfg);
        cfg_where = "ESP";
    } else if (file_exists(boot_cfg) && strcmp(boot_cfg, root_cfg) != 0) {
        snprintf(cfg_path, sizeof(cfg_path), "%s", boot_cfg);
        cfg_where = "boot filesystem";
    }

    if (!cfg_where) {
        printf("config: not found\n");
        printf("  looked at: %s\n", root_cfg);
        printf("             %s\n", esp_cfg);
        printf("             %s\n", boot_cfg);
        if (!build_host) inconsistent = 1;
    } else {
        printf("config: %s (on %s)\n", cfg_path, cfg_where);

        char sig_path[PATH_MAX];
        n = snprintf(sig_path, sizeof(sig_path), "%s.sig", cfg_path);
        int have_sig = (n > 0 && (size_t)n < sizeof(sig_path) &&
                        file_exists(sig_path));

        uint8_t *cfg = NULL;
        size_t cfg_len = 0;
        int parsed = 0;
        if (ivo_read_file(cfg_path, 64u << 20, &cfg, &cfg_len) == 0) {
            if (config_parse((const char *)cfg, cfg_len) == 0) {
                parsed = 1;
                int n_entries = 0;
                config_get_entries(&n_entries);
                printf("  version: %d\n", config_get_version());
                printf("  entries: %d\n", n_entries);
            } else {
                printf("  parse: FAILED at line %d\n", config_error_line());
                inconsistent = 1;
            }
            free(cfg);
        } else {
            printf("  parse: cannot read: %s\n", strerror(errno));
            inconsistent = 1;
        }

        printf("  signature: %s\n", have_sig ? "present" : "MISSING");

        if (has_sb && !have_sig) {
            printf("  WARNING: binary has SECURE_BOOT but config is unsigned\n");
            inconsistent = 1;
        }
        if (!has_sb && have_sig) {
            printf("  WARNING: binary lacks SECURE_BOOT but config is signed\n");
            inconsistent = 1;
        }
        if (has_sb && parsed) {
            int n_entries = 0;
            entry_t *e = config_get_entries(&n_entries);
            for (int i = 0; i < n_entries; i++) {
                if (!config_entry_hashes_complete(&e[i])) {
                    printf("  WARNING: entry '%s' lacks a required hash\n", e[i].name);
                    inconsistent = 1;
                }
            }
        }
    }

    char sealed_path[PATH_MAX];
    n = snprintf(sealed_path, sizeof(sealed_path),
                 "%s/EFI/ivo/sealed.bin", esp);
    int have_sealed = (n > 0 && (size_t)n < sizeof(sealed_path) &&
                       file_exists(sealed_path));
    if (have_sealed)
        printf("tpm seal: %s\n", sealed_path);
    else
        printf("tpm seal: not present\n");

    if (have_sealed && !has_tpm) {
        printf("  WARNING: sealed.bin exists but binary lacks TPM support\n");
        inconsistent = 1;
    }
    if (!have_sealed && has_tpm) {
        printf("  note: TPM compiled in but no seal enrolled\n");
        printf("        enroll via /EFI/ivo/seal-request on next boot\n");
    }

    char req_path[PATH_MAX];
    n = snprintf(req_path, sizeof(req_path), "%s/EFI/ivo/seal-request", esp);
    if (n > 0 && (size_t)n < sizeof(req_path) && file_exists(req_path))
        printf("seal-request: %s\n", req_path);

    if (inconsistent) {
        printf("\nresult: INCONSISTENT — see warnings above\n");
        return 1;
    }
    printf("\nresult: OK\n");
    return 0;
}

static int read_password_line(char *buf, size_t cap)
{
    if (!isatty(STDIN_FILENO)) {
        if (!fgets(buf, (int)cap, stdin)) return -1;
        size_t n = strlen(buf);
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
        return (int)n;
    }

    struct termios old, raw;
    if (tcgetattr(STDIN_FILENO, &old) != 0) return -1;
    raw = old;
    raw.c_lflag &= ~(tcflag_t)ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) return -1;

    int rc = -1;
    size_t n = 0;
    for (;;) {
        char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r <= 0) goto out;
        if (c == '\n') break;
        if (n + 1 < cap) buf[n++] = c;
    }
    buf[n] = 0;
    rc = (int)n;
out:
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fputc('\n', stderr);
    return rc;
}

static int cmd_key_password_hash(int argc, char **argv)
{
    int iter = 200000;
    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if (strcmp(argv[i], "--iterations") == 0 && v) {
            iter = atoi(argv[++i]);
            if (iter < 10000 || iter > 10000000) {
                fprintf(stderr, "ivo: iterations out of range\n");
                return 1;
            }
        } else {
            fprintf(stderr, "usage: ivo key password-hash [--iterations N]\n");
            return 1;
        }
    }

    char pass[256];
    fprintf(stderr, "Password: ");
    int n = read_password_line(pass, sizeof(pass));
    if (n <= 0) {
        fprintf(stderr, "ivo: empty or unreadable password\n");
        return 1;
    }

    uint8_t salt[16];
    if (getrandom(salt, sizeof(salt), 0) != (ssize_t)sizeof(salt)) {
        fprintf(stderr, "ivo: entropy source failed\n");
        ivo_wipe(pass, sizeof(pass));
        return 1;
    }

    uint8_t hash[32];
    if (pbkdf2_hmac_sha256((const uint8_t *)pass, (size_t)n,
                           salt, sizeof(salt), (uint32_t)iter,
                           hash, sizeof(hash)) != 0) {
        fprintf(stderr, "ivo: pbkdf2 failed\n");
        ivo_wipe(pass, sizeof(pass));
        return 1;
    }
    ivo_wipe(pass, sizeof(pass));

    printf("pbkdf2-sha256:%d:", iter);
    for (size_t i = 0; i < sizeof(salt); i++) printf("%02x", salt[i]);
    printf(":");
    for (size_t i = 0; i < sizeof(hash); i++) printf("%02x", hash[i]);
    printf("\n");

    ivo_wipe(salt, sizeof(salt));
    ivo_wipe(hash, sizeof(hash));
    return 0;
}

static char *with_suffix(const char *prefix, const char *suffix)
{
    size_t a = strlen(prefix), b = strlen(suffix);
    char *p = malloc(a + b + 1);
    if (!p) { fprintf(stderr, "ivo: out of memory\n"); exit(1); }
    memcpy(p, prefix, a);
    memcpy(p + a, suffix, b + 1);
    return p;
}

static int cmd_key_gen(int argc, char **argv)
{
    const char *prefix = NULL;
    int force = 0;
    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "--out-prefix") == 0 && v) prefix = argv[++i];
        else if (strcmp(argv[i], "--force") == 0)           force = 1;
        else {
            fprintf(stderr, "usage: ivo key gen --out-prefix DIR/NAME [--force]\n");
            return 1;
        }
    }
    if (!prefix || !prefix[0]) {
        fprintf(stderr, "usage: ivo key gen --out-prefix DIR/NAME [--force]\n");
        return 1;
    }

    char *path_pub = with_suffix(prefix, ".pub");
    char *path_sec = with_suffix(prefix, ".sec");
    char *path_h   = with_suffix(prefix, ".h");

    if (!force) {
        const char *paths[] = { path_sec, path_pub, path_h };
        for (int i = 0; i < 3; i++) {
            struct stat st;
            if (lstat(paths[i], &st) == 0) {
                fprintf(stderr, "ivo: %s exists; refusing to overwrite "
                        "(use --force to replace)\n", paths[i]);
                return 1;
            }
        }
    }

    uint8_t seed[ED25519_SEED_SIZE];
    uint8_t pub[ED25519_PUBLIC_KEY_SIZE];
    uint8_t expanded[ED25519_EXPANDED_KEY_SIZE];
    uint8_t sec[ED25519_SEED_SIZE + ED25519_PUBLIC_KEY_SIZE];

    if (ed25519_create_seed(seed) != 0) {
        fprintf(stderr, "ivo: seed generation failed\n");
        return 1;
    }
    ed25519_create_keypair(pub, expanded, seed);
    memcpy(sec, seed, ED25519_SEED_SIZE);
    memcpy(sec + ED25519_SEED_SIZE, pub, ED25519_PUBLIC_KEY_SIZE);

    {
        static const uint8_t msg[] = "ivo-keygen self-test";
        uint8_t sig[ED25519_SIGNATURE_SIZE];
        ed25519_sign(sig, msg, sizeof(msg), pub, expanded);
        int ok = ed25519_verify(sig, msg, sizeof(msg), pub);
        ivo_wipe(expanded, sizeof(expanded));
        ivo_wipe(seed, sizeof(seed));
        if (!ok) {
            ivo_wipe(sec, sizeof(sec));
            fprintf(stderr, "ivo: internal error: self-test failed\n");
            return 1;
        }
    }

    int flags = force ? 0 : IVO_WRITE_NOCLOBBER;

    int rc = ivo_write_file(path_sec, sec, sizeof(sec), 0600, flags);
    int err = errno;
    ivo_wipe(sec, sizeof(sec));
    if (rc != 0) {
        fprintf(stderr, "ivo: %s: %s\n", path_sec, strerror(err));
        return 1;
    }

    if (ivo_write_file(path_pub, pub, sizeof(pub), 0644, flags) != 0) {
        fprintf(stderr, "ivo: %s: %s\n", path_pub, strerror(errno));
        return 1;
    }

    ivo_buf_t h = {0};
    ivo_buf_puts(&h, "/* Generated by ivo key gen. Do not edit. */\n"
                     "#ifndef IVO_SECURE_BOOT_PUBKEY_H\n"
                     "#define IVO_SECURE_BOOT_PUBKEY_H\n\n"
                     "#include <stdint.h>\n\n"
                     "static const uint8_t ivo_pubkey[32] = {\n    ");
    for (int i = 0; i < 32; i++) {
        ivo_buf_printf(&h, "0x%02x", pub[i]);
        if (i < 31) ivo_buf_puts(&h, ", ");
        if ((i + 1) % 8 == 0 && i < 31) ivo_buf_puts(&h, "\n    ");
    }
    ivo_buf_puts(&h, "\n};\n\n#endif\n");
    if (h.failed || ivo_write_file(path_h, h.p, h.len, 0644, flags) != 0) {
        fprintf(stderr, "ivo: %s: %s\n", path_h,
                h.failed ? "out of memory" : strerror(errno));
        ivo_buf_free(&h);
        return 1;
    }
    ivo_buf_free(&h);

    printf("wrote %s\n", path_pub);
    printf("wrote %s  (KEEP SECRET)\n", path_sec);
    printf("wrote %s\n", path_h);
    free(path_pub);
    free(path_sec);
    free(path_h);
    return 0;
}

#define GEN_MAX_FILES  1024
#define GEN_MAX_NAME   256

typedef struct {
    char kernel[GEN_MAX_NAME];
    char initrd[GEN_MAX_NAME];
    char version[GEN_MAX_NAME];
    char entry[GEN_MAX_NAME];
} gen_pair_t;

static const char *gen_kernel_prefixes[] = {
    "vmlinuz-generic-", "vmlinuz-huge-", "vmlinuz.efi-",
    "vmlinuz-", "kernel-", "bzImage-", "Image-",
    NULL
};

static const char *gen_initrd_prefixes[] = {
    "initramfs-", "initrd.img-", "initrd-", "initramfs.", "initrd.",
    NULL
};

static const char *gen_initrd_exts[] = {
    ".img", ".gz", ".xz", ".zst", ".lz4", ".bz2", ".lzma", ".lzo",
    ".efi", ".signed",
    NULL
};

static int gen_strip_prefix(const char *name, const char *prefix,
                            char *out, size_t out_size)
{
    size_t plen = strlen(prefix);
    if (strncmp(name, prefix, plen) != 0) return 0;
    const char *rest = name + plen;
    if (*rest == '\0') return 0;
    size_t n = strlen(rest);
    if (n >= out_size) n = out_size - 1;
    memcpy(out, rest, n);
    out[n] = '\0';
    return 1;
}

static int gen_kernel_version(const char *name, char *out, size_t out_size)
{
    for (int i = 0; gen_kernel_prefixes[i]; i++)
        if (gen_strip_prefix(name, gen_kernel_prefixes[i], out, out_size))
            return 0;
    return -1;
}

static int gen_initrd_version(const char *name, char *out, size_t out_size)
{
    for (int i = 0; gen_initrd_prefixes[i]; i++) {
        char tmp[GEN_MAX_NAME];
        if (!gen_strip_prefix(name, gen_initrd_prefixes[i], tmp, sizeof(tmp)))
            continue;
        int changed = 1;
        while (changed) {
            changed = 0;
            for (int j = 0; gen_initrd_exts[j]; j++) {
                size_t elen = strlen(gen_initrd_exts[j]);
                size_t tlen = strlen(tmp);
                if (tlen > elen &&
                    strcmp(tmp + tlen - elen, gen_initrd_exts[j]) == 0) {
                    tmp[tlen - elen] = '\0';
                    changed = 1;
                    break;
                }
            }
        }
        size_t n = strlen(tmp);
        if (n >= out_size) n = out_size - 1;
        memcpy(out, tmp, n);
        out[n] = '\0';
        return 0;
    }
    return -1;
}

static int gen_versions_match(const char *kv, const char *iv)
{
    if (strcmp(kv, iv) == 0) return 1;
    size_t klen = strlen(kv), ilen = strlen(iv);
    if (klen > ilen && kv[ilen] == '-' && strncmp(kv, iv, ilen) == 0) return 1;
    if (ilen > klen && iv[klen] == '-' && strncmp(kv, iv, klen) == 0) return 1;
    return 0;
}

static int gen_pair_cmp(const void *a, const void *b)
{
    const gen_pair_t *pa = a, *pb = b;
    int c = strverscmp(pb->version, pa->version);
    return c ? c : strcmp(pa->kernel, pb->kernel);
}

static int gen_name_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int gen_join_path(char *out, size_t out_size, const char *prefix,
                         const char *name)
{
    size_t pl = strlen(prefix);
    while (pl > 0 && prefix[pl - 1] == '/') pl--;
    int n = snprintf(out, out_size, "%.*s/%s", (int)pl, prefix, name);
    return (n < 0 || (size_t)n >= out_size) ? -1 : 0;
}

static int cmd_config_generate(int argc, char **argv)
{
    const char *boot_dir = "/boot";
    const char *prefix = NULL;
    const char *output = NULL;
    const char *default_name = NULL;
    const char *options = "";
    unsigned long timeout = 5;

    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "-o")            == 0 && v) output = argv[++i];
        else if (strcmp(argv[i], "--boot")        == 0 && v) boot_dir = argv[++i];
        else if (strcmp(argv[i], "--path-prefix") == 0 && v) prefix = argv[++i];
        else if (strcmp(argv[i], "--default")     == 0 && v) default_name = argv[++i];
        else if (strcmp(argv[i], "--options")     == 0 && v) options = argv[++i];
        else if (strcmp(argv[i], "--timeout")     == 0 && v) {
            if (ivo_parse_uint(argv[++i], 86400, &timeout) != 0) {
                fprintf(stderr, "ivo: --timeout: expected 0..86400\n");
                return 1;
            }
        }
        else {
            fprintf(stderr, "ivo: config generate: unknown argument: %s\n", argv[i]);
            return 1;
        }
    }
    int detect_prefix = (prefix == NULL);
    if (!prefix) prefix = boot_dir;
    if (prefix[0] != '/') {
        fprintf(stderr, "ivo: path prefix must be absolute: %s\n", prefix);
        return 1;
    }

    /* If --path-prefix wasn't passed, detect: if boot_dir is a mount
     * point, paths are relative to /; if it's a directory inside the
     * root, paths are relative to /boot (or wherever boot_dir is). */
    if (detect_prefix) {
        char parent[PATH_MAX];
        snprintf(parent, sizeof(parent), "%s/..", boot_dir);
        char rp_boot[PATH_MAX], rp_parent[PATH_MAX];
        if (realpath(boot_dir, rp_boot) && realpath(parent, rp_parent)) {
            struct stat sb_boot, sb_parent;
            if (stat(rp_boot, &sb_boot) == 0 && stat(rp_parent, &sb_parent) == 0) {
                if (sb_boot.st_dev != sb_parent.st_dev) {
                    prefix = "/";
                }
            }
        }
    }

    DIR *d = opendir(boot_dir);
    if (!d) {
        fprintf(stderr, "ivo: %s: %s\n", boot_dir, strerror(errno));
        return 1;
    }

    char **names = calloc(GEN_MAX_FILES, sizeof(char *));
    if (!names) { closedir(d); return 1; }
    int n_names = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strlen(ent->d_name) >= GEN_MAX_NAME) continue;
        struct stat st;
        if (fstatat(dirfd(d), ent->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
            continue;
        if (S_ISLNK(st.st_mode)) {
            char kv[GEN_MAX_NAME];
            if (gen_kernel_version(ent->d_name, kv, sizeof(kv)) == 0)
                fprintf(stderr, "ivo: skipping symlink %s/%s\n",
                        boot_dir, ent->d_name);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;
        if (n_names >= GEN_MAX_FILES) break;
        names[n_names] = strdup(ent->d_name);
        if (!names[n_names]) { closedir(d); return 1; }
        n_names++;
    }
    closedir(d);

    if (n_names == 0) {
        fprintf(stderr, "ivo: %s: no files found\n", boot_dir);
        return 1;
    }
    qsort(names, (size_t)n_names, sizeof(char *), gen_name_cmp);

    gen_pair_t *pairs = calloc((size_t)n_names, sizeof(gen_pair_t));
    if (!pairs) return 1;
    int n_pairs = 0;

    for (int i = 0; i < n_names; i++) {
        char kver[GEN_MAX_NAME];
        if (gen_kernel_version(names[i], kver, sizeof(kver)) != 0) continue;

        gen_pair_t *p = &pairs[n_pairs];
        snprintf(p->kernel, sizeof(p->kernel), "%s", names[i]);
        snprintf(p->version, sizeof(p->version), "%s", kver);
        p->initrd[0] = '\0';
        for (int pass = 0; pass < 2 && !p->initrd[0]; pass++) {
            for (int j = 0; j < n_names; j++) {
                char iver[GEN_MAX_NAME];
                if (gen_initrd_version(names[j], iver, sizeof(iver)) != 0) continue;
                if (pass == 0 ? strcmp(kver, iver) == 0
                              : gen_versions_match(kver, iver)) {
                    snprintf(p->initrd, sizeof(p->initrd), "%s", names[j]);
                    break;
                }
            }
        }
        n_pairs++;
    }

    if (n_pairs == 0) {
        fprintf(stderr, "ivo: %s: no kernels found\n", boot_dir);
        return 1;
    }

    qsort(pairs, (size_t)n_pairs, sizeof(gen_pair_t), gen_pair_cmp);

    if (n_pairs > IVO_CFG_MAX_ENTRIES) {
        fprintf(stderr, "ivo: %d kernels found; keeping newest %d\n",
                n_pairs, IVO_CFG_MAX_ENTRIES);
        n_pairs = IVO_CFG_MAX_ENTRIES;
    }

    for (int i = 0; i < n_pairs; i++) {
        if (ivo_entry_name(pairs[i].version, pairs[i].entry,
                           sizeof(pairs[i].entry)) != 0) {
            fprintf(stderr, "ivo: %s: cannot derive an entry name\n",
                    pairs[i].kernel);
            return 1;
        }
        for (int j = 0; j < i; j++) {
            if (strcmp(pairs[i].entry, pairs[j].entry) == 0) {
                fprintf(stderr, "ivo: %s and %s both map to '%s'\n",
                        pairs[j].kernel, pairs[i].kernel, pairs[i].entry);
                return 1;
            }
        }
    }

    int default_idx = 0;
    if (default_name) {
        default_idx = -1;
        for (int i = 0; i < n_pairs; i++)
            if (strcmp(pairs[i].entry, default_name) == 0) { default_idx = i; break; }
        if (default_idx < 0) {
            fprintf(stderr, "ivo: --default %s: no such entry\n", default_name);
            return 1;
        }
    }

    ivo_buf_t o = {0};
    const char *why = NULL;
    ivo_buf_puts(&o, "# Generated by ivo config generate.\n");
    ivo_buf_puts(&o, "# Run `ivo config hash` to fill the kver/iver fields.\n\n");
    ivo_buf_printf(&o, "timeout = %lu\n", timeout);
    why = ivo_toml_kv(&o, "default", pairs[default_idx].entry);
    ivo_buf_puts(&o, "\n");

    for (int i = 0; i < n_pairs && !why; i++) {
        char path[4096];
        ivo_buf_printf(&o, "[entries.%s]\n", pairs[i].entry);

        if (gen_join_path(path, sizeof(path), prefix, pairs[i].kernel) != 0) {
            why = "path too long";
            break;
        }
        if ((why = ivo_boot_path_problem(path)) ||
            (why = ivo_toml_kv(&o, "kernel", path)))
            break;
        if (pairs[i].initrd[0]) {
            if (gen_join_path(path, sizeof(path), prefix, pairs[i].initrd) != 0) {
                why = "path too long";
                break;
            }
            if ((why = ivo_boot_path_problem(path)) ||
                (why = ivo_toml_kv(&o, "initrd", path)))
                break;
        } else {
            fprintf(stderr, "ivo: warning: no initrd found for %s\n",
                    pairs[i].kernel);
        }
        if (options[0] && (why = ivo_toml_kv(&o, "options", options)))
            break;
        ivo_buf_puts(&o, "\n");
    }
    if (why) {
        fprintf(stderr, "ivo: %s\n", why);
        return 1;
    }
    if (o.failed) {
        fprintf(stderr, "ivo: out of memory\n");
        return 1;
    }

    if (config_parse(o.p, o.len) != 0) {
        fprintf(stderr, "ivo: internal error: generated config does not "
                "parse (line %d)\n", config_error_line());
        return 1;
    }
    int n_parsed = 0;
    config_get_entries(&n_parsed);
    entry_t *def = config_get_default();
    if (n_parsed != n_pairs || !def ||
        strcmp(def->name, pairs[default_idx].entry) != 0) {
        fprintf(stderr, "ivo: internal error: round-trip failed\n");
        return 1;
    }

    int rc;
    if (output) {
        rc = ivo_write_file(output, o.p, o.len, 0644, IVO_WRITE_KEEP_MODE);
        if (rc != 0)
            fprintf(stderr, "ivo: %s: %s\n", output, strerror(errno));
    } else {
        rc = ivo_write_stdout(o.p, o.len);
        if (rc != 0) fprintf(stderr, "ivo: write error on stdout\n");
    }
    ivo_buf_free(&o);
    for (int i = 0; i < n_names; i++) free(names[i]);
    free(names);
    free(pairs);
    return rc == 0 ? 0 : 1;
}

#define CONV_MAX_ENTRIES  64
#define CONV_MAX_LINE     4096
#define CONV_MAX_INPUT    (1 << 20)

typedef struct {
    char name[CONV_MAX_LINE];
    char kernel[CONV_MAX_LINE];
    char initrd[CONV_MAX_LINE];
    char options[CONV_MAX_LINE];
    char type[32];
    char path[CONV_MAX_LINE];
    int  timeout;
    int  hidden;
    int  line;
} conv_entry_t;

typedef enum { DEF_NONE, DEF_INDEX0, DEF_INDEX1, DEF_TITLE, DEF_SUBSTR } def_kind_t;

typedef struct {
    conv_entry_t entries[CONV_MAX_ENTRIES];
    int          count;
    char         default_name[CONV_MAX_LINE];
    def_kind_t   default_kind;
    int          timeout;
} conv_config_t;

static int conv_read_input(const char *path, char **buf, size_t *len)
{
    uint8_t *b = NULL;
    int rc;
    if (strcmp(path, "-") == 0)
        rc = ivo_read_fd(STDIN_FILENO, CONV_MAX_INPUT, &b, len);
    else
        rc = ivo_read_file(path, CONV_MAX_INPUT, &b, len);
    if (rc != 0) return -1;
    if (memchr(b, '\0', *len)) { free(b); errno = EINVAL; return -1; }
    *buf = (char *)b;
    return 0;
}

static char *conv_trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' ||
                     e[-1] == '\r' || e[-1] == '\n')) e--;
    *e = '\0';
    return s;
}

static void conv_copy_str(char *dst, const char *src, size_t dst_size)
{
    if (dst_size == 0) return;
    size_t i = 0;
    while (i + 1 < dst_size && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

static const char *conv_next_line(const char *p, char *line, size_t line_size,
                                  const char *fname, int lineno)
{
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    if (len >= line_size) {
        fprintf(stderr, "%s:%d: line longer than %zu bytes\n",
                fname, lineno, line_size - 1);
        return NULL;
    }
    memcpy(line, p, len);
    line[len] = '\0';
    return nl ? nl + 1 : p + len;
}

static int conv_parse_timeout(const char *val, conv_config_t *c,
                              const char *fname, int lineno)
{
    unsigned long t;
    if (ivo_parse_uint(val, 86400, &t) != 0) {
        fprintf(stderr, "%s:%d: warning: timeout '%s' ignored\n",
                fname, lineno, val);
        return 0;
    }
    c->timeout = (int)t;
    return 0;
}

static void conv_set_default(conv_config_t *c, const char *val,
                             def_kind_t numeric, def_kind_t text)
{
    unsigned long dummy;
    conv_copy_str(c->default_name, val, sizeof(c->default_name));
    c->default_kind = ivo_parse_uint(val, 1000, &dummy) == 0 ? numeric : text;
}

static conv_entry_t *conv_new_entry(conv_config_t *c, const char *fname, int lineno)
{
    if (c->count >= CONV_MAX_ENTRIES) {
        fprintf(stderr, "%s:%d: too many entries\n", fname, lineno);
        return NULL;
    }
    conv_entry_t *e = &c->entries[c->count++];
    memset(e, 0, sizeof(*e));
    e->timeout = -1;
    e->line = lineno;
    return e;
}

static int conv_read_quoted(const char **p, char *out, size_t out_size)
{
    if (**p != '"' && **p != '\'') return -1;
    char q = *(*p)++;
    const char *s = *p;
    size_t j = 0;
    while (*s && *s != q) {
        if (j + 1 >= out_size) return -1;
        out[j++] = *s;
        s++;
    }
    if (*s != q) return -1;
    out[j] = '\0';
    *p = s + 1;
    return 0;
}

static int conv_read_token(const char **p, char *out, size_t out_size)
{
    while (**p == ' ' || **p == '\t') (*p)++;
    const char *s = *p;
    size_t j = 0;
    while (*s && *s != ' ' && *s != '\t' && *s != '\n' && *s != '\r') {
        if (j + 1 >= out_size) return -1;
        out[j++] = *s;
        s++;
    }
    out[j] = '\0';
    *p = s;
    return j > 0 ? 0 : -1;
}

static int conv_only_space(const char *p)
{
    while (*p == ' ' || *p == '\t') p++;
    return *p == '\0';
}

static int conv_pull_initrd(char *options, char *initrd_out, size_t initrd_size)
{
    char *p = options;
    while (*p) {
        while (*p == ' ') p++;
        char *tok = p;
        while (*p && *p != ' ') p++;
        size_t tl = (size_t)(p - tok);
        if (tl > 7 && strncmp(tok, "initrd=", 7) == 0) {
            size_t vl = tl - 7;
            if (vl >= initrd_size) vl = initrd_size - 1;
            memcpy(initrd_out, tok + 7, vl);
            initrd_out[vl] = '\0';
            memmove(tok, p, strlen(p) + 1);
            while (*tok == ' ') memmove(tok, tok + 1, strlen(tok));
            return 1;
        }
    }
    return 0;
}

static int conv_parse_grub(const char *src, conv_config_t *c, const char *fname)
{
    int lineno = 0;
    const char *p = src;
    conv_entry_t *cur = NULL;

    while (*p) {
        lineno++;
        char line[CONV_MAX_LINE];
        p = conv_next_line(p, line, sizeof(line), fname, lineno);
        if (!p) return -1;

        char *l = conv_trim(line);
        if (*l == '\0' || *l == '#') continue;

        static const char *refuse[] = {
            "submenu", "if ", "if(", "elif", "else", "fi",
            "for ", "while ", "function ", "configfile", "source ", NULL
        };
        for (int i = 0; refuse[i]; i++) {
            size_t rl = strlen(refuse[i]);
            if (strncmp(l, refuse[i], rl) != 0) continue;
            if (refuse[i][rl - 1] == ' ' || l[rl] == ' ' || l[rl] == '\0' ||
                l[rl] == '{' || l[rl] == '(') {
                fprintf(stderr, "%s:%d: refusing GRUB construct: %s\n",
                        fname, lineno, l);
                return -1;
            }
        }

        if (strchr(l, '$')) {
            fprintf(stderr, "%s:%d: variable expansion not supported\n",
                    fname, lineno);
            return -1;
        }

        if (strncmp(l, "set ", 4) == 0) {
            char *rest = conv_trim(l + 4);
            char *eq = strchr(rest, '=');
            if (eq) {
                *eq = '\0';
                char *key = conv_trim(rest);
                char *val = conv_trim(eq + 1);
                char unq[CONV_MAX_LINE];
                if (val[0] == '"' || val[0] == '\'') {
                    const char *vp = val;
                    if (conv_read_quoted(&vp, unq, sizeof(unq)) != 0 ||
                        !conv_only_space(vp)) {
                        fprintf(stderr, "%s:%d: bad quoted value\n", fname, lineno);
                        return -1;
                    }
                    val = unq;
                }
                if (strcmp(key, "default") == 0) {
                    if (strcmp(val, "saved") == 0)
                        fprintf(stderr, "%s:%d: default=saved not supported\n",
                                fname, lineno);
                    else
                        conv_set_default(c, val, DEF_INDEX0, DEF_TITLE);
                } else if (strcmp(key, "timeout") == 0) {
                    conv_parse_timeout(val, c, fname, lineno);
                }
            }
            continue;
        }

        if (strncmp(l, "menuentry ", 10) == 0) {
            const char *mp = l + 10;
            while (*mp == ' ' || *mp == '\t') mp++;
            char name[CONV_MAX_LINE];
            if (*mp == '"' || *mp == '\'') {
                if (conv_read_quoted(&mp, name, sizeof(name)) != 0) {
                    fprintf(stderr, "%s:%d: unterminated menuentry\n", fname, lineno);
                    return -1;
                }
            } else if (conv_read_token(&mp, name, sizeof(name)) != 0) {
                fprintf(stderr, "%s:%d: empty menuentry\n", fname, lineno);
                return -1;
            }
            int start = lineno;
            if (!strchr(mp, '{')) {
                while (*p) {
                    lineno++;
                    char l2[CONV_MAX_LINE];
                    const char *np = conv_next_line(p, l2, sizeof(l2), fname, lineno);
                    if (!np) return -1;
                    p = np;
                    if (strchr(l2, '{')) break;
                }
            }
            cur = conv_new_entry(c, fname, start);
            if (!cur) return -1;
            conv_copy_str(cur->name, name, sizeof(cur->name));
            continue;
        }

        if (strcmp(l, "}") == 0) { cur = NULL; continue; }

        if (cur) {
            if (strncmp(l, "linux ", 6) == 0 || strncmp(l, "linuxefi ", 9) == 0) {
                const char *kp = strchr(l, ' ') + 1;
                char path[CONV_MAX_LINE];
                if (conv_read_token(&kp, path, sizeof(path)) == 0) {
                    conv_copy_str(cur->kernel, path, sizeof(cur->kernel));
                    while (*kp == ' ' || *kp == '\t') kp++;
                    conv_copy_str(cur->options, kp, sizeof(cur->options));
                    char *oe = cur->options + strlen(cur->options);
                    while (oe > cur->options &&
                           (oe[-1] == ' ' || oe[-1] == '\t')) *--oe = '\0';
                }
                continue;
            }
            if (strncmp(l, "initrd ", 7) == 0 || strncmp(l, "initrdefi ", 10) == 0) {
                const char *ip = strchr(l, ' ') + 1;
                char path[CONV_MAX_LINE];
                if (conv_read_token(&ip, path, sizeof(path)) == 0) {
                    if (!conv_only_space(ip)) {
                        fprintf(stderr, "%s:%d: more than one initrd not supported\n",
                                fname, lineno);
                        return -1;
                    }
                    conv_copy_str(cur->initrd, path, sizeof(cur->initrd));
                }
                continue;
            }
            if (strncmp(l, "chainloader ", 12) == 0) {
                const char *cp = l + 12;
                char path[CONV_MAX_LINE];
                if (conv_read_token(&cp, path, sizeof(path)) == 0) {
                    conv_copy_str(cur->path, path, sizeof(cur->path));
                    conv_copy_str(cur->type, "efi-chainload", sizeof(cur->type));
                }
                continue;
            }
        }
    }

    for (int i = 0; i < c->count; i++) {
        conv_entry_t *e = &c->entries[i];
        if (e->kernel[0] && !e->initrd[0])
            conv_pull_initrd(e->options, e->initrd, sizeof(e->initrd));
    }
    return 0;
}

static void conv_strip_limine_prefix(const char *in, char *out, size_t out_size)
{
    const char *p = in;
    if      (strncmp(p, "boot:///", 8) == 0) p += 7;
    else if (strncmp(p, "boot://",  7) == 0) p += 6;
    else if (strncmp(p, "boot():/", 8) == 0) p += 7;
    else if (strncmp(p, "boot():",  7) == 0) p += 6;
    else if (strncmp(p, "boot(",    5) == 0) {
        const char *close = strchr(p, ')');
        if (close && close[1] == ':') p = close + 2;
    }
    conv_copy_str(out, p, out_size);
}

static int conv_limine_module(conv_entry_t *cur, const char *val,
                              const char *fname, int lineno)
{
    if (cur->initrd[0]) {
        fprintf(stderr, "%s:%d: more than one module not supported\n",
                fname, lineno);
        return -1;
    }
    conv_strip_limine_prefix(val, cur->initrd, sizeof(cur->initrd));
    return 0;
}

static int conv_parse_limine(const char *src, conv_config_t *c, const char *fname)
{
    int is_new = 0;
    {
        const char *p = src;
        while (*p) {
            const char *q = p;
            while (*q == ' ' || *q == '\t') q++;
            if (*q == '/') { is_new = 1; break; }
            if (*q == ':') { is_new = 0; break; }
            const char *nl = strchr(p, '\n');
            if (!nl) break;
            p = nl + 1;
        }
    }

    int lineno = 0;
    const char *p = src;
    conv_entry_t *cur = NULL;

    while (*p) {
        lineno++;
        char line[CONV_MAX_LINE];
        p = conv_next_line(p, line, sizeof(line), fname, lineno);
        if (!p) return -1;

        char *l = conv_trim(line);
        if (*l == '\0' || *l == '#') continue;

        if (strchr(l, '$')) {
            fprintf(stderr, "%s:%d: variable expansion not supported\n",
                    fname, lineno);
            return -1;
        }

        if (is_new) {
            if (*l == '/') {
                if (l[1] == '/') {
                    fprintf(stderr, "%s:%d: sub-entries not supported\n",
                            fname, lineno);
                    return -1;
                }
                const char *nm = l + 1;
                if (*nm == '+') nm++;
                cur = conv_new_entry(c, fname, lineno);
                if (!cur) return -1;
                conv_copy_str(cur->name, nm, sizeof(cur->name));
                continue;
            }
            char *colon = strchr(l, ':');
            if (!colon) continue;
            *colon = '\0';
            char *key = conv_trim(l);
            char *val = conv_trim(colon + 1);
            char val_buf[CONV_MAX_LINE];
            if (val[0] == '"' || val[0] == '\'') {
                const char *vp = val;
                if (conv_read_quoted(&vp, val_buf, sizeof(val_buf)) == 0 &&
                    conv_only_space(vp))
                    val = val_buf;
            }

            if (strcmp(key, "timeout") == 0) {
                if (!cur) conv_parse_timeout(val, c, fname, lineno);
            } else if (strcmp(key, "default_entry") == 0) {
                if (!cur) conv_set_default(c, val, DEF_INDEX1, DEF_TITLE);
            } else if (cur) {
                if (strcmp(key, "protocol") == 0) {
                    if (strcmp(val, "efi_chainload") == 0 ||
                        strcmp(val, "efi") == 0)
                        conv_copy_str(cur->type, "efi-chainload", sizeof(cur->type));
                } else if (strcmp(key, "kernel_path") == 0) {
                    conv_strip_limine_prefix(val, cur->kernel, sizeof(cur->kernel));
                } else if (strcmp(key, "path") == 0) {
                    if (cur->type[0])
                        conv_strip_limine_prefix(val, cur->path, sizeof(cur->path));
                    else
                        conv_strip_limine_prefix(val, cur->kernel, sizeof(cur->kernel));
                } else if (strcmp(key, "cmdline") == 0 ||
                           strcmp(key, "kernel_cmdline") == 0) {
                    conv_copy_str(cur->options, val, sizeof(cur->options));
                } else if (strcmp(key, "module_path") == 0) {
                    if (conv_limine_module(cur, val, fname, lineno) != 0) return -1;
                }
            }
        } else {
            if (*l == ':') {
                if (l[1] == ':') {
                    fprintf(stderr, "%s:%d: sub-entries not supported\n",
                            fname, lineno);
                    return -1;
                }
                cur = conv_new_entry(c, fname, lineno);
                if (!cur) return -1;
                conv_copy_str(cur->name, conv_trim(l + 1), sizeof(cur->name));
                continue;
            }
            char *eq = strchr(l, '=');
            if (!eq) continue;
            *eq = '\0';
            char *key = conv_trim(l);
            char *val = conv_trim(eq + 1);

            if (strcmp(key, "TIMEOUT") == 0) {
                if (!cur) conv_parse_timeout(val, c, fname, lineno);
            } else if (strcmp(key, "DEFAULT_ENTRY") == 0) {
                if (!cur) conv_set_default(c, val, DEF_INDEX1, DEF_TITLE);
            } else if (cur) {
                if (strcmp(key, "PROTOCOL") == 0) {
                    if (strcmp(val, "efi_chainload") == 0)
                        conv_copy_str(cur->type, "efi-chainload", sizeof(cur->type));
                } else if (strcmp(key, "KERNEL_PATH") == 0) {
                    conv_strip_limine_prefix(val, cur->kernel, sizeof(cur->kernel));
                } else if (strcmp(key, "PATH") == 0) {
                    if (cur->type[0])
                        conv_strip_limine_prefix(val, cur->path, sizeof(cur->path));
                    else
                        conv_strip_limine_prefix(val, cur->kernel, sizeof(cur->kernel));
                } else if (strcmp(key, "CMDLINE") == 0 ||
                           strcmp(key, "KERNEL_CMDLINE") == 0) {
                    conv_copy_str(cur->options, val, sizeof(cur->options));
                } else if (strcmp(key, "MODULE_PATH") == 0) {
                    if (conv_limine_module(cur, val, fname, lineno) != 0) return -1;
                }
            }
        }
    }

    for (int i = 0; i < c->count; i++) {
        conv_entry_t *e = &c->entries[i];
        if (e->type[0] && !e->path[0] && e->kernel[0]) {
            conv_copy_str(e->path, e->kernel, sizeof(e->path));
            e->kernel[0] = '\0';
        }
    }
    return 0;
}

static void conv_strip_refind_comment(char *line)
{
    char q = 0;
    for (char *s = line; *s; s++) {
        if (q) { if (*s == q) q = 0; continue; }
        if (*s == '"') { q = *s; continue; }
        if (*s == '#') { *s = '\0'; return; }
    }
}

static int conv_refind_value(const char *vp, char *val, size_t val_size,
                             const char *fname, int lineno)
{
    while (*vp == ' ' || *vp == '\t') vp++;
    if (*vp == '"') {
        if (conv_read_quoted(&vp, val, val_size) != 0 || !conv_only_space(vp)) {
            fprintf(stderr, "%s:%d: bad quoted value\n", fname, lineno);
            return -1;
        }
        return 0;
    }
    conv_copy_str(val, vp, val_size);
    return 0;
}

static int conv_parse_refind(const char *src, conv_config_t *c, const char *fname,
                             const char *kernel_override,
                             const char *initrd_override)
{
    int saw_menuentry = 0;
    int saw_quoted_line = 0;
    {
        const char *p = src;
        while (*p) {
            while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
            if (*p == '#') { while (*p && *p != '\n') p++; continue; }
            if (*p == '\0') break;
            if (strncmp(p, "menuentry", 9) == 0) saw_menuentry = 1;
            if (*p == '"') saw_quoted_line = 1;
            while (*p && *p != '\n') p++;
        }
    }

    if (!saw_menuentry && !saw_quoted_line) {
        fprintf(stderr, "%s: not a rEFInd config\n", fname);
        return -1;
    }

    int is_linux_conf = (!saw_menuentry && saw_quoted_line);
    int lineno = 0;
    const char *p = src;

    if (is_linux_conf) {
        if (!kernel_override) {
            fprintf(stderr, "%s: refind_linux.conf has no kernel path; pass --kernel\n",
                    fname);
            return -1;
        }
        while (*p) {
            lineno++;
            char line[CONV_MAX_LINE];
            p = conv_next_line(p, line, sizeof(line), fname, lineno);
            if (!p) return -1;
            char *l = conv_trim(line);
            if (!*l || *l == '#') continue;
            const char *lp = l;
            char title[CONV_MAX_LINE], opts[CONV_MAX_LINE];
            if (conv_read_quoted(&lp, title, sizeof(title)) != 0) {
                fprintf(stderr, "%s:%d: expected \"title\" \"options\"\n",
                        fname, lineno);
                return -1;
            }
            while (*lp == ' ' || *lp == '\t') lp++;
            if (conv_read_quoted(&lp, opts, sizeof(opts)) != 0) {
                fprintf(stderr, "%s:%d: expected \"title\" \"options\"\n",
                        fname, lineno);
                return -1;
            }
            conv_entry_t *e = conv_new_entry(c, fname, lineno);
            if (!e) return -1;
            conv_copy_str(e->name, title, sizeof(e->name));
            conv_copy_str(e->kernel, kernel_override, sizeof(e->kernel));
            if (initrd_override)
                conv_copy_str(e->initrd, initrd_override, sizeof(e->initrd));
            conv_copy_str(e->options, opts, sizeof(e->options));
        }
        return 0;
    }

    conv_entry_t *cur = NULL;

    while (*p) {
        lineno++;
        char line[CONV_MAX_LINE];
        p = conv_next_line(p, line, sizeof(line), fname, lineno);
        if (!p) return -1;

        conv_strip_refind_comment(line);
        char *l = conv_trim(line);
        if (*l == '\0') continue;

        if (strchr(l, '$')) {
            fprintf(stderr, "%s:%d: variable expansion not supported\n",
                    fname, lineno);
            return -1;
        }

        if (strncmp(l, "submenuentry", 12) == 0) {
            fprintf(stderr, "%s:%d: submenuentry not supported\n", fname, lineno);
            return -1;
        }
        if (strncmp(l, "include ", 8) == 0) {
            fprintf(stderr, "%s:%d: include not supported\n", fname, lineno);
            return -1;
        }

        if (strncmp(l, "timeout ", 8) == 0) {
            conv_parse_timeout(conv_trim(l + 8), c, fname, lineno);
            continue;
        }
        if (strncmp(l, "default_selection ", 18) == 0) {
            const char *dp = l + 18;
            while (*dp == ' ' || *dp == '\t') dp++;
            char name[CONV_MAX_LINE];
            if (*dp == '"' || *dp == '\'') {
                if (conv_read_quoted(&dp, name, sizeof(name)) == 0)
                    conv_set_default(c, name, DEF_INDEX1, DEF_SUBSTR);
            } else if (conv_read_token(&dp, name, sizeof(name)) == 0) {
                conv_set_default(c, name, DEF_INDEX1, DEF_SUBSTR);
            }
            continue;
        }

        if (strncmp(l, "menuentry ", 10) == 0) {
            const char *mp = l + 10;
            while (*mp == ' ' || *mp == '\t') mp++;
            char name[CONV_MAX_LINE];
            if (*mp == '"' || *mp == '\'') {
                if (conv_read_quoted(&mp, name, sizeof(name)) != 0) {
                    fprintf(stderr, "%s:%d: bad menuentry name\n", fname, lineno);
                    return -1;
                }
            } else if (conv_read_token(&mp, name, sizeof(name)) != 0) {
                fprintf(stderr, "%s:%d: empty menuentry\n", fname, lineno);
                return -1;
            }
            cur = conv_new_entry(c, fname, lineno);
            if (!cur) return -1;
            conv_copy_str(cur->name, name, sizeof(cur->name));
            continue;
        }

        if (strcmp(l, "}") == 0) { cur = NULL; continue; }

        if (cur) {
            char val[CONV_MAX_LINE];
            if (strncmp(l, "loader ", 7) == 0) {
                if (conv_refind_value(l + 7, val, sizeof(val), fname, lineno) != 0)
                    return -1;
                size_t vl = strlen(val);
                if (vl > 4 && strcmp(val + vl - 4, ".efi") == 0) {
                    conv_copy_str(cur->path, val, sizeof(cur->path));
                    conv_copy_str(cur->type, "efi-chainload", sizeof(cur->type));
                } else if (vl) {
                    conv_copy_str(cur->kernel, val, sizeof(cur->kernel));
                }
            } else if (strncmp(l, "initrd ", 7) == 0) {
                if (conv_refind_value(l + 7, val, sizeof(val), fname, lineno) != 0)
                    return -1;
                if (val[0]) conv_copy_str(cur->initrd, val, sizeof(cur->initrd));
            } else if (strncmp(l, "options ", 8) == 0) {
                if (conv_refind_value(l + 8, val, sizeof(val), fname, lineno) != 0)
                    return -1;
                if (val[0]) conv_copy_str(cur->options, val, sizeof(cur->options));
            } else if (strcmp(l, "disabled") == 0) {
                cur->hidden = 1;
            }
        }
    }
    return 0;
}

static int conv_resolve_default(const conv_config_t *c, const char *fname)
{
    if (c->default_kind == DEF_NONE) return -1;
    unsigned long idx;
    switch (c->default_kind) {
    case DEF_INDEX0:
    case DEF_INDEX1:
        ivo_parse_uint(c->default_name, 1000, &idx);
        if (c->default_kind == DEF_INDEX1) {
            if (idx == 0) break;
            idx--;
        }
        if (idx < (unsigned long)c->count) return (int)idx;
        break;
    case DEF_TITLE:
        for (int i = 0; i < c->count; i++)
            if (strcmp(c->entries[i].name, c->default_name) == 0) return i;
        break;
    case DEF_SUBSTR:
        for (int i = 0; i < c->count; i++)
            if (strstr(c->entries[i].name, c->default_name)) return i;
        break;
    default:
        break;
    }
    fprintf(stderr, "%s: warning: default '%s' matches no entry\n",
            fname, c->default_name);
    return -1;
}

static int conv_emit(ivo_buf_t *o, const conv_config_t *c, const char *source)
{
    static char names[CONV_MAX_ENTRIES][IVO_CFG_MAX_NAME + 1];
    const char *why = NULL;

    if (c->count > IVO_CFG_MAX_ENTRIES) {
        fprintf(stderr, "%s: %d entries; max is %d\n",
                source, c->count, IVO_CFG_MAX_ENTRIES);
        return -1;
    }

    for (int i = 0; i < c->count; i++) {
        char base[IVO_CFG_MAX_NAME - 8];
        if (ivo_entry_name(c->entries[i].name, base, sizeof(base)) != 0)
            snprintf(base, sizeof(base), "entry");
        snprintf(names[i], sizeof(names[i]), "%s", base);
        for (int n = 2; n <= CONV_MAX_ENTRIES + 1; n++) {
            int dup = 0;
            for (int j = 0; j < i; j++)
                if (strcmp(names[i], names[j]) == 0) { dup = 1; break; }
            if (!dup) break;
            snprintf(names[i], sizeof(names[i]), "%.240s_%d", base, n % 100);
        }
    }

    ivo_buf_puts(o, "# Generated by ivo config convert.\n");
    ivo_buf_puts(o, "# Paths are verbatim from the source; verify with:\n");
    ivo_buf_puts(o, "#     ivo config check --config config.toml --root ROOT\n\n");

    if (c->timeout >= 0)
        ivo_buf_printf(o, "timeout = %d\n", c->timeout);
    int def = conv_resolve_default(c, source);
    if (def >= 0) ivo_toml_kv(o, "default", names[def]);
    ivo_buf_puts(o, "\n");

    for (int i = 0; i < c->count; i++) {
        const conv_entry_t *e = &c->entries[i];
        int chain = e->type[0] && strcmp(e->type, "efi-chainload") == 0;
        const char *what = NULL;

        ivo_buf_printf(o, "[entries.%s]\n", names[i]);

        if (chain) {
            ivo_buf_printf(o, "type = \"%s\"\n", e->type);
            if (!e->path[0]) why = "chainload entry has no loader path";
            else if ((why = ivo_boot_path_problem(e->path)) ||
                     (why = ivo_toml_kv(o, "path", e->path))) {
                what = e->path;
            }
        } else {
            if (!e->kernel[0]) why = "entry has no kernel";
            else if ((why = ivo_boot_path_problem(e->kernel)) ||
                     (why = ivo_toml_kv(o, "kernel", e->kernel))) {
                what = e->kernel;
            } else if (e->initrd[0] &&
                       ((why = ivo_boot_path_problem(e->initrd)) ||
                        (why = ivo_toml_kv(o, "initrd", e->initrd)))) {
                what = e->initrd;
            } else if (e->options[0] &&
                       (why = ivo_toml_kv(o, "options", e->options))) {
                what = "options";
            }
        }
        if (why) {
            fprintf(stderr, "%s:%d: entry '%s': %s%s%s\n", source, e->line,
                    e->name, why, what ? ": " : "", what ? what : "");
            return -1;
        }

        if (e->timeout >= 0)
            ivo_buf_printf(o, "timeout = %d\n", e->timeout);
        if (e->hidden)
            ivo_buf_puts(o, "hidden = true\n");

        ivo_buf_puts(o, "\n");
    }
    if (o->failed) {
        fprintf(stderr, "ivo: out of memory\n");
        return -1;
    }
    return 0;
}

static int cmd_config_convert(int argc, char **argv)
{
    const char *from = NULL;
    const char *input = NULL;
    const char *output = NULL;
    const char *kernel_override = NULL;
    const char *initrd_override = NULL;

    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "--from")   == 0 && v) from = argv[++i];
        else if (strcmp(argv[i], "-o")       == 0 && v) output = argv[++i];
        else if (strcmp(argv[i], "--kernel") == 0 && v) kernel_override = argv[++i];
        else if (strcmp(argv[i], "--initrd") == 0 && v) initrd_override = argv[++i];
        else if (!input) input = argv[i];
        else {
            fprintf(stderr, "ivo: config convert: unexpected arg: %s\n", argv[i]);
            return 1;
        }
    }

    if (!from || !input) {
        fprintf(stderr,
            "usage:\n"
            "  ivo config convert --from grub|limine|refind INPUT [-o OUTPUT]\n"
            "                      [--kernel K] [--initrd I]\n"
            "\n"
            "INPUT may be '-' for stdin.\n");
        return 1;
    }

    char *src = NULL;
    size_t src_len = 0;
    if (conv_read_input(input, &src, &src_len) != 0) {
        fprintf(stderr, "ivo: %s: %s\n", input,
                errno == EINVAL ? "not a text file" : strerror(errno));
        return 1;
    }

    const char *fname = strcmp(input, "-") == 0 ? "<stdin>" : input;

    conv_config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) { free(src); return 1; }
    cfg->timeout = -1;

    int rc;
    if      (strcmp(from, "grub")   == 0) rc = conv_parse_grub(src, cfg, fname);
    else if (strcmp(from, "limine") == 0) rc = conv_parse_limine(src, cfg, fname);
    else if (strcmp(from, "refind") == 0) rc = conv_parse_refind(src, cfg, fname,
                                                                kernel_override,
                                                                initrd_override);
    else {
        fprintf(stderr, "ivo: unknown --from: %s\n", from);
        free(src); free(cfg);
        return 1;
    }
    free(src);

    if (rc != 0) { free(cfg); return 1; }
    if (cfg->count == 0) {
        fprintf(stderr, "ivo: %s: no entries found\n", fname);
        free(cfg);
        return 1;
    }

    ivo_buf_t out = {0};
    if (conv_emit(&out, cfg, fname) != 0) {
        ivo_buf_free(&out); free(cfg);
        return 1;
    }
    free(cfg);

    if (config_parse(out.p, out.len) != 0) {
        fprintf(stderr, "ivo: internal error: generated config does not parse "
                "(line %d)\n", config_error_line());
        ivo_buf_free(&out);
        return 1;
    }

    if (output) {
        rc = ivo_write_file(output, out.p, out.len, 0644, IVO_WRITE_KEEP_MODE);
        if (rc != 0)
            fprintf(stderr, "ivo: %s: %s\n", output, strerror(errno));
    } else {
        rc = ivo_write_stdout(out.p, out.len);
        if (rc != 0) fprintf(stderr, "ivo: write error on stdout\n");
    }
    ivo_buf_free(&out);
    return rc == 0 ? 0 : 1;
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
        fprintf(stderr, "ivo: cannot run %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    int werr = 0;
    if (input) {
        close(pfd[0]);
        size_t len = strlen(input);
        const char *p = input;
        while (len > 0) {
            ssize_t w = write(pfd[1], p, len);
            if (w < 0) {
                if (errno == EINTR) continue;
                werr = 1;
                break;
            }
            p += w;
            len -= (size_t)w;
        }
        close(pfd[1]);
    }

    int status;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && !werr) return 0;
    if (WIFEXITED(status))
        fprintf(stderr, "ivo: %s exited with status %d\n",
                argv[0], WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        fprintf(stderr, "ivo: %s killed by signal %d\n",
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

static int split_disk_part(const char *name, char *disk_out, size_t disk_size,
                           int *part_out)
{
    size_t len = strlen(name);
    size_t i = len;
    while (i > 0 && name[i - 1] >= '0' && name[i - 1] <= '9') i--;
    if (i == len) return -1;

    int part = atoi(name + i);

    size_t disk_len = i;
    if (i > 0 && name[i - 1] == 'p') disk_len = i - 1;
    if (disk_len == 0 || disk_len >= disk_size) return -1;

    memcpy(disk_out, name, disk_len);
    disk_out[disk_len] = '\0';
    *part_out = part;
    return 0;
}

static int esp_device(const char *mount_point, char *disk_out, size_t disk_size,
                      int *part_out)
{
    struct stat st;
    if (stat(mount_point, &st) != 0) {
        fprintf(stderr, "ivo: %s: %s\n", mount_point, strerror(errno));
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "ivo: %s: not a directory\n", mount_point);
        return -1;
    }

    char sys[PATH_MAX], link[PATH_MAX];
    snprintf(sys, sizeof(sys), "/sys/dev/block/%u:%u",
             major(st.st_dev), minor(st.st_dev));
    ssize_t ln = readlink(sys, link, sizeof(link) - 1);
    if (ln <= 0) {
        fprintf(stderr, "ivo: %s: not a block device (tmpfs?)\n", mount_point);
        return -1;
    }
    link[ln] = '\0';
    const char *base = strrchr(link, '/');
    base = base ? base + 1 : link;

    char disk[NAME_MAX + 1];
    int part_no;
    if (split_disk_part(base, disk, sizeof(disk), &part_no) != 0) {
        fprintf(stderr, "ivo: %s: cannot determine disk/partition from '%s'\n",
                mount_point, base);
        return -1;
    }

    snprintf(disk_out, disk_size, "/dev/%s", disk);
    *part_out = part_no;
    return 0;
}

static int confirm(const char *prompt)
{
    fprintf(stderr, "%s [y/N] ", prompt);
    fflush(stderr);
    char line[16];
    if (!fgets(line, sizeof(line), stdin)) return 0;
    return (line[0] == 'y' || line[0] == 'Y') &&
           (line[1] == '\n' || line[1] == '\0');
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

static int read_efi_file(const char *path, uint8_t **out, size_t *len)
{
    if (ivo_read_file(path, 64u << 20, out, len) != 0) {
        fprintf(stderr, "ivo: %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (*len < 2 || (*out)[0] != 'M' || (*out)[1] != 'Z') {
        fprintf(stderr, "ivo: %s: not a PE/COFF image (no MZ header)\n", path);
        free(*out);
        return -1;
    }
    return 0;
}

/* Try to add an NVRAM entry via efibootmgr. Returns 0 on confirmed
 * addition, -1 otherwise.*/
static int add_nvram_entry(const char *esp, const char *efi_rel_path)
{
    char disk[NAME_MAX + 8];
    int part_no;
    if (esp_device(esp, disk, sizeof(disk), &part_no) != 0)
        return -1;

    char win_path[PATH_MAX];
    {
        size_t j = 0;
        win_path[j++] = '\\';
        for (const char *p = efi_rel_path; *p && j + 1 < sizeof(win_path); p++)
            win_path[j++] = (*p == '/') ? '\\' : *p;
        win_path[j] = '\0';
    }

    char part_str[16];
    snprintf(part_str, sizeof(part_str), "%d", part_no);
    {
        FILE *f = popen("efibootmgr 2>/dev/null", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                unsigned boot;
                char label[128];
                if (sscanf(line, "Boot%04X%*c %127[^*]", &boot, label) == 2) {
                    size_t L = strlen(label);
                    while (L > 0 && (label[L-1] == ' ' || label[L-1] == '\t'))
                        label[--L] = '\0';
                    if (strcmp(label, "Ivo") == 0) {
                        char bnum[8];
                        snprintf(bnum, sizeof(bnum), "%04X", boot);
                        char *rm[] = { "efibootmgr", "-b", bnum, "-B", NULL };
                        run_cmd(rm, NULL, 1);
                    }
                }
            }
            pclose(f);
        }
    }

    char *add[] = { "efibootmgr", "-c", "-d", disk, "-p", part_str,
                    "-L", "Ivo", "-l", win_path, NULL };
    if (run_cmd(add, NULL, 1) != 0) {
        fprintf(stderr, "ivo: NVRAM entry was not added (efibootmgr failed)\n");
        fprintf(stderr, "  You can add it from firmware setup:\n");
        fprintf(stderr, "    Boot option: %s on %s partition %d\n",
                win_path, disk, part_no);
        return -1;
    }

    FILE *f = popen("efibootmgr 2>/dev/null", "r");
    if (!f) return -1;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "Ivo") != NULL && strncmp(line, "Boot", 4) == 0) {
            found = 1;
            break;
        }
    }
    pclose(f);
    if (!found) {
        fprintf(stderr, "ivo: NVRAM entry written but does not appear in "
                "efibootmgr output; firmware may have rejected it\n");
        return -1;
    }
    return 0;
}

static int cmd_install_uefi(int argc, char **argv)
{
    const char *esp = NULL;
    const char *efi = "ivo.efi";
    int force = 0;
    int replace_boot = 0;

    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "--esp") == 0 && v)          esp = argv[++i];
        else if (strcmp(argv[i], "--efi") == 0 && v)          efi = argv[++i];
        else if (strcmp(argv[i], "--force") == 0)             force = 1;
        else if (strcmp(argv[i], "--replace-boot") == 0)      replace_boot = 1;
        else {
            fprintf(stderr,
                "usage: ivo install uefi --esp DIR [--efi PATH]\n"
                "                        [--replace-boot] [--force]\n"
                "\n"
                "  --esp DIR         EFI system partition mount point\n"
                "  --efi PATH        ivo.efi to install (default: ivo.efi)\n"
                "  --replace-boot    ALSO replace EFI/BOOT/BOOTX64.EFI.\n"
                "                    Removes the firmware fallback boot path.\n"
                "                    Detects and backs up the original to\n"
                "                    BOOTX64.EFI.bak. Do not use on dual-boot.\n"
                "  --force           overwrite existing ivo.efi\n");
            return 1;
        }
    }

    if (!esp) {
        fprintf(stderr, "usage: ivo install uefi --esp DIR [--efi PATH]\n");
        return 1;
    }

    struct stat st;
    if (stat(esp, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "ivo: %s: not a directory\n", esp);
        return 1;
    }

    uint8_t *src = NULL;
    size_t src_len = 0;
    if (read_efi_file(efi, &src, &src_len) != 0) return 1;

    char flags[256];
    int have_flags = (ivo_read_efi_flags(efi, flags, sizeof(flags)) == 0);
    if (!have_flags) {
        fprintf(stderr, "ivo: warning: %s has no IVO_FLAGS marker\n", efi);
        fprintf(stderr, "  (built by an older tree? rebuild to embed flags)\n");
    } else {
        printf("installing %s\n", efi);
        printf("  flags: %s\n", flags[0] ? flags : "(none)");
    }

    char *ivo_dir = NULL;
    char *ivo_dst = NULL;
    if (asprintf(&ivo_dir, "%s/EFI/ivo", esp) < 0 ||
        asprintf(&ivo_dst, "%s/ivo.efi", ivo_dir) < 0) {
        fprintf(stderr, "ivo: out of memory\n");
        free(ivo_dir);
        free(src);
        return 1;
    }

    struct stat dst_st;
    if (lstat(ivo_dst, &dst_st) == 0 && !force) {
        fprintf(stderr, "ivo: %s exists; use --force to overwrite\n", ivo_dst);
        free(src);
        return 1;
    }

    if (mkdir_p(ivo_dir) != 0) {
        fprintf(stderr, "ivo: %s: cannot create: %s\n",
                ivo_dir, strerror(errno));
        free(src);
        free(ivo_dir);
        free(ivo_dst);
        return 1;
    }

    if (ivo_write_file(ivo_dst, src, src_len, 0644, 0) != 0) {
        fprintf(stderr, "ivo: %s: %s\n", ivo_dst, strerror(errno));
        free(src);
        free(ivo_dir);
        free(ivo_dst);
        return 1;
    }

    printf("  wrote %s (%zu bytes)\n", ivo_dst, src_len);

    int nv_ok = (add_nvram_entry(esp, "/EFI/ivo/ivo.efi") == 0);
    if (nv_ok)
        printf("  added NVRAM entry \"Ivo\"\n");
    else
        printf("  WARNING: no NVRAM entry; add one from firmware setup\n");

    /* Optional: replace BOOTX64.EFI as well. */
    if (replace_boot) {
        char *boot_dir = NULL;
        char *boot_dst = NULL;
        char *boot_bak = NULL;
        if (asprintf(&boot_dir, "%s/EFI/BOOT", esp) < 0 ||
            asprintf(&boot_dst, "%s/BOOTX64.EFI", boot_dir) < 0 ||
            asprintf(&boot_bak, "%s.bak", boot_dst) < 0) {
            fprintf(stderr, "ivo: out of memory\n");
            free(boot_dir);
            free(boot_dst);
            free(boot_bak);
            free(src);
            return 1;
        }

        if (mkdir_p(boot_dir) != 0) {
            fprintf(stderr, "ivo: %s: cannot create: %s\n",
                    boot_dir, strerror(errno));
        } else {
            struct stat bst;
            int have_existing = (lstat(boot_dst, &bst) == 0);
            int existing_is_ivo = 0;
            if (have_existing) {
                char old_flags[256];
                existing_is_ivo = (ivo_read_efi_flags(boot_dst, old_flags,
                                                     sizeof(old_flags)) == 0);
            }

            if (have_existing && !existing_is_ivo && lstat(boot_bak, &bst) != 0) {
                /* Back up the original once. */
                if (rename(boot_dst, boot_bak) != 0) {
                    fprintf(stderr, "ivo: backup %s -> %s: %s\n",
                            boot_dst, boot_bak, strerror(errno));
                } else {
                    printf("  backed up %s -> %s\n", boot_dst, boot_bak);
                }
            } else if (have_existing && !existing_is_ivo &&
                       lstat(boot_bak, &bst) == 0) {
                printf("  WARNING: %s already has a .bak; not overwriting it\n",
                       boot_dst);
            }

            if (ivo_write_file(boot_dst, src, src_len, 0644, 0) != 0) {
                fprintf(stderr, "ivo: %s: %s\n", boot_dst, strerror(errno));
            } else {
                printf("  wrote %s (fallback path)\n", boot_dst);
            }
        }
        free(boot_dir);
        free(boot_dst);
        free(boot_bak);
    }

    free(src);
    free(ivo_dir);
    free(ivo_dst);

    printf("\ninstalled.\n");
    if (!nv_ok) {
        printf("\nNext step: your firmware has no Ivo boot entry.\n");
        printf("  Enter firmware setup and add a boot option for:\n");
        printf("    %s/EFI/ivo/ivo.efi\n", esp);
        printf("  Or run: efibootmgr -c -L Ivo -l '\\\\EFI\\\\ivo\\\\ivo.efi'\n");
    } else {
        printf("Reboot into Ivo to test.\n");
    }
    return 0;
}

#define ISO_SECTOR     2048
#define ISO_MAX_DIR    (1u << 20)
#define MAX_PARTS      128
#define MAX_ISO_ENTRIES 1024

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

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
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
    struct find_dir fd = { .name = "boot", .ok = 0 };
    if (iso_walk(iso, iso->root_lba, iso->root_size, visit_find_dir, &fd) < 0) {
        fprintf(stderr, "ivo: %s: malformed root directory\n", iso_path);
        return -1;
    }
    if (!fd.ok) {
        fprintf(stderr, "ivo: %s: no /boot directory\n", iso_path);
        return -1;
    }

    struct find_boot fb;
    memset(&fb, 0, sizeof(fb));
    if (iso_walk(iso, fd.found.lba, fd.found.size, visit_find_boot, &fb) < 0) {
        fprintf(stderr, "ivo: %s: malformed /boot directory\n", iso_path);
        return -1;
    }
    if (!fb.have_k || !fb.have_i) {
        fprintf(stderr, "ivo: %s: no kernel/initrd found in /boot\n", iso_path);
        return -1;
    }

    iso_rec_t *recs[2] = { &fb.kernel, &fb.initrd };
    for (int i = 0; i < 2; i++) {
        iso_rec_t *r = recs[i];
        if (r->plain)
            for (char *c = r->name; *c; c++)
                if (*c >= 'A' && *c <= 'Z') *c = (char)(*c + 32);
        if (!safe_file_name(r->name)) {
            fprintf(stderr, "ivo: %s: refusing unsafe file name in /boot\n",
                    iso_path);
            return -1;
        }
        if (!iso_extent_ok(iso, r->lba, r->size)) {
            fprintf(stderr, "ivo: %s: /boot/%s points outside the image\n",
                    iso_path, r->name);
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
        if (pread_all(in, buf, want, off) != 0 ||
            write_all(out, buf, want) != 0) {
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

static int resolve_disk(const char *arg, disk_t *d)
{
    memset(d, 0, sizeof(*d));
    if (!realpath(arg, d->path)) {
        fprintf(stderr, "ivo: %s: %s\n", arg, strerror(errno));
        return -1;
    }
    struct stat st;
    if (stat(d->path, &st) != 0) {
        fprintf(stderr, "ivo: %s: %s\n", d->path, strerror(errno));
        return -1;
    }
    if (!S_ISBLK(st.st_mode)) {
        fprintf(stderr, "ivo: %s: not a block device\n", d->path);
        return -1;
    }
    d->rdev = st.st_rdev;

    char sys[PATH_MAX], link[PATH_MAX];
    snprintf(sys, sizeof(sys), "/sys/dev/block/%u:%u",
             major(d->rdev), minor(d->rdev));
    ssize_t ln = readlink(sys, link, sizeof(link) - 1);
    if (ln <= 0) {
        fprintf(stderr, "ivo: %s: not found in sysfs\n", d->path);
        return -1;
    }
    link[ln] = '\0';
    const char *base = strrchr(link, '/');
    snprintf(d->name, sizeof(d->name), "%.255s", base ? base + 1 : link);

    char pfile[PATH_MAX + 16];
    snprintf(pfile, sizeof(pfile), "%s/partition", sys);
    if (access(pfile, F_OK) == 0) {
        fprintf(stderr, "ivo: %s is a partition; pass the whole disk\n", d->path);
        return -1;
    }

    int fd = open(d->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "ivo: %s: %s\n", d->path, strerror(errno));
        return -1;
    }
    int ssz = 0;
    if (ioctl(fd, BLKGETSIZE64, &d->size) != 0 ||
        ioctl(fd, BLKSSZGET, &ssz) != 0 || ssz <= 0) {
        fprintf(stderr, "ivo: %s: cannot query size: %s\n",
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
        fprintf(stderr, "ivo: %s is mounted (%s); unmount it first\n",
                d->path, what);
        return 1;
    }
    if (table_uses("/proc/swaps", devs, np + 1, what, sizeof(what))) {
        fprintf(stderr, "ivo: %s is in use as swap (%s)\n", d->path, what);
        return 1;
    }
    if (holders_nonempty(d->name)) {
        fprintf(stderr, "ivo: %s is held by another device (dm/md/LVM)\n",
                d->path);
        return 1;
    }
    for (int i = 0; i < np; i++) {
        if (holders_nonempty(parts[i].name)) {
            fprintf(stderr, "ivo: %s is held by another device\n", parts[i].name);
            return 1;
        }
    }
    int fd = open(d->path, O_RDONLY | O_EXCL | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "ivo: %s: %s\n", d->path,
                errno == EBUSY ? "device is busy (in use)" : strerror(errno));
        return 1;
    }
    close(fd);
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
                snprintf(p, sizeof(p), "/sys/class/block/%.255s/size",
                         parts[i].name);
                if (read_sysfs(p, buf, sizeof(buf)) != 0) break;
                *size_bytes = strtoull(buf, NULL, 10) * 512ull;
                snprintf(out, out_size, "%s", node);
                return 0;
            }
        }
        sleep_ms(100);
    }
    fprintf(stderr, "ivo: partition %d of %s did not appear\n",
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
        fprintf(stderr, "ivo: BOOTX64.EFI: %s\n", strerror(errno));
        goto out;
    }
    if (create_file(bootdir, kernel->name, NULL, 0, iso, kernel) != 0) {
        fprintf(stderr, "ivo: /boot/%s: %s\n", kernel->name, strerror(errno));
        goto out;
    }
    if (create_file(bootdir, initrd->name, NULL, 0, iso, initrd) != 0) {
        fprintf(stderr, "ivo: /boot/%s: %s\n", initrd->name, strerror(errno));
        goto out;
    }
    if (create_file(ivodir, "config.toml", config, config_len, NULL, NULL) != 0) {
        fprintf(stderr, "ivo: config.toml: %s\n", strerror(errno));
        goto out;
    }
    if (syncfs(root) != 0) goto out;
    rc = 0;
out:
    if (rc != 0 && errno)
        fprintf(stderr, "ivo: ESP: %s\n", strerror(errno));
    if (efidir >= 0) close(efidir);
    if (bootdir >= 0) close(bootdir);
    if (ivodir >= 0) close(ivodir);
    close(root);
    return rc;
}

static int cmd_install_usb(int argc, char **argv)
{
    const char *device = NULL;
    const char *iso_path = NULL;
    const char *efi = "ivo.efi";
    int yes = 0;

    for (int i = 0; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "--device") == 0 && v) device = argv[++i];
        else if (strcmp(argv[i], "--iso") == 0 && v)    iso_path = argv[++i];
        else if (strcmp(argv[i], "--efi") == 0 && v)    efi = argv[++i];
        else if (strcmp(argv[i], "--yes") == 0)         yes = 1;
        else if (strcmp(argv[i], "-y") == 0)            yes = 1;
        else {
            fprintf(stderr,
                "usage: ivo install usb --device DEV --iso IMG\n"
                "                       [--efi PATH] [--yes]\n"
                "\n"
                "  Builds a bootable test USB stick from an ISO. Erases the\n"
                "  target device. Uses EFI/BOOT/BOOTX64.EFI (portable\n"
                "  fallback path) so the stick boots on any UEFI firmware.\n");
            return 1;
        }
    }
    if (!device || !iso_path) {
        fprintf(stderr, "usage: ivo install usb --device DEV --iso IMG "
                "[--efi PATH] [--yes]\n");
        return 1;
    }

    disk_t d;
    if (resolve_disk(device, &d) != 0) return 1;
    if (disk_in_use(&d)) return 1;

    uint8_t *efi_data = NULL;
    size_t efi_len = 0;
    if (read_efi_file(efi, &efi_data, &efi_len) != 0) return 1;

    iso_t iso;
    if (iso_open(iso_path, &iso) != 0) {
        fprintf(stderr, "ivo: %s: not an ISO9660 image\n", iso_path);
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
        fprintf(stderr, "ivo: %s too small for ESP + ISO\n", d.path);
        iso_close(&iso); free(efi_data);
        return 1;
    }
    if ((uint64_t)kernel.size + initrd.size + efi_len >
        esp_bytes - (16ull << 20)) {
        fprintf(stderr, "ivo: kernel + initrd do not fit the ESP\n");
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
        fprintf(stderr, "ivo: config: %s\n", why);
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
        "ivo: about to ERASE and repartition %s%s%s%s (%llu MB)\n"
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
    char mnt[] = "/tmp/ivo-usb.XXXXXX";
    int mounted = 0, have_mnt = 0;
    char esp_part[PATH_MAX], iso_part[PATH_MAX];
    uint64_t esp_size = 0, iso_part_size = 0;

    {
        char *wipefs[] = { "wipefs", "-a", d.path, NULL };
        if (run_cmd(wipefs, NULL, 1) != 0) {
            fprintf(stderr, "ivo: wipefs failed on %s\n", d.path);
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
            fprintf(stderr, "ivo: sfdisk failed on %s\n", d.path);
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
        fprintf(stderr, "ivo: %s smaller than ISO\n", iso_part);
        goto out;
    }

    {
        char *mkfs[] = { "mkfs.vfat", "-F", "32", "-n", "IVO", esp_part, NULL };
        if (run_cmd(mkfs, NULL, 1) != 0) {
            fprintf(stderr, "ivo: mkfs.vfat failed on %s\n", esp_part);
            goto out;
        }
    }

    if (!mkdtemp(mnt)) {
        fprintf(stderr, "ivo: mkdtemp: %s\n", strerror(errno));
        goto out;
    }
    have_mnt = 1;
    if (mount(esp_part, mnt, "vfat", MS_NOSUID | MS_NODEV | MS_NOEXEC, "") != 0) {
        fprintf(stderr, "ivo: mount %s: %s\n", esp_part, strerror(errno));
        goto out;
    }
    mounted = 1;

    if (write_usb_esp(mnt, efi_data, efi_len, &iso, &kernel, &initrd,
                      cfg.p, cfg.len) != 0)
        goto out;

    if (umount2(mnt, 0) != 0) {
        fprintf(stderr, "ivo: umount %s: %s\n", mnt, strerror(errno));
        goto out;
    }
    mounted = 0;

    fprintf(stderr, "ivo: writing ISO to %s\n", iso_part);
    {
        int out_fd = open(iso_part, O_WRONLY | O_EXCL | O_CLOEXEC);
        if (out_fd < 0) {
            fprintf(stderr, "ivo: %s: %s\n", iso_part, strerror(errno));
            goto out;
        }
        int rc = copy_range(iso.fd, 0, iso.size, out_fd);
        if (rc == 0) rc = fsync(out_fd);
        int e = errno;
        if (close(out_fd) != 0 && rc == 0) { rc = -1; e = errno; }
        if (rc != 0) {
            fprintf(stderr, "ivo: writing %s: %s\n", iso_part, strerror(e));
            goto out;
        }
    }
    ok = 1;

out:
    if (mounted && umount2(mnt, 0) != 0)
        fprintf(stderr, "ivo: warning: %s is still mounted\n", mnt);
    else if (have_mnt)
        rmdir(mnt);
    ivo_buf_free(&cfg);
    iso_close(&iso);
    free(efi_data);
    if (!ok) {
        fprintf(stderr, "ivo: USB install FAILED; %s is not usable\n", d.path);
        return 1;
    }
    fprintf(stderr, "ivo: USB ready on %s\n", d.path);
    fprintf(stderr, "  Boot it with Secure Boot off and CSM off.\n");
    return 0;
}

static int dispatch_config(int argc, char **argv)
{
    if (argc == 0) {
        fprintf(stderr, "usage: ivo config <hash|check|sign|verify|generate|convert> ...\n");
        return 1;
    }
    if (strcmp(argv[0], "hash") == 0)     return cmd_config_hash(argc - 1, argv + 1);
    if (strcmp(argv[0], "check") == 0)    return cmd_config_check(argc - 1, argv + 1);
    if (strcmp(argv[0], "sign") == 0)     return cmd_config_sign(argc - 1, argv + 1);
    if (strcmp(argv[0], "verify") == 0)   return cmd_config_verify(argc - 1, argv + 1);
    if (strcmp(argv[0], "generate") == 0) return cmd_config_generate(argc - 1, argv + 1);
    if (strcmp(argv[0], "convert") == 0)  return cmd_config_convert(argc - 1, argv + 1);
    fprintf(stderr, "ivo: unknown config subcommand: %s\n", argv[0]);
    return 1;
}

static int dispatch_key(int argc, char **argv)
{
    if (argc == 0) {
        fprintf(stderr, "usage: ivo key <gen|password-hash> ...\n");
        return 1;
    }
    if (strcmp(argv[0], "gen") == 0)           return cmd_key_gen(argc - 1, argv + 1);
    if (strcmp(argv[0], "password-hash") == 0) return cmd_key_password_hash(argc - 1, argv + 1);
    fprintf(stderr, "ivo: unknown key subcommand: %s\n", argv[0]);
    return 1;
}

static int dispatch_install(int argc, char **argv)
{
    if (argc == 0) {
        fprintf(stderr, "usage: ivo install <uefi|usb> ...\n");
        return 1;
    }
    if (strcmp(argv[0], "uefi") == 0) return cmd_install_uefi(argc - 1, argv + 1);
    if (strcmp(argv[0], "usb") == 0)  return cmd_install_usb(argc - 1, argv + 1);
    fprintf(stderr, "ivo: unknown install target: %s\n", argv[0]);
    return 1;
}

static void usage(void)
{
    fprintf(stderr,
        "usage: ivo <command> [args]\n"
        "\n"
        "  status                              report current Ivo state\n"
        "\n"
        "  key gen          --out-prefix P [--force]\n"
        "  key password-hash [--iterations N]\n"
        "\n"
        "  config generate  ...                emit config.toml from a /boot scan\n"
        "  config hash      --config C --root R [--subvol-root R] [--iso I]... [-v]\n"
        "  config check     --config C --root R [--subvol-root R] [--iso I]... [-v]\n"
        "  config sign      --config C --key K\n"
        "  config verify    --config C --pub P\n"
        "  config convert   ...                convert grub/limine/refind config\n"
        "\n"
        "  install uefi     --esp DIR [--efi PATH] [--force]\n"
        "  install usb      --device DEV --iso IMG [--efi PATH] [--yes]\n");
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2) { usage(); return 1; }

    if (strcmp(argv[1], "status") == 0)  return cmd_status(argc - 2, argv + 2);
    if (strcmp(argv[1], "config") == 0)  return dispatch_config(argc - 2, argv + 2);
    if (strcmp(argv[1], "key") == 0)     return dispatch_key(argc - 2, argv + 2);
    if (strcmp(argv[1], "install") == 0) return dispatch_install(argc - 2, argv + 2);
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        usage();
        return 0;
    }
    usage();
    return 1;
}