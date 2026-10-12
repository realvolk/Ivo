/* ivo-sign — hash, check, sign, or verify an Ivo config.toml.
 *
 * --hash   computes kver/iver/cver for every entry from the files under
 *          --root and rewrites the config (atomically, temp + rename).
 * --check  recomputes every referenced file's hash and compares.
 * --sign   writes CFG.sig, Ed25519 over the exact CFG bytes.
 * --verify checks CFG against CFG.sig.
 *
 * The config is parsed by src/uefi/config.c — the bootloader's own
 * parser — so this tool and the bootloader can never disagree about
 * which files an entry boots or which hash covers them.
 *
 * Path semantics match the bootloader:
 *   - kernel/initrd/path are absolute paths inside the boot filesystem,
 *     resolved beneath --root. ".." components and symlinks anywhere
 *     below --root are refused (Ivo's filesystem drivers do not follow
 *     symlinks, so a symlink would make us hash a different file).
 *   - subvol entries resolve beneath SUBVOL_ROOT/<subvol>, where
 *     SUBVOL_ROOT (--subvol-root, default --root) is a mount of the
 *     btrfs top level (subvolid=5): Ivo resolves subvol from there.
 *   - iso-boot entries read kernel/initrd from inside the ISO volume
 *     whose label is iso_label; pass the image with --iso (repeatable).
 *
 * All modes exit 0 on success, 1 on failure.
 * Host-only. Links Ivo's crypto, config parser and ISO9660 reader.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "config.h"
#include "ed25519.h"
#include "ge.h"
#include "wipe.h"
#include "ivo-util.h"

/* ivo-sign-host.c */
int ivo_iso_volume_id(const uint8_t *img, size_t size,
                      char *out, size_t out_size);
int ivo_iso_read_file(const uint8_t *img, size_t size, const char *path,
                      uint8_t **out, size_t *out_len);

/* secure_boot.c: CONFIG_MAX. The bootloader refuses anything larger. */
#define CONFIG_MAX   (64 * 1024)
#define SEC_KEY_LEN  64
#define MAX_ISOS     8

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

/* A private copy of a parsed entry. config.c keeps its results in
 * static storage that the next config_parse() overwrites. */
typedef struct {
    char *name, *kernel, *initrd, *cmdline, *chain, *iso_label, *subvol;
    char *kver, *iver, *cver;
    int   is_chainload, is_iso, hidden, timeout;
} snap_t;

typedef struct {
    const char *key;        /* "kver" / "iver" / "cver" */
    const char *path;
    const char *recorded;   /* hash in the config, or NULL/"" */
} file_ref_t;

static char *xstrdup(const char *s)
{
    if (!s) return NULL;
    char *d = strdup(s);
    if (!d) { fprintf(stderr, "ivo-sign: out of memory\n"); exit(1); }
    return d;
}

static int str_eq(const char *a, const char *b)
{
    if (!a || !b) return a == b;
    return strcmp(a, b) == 0;
}

/* Treat NULL and "" alike: both mean "not set" to the bootloader. */
static int str_eq0(const char *a, const char *b)
{
    return str_eq(a && a[0] ? a : NULL, b && b[0] ? b : NULL);
}

static int read_config(const char *path, uint8_t **buf, size_t *len)
{
    if (ivo_read_file(path, CONFIG_MAX + 1, buf, len) != 0) {
        fprintf(stderr, "ivo-sign: %s: %s\n", path,
                errno == EFBIG ? "larger than the bootloader's 64 KiB limit"
                               : strerror(errno));
        return -1;
    }
    if (*len > CONFIG_MAX || *len == 0) {
        fprintf(stderr, "ivo-sign: %s: %s\n", path, *len ?
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
            fprintf(stderr, "ivo-sign: %s:%d: parse error "
                    "(the bootloader would reject this config)\n", path, line);
        else
            fprintf(stderr, "ivo-sign: %s: parse error: no entries, or the "
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
    if (!s) { fprintf(stderr, "ivo-sign: out of memory\n"); exit(1); }
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

/* The files an entry makes the bootloader read, in the order
 * config_entry_hashes_complete() checks them. */
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

/* Hash one file exactly as the bootloader would read it. */
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
                 "ISO volume labelled '%s' (Ivo reads this file from inside "
                 "that ISO, not from --root)", e->iso_label);
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
    else
        snprintf(out, out_size, "%s%s", o->root, path);
}


typedef struct {
    const char *start;
    size_t      len;        /* content, without "\n" / "\r\n" */
    size_t      full;       /* including the line ending */
    int         has_nl;
    int         crlf;
    int         kind;       /* see LINE_* */
    int         section;    /* entry index, -1 before the first one */
} line_t;

enum { LINE_BLANK, LINE_SECTION, LINE_KEY, LINE_HASHKEY };

/* Classify lines the way config.c does. Only called on text that
 * config_parse() accepted, so every non-blank line is a section
 * header or `key = value`. */
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

static int do_hash(const char *cfg_path, const opts_t *o)
{
    uint8_t *cfg = NULL;
    size_t cfg_len = 0;
    if (read_config(cfg_path, &cfg, &cfg_len) != 0) return 1;
    if (parse_config(cfg_path, cfg, cfg_len) != 0) { free(cfg); return 1; }

    int n = 0;
    snap_t *s = snapshot(&n);

    /* Compute every hash before touching anything. */
    typedef struct { char kver[129], iver[129], cver[129]; } want_t;
    want_t *want = calloc((size_t)n, sizeof(*want));
    if (!want) { fprintf(stderr, "ivo-sign: out of memory\n"); return 1; }

    int failed = 0;
    int changed = 0;
    for (int i = 0; i < n; i++) {
        file_ref_t refs[2];
        int nr = entry_files(&s[i], refs);
        for (int r = 0; r < nr; r++) {
            char hex[IVO_HASH_HEX_LEN + 1], err[512], where[1024];
            describe(o, &s[i], refs[r].path, where, sizeof(where));
            if (hash_ref(o, &s[i], refs[r].path, hex, err, sizeof(err)) != 0) {
                fprintf(stderr, "ivo-sign: [%s] %s: %s\n",
                        s[i].name, where, err);
                failed = 1;
                continue;
            }
            char *dst = refs[r].key[0] == 'k' ? want[i].kver :
                        refs[r].key[0] == 'i' ? want[i].iver : want[i].cver;
            memcpy(dst, hex, sizeof(hex));
            if (!refs[r].recorded || strcmp(hex, refs[r].recorded) != 0)
                changed = 1;
            if (o->verbose) printf("[%s] %s = %s\n", s[i].name, refs[r].key, where);
        }
    }
    if (failed) {
        fprintf(stderr,
            "ivo-sign: %s: not modified\n"
            "\n"
            "  One or more files referenced by the config could not be hashed.\n"
            "  The config on disk is now stale relative to the filesystem.\n"
            "  If this is /boot, the machine may not boot. Fix by:\n"
            "\n"
            "    ivo-sign --hash --config %s --root <root>\n"
            "\n"
            "  If the missing file is a kernel or initrd, restore it, or add\n"
            "  a fallback entry in the config that names the previous kernel.\n",
            cfg_path, cfg_path);
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
    if (!o->no_bump) {
        if (isatty(STDIN_FILENO)) {
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

    /* Rewrite: drop every kver/iver/cver line inside an entry, insert
     * fresh ones after the entry's last key line. Everything else is
     * copied byte for byte. */
    int nl_count = 0;
    line_t *lines = split_lines((const char *)cfg, cfg_len, &nl_count);
    if (!lines) { fprintf(stderr, "ivo-sign: out of memory\n"); return 1; }

    int *insert_after = malloc((size_t)n * sizeof(int));
    if (!insert_after) { fprintf(stderr, "ivo-sign: out of memory\n"); return 1; }
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
    if (out.failed) { fprintf(stderr, "ivo-sign: out of memory\n"); return 1; }

    /* Self-check: the new text must parse to the same entries with
     * exactly the hashes computed above. */
    int ok = 1;
    if (out.len > CONFIG_MAX) {
        fprintf(stderr, "ivo-sign: result exceeds the bootloader's 64 KiB "
                "config limit\n");
        ok = 0;
    } else if (config_parse(out.p, out.len) != 0) {
        fprintf(stderr, "ivo-sign: internal error: rewritten config does "
                "not parse (line %d)\n", config_error_line());
        ok = 0;
    } else {
        int n2 = 0;
        entry_t *e = config_get_entries(&n2);
        if (bump && config_get_version() != old_ver + 1)
            ok = 0;
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
            fprintf(stderr, "ivo-sign: internal error: rewritten config "
                    "does not carry the computed hashes\n");
    }

    int rc = 1;
    if (ok) {
        if (ivo_write_file(cfg_path, out.p, out.len, 0644,
                           IVO_WRITE_KEEP_MODE) != 0) {
            fprintf(stderr, "ivo-sign: %s: cannot write: %s\n",
                    cfg_path, strerror(errno));
        } else {
            printf("hashed %s: %d entr%s (%zu bytes)\n", cfg_path, n,
                   n == 1 ? "y" : "ies", out.len);
            rc = 0;
        }
    } else {
        fprintf(stderr, "ivo-sign: %s: not modified\n", cfg_path);
    }

    ivo_buf_free(&out);
    snapshot_free(s, n);
    free(want);
    free(cfg);
    return rc;
}


static int do_check(const char *cfg_path, const opts_t *o)
{
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
            describe(o, &s[i], refs[r].path, where, sizeof(where));
            if (!refs[r].recorded || !refs[r].recorded[0]) {
                printf("[%s] %s: NO-HASH (no %s; the bootloader refuses "
                       "this entry under SECURE_BOOT)\n",
                       s[i].name, where, refs[r].key);
                n_nohash++;
                continue;
            }
            if (hash_ref(o, &s[i], refs[r].path, hex, err, sizeof(err)) != 0) {
                printf("[%s] %s: MISSING (%s)\n", s[i].name, where, err);
                n_missing++;
                continue;
            }
            if (strcmp(hex, refs[r].recorded) != 0) {
                printf("[%s] %s: MISMATCH (%s)\n", s[i].name, where, refs[r].key);
                n_bad++;
                continue;
            }
            if (o->verbose) printf("[%s] %s: OK\n", s[i].name, where);
            n_ok++;
        }
    }
    snapshot_free(s, n);

    printf("\n%d OK, %d mismatch, %d missing, %d no-hash\n",
           n_ok, n_bad, n_missing, n_nohash);
    return (n_bad || n_missing || n_nohash) ? 1 : 0;
}


/* .sec format (since the key-handling fix): seed[32] || public[32],
 * the libsodium / OpenSSH layout. The 64-byte expanded key is derived
 * from the seed on every use and the stored public key must match.
 *
 * Older ivo-keygen wrote public[32] || scalar[32] and dropped the
 * nonce prefix; signatures made from such a file used uninitialised
 * heap bytes as the nonce prefix and can leak the private key. Those
 * files are refused. */
static int load_secret_key(const char *path,
                           uint8_t pub[ED25519_PUBLIC_KEY_SIZE],
                           uint8_t expanded[ED25519_EXPANDED_KEY_SIZE])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "ivo-sign: %s: %s\n", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != SEC_KEY_LEN) {
        fprintf(stderr, "ivo-sign: %s: not a %d-byte key file\n",
                path, SEC_KEY_LEN);
        close(fd);
        return -1;
    }
    if (st.st_mode & 077)
        fprintf(stderr, "ivo-sign: warning: %s is accessible by group/others "
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
        fprintf(stderr, "ivo-sign: %s: short read\n", path);
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

    /* Old layout? public || clamped scalar. */
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
            "ivo-sign: %s: this key was written by an older ivo-keygen\n"
            "  (public||scalar layout). That layout lost half of the private\n"
            "  key, and signatures made with it may have leaked the rest.\n"
            "  Treat this key as compromised and rotate it:\n"
            "    1. tools/ivo-keygen --out-prefix NEWKEY\n"
            "    2. cp NEWKEY.h src/uefi/secure_boot_pubkey.h\n"
            "    3. rebuild ivo.efi (make SECURE_BOOT=1 ...), re-sign it for\n"
            "       firmware Secure Boot, and reinstall it\n"
            "    4. ivo-sign --sign --key NEWKEY.sec, install the new .sig\n"
            "    5. destroy the old .sec\n", path);
    } else {
        fprintf(stderr, "ivo-sign: %s: public key half does not match the "
                "seed; corrupt or not an Ivo key file\n", path);
    }
    return -1;
}

static char *sig_path_for(const char *cfg_path)
{
    char *p = NULL;
    if (asprintf(&p, "%s.sig", cfg_path) < 0) {
        fprintf(stderr, "ivo-sign: out of memory\n");
        exit(1);
    }
    return p;
}


static int do_sign(const char *cfg_path, const char *key_path)
{
    uint8_t *cfg = NULL;
    size_t cfg_len = 0;

    /* One read. These bytes are parsed, checked and signed. */
    if (read_config(cfg_path, &cfg, &cfg_len) != 0) return 1;
    if (parse_config(cfg_path, cfg, cfg_len) != 0) {
        fprintf(stderr, "ivo-sign: refusing to sign\n");
        free(cfg);
        return 1;
    }

    int n = 0;
    entry_t *e = config_get_entries(&n);
    int incomplete = 0;
    for (int i = 0; i < n; i++) {
        if (!config_entry_hashes_complete(&e[i])) {
            fprintf(stderr, "ivo-sign: [%s] is missing %s\n", e[i].name,
                    e[i].is_chainload ? "cver" :
                    (!e[i].kernel_hash || !e[i].kernel_hash[0]) ? "kver" : "iver");
            incomplete = 1;
        }
    }
    if (incomplete) {
        fprintf(stderr, "ivo-sign: refusing to sign: every entry needs the "
                "hash of every file it boots (run ivo-sign --hash first)\n");
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
        fprintf(stderr, "ivo-sign: internal error: signature does not "
                "verify; nothing written\n");
        free(cfg);
        return 1;
    }

    char *sig_path = sig_path_for(cfg_path);
    if (ivo_write_file(sig_path, sig, sizeof(sig), 0644, 0) != 0) {
        fprintf(stderr, "ivo-sign: %s: cannot write: %s\n",
                sig_path, strerror(errno));
        free(sig_path); free(cfg);
        return 1;
    }
    printf("signed %s -> %s\n", cfg_path, sig_path);
    free(sig_path);
    free(cfg);
    return 0;
}


static int do_verify(const char *cfg_path, const char *pub_path)
{
    uint8_t *cfg = NULL, *pub = NULL, *sig = NULL;
    size_t cfg_len = 0, pub_len = 0, sig_len = 0;

    if (read_config(cfg_path, &cfg, &cfg_len) != 0) return 1;
    if (ivo_read_file(pub_path, 64, &pub, &pub_len) != 0 ||
        pub_len != ED25519_PUBLIC_KEY_SIZE) {
        fprintf(stderr, "ivo-sign: %s: public key must be 32 bytes\n", pub_path);
        free(pub); free(cfg);
        return 1;
    }

    char *sig_path = sig_path_for(cfg_path);
    if (ivo_read_file(sig_path, 128, &sig, &sig_len) != 0 ||
        sig_len != ED25519_SIGNATURE_SIZE) {
        fprintf(stderr, "ivo-sign: %s: signature must be 64 bytes\n", sig_path);
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

    /* The bootloader parses what it verified; say if that will fail. */
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


static int add_iso(opts_t *o, const char *path)
{
    if (o->n_isos >= MAX_ISOS) {
        fprintf(stderr, "ivo-sign: too many --iso (max %d)\n", MAX_ISOS);
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0) {
        fprintf(stderr, "ivo-sign: %s: %s\n", path,
                fd < 0 ? strerror(errno) : "not a regular file");
        if (fd >= 0) close(fd);
        return -1;
    }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) {
        fprintf(stderr, "ivo-sign: %s: mmap: %s\n", path, strerror(errno));
        return -1;
    }
    iso_image_t *img = &o->isos[o->n_isos];
    img->path = path;
    img->map  = m;
    img->size = (size_t)st.st_size;
    if (ivo_iso_volume_id(img->map, img->size, img->label,
                          sizeof(img->label)) != 0) {
        fprintf(stderr, "ivo-sign: %s: not an ISO9660 image\n", path);
        munmap(m, img->size);
        return -1;
    }
    o->n_isos++;
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
        "usage:\n"
        "  ivo-sign --hash   --config CFG --root DIR [--subvol-root DIR] [--iso IMG]... [-v]\n"
        "  ivo-sign --check  --config CFG --root DIR [--subvol-root DIR] [--iso IMG]... [-v]\n"
        "  ivo-sign --sign   --config CFG --key KEY.sec\n"
        "  ivo-sign --verify --config CFG --pub KEY.pub\n"
        "\n"
        "  --root DIR         where the boot filesystem is mounted; entry\n"
        "                     paths resolve beneath it, symlinks refused\n"
        "  --subvol-root DIR  btrfs top level (subvolid=5) for entries with\n"
        "                     subvol; default --root\n"
        "  --iso IMG          ISO image for iso-boot entries, matched by\n"
        "                     volume label against iso_label\n"
        "  --no-bump          do not prompt to bump the config version\n");
}

int main(int argc, char **argv)
{
    const char *mode = NULL;
    const char *cfg = NULL;
    const char *key = NULL;
    const char *pub = NULL;
    opts_t o;
    memset(&o, 0, sizeof(o));

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int has_val = i + 1 < argc;
        const char *m = NULL;
        if      (strcmp(a, "--hash")   == 0) m = "hash";
        else if (strcmp(a, "--check")  == 0) m = "check";
        else if (strcmp(a, "--sign")   == 0) m = "sign";
        else if (strcmp(a, "--verify") == 0) m = "verify";

        if (m) {
            if (mode && strcmp(mode, m) != 0) {
                fprintf(stderr, "ivo-sign: choose one of --hash, --check, "
                        "--sign, --verify\n");
                return 1;
            }
            mode = m;
        }
        else if (strcmp(a, "-v") == 0) o.verbose = 1;
        else if (strcmp(a, "--no-bump") == 0) o.no_bump = 1;
        else if (strcmp(a, "--config") == 0 && has_val) cfg = argv[++i];
        else if (strcmp(a, "--root") == 0 && has_val) o.root = argv[++i];
        else if (strcmp(a, "--subvol-root") == 0 && has_val) o.subvol_root = argv[++i];
        else if (strcmp(a, "--key") == 0 && has_val) key = argv[++i];
        else if (strcmp(a, "--pub") == 0 && has_val) pub = argv[++i];
        else if (strcmp(a, "--iso") == 0 && has_val) {
            if (add_iso(&o, argv[++i]) != 0) return 1;
        }
        else {
            fprintf(stderr, "ivo-sign: unknown argument: %s\n", a);
            usage();
            return 1;
        }
    }

    if (!mode || !cfg) { usage(); return 1; }

    if (strcmp(mode, "hash") == 0 || strcmp(mode, "check") == 0) {
        if (!o.root) {
            fprintf(stderr, "ivo-sign: --%s needs --root\n", mode);
            return 1;
        }
        return strcmp(mode, "hash") == 0 ? do_hash(cfg, &o) : do_check(cfg, &o);
    }
    if (strcmp(mode, "sign") == 0) {
        if (!key) { fprintf(stderr, "ivo-sign: --sign needs --key\n"); return 1; }
        return do_sign(cfg, key);
    }
    if (!pub) { fprintf(stderr, "ivo-sign: --verify needs --pub\n"); return 1; }
    return do_verify(cfg, pub);
}
