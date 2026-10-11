/* ivo-config — scan for installed kernels and write a config.toml.
 *
 *   ivo-config [-o OUTPUT] [--boot DIR] [--path-prefix P] [--default NAME]
 *              [--timeout N] [--options "CMDLINE"]
 *
 * Matches a vmlinuz/kernel file with its initrd sibling by comparing
 * the version fragment each name carries. This works across naming
 * conventions used by Arch, Debian, Fedora, openSUSE, Alpine, Gentoo,
 * Slackware, Void, Solus, and others.
 *
 * Entries are ordered newest version first, and the default is the
 * newest kernel unless --default names another entry.
 *
 * Paths in the config are --path-prefix (default: --boot) + file name:
 * they must be the paths inside the filesystem Ivo boots from. If /boot
 * is its own partition, pass --path-prefix /.
 *
 * The output is re-parsed with the bootloader's own parser before it
 * is written. Does not compute hashes; run ivo-sign --hash afterward.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"
#include "ivo-util.h"

#define MAX_FILES     1024
#define MAX_NAME      256

void *mm_alloc(size_t size) { return malloc(size); }

typedef struct {
    char kernel[MAX_NAME];   /* basename */
    char initrd[MAX_NAME];   /* basename, or empty */
    char version[MAX_NAME];  /* version fragment from kernel name */
    char entry[MAX_NAME];    /* sanitized entry name */
} pair_t;

static const char *kernel_prefixes[] = {
    "vmlinuz-generic-",      /* Slackware */
    "vmlinuz-huge-",         /* Slackware */
    "vmlinuz.efi-",          /* rare */
    "vmlinuz-",              /* most distros */
    "kernel-",               /* Gentoo, some others */
    "bzImage-",              /* rare */
    "Image-",                /* AArch64, harmless here */
    NULL
};

static const char *initrd_prefixes[] = {
    "initramfs-",            /* Arch, Fedora, most */
    "initrd.img-",           /* Debian, Ubuntu */
    "initrd-",               /* openSUSE, Slackware */
    "initramfs.",            /* unusual */
    "initrd.",               /* unusual */
    NULL
};

static const char *initrd_exts[] = {
    ".img", ".gz", ".xz", ".zst", ".lz4", ".bz2", ".lzma", ".lzo",
    ".efi", ".signed",
    NULL
};

/* If `name` starts with `prefix`, copy the remainder into `out`. */
static int strip_prefix(const char *name, const char *prefix,
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

/* Try each kernel prefix in turn; return the first match's remainder. */
static int kernel_version(const char *name, char *out, size_t out_size)
{
    for (int i = 0; kernel_prefixes[i]; i++) {
        if (strip_prefix(name, kernel_prefixes[i], out, out_size))
            return 0;
    }
    return -1;
}

/* Try each initrd prefix; on match, strip any trailing extension
 * (.img, .gz, ...) and return the remainder. */
static int initrd_version(const char *name, char *out, size_t out_size)
{
    for (int i = 0; initrd_prefixes[i]; i++) {
        char tmp[MAX_NAME];
        if (!strip_prefix(name, initrd_prefixes[i], tmp, sizeof(tmp)))
            continue;

        /* Strip trailing extensions one at a time. Debian's signed
         * kernels end in ".efi.signed", so a single pass would leave
         * ".efi" behind. */
        int changed = 1;
        while (changed) {
            changed = 0;
            for (int j = 0; initrd_exts[j]; j++) {
                size_t elen = strlen(initrd_exts[j]);
                size_t tlen = strlen(tmp);
                if (tlen > elen &&
                    strcmp(tmp + tlen - elen, initrd_exts[j]) == 0) {
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

/* Same version? Or one is a prefix of the other, at a `-` boundary.
 * That last rule catches "6.12.13" matching "6.12.13-gentoo" without
 * allowing "6.12" to match "6.12.13". */
static int versions_match(const char *kv, const char *iv)
{
    if (strcmp(kv, iv) == 0) return 1;
    size_t klen = strlen(kv), ilen = strlen(iv);
    if (klen > ilen && kv[ilen] == '-' && strncmp(kv, iv, ilen) == 0)
        return 1;
    if (ilen > klen && iv[klen] == '-' && strncmp(kv, iv, klen) == 0)
        return 1;
    return 0;
}

/* Newest first. strverscmp orders "6.9" before "6.12". */
static int sort_cmp(const void *a, const void *b)
{
    const pair_t *pa = a, *pb = b;
    int c = strverscmp(pb->version, pa->version);
    return c ? c : strcmp(pa->kernel, pb->kernel);
}

static int name_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int join_path(char *out, size_t out_size, const char *prefix,
                     const char *name)
{
    size_t pl = strlen(prefix);
    while (pl > 0 && prefix[pl - 1] == '/') pl--;
    int n = snprintf(out, out_size, "%.*s/%s", (int)pl, prefix, name);
    return (n < 0 || (size_t)n >= out_size) ? -1 : 0;
}

int main(int argc, char **argv)
{
    const char *boot_dir = "/boot";
    const char *prefix = NULL;
    const char *output = NULL;
    const char *default_name = NULL;
    const char *options = "";
    unsigned long timeout = 5;

    for (int i = 1; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "-o")            == 0 && v) output = argv[++i];
        else if (strcmp(argv[i], "--boot")        == 0 && v) boot_dir = argv[++i];
        else if (strcmp(argv[i], "--path-prefix") == 0 && v) prefix = argv[++i];
        else if (strcmp(argv[i], "--default")     == 0 && v) default_name = argv[++i];
        else if (strcmp(argv[i], "--options")     == 0 && v) options = argv[++i];
        else if (strcmp(argv[i], "--timeout")     == 0 && v) {
            if (ivo_parse_uint(argv[++i], 86400, &timeout) != 0) {
                fprintf(stderr, "ivo-config: --timeout: expected 0..86400\n");
                return 1;
            }
        }
        else {
            fprintf(stderr, "ivo-config: unknown argument: %s\n", argv[i]);
            return 1;
        }
    }
    if (!prefix) prefix = boot_dir;
    if (prefix[0] != '/') {
        fprintf(stderr, "ivo-config: path prefix must be absolute: %s\n", prefix);
        return 1;
    }

    DIR *d = opendir(boot_dir);
    if (!d) {
        fprintf(stderr, "ivo-config: %s: %s\n", boot_dir, strerror(errno));
        return 1;
    }

    char **names = calloc(MAX_FILES, sizeof(char *));
    if (!names) { closedir(d); return 1; }
    int n_names = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strlen(ent->d_name) >= MAX_NAME) continue;

        struct stat st;
        if (fstatat(dirfd(d), ent->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
            continue;
        if (S_ISLNK(st.st_mode)) {
            /* Ivo's filesystem drivers do not follow symlinks. */
            char kv[MAX_NAME];
            if (kernel_version(ent->d_name, kv, sizeof(kv)) == 0)
                fprintf(stderr, "ivo-config: skipping symlink %s/%s\n",
                        boot_dir, ent->d_name);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;
        if (n_names >= MAX_FILES) {
            fprintf(stderr, "ivo-config: %s: more than %d files; "
                    "some were not considered\n", boot_dir, MAX_FILES);
            break;
        }
        names[n_names] = strdup(ent->d_name);
        if (!names[n_names]) { closedir(d); return 1; }
        n_names++;
    }
    closedir(d);

    if (n_names == 0) {
        fprintf(stderr, "ivo-config: %s: no files found\n", boot_dir);
        return 1;
    }
    /* readdir order is arbitrary; make initrd matching deterministic. */
    qsort(names, (size_t)n_names, sizeof(char *), name_cmp);

    pair_t *pairs = calloc((size_t)n_names, sizeof(pair_t));
    if (!pairs) return 1;
    int n_pairs = 0;

    for (int i = 0; i < n_names; i++) {
        char kver[MAX_NAME];
        if (kernel_version(names[i], kver, sizeof(kver)) != 0) continue;

        pair_t *p = &pairs[n_pairs];
        snprintf(p->kernel, sizeof(p->kernel), "%s", names[i]);
        snprintf(p->version, sizeof(p->version), "%s", kver);
        p->initrd[0] = '\0';

        /* Exact version match first, so "linux" pairs with
         * initramfs-linux.img rather than initramfs-linux-fallback.img. */
        for (int pass = 0; pass < 2 && !p->initrd[0]; pass++) {
            for (int j = 0; j < n_names; j++) {
                char iver[MAX_NAME];
                if (initrd_version(names[j], iver, sizeof(iver)) != 0) continue;
                if (pass == 0 ? strcmp(kver, iver) == 0
                              : versions_match(kver, iver)) {
                    snprintf(p->initrd, sizeof(p->initrd), "%s", names[j]);
                    break;
                }
            }
        }
        n_pairs++;
    }

    if (n_pairs == 0) {
        fprintf(stderr,
            "ivo-config: %s: no kernels found (looked for vmlinuz-*, "
            "kernel-*, bzImage-*, Image-*)\n", boot_dir);
        return 1;
    }

    qsort(pairs, (size_t)n_pairs, sizeof(pair_t), sort_cmp);

    if (n_pairs > IVO_CFG_MAX_ENTRIES) {
        fprintf(stderr, "ivo-config: %d kernels found; Ivo supports %d "
                "entries, keeping the newest %d\n",
                n_pairs, IVO_CFG_MAX_ENTRIES, IVO_CFG_MAX_ENTRIES);
        n_pairs = IVO_CFG_MAX_ENTRIES;
    }

    for (int i = 0; i < n_pairs; i++) {
        if (ivo_entry_name(pairs[i].version, pairs[i].entry,
                           sizeof(pairs[i].entry)) != 0) {
            fprintf(stderr, "ivo-config: %s: cannot derive an entry name\n",
                    pairs[i].kernel);
            return 1;
        }
        for (int j = 0; j < i; j++) {
            if (strcmp(pairs[i].entry, pairs[j].entry) == 0) {
                fprintf(stderr, "ivo-config: %s and %s both map to entry "
                        "name '%s'\n", pairs[j].kernel, pairs[i].kernel,
                        pairs[i].entry);
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
            fprintf(stderr, "ivo-config: --default %s: no such entry; "
                    "entries are:\n", default_name);
            for (int i = 0; i < n_pairs; i++)
                fprintf(stderr, "  %s\n", pairs[i].entry);
            return 1;
        }
    }

    ivo_buf_t o = {0};
    const char *why = NULL;
    ivo_buf_puts(&o, "# Generated by ivo-config.\n");
    ivo_buf_puts(&o, "# Run ivo-sign --hash to fill the kver/iver fields.\n\n");
    ivo_buf_printf(&o, "timeout = %lu\n", timeout);
    why = ivo_toml_kv(&o, "default", pairs[default_idx].entry);
    ivo_buf_puts(&o, "\n");

    for (int i = 0; i < n_pairs && !why; i++) {
        char path[4096];
        ivo_buf_printf(&o, "[entries.%s]\n", pairs[i].entry);

        if (join_path(path, sizeof(path), prefix, pairs[i].kernel) != 0) {
            why = "path too long";
            break;
        }
        if ((why = ivo_boot_path_problem(path)) ||
            (why = ivo_toml_kv(&o, "kernel", path)))
            break;
        if (pairs[i].initrd[0]) {
            if (join_path(path, sizeof(path), prefix, pairs[i].initrd) != 0) {
                why = "path too long";
                break;
            }
            if ((why = ivo_boot_path_problem(path)) ||
                (why = ivo_toml_kv(&o, "initrd", path)))
                break;
        } else {
            fprintf(stderr, "ivo-config: warning: no initrd found for %s\n",
                    pairs[i].kernel);
        }
        if (options[0] && (why = ivo_toml_kv(&o, "options", options)))
            break;
        ivo_buf_puts(&o, "\n");
    }
    if (why) {
        fprintf(stderr, "ivo-config: %s\n", why);
        return 1;
    }
    if (o.failed) {
        fprintf(stderr, "ivo-config: out of memory\n");
        return 1;
    }

    /* Self-check with the bootloader's parser. */
    if (config_parse(o.p, o.len) != 0) {
        fprintf(stderr, "ivo-config: internal error: generated config does "
                "not parse (line %d)\n", config_error_line());
        return 1;
    }
    int n_parsed = 0;
    config_get_entries(&n_parsed);
    entry_t *def = config_get_default();
    if (n_parsed != n_pairs || !def ||
        strcmp(def->name, pairs[default_idx].entry) != 0) {
        fprintf(stderr, "ivo-config: internal error: generated config does "
                "not round-trip\n");
        return 1;
    }

    int rc;
    if (output) {
        rc = ivo_write_file(output, o.p, o.len, 0644, IVO_WRITE_KEEP_MODE);
        if (rc != 0)
            fprintf(stderr, "ivo-config: %s: %s\n", output, strerror(errno));
    } else {
        rc = ivo_write_stdout(o.p, o.len);
        if (rc != 0) fprintf(stderr, "ivo-config: write error on stdout\n");
    }
    ivo_buf_free(&o);
    for (int i = 0; i < n_names; i++) free(names[i]);
    free(names);
    free(pairs);
    return rc == 0 ? 0 : 1;
}
