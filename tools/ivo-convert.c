/* ivo-convert — convert GRUB, Limine, or rEFInd boot configs to config.toml.
 *
 * Usage:
 *   ivo-convert --from grub|limine|refind INPUT [-o OUTPUT] [--kernel K] [--initrd I]
 *
 * INPUT may be '-' for stdin. Without -o, writes to stdout.
 *
 * Refuses (with a line number) any construct that doesn't map cleanly,
 * and any value config.toml cannot carry (it has no escapes, and lines
 * are limited to 4095 bytes). The output is re-parsed with the
 * bootloader's own parser before it is written.
 * Does not hash or sign; run ivo-sign --hash afterward.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "config.h"
#include "ivo-util.h"

#define CONV_MAX_ENTRIES 64
#define MAX_LINE    4096
#define MAX_INPUT   (1 << 20)

void *mm_alloc(size_t size) { return malloc(size); }

typedef struct {
    char name[MAX_LINE];
    char kernel[MAX_LINE];
    char initrd[MAX_LINE];
    char options[MAX_LINE];
    char type[32];
    char path[MAX_LINE];
    int  timeout;            /* -1 = unset */
    int  hidden;
    int  line;               /* where the entry starts */
} conv_entry_t;

typedef enum { DEF_NONE, DEF_INDEX0, DEF_INDEX1, DEF_TITLE, DEF_SUBSTR } def_kind_t;

typedef struct {
    conv_entry_t entries[CONV_MAX_ENTRIES];
    int          count;
    char         default_name[MAX_LINE];
    def_kind_t   default_kind;
    int          timeout;    /* -1 = unset */
} conv_config_t;

static int read_input(const char *path, char **buf, size_t *len)
{
    uint8_t *b = NULL;
    int rc;
    if (strcmp(path, "-") == 0)
        rc = ivo_read_fd(STDIN_FILENO, MAX_INPUT, &b, len);
    else
        rc = ivo_read_file(path, MAX_INPUT, &b, len);
    if (rc != 0) return -1;
    if (memchr(b, '\0', *len)) {
        free(b);
        errno = EINVAL;
        return -1;
    }
    *buf = (char *)b;
    return 0;
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' ||
                     e[-1] == '\r' || e[-1] == '\n')) e--;
    *e = '\0';
    return s;
}

/* Bounded copy that always null-terminates. Every destination here is
 * MAX_LINE bytes and every source comes from one input line, which is
 * shorter, so nothing is ever cut off. */
static void copy_str(char *dst, const char *src, size_t dst_size)
{
    if (dst_size == 0) return;
    size_t i = 0;
    while (i + 1 < dst_size && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/* Fetch line `p` into `line`. Returns the start of the next line, or
 * NULL (with a message) if the line is longer than the buffer. */
static const char *next_line(const char *p, char *line, size_t line_size,
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

static int parse_timeout(const char *val, conv_config_t *c,
                         const char *fname, int lineno)
{
    unsigned long t;
    if (ivo_parse_uint(val, 86400, &t) != 0) {
        fprintf(stderr, "%s:%d: warning: timeout '%s' ignored "
                "(Ivo takes 0..86400 seconds)\n", fname, lineno, val);
        return 0;
    }
    c->timeout = (int)t;
    return 0;
}

static void set_default(conv_config_t *c, const char *val, def_kind_t numeric,
                        def_kind_t text)
{
    unsigned long dummy;
    copy_str(c->default_name, val, sizeof(c->default_name));
    c->default_kind = ivo_parse_uint(val, 1000, &dummy) == 0 ? numeric : text;
}

static conv_entry_t *new_entry(conv_config_t *c, const char *fname, int lineno)
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

/* Read a quoted string. *p must point at the opening quote. */
static int read_quoted(const char **p, char *out, size_t out_size)
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

/* Read a bare token up to whitespace. */
static int read_token(const char **p, char *out, size_t out_size)
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

static int only_space(const char *p)
{
    while (*p == ' ' || *p == '\t') p++;
    return *p == '\0';
}

/* Pull an `initrd=PATH` token out of an options string, removing it.
 * GRUB sometimes carries the initrd inside the `linux` line args. */
static int pull_initrd_from_options(char *options, char *initrd_out,
                                    size_t initrd_size)
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

static int parse_grub(const char *src, conv_config_t *c, const char *fname)
{
    int lineno = 0;
    const char *p = src;
    conv_entry_t *cur = NULL;

    while (*p) {
        lineno++;
        char line[MAX_LINE];
        p = next_line(p, line, sizeof(line), fname, lineno);
        if (!p) return -1;

        char *l = trim(line);
        if (*l == '\0' || *l == '#') continue;

        /* Unsupported GRUB constructs. Check before anything else. */
        static const char *refuse[] = {
            "submenu", "if ", "if(", "elif", "else", "fi",
            "for ", "while ", "function ", "configfile",
            "source ", NULL
        };
        for (int i = 0; refuse[i]; i++) {
            size_t rl = strlen(refuse[i]);
            if (strncmp(l, refuse[i], rl) != 0) continue;
            if (refuse[i][rl - 1] == ' ' ||
                l[rl] == ' ' || l[rl] == '\0' ||
                l[rl] == '{' || l[rl] == '(') {
                fprintf(stderr, "%s:%d: refusing GRUB construct: %s\n",
                        fname, lineno, l);
                return -1;
            }
        }

        if (strchr(l, '$')) {
            fprintf(stderr, "%s:%d: variable expansion is not supported\n",
                    fname, lineno);
            return -1;
        }

        if (strncmp(l, "set ", 4) == 0) {
            char *rest = trim(l + 4);
            char *eq = strchr(rest, '=');
            if (eq) {
                *eq = '\0';
                char *key = trim(rest);
                char *val = trim(eq + 1);
                char unq[MAX_LINE];
                if (val[0] == '"' || val[0] == '\'') {
                    const char *vp = val;
                    if (read_quoted(&vp, unq, sizeof(unq)) != 0 || !only_space(vp)) {
                        fprintf(stderr, "%s:%d: bad quoted value\n", fname, lineno);
                        return -1;
                    }
                    val = unq;
                }
                if (strcmp(key, "default") == 0) {
                    if (strcmp(val, "saved") == 0)
                        fprintf(stderr, "%s:%d: warning: default=saved is not "
                                "supported; first entry is the default\n",
                                fname, lineno);
                    else
                        set_default(c, val, DEF_INDEX0, DEF_TITLE);
                } else if (strcmp(key, "timeout") == 0) {
                    parse_timeout(val, c, fname, lineno);
                }
            }
            continue;
        }

        if (strncmp(l, "menuentry ", 10) == 0) {
            const char *mp = l + 10;
            while (*mp == ' ' || *mp == '\t') mp++;
            char name[MAX_LINE];
            if (*mp == '"' || *mp == '\'') {
                if (read_quoted(&mp, name, sizeof(name)) != 0) {
                    fprintf(stderr, "%s:%d: unterminated menuentry name\n",
                            fname, lineno);
                    return -1;
                }
            } else if (read_token(&mp, name, sizeof(name)) != 0) {
                fprintf(stderr, "%s:%d: empty menuentry\n", fname, lineno);
                return -1;
            }

            int start = lineno;
            if (!strchr(mp, '{')) {
                /* Brace is on a later line. Skip ahead. */
                while (*p) {
                    lineno++;
                    char l2[MAX_LINE];
                    const char *np = next_line(p, l2, sizeof(l2), fname, lineno);
                    if (!np) return -1;
                    p = np;
                    if (strchr(l2, '{')) break;
                }
            }

            cur = new_entry(c, fname, start);
            if (!cur) return -1;
            copy_str(cur->name, name, sizeof(cur->name));
            continue;
        }

        if (strcmp(l, "}") == 0) {
            cur = NULL;
            continue;
        }

        if (cur) {
            if (strncmp(l, "linux ", 6) == 0 ||
                strncmp(l, "linuxefi ", 9) == 0) {
                const char *kp = strchr(l, ' ') + 1;
                char path[MAX_LINE];
                if (read_token(&kp, path, sizeof(path)) == 0) {
                    copy_str(cur->kernel, path, sizeof(cur->kernel));
                    while (*kp == ' ' || *kp == '\t') kp++;
                    copy_str(cur->options, kp, sizeof(cur->options));
                    char *oe = cur->options + strlen(cur->options);
                    while (oe > cur->options &&
                           (oe[-1] == ' ' || oe[-1] == '\t')) *--oe = '\0';
                }
                continue;
            }
            if (strncmp(l, "initrd ", 7) == 0 ||
                strncmp(l, "initrdefi ", 10) == 0) {
                const char *ip = strchr(l, ' ') + 1;
                char path[MAX_LINE];
                if (read_token(&ip, path, sizeof(path)) == 0) {
                    if (!only_space(ip)) {
                        /* e.g. initrd /intel-ucode.img /initramfs.img */
                        fprintf(stderr, "%s:%d: more than one initrd is not "
                                "supported\n", fname, lineno);
                        return -1;
                    }
                    copy_str(cur->initrd, path, sizeof(cur->initrd));
                }
                continue;
            }
            if (strncmp(l, "chainloader ", 12) == 0) {
                const char *cp = l + 12;
                char path[MAX_LINE];
                if (read_token(&cp, path, sizeof(path)) == 0) {
                    copy_str(cur->path, path, sizeof(cur->path));
                    copy_str(cur->type, "efi-chainload", sizeof(cur->type));
                }
                continue;
            }
        }

        /* insmod, search, load_video, echo, terminal_*, ... */
    }

    for (int i = 0; i < c->count; i++) {
        conv_entry_t *e = &c->entries[i];
        if (e->kernel[0] && !e->initrd[0])
            pull_initrd_from_options(e->options, e->initrd, sizeof(e->initrd));
    }
    return 0;
}

/* boot:///path, boot://path, boot():/path, boot(N,M):/path -> /path */
static void strip_limine_prefix(const char *in, char *out, size_t out_size)
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
    copy_str(out, p, out_size);
}

static int limine_module(conv_entry_t *cur, const char *val,
                         const char *fname, int lineno)
{
    if (cur->initrd[0]) {
        fprintf(stderr, "%s:%d: more than one module is not supported\n",
                fname, lineno);
        return -1;
    }
    strip_limine_prefix(val, cur->initrd, sizeof(cur->initrd));
    return 0;
}

static int parse_limine(const char *src, conv_config_t *c, const char *fname)
{
    /* New format (v8+) uses `/name` and `key: value`. Old format (v7)
     * uses `:name` and `KEY=value`. The first header line picks. */
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
        char line[MAX_LINE];
        p = next_line(p, line, sizeof(line), fname, lineno);
        if (!p) return -1;

        /* Limine comments are whole lines starting with '#'. A '#'
         * inside a value (a cmdline, a path) is data. */
        char *l = trim(line);
        if (*l == '\0' || *l == '#') continue;

        if (strchr(l, '$')) {
            fprintf(stderr, "%s:%d: variable expansion is not supported\n",
                    fname, lineno);
            return -1;
        }

        if (is_new) {
            if (*l == '/') {
                /* Sub-entries are //name, ///name, ... Not supported. */
                if (l[1] == '/') {
                    fprintf(stderr, "%s:%d: sub-entries are not supported\n",
                            fname, lineno);
                    return -1;
                }
                const char *nm = l + 1;
                if (*nm == '+') nm++;       /* "expanded" directory marker */
                cur = new_entry(c, fname, lineno);
                if (!cur) return -1;
                copy_str(cur->name, nm, sizeof(cur->name));
                continue;
            }
            char *colon = strchr(l, ':');
            if (!colon) continue;
            *colon = '\0';
            char *key = trim(l);
            char *val = trim(colon + 1);

            char val_buf[MAX_LINE];
            if (val[0] == '"' || val[0] == '\'') {
                const char *vp = val;
                if (read_quoted(&vp, val_buf, sizeof(val_buf)) == 0 &&
                    only_space(vp))
                    val = val_buf;
            }

            if (strcmp(key, "timeout") == 0) {
                if (!cur) parse_timeout(val, c, fname, lineno);
            } else if (strcmp(key, "default_entry") == 0) {
                if (!cur) set_default(c, val, DEF_INDEX1, DEF_TITLE);
            } else if (cur) {
                if (strcmp(key, "protocol") == 0) {
                    if (strcmp(val, "efi_chainload") == 0 ||
                        strcmp(val, "efi") == 0)
                        copy_str(cur->type, "efi-chainload", sizeof(cur->type));
                } else if (strcmp(key, "kernel_path") == 0) {
                    strip_limine_prefix(val, cur->kernel, sizeof(cur->kernel));
                } else if (strcmp(key, "path") == 0) {
                    if (cur->type[0])
                        strip_limine_prefix(val, cur->path, sizeof(cur->path));
                    else
                        strip_limine_prefix(val, cur->kernel, sizeof(cur->kernel));
                } else if (strcmp(key, "cmdline") == 0 ||
                           strcmp(key, "kernel_cmdline") == 0) {
                    copy_str(cur->options, val, sizeof(cur->options));
                } else if (strcmp(key, "module_path") == 0) {
                    if (limine_module(cur, val, fname, lineno) != 0) return -1;
                }
            }
        } else {
            if (*l == ':') {
                if (l[1] == ':') {
                    fprintf(stderr, "%s:%d: sub-entries are not supported\n",
                            fname, lineno);
                    return -1;
                }
                cur = new_entry(c, fname, lineno);
                if (!cur) return -1;
                copy_str(cur->name, trim(l + 1), sizeof(cur->name));
                continue;
            }
            char *eq = strchr(l, '=');
            if (!eq) continue;
            *eq = '\0';
            char *key = trim(l);
            char *val = trim(eq + 1);

            if (strcmp(key, "TIMEOUT") == 0) {
                if (!cur) parse_timeout(val, c, fname, lineno);
            } else if (strcmp(key, "DEFAULT_ENTRY") == 0) {
                if (!cur) set_default(c, val, DEF_INDEX1, DEF_TITLE);
            } else if (cur) {
                if (strcmp(key, "PROTOCOL") == 0) {
                    if (strcmp(val, "efi_chainload") == 0)
                        copy_str(cur->type, "efi-chainload", sizeof(cur->type));
                } else if (strcmp(key, "KERNEL_PATH") == 0) {
                    strip_limine_prefix(val, cur->kernel, sizeof(cur->kernel));
                } else if (strcmp(key, "PATH") == 0) {
                    if (cur->type[0])
                        strip_limine_prefix(val, cur->path, sizeof(cur->path));
                    else
                        strip_limine_prefix(val, cur->kernel, sizeof(cur->kernel));
                } else if (strcmp(key, "CMDLINE") == 0 ||
                           strcmp(key, "KERNEL_CMDLINE") == 0) {
                    copy_str(cur->options, val, sizeof(cur->options));
                } else if (strcmp(key, "MODULE_PATH") == 0) {
                    if (limine_module(cur, val, fname, lineno) != 0) return -1;
                }
            }
        }
    }

    /* A path given before `protocol: efi` landed in kernel. */
    for (int i = 0; i < c->count; i++) {
        conv_entry_t *e = &c->entries[i];
        if (e->type[0] && !e->path[0] && e->kernel[0]) {
            copy_str(e->path, e->kernel, sizeof(e->path));
            e->kernel[0] = '\0';
        }
    }
    return 0;
}

/* rEFInd: '#' starts a comment unless it is inside quotes. */
static void strip_refind_comment(char *line)
{
    char q = 0;
    for (char *s = line; *s; s++) {
        if (q) { if (*s == q) q = 0; continue; }
        if (*s == '"') { q = *s; continue; }
        if (*s == '#') { *s = '\0'; return; }
    }
}

static int refind_value(const char *vp, char *val, size_t val_size,
                        const char *fname, int lineno)
{
    while (*vp == ' ' || *vp == '\t') vp++;
    if (*vp == '"') {
        if (read_quoted(&vp, val, val_size) != 0 || !only_space(vp)) {
            fprintf(stderr, "%s:%d: bad quoted value\n", fname, lineno);
            return -1;
        }
        return 0;
    }
    copy_str(val, vp, val_size);
    return 0;
}

static int parse_refind(const char *src, conv_config_t *c, const char *fname,
                        const char *kernel_override,
                        const char *initrd_override)
{
    /* refind.conf has `menuentry { ... }` blocks. refind_linux.conf is a
     * list of quoted pairs and has no kernel path — the kernel sits next
     * to the file. Detect by content, not by the first line: a real
     * refind.conf starts with `timeout` or `default_selection`, not with
     * a menuentry. */
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
        fprintf(stderr,
            "%s: not a recognizable rEFInd config (no menuentry, no quoted entries)\n",
            fname);
        return -1;
    }

    int is_linux_conf = (!saw_menuentry && saw_quoted_line);
    int lineno = 0;
    const char *p = src;

    if (is_linux_conf) {
        if (!kernel_override) {
            fprintf(stderr,
                "%s: refind_linux.conf has no kernel path; pass --kernel\n",
                fname);
            return -1;
        }
        while (*p) {
            lineno++;
            char line[MAX_LINE];
            p = next_line(p, line, sizeof(line), fname, lineno);
            if (!p) return -1;

            char *l = trim(line);
            if (!*l || *l == '#') continue;
            const char *lp = l;
            char title[MAX_LINE], opts[MAX_LINE];
            if (read_quoted(&lp, title, sizeof(title)) != 0) {
                fprintf(stderr, "%s:%d: expected \"title\" \"options\"\n",
                        fname, lineno);
                return -1;
            }
            while (*lp == ' ' || *lp == '\t') lp++;
            if (read_quoted(&lp, opts, sizeof(opts)) != 0) {
                fprintf(stderr, "%s:%d: expected \"title\" \"options\"\n",
                        fname, lineno);
                return -1;
            }
            conv_entry_t *e = new_entry(c, fname, lineno);
            if (!e) return -1;
            copy_str(e->name, title, sizeof(e->name));
            copy_str(e->kernel, kernel_override, sizeof(e->kernel));
            if (initrd_override)
                copy_str(e->initrd, initrd_override, sizeof(e->initrd));
            copy_str(e->options, opts, sizeof(e->options));
        }
        return 0;
    }

    conv_entry_t *cur = NULL;

    while (*p) {
        lineno++;
        char line[MAX_LINE];
        p = next_line(p, line, sizeof(line), fname, lineno);
        if (!p) return -1;

        strip_refind_comment(line);
        char *l = trim(line);
        if (*l == '\0') continue;

        if (strchr(l, '$')) {
            fprintf(stderr, "%s:%d: variable expansion is not supported\n",
                    fname, lineno);
            return -1;
        }

        if (strncmp(l, "submenuentry", 12) == 0) {
            fprintf(stderr, "%s:%d: submenuentry is not supported\n",
                    fname, lineno);
            return -1;
        }
        if (strncmp(l, "include ", 8) == 0) {
            fprintf(stderr, "%s:%d: include is not supported\n",
                    fname, lineno);
            return -1;
        }

        if (strncmp(l, "timeout ", 8) == 0) {
            parse_timeout(trim(l + 8), c, fname, lineno);
            continue;
        }
        if (strncmp(l, "default_selection ", 18) == 0) {
            const char *dp = l + 18;
            while (*dp == ' ' || *dp == '\t') dp++;
            char name[MAX_LINE];
            if (*dp == '"' || *dp == '\'') {
                if (read_quoted(&dp, name, sizeof(name)) == 0)
                    set_default(c, name, DEF_INDEX1, DEF_SUBSTR);
            } else if (read_token(&dp, name, sizeof(name)) == 0) {
                set_default(c, name, DEF_INDEX1, DEF_SUBSTR);
            }
            continue;
        }

        if (strncmp(l, "menuentry ", 10) == 0) {
            const char *mp = l + 10;
            while (*mp == ' ' || *mp == '\t') mp++;
            char name[MAX_LINE];
            if (*mp == '"' || *mp == '\'') {
                if (read_quoted(&mp, name, sizeof(name)) != 0) {
                    fprintf(stderr, "%s:%d: bad menuentry name\n",
                            fname, lineno);
                    return -1;
                }
            } else if (read_token(&mp, name, sizeof(name)) != 0) {
                fprintf(stderr, "%s:%d: empty menuentry\n", fname, lineno);
                return -1;
            }
            cur = new_entry(c, fname, lineno);
            if (!cur) return -1;
            copy_str(cur->name, name, sizeof(cur->name));
            continue;
        }

        if (strcmp(l, "}") == 0) {
            cur = NULL;
            continue;
        }

        if (cur) {
            char val[MAX_LINE];
            if (strncmp(l, "loader ", 7) == 0) {
                if (refind_value(l + 7, val, sizeof(val), fname, lineno) != 0)
                    return -1;
                size_t vl = strlen(val);
                if (vl > 4 && strcmp(val + vl - 4, ".efi") == 0) {
                    copy_str(cur->path, val, sizeof(cur->path));
                    copy_str(cur->type, "efi-chainload", sizeof(cur->type));
                } else if (vl) {
                    copy_str(cur->kernel, val, sizeof(cur->kernel));
                }
            } else if (strncmp(l, "initrd ", 7) == 0) {
                if (refind_value(l + 7, val, sizeof(val), fname, lineno) != 0)
                    return -1;
                if (val[0]) copy_str(cur->initrd, val, sizeof(cur->initrd));
            } else if (strncmp(l, "options ", 8) == 0) {
                if (refind_value(l + 8, val, sizeof(val), fname, lineno) != 0)
                    return -1;
                if (val[0]) copy_str(cur->options, val, sizeof(cur->options));
            } else if (strcmp(l, "disabled") == 0) {
                cur->hidden = 1;
            }
        }
    }

    return 0;
}

/* Which entry does the source's default mean? -1 if none. */
static int resolve_default(const conv_config_t *c, const char *fname)
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
    fprintf(stderr, "%s: warning: default '%s' matches no entry; "
            "the first entry will be the default\n", fname, c->default_name);
    return -1;
}

static int emit(ivo_buf_t *o, const conv_config_t *c, const char *source)
{
    static char names[CONV_MAX_ENTRIES][IVO_CFG_MAX_NAME + 1];
    const char *why = NULL;

    if (c->count > IVO_CFG_MAX_ENTRIES) {
        fprintf(stderr, "%s: %d entries; Ivo supports at most %d\n",
                source, c->count, IVO_CFG_MAX_ENTRIES);
        return -1;
    }

    /* Entry names: sanitized the same way for the section header and
     * for `default`, and made unique. */
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

    ivo_buf_puts(o, "# Generated by ivo-convert.\n");
    ivo_buf_puts(o, "# Paths are verbatim from the source; verify with:\n");
    ivo_buf_puts(o, "#     ivo-sign --check --config config.toml --root ROOT\n\n");

    if (c->timeout >= 0)
        ivo_buf_printf(o, "timeout = %d\n", c->timeout);
    int def = resolve_default(c, source);
    if (def >= 0) ivo_toml_kv(o, "default", names[def]);
    ivo_buf_puts(o, "\n");

    for (int i = 0; i < c->count; i++) {
        const conv_entry_t *e = &c->entries[i];
        int chain = e->type[0] && strcmp(e->type, "efi-chainload") == 0;
        const char *what = NULL;

        ivo_buf_printf(o, "[entries.%s]\n", names[i]);

        if (chain) {
            ivo_buf_printf(o, "type = \"%s\"\n", e->type);
            if (!e->path[0]) {
                why = "chainload entry has no loader path";
            } else if ((why = ivo_boot_path_problem(e->path)) ||
                       (why = ivo_toml_kv(o, "path", e->path))) {
                what = e->path;
            }
        } else {
            if (!e->kernel[0]) {
                why = "entry has no kernel";
            } else if ((why = ivo_boot_path_problem(e->kernel)) ||
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
        fprintf(stderr, "ivo-convert: out of memory\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *from = NULL;
    const char *input = NULL;
    const char *output = NULL;
    const char *kernel_override = NULL;
    const char *initrd_override = NULL;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--from")   == 0 && i + 1 < argc) from = argv[++i];
        else if (strcmp(argv[i], "-o")       == 0 && i + 1 < argc) output = argv[++i];
        else if (strcmp(argv[i], "--kernel") == 0 && i + 1 < argc) kernel_override = argv[++i];
        else if (strcmp(argv[i], "--initrd") == 0 && i + 1 < argc) initrd_override = argv[++i];
        else if (!input) input = argv[i];
        else {
            fprintf(stderr, "ivo-convert: unexpected argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!from || !input) {
        fprintf(stderr,
            "usage:\n"
            "  ivo-convert --from grub   INPUT [-o OUTPUT]\n"
            "  ivo-convert --from limine INPUT [-o OUTPUT]\n"
            "  ivo-convert --from refind INPUT [-o OUTPUT] [--kernel K] [--initrd I]\n"
            "\n"
            "INPUT may be '-' for stdin. Without -o, writes to stdout.\n");
        return 1;
    }

    char *src = NULL;
    size_t src_len = 0;
    if (read_input(input, &src, &src_len) != 0) {
        fprintf(stderr, "ivo-convert: %s: %s\n", input,
                errno == EINVAL ? "not a text file" : strerror(errno));
        return 1;
    }

    const char *fname = strcmp(input, "-") == 0 ? "<stdin>" : input;

    conv_config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) { free(src); return 1; }
    cfg->timeout = -1;

    int rc;
    if      (strcmp(from, "grub")   == 0) rc = parse_grub(src, cfg, fname);
    else if (strcmp(from, "limine") == 0) rc = parse_limine(src, cfg, fname);
    else if (strcmp(from, "refind") == 0) rc = parse_refind(src, cfg, fname,
                                                            kernel_override,
                                                            initrd_override);
    else {
        fprintf(stderr, "ivo-convert: unknown --from: %s\n", from);
        free(src); free(cfg);
        return 1;
    }
    free(src);

    if (rc != 0) { free(cfg); return 1; }

    if (cfg->count == 0) {
        fprintf(stderr, "ivo-convert: %s: no entries found\n", fname);
        free(cfg);
        return 1;
    }

    ivo_buf_t out = {0};
    if (emit(&out, cfg, fname) != 0) {
        ivo_buf_free(&out); free(cfg);
        return 1;
    }
    free(cfg);

    /* Self-check with the bootloader's parser. */
    if (config_parse(out.p, out.len) != 0) {
        fprintf(stderr, "ivo-convert: internal error: generated config does "
                "not parse (line %d)\n", config_error_line());
        ivo_buf_free(&out);
        return 1;
    }

    if (output) {
        rc = ivo_write_file(output, out.p, out.len, 0644, IVO_WRITE_KEEP_MODE);
        if (rc != 0)
            fprintf(stderr, "ivo-convert: %s: %s\n", output, strerror(errno));
    } else {
        rc = ivo_write_stdout(out.p, out.len);
        if (rc != 0) fprintf(stderr, "ivo-convert: write error on stdout\n");
    }
    ivo_buf_free(&out);
    return rc == 0 ? 0 : 1;
}
