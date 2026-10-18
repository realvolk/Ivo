#ifdef CONFIG_HOST
#include "boot/config.h"
#include <stdlib.h>
#include <string.h>
void *mm_alloc(size_t size);
#else
#include "core.h"
#include "fs/fs.h"
#include "security/secure_boot.h"
#endif
#include "security/password.h"

/* Strict parser. The signing tool links this same file, so the
 * bootloader and ivo-sign can never disagree about what a config
 * means. Anything outside the grammar below is rejected rather than
 * guessed at:
 *
 *   - lines end in "\n" ("\r\n" accepted); no other control bytes
 *   - a line longer than MAX_LINE - 1 bytes is an error, not truncated
 *   - string values are "..." or '...', closed, followed only by
 *     whitespace or a # comment
 *   - timeout is decimal digits, hidden is true/false
 *   - unknown keys, duplicate keys, and duplicate entries are errors
 *   - hash values are empty or exactly 128 lowercase hex digits */

#define MAX_ENTRIES   16
#define MAX_LINE      4096
#define MAX_PATH      256
#define MAX_TIMEOUT   86400

static entry_t entries[MAX_ENTRIES];
static int entry_count;
static char default_name[MAX_PATH];
static int timeout_sec;
static int version_sec;
static int version_given;
static int error_line;

static char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = mm_alloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    char *end = s;
    while (*end) end++;
    while (end > s && (end[-1] == ' ' || end[-1] == '\t')) end--;
    *end = '\0';
    return s;
}

static int rest_is_empty(const char *p)
{
    while (*p == ' ' || *p == '\t') p++;
    return *p == '\0' || *p == '#';
}

static int parse_section(const char *line, char *name_out, size_t name_size)
{
    const char *start = line + 1;
    if (strncmp(start, "entries.", 8) != 0) return -1;
    start += 8;
    const char *end = start;
    while (*end && *end != ']') {
        if (*end == '"' || *end == '\'' || *end == '[') return -1;
        end++;
    }
    if (*end != ']') return -1;
    if (end == start) return -1;
    if ((size_t)(end - start) >= name_size) return -1;
    if (!rest_is_empty(end + 1)) return -1;
    memcpy(name_out, start, end - start);
    name_out[end - start] = '\0';
    return 0;
}

static char *parse_string(char *v)
{
    char quote = v[0];
    if (quote != '"' && quote != '\'') return 0;
    char *s = v + 1;
    char *end = s;
    while (*end && *end != quote) end++;
    if (*end != quote) return 0;
    if (!rest_is_empty(end + 1)) return 0;
    *end = '\0';
    return s;
}

static int parse_uint(const char *v, int max, int *out)
{
    const char *d = v;
    int n = 0;
    if (*d < '0' || *d > '9') return -1;
    while (*d >= '0' && *d <= '9') {
        n = n * 10 + (*d - '0');
        if (n > max) return -1;
        d++;
    }
    if (!rest_is_empty(d)) return -1;
    *out = n;
    return 0;
}

static int parse_bool(const char *v, int *out)
{
    if (strncmp(v, "true", 4) == 0 && rest_is_empty(v + 4)) { *out = 1; return 0; }
    if (strncmp(v, "false", 5) == 0 && rest_is_empty(v + 5)) { *out = 0; return 0; }
    return -1;
}

static int valid_hash(const char *h)
{
    if (h[0] == '\0') return 1;
    size_t n = 0;
    for (; h[n]; n++) {
        char c = h[n];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return n == 128;
}

static int parse_entry_key(entry_t *e, const char *key, char *raw)
{
    char **str_field = 0;
    int is_hash = 0;
    int is_pw   = 0;

    if      (strcmp(key, "kernel")    == 0) str_field = &e->kernel_path;
    else if (strcmp(key, "subvol")    == 0) str_field = &e->subvol;
    else if (strcmp(key, "initrd")    == 0) str_field = &e->initrd_path;
    else if (strcmp(key, "options")   == 0) str_field = &e->cmdline;
    else if (strcmp(key, "iso_label") == 0) str_field = &e->iso_label;
    else if (strcmp(key, "path")      == 0) str_field = &e->chainload_path;
    else if (strcmp(key, "kver")      == 0) { str_field = &e->kernel_hash;    is_hash = 1; }
    else if (strcmp(key, "iver")      == 0) { str_field = &e->initrd_hash;    is_hash = 1; }
    else if (strcmp(key, "cver")      == 0) { str_field = &e->chainload_hash; is_hash = 1; }
    else if (strcmp(key, "password_hash") == 0) { str_field = &e->password_hash; is_pw = 1; }

    if (str_field) {
        if (*str_field) return -1;
        char *v = parse_string(raw);
        if (!v) return -1;
        if (is_hash && !valid_hash(v)) return -1;
        if (is_pw && !password_hash_valid(v)) return -1;
        *str_field = dup_str(v);
        return *str_field ? 0 : -1;
    }

    if (strcmp(key, "type") == 0) {
        if (e->has_type) return -1;
        char *v = parse_string(raw);
        if (!v) return -1;
        if      (strcmp(v, "linux") == 0)         { }
        else if (strcmp(v, "efi-chainload") == 0) e->is_chainload = 1;
        else if (strcmp(v, "iso-boot") == 0)      e->is_iso_boot = 1;
        else return -1;
        e->has_type = 1;
        return 0;
    }
    if (strcmp(key, "if") == 0) {
        /* Only "exists(/path)" is recognised. Everything else is
         * refused: this parser does not guess. */
        if (e->if_exists_path) return -1;
        char *v = parse_string(raw);
        if (!v) return -1;
        if (strncmp(v, "exists(", 7) != 0) return -1;
        size_t n = strlen(v);
        if (n < 9 || v[n - 1] != ')') return -1;
        v[n - 1] = '\0';
        char *path = v + 7;
        if (path[0] != '/') return -1;
        e->if_exists_path = dup_str(path);
        return e->if_exists_path ? 0 : -1;
    }
    if (strcmp(key, "hidden") == 0) {
        if (e->hidden >= 0) return -1;
        return parse_bool(raw, &e->hidden);
    }
    if (strcmp(key, "timeout") == 0) {
        if (e->timeout >= 0) return -1;
        return parse_uint(raw, MAX_TIMEOUT, &e->timeout);
    }
    return -1;
}

static int entry_complete(entry_t *e)
{
    if (e->hidden < 0) e->hidden = 0;
    if (e->is_chainload) {
        if (!e->chainload_path || !e->chainload_path[0]) return -1;
        if (e->kernel_path || e->initrd_path || e->subvol || e->iso_label)
            return -1;
        return 0;
    }
    if (e->chainload_path || e->chainload_hash) return -1;
    if (!e->kernel_path || !e->kernel_path[0]) return -1;
    if (e->is_iso_boot && (!e->iso_label || !e->iso_label[0])) return -1;
    return 0;
}

int config_parse(const char *data, size_t len)
{
    entry_count = 0;
    timeout_sec = 5;
    version_sec = 0;
    version_given = 0;
    default_name[0] = '\0';
    error_line = 0;

    entry_t *current_entry = 0;
    int have_timeout = 0, have_default = 0;
    static char line[MAX_LINE];
    size_t pos = 0;
    int lineno = 0;

    while (pos < len) {
        size_t line_len = 0;
        lineno++;
        error_line = lineno;
        while (pos < len && data[pos] != '\n') {
            unsigned char c = (unsigned char)data[pos];
            if (c == '\r' && pos + 1 < len && data[pos + 1] == '\n') {
                pos++;
                continue;
            }
            if ((c < 0x20 && c != '\t') || c == 0x7F) return -1;
            if (line_len >= MAX_LINE - 1) return -1;
            line[line_len++] = (char)c;
            pos++;
        }
        line[line_len] = '\0';
        if (pos < len) pos++;

        char *l = trim(line);
        if (l[0] == '#' || l[0] == '\0') continue;

        if (l[0] == '[') {
            char name[MAX_PATH];
            if (parse_section(l, name, sizeof(name)) != 0) return -1;
            if (current_entry && entry_complete(current_entry) != 0) return -1;
            for (int i = 0; i < entry_count; i++)
                if (strcmp(entries[i].name, name) == 0) return -1;
            if (entry_count >= MAX_ENTRIES) return -1;
            current_entry = &entries[entry_count++];
            memset(current_entry, 0, sizeof(entry_t));
            current_entry->timeout = -1;
            current_entry->hidden  = -1;
            current_entry->name = dup_str(name);
            if (!current_entry->name) return -1;
            continue;
        }

        char *eq = l;
        while (*eq && *eq != '=') eq++;
        if (*eq != '=') return -1;
        *eq = '\0';
        char *key = trim(l);
        char *raw = trim(eq + 1);
        for (char *k = key; *k; k++)
            if (!((*k >= 'a' && *k <= 'z') || *k == '_')) return -1;

        if (current_entry) {
            if (parse_entry_key(current_entry, key, raw) != 0) return -1;
        } else if (strcmp(key, "timeout") == 0) {
            if (have_timeout++) return -1;
            if (parse_uint(raw, MAX_TIMEOUT, &timeout_sec) != 0) return -1;
        } else if (strcmp(key, "default") == 0) {
            if (have_default++) return -1;
            char *v = parse_string(raw);
            if (!v || strlen(v) >= MAX_PATH) return -1;
            memcpy(default_name, v, strlen(v) + 1);
        } else if (strcmp(key, "version") == 0) {
            if (version_given++) return -1;
            if (parse_uint(raw, 0x7FFFFFFF, &version_sec) != 0) return -1;
        } else {
            return -1;
        }
    }

    if (current_entry && entry_complete(current_entry) != 0) return -1;
    error_line = 0;
    return entry_count > 0 ? 0 : -1;
}

int config_error_line(void)
{
    return error_line;
}

int config_entry_hashes_complete(const entry_t *e)
{
    if (e->is_chainload)
        return e->chainload_hash && e->chainload_hash[0];
    if (!e->kernel_hash || !e->kernel_hash[0]) return 0;
    if (e->initrd_path && e->initrd_path[0] &&
        (!e->initrd_hash || !e->initrd_hash[0]))
        return 0;
    return 1;
}

#ifndef CONFIG_HOST
int config_load(boot_context_t *ctx)
{
    (void)ctx;
    uint8_t *buf = 0;
    size_t len = 0;
    int rc = sb_read_config(&buf, &len);
    if (rc != 0) return rc;
    rc = config_parse((const char *)buf, len);
    mm_free(buf);
    return rc == 0 ? 0 : CONFIG_ERR_PARSE;
}
#endif

entry_t *config_get_entries(int *count)
{
    *count = entry_count;
    return entries;
}

entry_t *config_get_default(void)
{
    if (default_name[0]) {
        for (int i = 0; i < entry_count; i++) {
            if (strcmp(entries[i].name, default_name) == 0) return &entries[i];
        }
    }
    return entry_count > 0 ? &entries[0] : 0;
}

int config_get_timeout(void)
{
    return timeout_sec;
}

int config_get_version(void)
{
    return version_given ? version_sec : -1;
}