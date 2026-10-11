/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Recursive-descent JSON parser and writer. LUKS2's
 * JSON area is the only caller; the writer side exists for the host
 * tooling and isn't linked into the bootloader.
 *
 * The input is attacker-controlled (up to 4 MiB of header) and the
 * allocator never frees, so the parser is bounded: depth 32,
 * 16384 values, 64 KiB per string. A real LUKS2 header has a few
 * hundred values.
 */

#include "luks/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct json_value {
    enum json_type type;
    union {
        int b;
        char *num_str;
        char *str;
        struct {
            struct json_value **items;
            size_t count;
            size_t cap;
        } arr;
        struct {
            char **keys;
            struct json_value **vals;
            size_t count;
            size_t cap;
        } obj;
    } u;
};

#define JSON_MAX_DEPTH  32
#define JSON_MAX_NODES  16384
#define JSON_MAX_STRING 65536

struct parser {
    const char *p;
    const char *end;
    int error;
    int depth;
    size_t nodes;
};

static void skip_ws(struct parser *ps) {
    while (ps->p < ps->end) {
        char c = *ps->p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\0') ps->p++;
        else break;
    }
}

static struct json_value *new_value(enum json_type t) {
    struct json_value *v = malloc(sizeof(*v));
    if (!v) return NULL;
    memset(v, 0, sizeof(*v));
    v->type = t;
    return v;
}

static int utf8_encode(uint32_t cp, char *out) {
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

static int hex4(const char *p, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if      (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (uint32_t)(c - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

static char *parse_string_raw(struct parser *ps) {
    if (ps->p >= ps->end || *ps->p != '"') {
        ps->error = 1;
        return NULL;
    }
    ps->p++;

    size_t cap = 32;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) { ps->error = 1; return NULL; }

    while (ps->p < ps->end) {
        unsigned char c = (unsigned char)*ps->p;
        if (c == '"') {
            ps->p++;
            buf[len] = '\0';
            return buf;
        }
        if (c == '\\') {
            ps->p++;
            if (ps->p >= ps->end) break;
            char e = *ps->p++;
            char tmp[4];
            int n = 0;
            switch (e) {
                case '"':  tmp[0] = '"';  n = 1; break;
                case '\\': tmp[0] = '\\'; n = 1; break;
                case '/':  tmp[0] = '/';  n = 1; break;
                case 'b':  tmp[0] = '\b'; n = 1; break;
                case 'f':  tmp[0] = '\f'; n = 1; break;
                case 'n':  tmp[0] = '\n'; n = 1; break;
                case 'r':  tmp[0] = '\r'; n = 1; break;
                case 't':  tmp[0] = '\t'; n = 1; break;
                case 'u': {
                    if (ps->p + 4 > ps->end) { ps->error = 1; free(buf); return NULL; }
                    uint32_t cp;
                    if (hex4(ps->p, &cp) != 0) { ps->error = 1; free(buf); return NULL; }
                    ps->p += 4;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (ps->p + 6 > ps->end || ps->p[0] != '\\' || ps->p[1] != 'u') {
                            ps->error = 1; free(buf); return NULL;
                        }
                        uint32_t lo;
                        if (hex4(ps->p + 2, &lo) != 0 || lo < 0xDC00 || lo > 0xDFFF) {
                            ps->error = 1; free(buf); return NULL;
                        }
                        ps->p += 6;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        ps->error = 1; free(buf); return NULL;
                    }
                    n = utf8_encode(cp, tmp);
                    break;
                }
                default:
                    ps->error = 1;
                    free(buf);
                    return NULL;
            }
            if (len + (size_t)n >= JSON_MAX_STRING) break;
            while (len + (size_t)n + 1 > cap) {
                cap *= 2;
                char *nb = realloc(buf, cap);
                if (!nb) { ps->error = 1; free(buf); return NULL; }
                buf = nb;
            }
            memcpy(buf + len, tmp, (size_t)n);
            len += (size_t)n;
        } else if (c < 0x20) {
            ps->error = 1;
            free(buf);
            return NULL;
        } else {
            if (len + 1 >= JSON_MAX_STRING) break;
            if (len + 2 > cap) {
                cap *= 2;
                char *nb = realloc(buf, cap);
                if (!nb) { ps->error = 1; free(buf); return NULL; }
                buf = nb;
            }
            buf[len++] = (char)c;
            ps->p++;
        }
    }

    free(buf);
    ps->error = 1;
    return NULL;
}

static struct json_value *parse_value(struct parser *ps);

static struct json_value *parse_object(struct parser *ps) {
    ps->p++;
    struct json_value *v = new_value(JSON_OBJECT);
    if (!v) { ps->error = 1; return NULL; }

    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == '}') {
        ps->p++;
        return v;
    }

    for (;;) {
        skip_ws(ps);
        char *key = parse_string_raw(ps);
        if (!key) { json_free(v); ps->error = 1; return NULL; }

        skip_ws(ps);
        if (ps->p >= ps->end || *ps->p != ':') {
            free(key);
            json_free(v);
            ps->error = 1;
            return NULL;
        }
        ps->p++;

        struct json_value *item = parse_value(ps);
        if (!item) {
            free(key);
            json_free(v);
            ps->error = 1;
            return NULL;
        }

        if (v->u.obj.count == v->u.obj.cap) {
            size_t ncap = v->u.obj.cap ? v->u.obj.cap * 2 : 8;
            char **nk = realloc(v->u.obj.keys, ncap * sizeof(*nk));
            if (!nk) { free(key); json_free(item); json_free(v); ps->error = 1; return NULL; }
            v->u.obj.keys = nk;
            struct json_value **nv = realloc(v->u.obj.vals, ncap * sizeof(*nv));
            if (!nv) { free(key); json_free(item); json_free(v); ps->error = 1; return NULL; }
            v->u.obj.vals = nv;
            v->u.obj.cap = ncap;
        }
        v->u.obj.keys[v->u.obj.count] = key;
        v->u.obj.vals[v->u.obj.count] = item;
        v->u.obj.count++;

        skip_ws(ps);
        if (ps->p >= ps->end) { json_free(v); ps->error = 1; return NULL; }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == '}') { ps->p++; return v; }
        json_free(v);
        ps->error = 1;
        return NULL;
    }
}

static struct json_value *parse_array(struct parser *ps) {
    ps->p++;
    struct json_value *v = new_value(JSON_ARRAY);
    if (!v) { ps->error = 1; return NULL; }

    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == ']') {
        ps->p++;
        return v;
    }

    for (;;) {
        skip_ws(ps);
        struct json_value *item = parse_value(ps);
        if (!item) { json_free(v); ps->error = 1; return NULL; }

        if (v->u.arr.count == v->u.arr.cap) {
            size_t ncap = v->u.arr.cap ? v->u.arr.cap * 2 : 8;
            struct json_value **ni = realloc(v->u.arr.items, ncap * sizeof(*ni));
            if (!ni) { json_free(item); json_free(v); ps->error = 1; return NULL; }
            v->u.arr.items = ni;
            v->u.arr.cap = ncap;
        }
        v->u.arr.items[v->u.arr.count++] = item;

        skip_ws(ps);
        if (ps->p >= ps->end) { json_free(v); ps->error = 1; return NULL; }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == ']') { ps->p++; return v; }
        json_free(v);
        ps->error = 1;
        return NULL;
    }
}

static struct json_value *parse_number(struct parser *ps) {
    const char *start = ps->p;
    if (ps->p < ps->end && *ps->p == '-') ps->p++;
    if (ps->p >= ps->end) { ps->error = 1; return NULL; }
    if (*ps->p == '0') {
        ps->p++;
    } else if (*ps->p >= '1' && *ps->p <= '9') {
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    } else {
        ps->error = 1;
        return NULL;
    }
    if (ps->p < ps->end && *ps->p == '.') {
        ps->p++;
        if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') { ps->error = 1; return NULL; }
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }
    if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
        ps->p++;
        if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-')) ps->p++;
        if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') { ps->error = 1; return NULL; }
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }

    size_t n = (size_t)(ps->p - start);
    char *s = malloc(n + 1);
    if (!s) { ps->error = 1; return NULL; }
    memcpy(s, start, n);
    s[n] = '\0';

    struct json_value *v = new_value(JSON_NUMBER);
    if (!v) { free(s); ps->error = 1; return NULL; }
    v->u.num_str = s;
    return v;
}

static struct json_value *parse_literal(struct parser *ps, const char *lit, enum json_type t) {
    size_t n = strlen(lit);
    if ((size_t)(ps->end - ps->p) < n || memcmp(ps->p, lit, n) != 0) {
        ps->error = 1;
        return NULL;
    }
    ps->p += n;
    struct json_value *v = new_value(t);
    if (!v) { ps->error = 1; return NULL; }
    if (t == JSON_BOOL) v->u.b = (lit[0] == 't');
    return v;
}

static struct json_value *parse_value(struct parser *ps) {
    if (ps->depth >= JSON_MAX_DEPTH || ps->nodes >= JSON_MAX_NODES) {
        ps->error = 1;
        return NULL;
    }
    ps->depth++;
    ps->nodes++;

    struct json_value *result = NULL;

    skip_ws(ps);
    if (ps->p >= ps->end) {
        ps->error = 1;
    } else {
        char c = *ps->p;
        if (c == '{') {
            result = parse_object(ps);
        } else if (c == '[') {
            result = parse_array(ps);
        } else if (c == '"') {
            char *s = parse_string_raw(ps);
            if (s) {
                struct json_value *v = new_value(JSON_STRING);
                if (!v) {
                    free(s);
                    ps->error = 1;
                } else {
                    v->u.str = s;
                    result = v;
                }
            }
        } else if (c == '-' || (c >= '0' && c <= '9')) {
            result = parse_number(ps);
        } else if (c == 't') {
            result = parse_literal(ps, "true", JSON_BOOL);
        } else if (c == 'f') {
            result = parse_literal(ps, "false", JSON_BOOL);
        } else if (c == 'n') {
            result = parse_literal(ps, "null", JSON_NULL);
        } else {
            ps->error = 1;
        }
    }

    ps->depth--;
    return result;
}

int json_parse(const char *text, size_t len, struct json_value **out) {
    *out = NULL;
    struct parser ps = { .p = text, .end = text + len, .error = 0, .depth = 0,
                         .nodes = 0 };
    struct json_value *v = parse_value(&ps);
    if (!v) {
        return -1;
    }
    skip_ws(&ps);
    if (ps.p != ps.end) {
        json_free(v);
        return -1;
    }
    *out = v;
    return 0;
}

void json_free(struct json_value *v) {
    if (!v) return;
    switch (v->type) {
        case JSON_STRING:
            free(v->u.str);
            break;
        case JSON_NUMBER:
            free(v->u.num_str);
            break;
        case JSON_ARRAY:
            for (size_t i = 0; i < v->u.arr.count; i++)
                json_free(v->u.arr.items[i]);
            free(v->u.arr.items);
            break;
        case JSON_OBJECT:
            for (size_t i = 0; i < v->u.obj.count; i++) {
                free(v->u.obj.keys[i]);
                json_free(v->u.obj.vals[i]);
            }
            free(v->u.obj.keys);
            free(v->u.obj.vals);
            break;
        default:
            break;
    }
    free(v);
}

enum json_type json_type(const struct json_value *v) {
    return v ? v->type : JSON_NULL;
}

int json_is_null(const struct json_value *v) {
    return !v || v->type == JSON_NULL;
}

int json_bool(const struct json_value *v) {
    if (!v || v->type != JSON_BOOL) return 0;
    return v->u.b;
}

double json_number(const struct json_value *v) {
    (void)v;
    /* LUKS2 uses no floating-point fields, so this always returns 0. */
    return 0.0;
}

/* Leading digits of a number; 0 for negatives, UINT64_MAX on
 * overflow. Lenient: use json_get_u64 where the value matters. */
uint64_t json_number_u64(const struct json_value *v) {
    if (!v || v->type != JSON_NUMBER) return 0;
    uint64_t r = 0;
    const char *s = v->u.num_str;
    if (*s == '-') return 0;
    while (*s >= '0' && *s <= '9') {
        uint64_t d = (uint64_t)(*s - '0');
        if (r > (UINT64_MAX - d) / 10) return UINT64_MAX;
        r = r * 10 + d;
        s++;
    }
    return r;
}

int json_str_to_u64(const char *s, uint64_t *out) {
    if (!s || !*s) return -1;
    uint64_t r = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        uint64_t d = (uint64_t)(*s - '0');
        if (r > (UINT64_MAX - d) / 10) return -1;
        r = r * 10 + d;
    }
    *out = r;
    return 0;
}

/* A non-negative integer, as a JSON number or as a decimal string
 * (LUKS2 writes 64-bit fields as strings). Fractions, exponents,
 * signs, trailing junk and overflow are errors. */
int json_get_u64(const struct json_value *v, uint64_t *out) {
    if (!v) return -1;
    if (v->type == JSON_NUMBER) return json_str_to_u64(v->u.num_str, out);
    if (v->type == JSON_STRING) return json_str_to_u64(v->u.str, out);
    return -1;
}

const char *json_string(const struct json_value *v) {
    if (!v || v->type != JSON_STRING) return NULL;
    return v->u.str;
}

struct json_value *json_object_get(const struct json_value *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT) return NULL;
    for (size_t i = 0; i < obj->u.obj.count; i++) {
        if (strcmp(obj->u.obj.keys[i], key) == 0)
            return obj->u.obj.vals[i];
    }
    return NULL;
}

size_t json_object_count(const struct json_value *obj) {
    if (!obj || obj->type != JSON_OBJECT) return 0;
    return obj->u.obj.count;
}

const char *json_object_key_at(const struct json_value *obj, size_t idx) {
    if (!obj || obj->type != JSON_OBJECT || idx >= obj->u.obj.count) return NULL;
    return obj->u.obj.keys[idx];
}

struct json_value *json_object_value_at(const struct json_value *obj, size_t idx) {
    if (!obj || obj->type != JSON_OBJECT || idx >= obj->u.obj.count) return NULL;
    return obj->u.obj.vals[idx];
}

size_t json_array_size(const struct json_value *arr) {
    if (!arr || arr->type != JSON_ARRAY) return 0;
    return arr->u.arr.count;
}

struct json_value *json_array_get(const struct json_value *arr, size_t idx) {
    if (!arr || arr->type != JSON_ARRAY) return NULL;
    if (idx >= arr->u.arr.count) return NULL;
    return arr->u.arr.items[idx];
}

struct json_buf {
    char  *p;
    size_t len;
    size_t cap;
    int    overflow;
};

static void jb_putc(struct json_buf *b, char c) {
    if (b->len + 1 > b->cap) { b->overflow = 1; return; }
    b->p[b->len++] = c;
}

static void jb_puts(struct json_buf *b, const char *s, size_t n) {
    if (b->len + n > b->cap) { b->overflow = 1; return; }
    memcpy(b->p + b->len, s, n);
    b->len += n;
}

static void json_write_value(struct json_buf *b, const struct json_value *v) {
    if (!v) { jb_puts(b, "null", 4); return; }

    switch (v->type) {
        case JSON_NULL:
            jb_puts(b, "null", 4);
            break;
        case JSON_BOOL:
            if (v->u.b) jb_puts(b, "true", 4);
            else        jb_puts(b, "false", 5);
            break;
        case JSON_NUMBER:
            jb_puts(b, v->u.num_str, strlen(v->u.num_str));
            break;
        case JSON_STRING: {
            jb_putc(b, '"');
            const char *s = v->u.str;
            for (size_t i = 0; s[i]; i++) {
                unsigned char c = (unsigned char)s[i];
                switch (c) {
                    case '"':  jb_puts(b, "\\\"", 2); break;
                    case '\\': jb_puts(b, "\\\\", 2); break;
                    case '\b': jb_puts(b, "\\b", 2);  break;
                    case '\f': jb_puts(b, "\\f", 2);  break;
                    case '\n': jb_puts(b, "\\n", 2);  break;
                    case '\r': jb_puts(b, "\\r", 2);  break;
                    case '\t': jb_puts(b, "\\t", 2);  break;
                    default:
                        if (c < 0x20) {
                            static const char hex[] = "0123456789abcdef";
                            char esc[6];
                            esc[0] = '\\';
                            esc[1] = 'u';
                            esc[2] = '0';
                            esc[3] = '0';
                            esc[4] = hex[(c >> 4) & 0xF];
                            esc[5] = hex[c & 0xF];
                            jb_puts(b, esc, 6);
                        } else {
                            jb_putc(b, (char)c);
                        }
                }
            }
            jb_putc(b, '"');
            break;
        }
        case JSON_ARRAY:
            jb_putc(b, '[');
            for (size_t i = 0; i < v->u.arr.count; i++) {
                if (i) jb_putc(b, ',');
                json_write_value(b, v->u.arr.items[i]);
            }
            jb_putc(b, ']');
            break;
        case JSON_OBJECT:
            jb_putc(b, '{');
            for (size_t i = 0; i < v->u.obj.count; i++) {
                if (i) jb_putc(b, ',');
                jb_putc(b, '"');
                const char *k = v->u.obj.keys[i];
                for (size_t j = 0; k[j]; j++) {
                    unsigned char c = (unsigned char)k[j];
                    if (c == '"' || c == '\\') jb_putc(b, '\\');
                    jb_putc(b, (char)c);
                }
                jb_putc(b, '"');
                jb_putc(b, ':');
                json_write_value(b, v->u.obj.vals[i]);
            }
            jb_putc(b, '}');
            break;
    }
}

int json_write(const struct json_value *v, char *buf, size_t bufsz, size_t *out_len) {
    struct json_buf b = { .p = buf, .len = 0, .cap = bufsz, .overflow = 0 };
    json_write_value(&b, v);
    if (b.overflow) { return -1; }
    if (out_len) *out_len = b.len;
    return 0;
}

struct json_value *json_new_string(const char *s) {
    struct json_value *v = new_value(JSON_STRING);
    if (!v) return NULL;
    v->u.str = strdup(s);
    if (!v->u.str) { free(v); return NULL; }
    return v;
}

static void u64_to_decimal(char *out, uint64_t n) {
    char tmp[20];
    int i = 0;
    if (n == 0) { out[0] = '0'; out[1] = 0; return; }
    while (n > 0) {
        tmp[i++] = (char)('0' + (n % 10));
        n /= 10;
    }
    int j = 0;
    while (i > 0) out[j++] = tmp[--i];
    out[j] = 0;
}

struct json_value *json_new_string_u64(uint64_t n) {
    char tmp[32];
    u64_to_decimal(tmp, n);
    return json_new_string(tmp);
}

struct json_value *json_new_number_u64(uint64_t n) {
    struct json_value *v = new_value(JSON_NUMBER);
    if (!v) return NULL;
    char tmp[32];
    u64_to_decimal(tmp, n);
    v->u.num_str = strdup(tmp);
    if (!v->u.num_str) { free(v); return NULL; }
    return v;
}

struct json_value *json_new_object(void) {
    return new_value(JSON_OBJECT);
}

struct json_value *json_new_array(void) {
    return new_value(JSON_ARRAY);
}

int json_object_set(struct json_value *obj, const char *key, struct json_value *val) {
    if (!obj || obj->type != JSON_OBJECT || !key) {
        json_free(val);
        return -1;
    }

    for (size_t i = 0; i < obj->u.obj.count; i++) {
        if (strcmp(obj->u.obj.keys[i], key) == 0) {
            json_free(obj->u.obj.vals[i]);
            obj->u.obj.vals[i] = val;
            return 0;
        }
    }

    if (obj->u.obj.count == obj->u.obj.cap) {
        size_t ncap = obj->u.obj.cap ? obj->u.obj.cap * 2 : 8;
        char **nk = realloc(obj->u.obj.keys, ncap * sizeof(*nk));
        if (!nk) { json_free(val); return -1; }
        obj->u.obj.keys = nk;
        struct json_value **nv = realloc(obj->u.obj.vals, ncap * sizeof(*nv));
        if (!nv) { json_free(val); return -1; }
        obj->u.obj.vals = nv;
        obj->u.obj.cap = ncap;
    }

    char *kdup = strdup(key);
    if (!kdup) { json_free(val); return -1; }
    obj->u.obj.keys[obj->u.obj.count] = kdup;
    obj->u.obj.vals[obj->u.obj.count] = val;
    obj->u.obj.count++;
    return 0;
}

int json_object_remove(struct json_value *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT || !key) {
        return -1;
    }

    for (size_t i = 0; i < obj->u.obj.count; i++) {
        if (strcmp(obj->u.obj.keys[i], key) == 0) {
            free(obj->u.obj.keys[i]);
            json_free(obj->u.obj.vals[i]);
            memmove(&obj->u.obj.keys[i], &obj->u.obj.keys[i + 1],
                    (obj->u.obj.count - i - 1) * sizeof(char *));
            memmove(&obj->u.obj.vals[i], &obj->u.obj.vals[i + 1],
                    (obj->u.obj.count - i - 1) * sizeof(struct json_value *));
            obj->u.obj.count--;
            return 0;
        }
    }

    return -1;
}

int json_array_append(struct json_value *arr, struct json_value *val) {
    if (!arr || arr->type != JSON_ARRAY) {
        json_free(val);
        return -1;
    }

    if (arr->u.arr.count == arr->u.arr.cap) {
        size_t ncap = arr->u.arr.cap ? arr->u.arr.cap * 2 : 8;
        struct json_value **ni = realloc(arr->u.arr.items, ncap * sizeof(*ni));
        if (!ni) { json_free(val); return -1; }
        arr->u.arr.items = ni;
        arr->u.arr.cap = ncap;
    }

    arr->u.arr.items[arr->u.arr.count++] = val;
    return 0;
}

int json_array_remove_at(struct json_value *arr, size_t idx) {
    if (!arr || arr->type != JSON_ARRAY || idx >= arr->u.arr.count) {
        return -1;
    }

    json_free(arr->u.arr.items[idx]);
    memmove(&arr->u.arr.items[idx], &arr->u.arr.items[idx + 1],
            (arr->u.arr.count - idx - 1) * sizeof(struct json_value *));
    arr->u.arr.count--;
    return 0;
}