/* libc allocator shims for json.c, on top of mm_alloc.
 *
 * mm_alloc is a bump allocator, so free is a no-op. Each block carries
 * its requested size in a 16-byte header (16 keeps the payload as
 * aligned as mm_alloc's own blocks) so realloc copies only what the
 * old block holds.
 */

#include "core.h"
#include <stddef.h>
#include <string.h>

#define MEM_HDR 16

void *malloc(size_t n)
{
    if (n > SIZE_MAX - MEM_HDR) return 0;
    uint8_t *p = mm_alloc(n + MEM_HDR);
    if (!p) return 0;
    *(size_t *)p = n;
    return p + MEM_HDR;
}

void free(void *p)
{
    if (!p) return;
    mm_free((uint8_t *)p - MEM_HDR);
}

void *realloc(void *p, size_t n)
{
    if (!p) return malloc(n);
    size_t old = *(const size_t *)((const uint8_t *)p - MEM_HDR);
    void *q = malloc(n);
    if (!q) return 0;
    memcpy(q, p, old < n ? old : n);
    free(p);
    return q;
}

char *strdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}
