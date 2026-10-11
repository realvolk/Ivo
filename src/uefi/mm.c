#include "core.h"
#include <stddef.h>

#define SMALL_HEAP_SIZE (1 * 1024 * 1024)
#define BLOCK_ALIGN     16

typedef struct blk {
    size_t      size;      /* total bytes incl. header; multiple of BLOCK_ALIGN */
    struct blk *next;      /* next free block; meaningful when free */
    uint32_t    free;
    uint32_t    _pad;
} __attribute__((aligned(BLOCK_ALIGN))) blk_t;

#define HDR_SIZE  ((size_t)sizeof(blk_t))
#define MIN_BLOCK (HDR_SIZE + BLOCK_ALIGN)

static uint8_t small_heap[SMALL_HEAP_SIZE] __attribute__((aligned(BLOCK_ALIGN)));
static blk_t  *small_free;
static blk_t  *page_free;

static size_t align_up(size_t s)
{
    return (s + BLOCK_ALIGN - 1) & ~(size_t)(BLOCK_ALIGN - 1);
}

static int in_small_heap(const void *p)
{
    const uint8_t *b = p;
    return b >= small_heap && b < small_heap + SMALL_HEAP_SIZE;
}

static void list_insert(blk_t **list, blk_t *b)
{
    blk_t *prev = NULL;
    blk_t *cur  = *list;

    while (cur && (uintptr_t)cur < (uintptr_t)b) {
        prev = cur;
        cur  = cur->next;
    }

    b->next = cur;
    b->free = 1;
    if (prev) prev->next = b;
    else      *list = b;

    if (cur && (uint8_t *)b + b->size == (uint8_t *)cur) {
        b->size += cur->size;
        b->next  = cur->next;
    }
    if (prev && (uint8_t *)prev + prev->size == (uint8_t *)b) {
        prev->size += b->size;
        prev->next  = b->next;
    }
}

static blk_t *list_alloc(blk_t **list, size_t total)
{
    blk_t *prev = NULL;
    blk_t *b    = *list;

    while (b && b->size < total) {
        prev = b;
        b    = b->next;
    }
    if (!b) return NULL;

    size_t rem = b->size - total;
    if (rem >= MIN_BLOCK) {
        blk_t *tail = (blk_t *)((uint8_t *)b + total);
        tail->size  = rem;
        tail->free  = 1;
        tail->next  = b->next;
        if (prev) prev->next = tail;
        else      *list = tail;
        b->size = total;
    } else {
        if (prev) prev->next = b->next;
        else      *list = b->next;
    }

    b->free = 0;
    b->next = NULL;
    return b;
}

void mm_init(boot_context_t *ctx)
{
    (void)ctx;
    small_free = (blk_t *)small_heap;
    small_free->size = SMALL_HEAP_SIZE;
    small_free->free = 1;
    small_free->next = NULL;
    page_free = NULL;
}

void *mm_alloc(size_t size)
{
    if (size == 0) return NULL;
    if (size > SIZE_MAX - HDR_SIZE - BLOCK_ALIGN) return NULL;

    size_t total = align_up(HDR_SIZE + size);

    blk_t *b = list_alloc(&small_free, total);
    if (!b) b = list_alloc(&page_free, total);

    if (!b) {
        size_t pages = (total + 4095) / 4096;
        uint8_t *base = (uint8_t *)hal_allocate_pages(pages);
        if (!base) return NULL;

        size_t actual = pages * 4096;
        for (size_t i = 0; i < actual; i++) base[i] = 0;

        b = (blk_t *)base;
        if (actual > total + MIN_BLOCK) {
            blk_t *tail = (blk_t *)(base + total);
            tail->size = actual - total;
            tail->free = 1;
            tail->next = NULL;
            list_insert(&page_free, tail);
            b->size = total;
        } else {
            b->size = actual;
        }
        b->free = 0;
        b->next = NULL;
    }

    return (uint8_t *)b + HDR_SIZE;
}

void mm_free(void *p)
{
    if (!p) return;

    blk_t *b = (blk_t *)((uint8_t *)p - HDR_SIZE);
    if (b->free) return;

    size_t sz = b->size;
    uint8_t *raw = (uint8_t *)b;
    for (size_t i = HDR_SIZE; i < sz; i++) raw[i] = 0;

    if (in_small_heap(b)) list_insert(&small_free, b);
    else                  list_insert(&page_free, b);
}