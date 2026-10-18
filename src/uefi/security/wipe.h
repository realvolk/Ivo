#ifndef IVO_WIPE_H
#define IVO_WIPE_H

#include <stddef.h>
#include <stdint.h>

static inline void ivo_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
    __asm__ volatile("" : : "r"(p) : "memory");
}

#endif
