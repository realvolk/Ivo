#ifndef IVO_WIPE_H
#define IVO_WIPE_H

#include <stddef.h>
#include <stdint.h>

/* Zero a buffer holding secret material. The volatile stores and the
 * memory clobber keep the compiler from eliding the wipe as a dead
 * store, which a plain loop or memset before free/return does not. */
static inline void ivo_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
    __asm__ volatile("" : : "r"(p) : "memory");
}

#endif
