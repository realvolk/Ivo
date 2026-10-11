#ifndef IVO_ARGON2_INTERNAL_H
#define IVO_ARGON2_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#if defined(__i386__) && !defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void argon2_fill_block_sse2(const void *prev_block,
                            const void *ref_block,
                            void *next_block,
                            int with_xor);

#endif