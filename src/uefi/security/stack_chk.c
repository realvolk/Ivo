#include <stdint.h>

uintptr_t __stack_chk_guard = 0;

void panic(const char *msg) __attribute__((noreturn));
void __stack_chk_fail(void) { panic("stack smashing detected"); }

void stack_chk_init(void)
{
    uint32_t lo = 0, hi = 0;
    uint8_t  ok = 0;

    uint32_t a = 1, b = 0, c = 0, d = 0;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d) : : "memory");
    if (c & (1u << 30)) {
        for (int i = 0; i < 10 && !ok; i++)
            __asm__ volatile("rdrand %0; setc %1" : "=r"(lo), "=qm"(ok));
    }
    if (!ok) {
        __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
        lo ^= hi;
        lo = (lo << 13) | (lo >> 19);
        lo *= 0x9E3779B1u;
    }
    __stack_chk_guard = (uintptr_t)lo;
}