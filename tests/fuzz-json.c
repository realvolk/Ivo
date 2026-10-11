/* Fuzz target for the LUKS2 JSON parser (src/uefi/luks/json.c).
 *
 * libFuzzer + ASan, parser only, libc allocator:
 *
 *   clang -g -O1 -fsanitize=fuzzer,address -Isrc/uefi \
 *       tests/fuzz-json.c src/uefi/luks/json.c -o fuzz-json
 *
 * Against the bootloader's allocator shims (luks/mem.c: size-header
 * realloc, no-op free), as a standalone driver that parses each file
 * named on the command line:
 *
 *   cc -g -O1 -fsanitize=undefined -DFUZZ_JSON_STANDALONE -DFUZZ_JSON_MEMC \
 *       -Itests -Isrc/uefi -Isrc/uefi/include \
 *       tests/fuzz-json.c src/uefi/luks/json.c src/uefi/luks/mem.c \
 *       -o fuzz-json-memc
 *
 * mem.c defines malloc/realloc/free itself, so it can't be combined
 * with ASan or libFuzzer, which interpose the same symbols.
 */

#include <stdint.h>
#include <stddef.h>
#include "luks/json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct json_value *v = NULL;
    if (json_parse((const char *)data, size, &v) == 0)
        json_free(v);
    return 0;
}

#ifdef FUZZ_JSON_MEMC
/* mem.c's backing store. glibc's calloc does not call malloc, so this
 * does not recurse into mem.c. */
void *calloc(size_t n, size_t m);
void *mm_alloc(size_t n) { return calloc(1, n); }
void  mm_free(void *p)   { (void)p; }
#endif

#ifdef FUZZ_JSON_STANDALONE
#include <stdio.h>

int main(int argc, char **argv)
{
    static uint8_t buf[4 << 20];
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); return 1; }
        size_t n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, n);
    }
    return 0;
}
#endif
