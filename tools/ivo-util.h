/* Shared helpers for the host tools: whole-file I/O, crash-safe
 * writes, boot-path handling, SHA-512, and TOML value emission that
 * stays inside config.c's grammar. Host-only. */

#ifndef IVO_TOOLS_UTIL_H
#define IVO_TOOLS_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define IVO_HASH_HEX_LEN   128
#define IVO_CFG_MAX_LINE   4095
#define IVO_CFG_MAX_NAME   255
#define IVO_CFG_MAX_ENTRIES 16
int ivo_read_file(const char *path, size_t max, uint8_t **out, size_t *len);
int ivo_read_fd(int fd, size_t max, uint8_t **out, size_t *len);

#define IVO_WRITE_NOCLOBBER  0x1   /* fail with EEXIST if path exists  */
#define IVO_WRITE_KEEP_MODE  0x2   /* keep an existing file's mode/owner */

int ivo_write_file(const char *path, const void *data, size_t len,
                   mode_t mode, int flags);
int ivo_write_stdout(const void *data, size_t len);
const char *ivo_boot_path_problem(const char *path);
int ivo_open_beneath(const char *root, const char *subdir,
                     const char *path, char *err, size_t err_size);
void ivo_sha512_hex(const uint8_t *data, size_t len,
                    char out[IVO_HASH_HEX_LEN + 1]);
int  ivo_sha512_fd(int fd, char out[IVO_HASH_HEX_LEN + 1]);


typedef struct {
    char  *p;
    size_t len;
    size_t cap;
    int    failed;      /* sticky: an append ran out of memory */
} ivo_buf_t;

void ivo_buf_append(ivo_buf_t *b, const char *s, size_t n);
void ivo_buf_puts(ivo_buf_t *b, const char *s);
void ivo_buf_printf(ivo_buf_t *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void ivo_buf_free(ivo_buf_t *b);

const char *ivo_toml_kv(ivo_buf_t *b, const char *key, const char *value);
int ivo_entry_name(const char *in, char *out, size_t out_size);
int ivo_parse_uint(const char *s, unsigned long max, unsigned long *out);

int ivo_read_efi_flags(const char *path, char *out, size_t out_size);
int ivo_find_esp(char *out, size_t out_size);
#endif
