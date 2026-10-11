/* Shared helpers for the host tools: whole-file I/O, crash-safe
 * writes, boot-path handling, SHA-512, and TOML value emission that
 * stays inside config.c's grammar. Host-only. */

#ifndef IVO_TOOLS_UTIL_H
#define IVO_TOOLS_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define IVO_HASH_HEX_LEN   128
/* config.c: MAX_LINE is 4096 including the terminator. */
#define IVO_CFG_MAX_LINE   4095
/* config.c: section and default names are < MAX_PATH (256). */
#define IVO_CFG_MAX_NAME   255
/* config.c: MAX_ENTRIES. */
#define IVO_CFG_MAX_ENTRIES 16


/* Read a whole regular file (at most `max` bytes). The buffer is
 * NUL-terminated one past `*len`. Returns 0, or -1 with errno set. */
int ivo_read_file(const char *path, size_t max, uint8_t **out, size_t *len);

/* Read everything from an already-open fd (regular file or pipe). */
int ivo_read_fd(int fd, size_t max, uint8_t **out, size_t *len);

#define IVO_WRITE_NOCLOBBER  0x1   /* fail with EEXIST if path exists  */
#define IVO_WRITE_KEEP_MODE  0x2   /* keep an existing file's mode/owner */

/* Crash-safe write. Default: temp file in the same directory, fsync,
 * rename over `path`, fsync the directory. With IVO_WRITE_NOCLOBBER:
 * O_CREAT|O_EXCL|O_NOFOLLOW directly at `path`, removed again on any
 * error. Refuses to replace a symlink. Returns 0, or -1 with errno. */
int ivo_write_file(const char *path, const void *data, size_t len,
                   mode_t mode, int flags);

/* Write to stdout and confirm it reached the fd. */
int ivo_write_stdout(const void *data, size_t len);


/* Check a path as the bootloader sees it: absolute, no "." / ".."
 * components, no empty components, no control bytes. Returns NULL if
 * fine, or a reason. */
const char *ivo_boot_path_problem(const char *path);

/* Open `path` (a boot path) beneath `root`, optionally beneath
 * `root/subdir` first. Every component is opened with O_NOFOLLOW, so
 * a symlink anywhere below root is refused — the bootloader's
 * filesystem drivers do not follow symlinks either. The final
 * component must be a regular file. Returns an fd, or -1 with a
 * message in `err`. */
int ivo_open_beneath(const char *root, const char *subdir,
                     const char *path, char *err, size_t err_size);


void ivo_sha512_hex(const uint8_t *data, size_t len,
                    char out[IVO_HASH_HEX_LEN + 1]);
/* Stream an fd to EOF. Returns 0 or -1 with errno. */
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


/* Append `key = "value"\n`. The grammar has no escapes, so the value
 * is quoted with whichever of " or ' it does not contain. Fails (and
 * appends nothing) if it contains both, contains a control byte, or
 * the line would exceed IVO_CFG_MAX_LINE. Returns NULL or a reason. */
const char *ivo_toml_kv(ivo_buf_t *b, const char *key, const char *value);

/* Map an arbitrary title to an entry name config.c accepts and that
 * survives as a `default = "..."` value: [A-Za-z0-9._+-], everything
 * else becomes '_'. Truncated to fit `out` (and the 255-byte limit).
 * Returns -1 if the result would be empty. */
int ivo_entry_name(const char *in, char *out, size_t out_size);

/* Parse a non-negative decimal no larger than `max`. */
int ivo_parse_uint(const char *s, unsigned long max, unsigned long *out);

#endif
