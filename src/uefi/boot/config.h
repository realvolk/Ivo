#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char     *name;
    char     *kernel_path;
    uint8_t  *kernel;
    size_t    kernel_size;
    char     *initrd_path;
    uint8_t  *initrd;
    size_t    initrd_size;
    char     *cmdline;
    uint32_t  code32_start;
    uint32_t  handover_offset;
    uint8_t  *setup_block;
    size_t    setup_size;
    uint8_t   is_chainload;
    char     *chainload_path;
    uint8_t   is_iso_boot;
    uint8_t   has_type;
    char     *iso_label;
    char     *kernel_hash;
    char     *subvol;
    char     *initrd_hash;
    char     *chainload_hash;
    char     *if_exists_path;  /* from `if = "exists(/path)"`, or NULL */
    char     *password_hash;   /* NULL = no password */
    int       hidden;       /* -1 while parsing = not given */
    int       timeout;      /* -1 = use global */
    int       password_proven; /* runtime-only; set on successful prompt */
} entry_t;

/* config_load return codes besides 0. */
#define CONFIG_ERR_READ       (-1)
#define CONFIG_ERR_SIGNATURE  (-2)
#define CONFIG_ERR_PARSE      (-3)

int      config_parse(const char *data, size_t len);
int      config_error_line(void);
/* 1 if every file the entry boots has a hash, 0 otherwise. */
int      config_entry_hashes_complete(const entry_t *e);
entry_t *config_get_entries(int *count);
entry_t *config_get_default(void);
int      config_get_timeout(void);

/* Monotonic config version, from the top-level `version = N` key.
 * Returns -1 when the key is absent; the config then does not
 * participate in rollback protection. */
int      config_get_version(void);

#endif