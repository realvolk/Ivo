#ifndef IVO_LUKS_H
#define IVO_LUKS_H

#include <stddef.h>
#include <stdint.h>

#define LUKS_PASS_MAX       512
#define LUKS_MAX_KEY        64
#define LUKS_AF_MAX_STRIPES 65536u
#define LUKS_HASH_SHA1      1
#define LUKS_HASH_SHA256    2

int    luks_hash_id(const char *name);
size_t luks_hash_size(int hash);
int    luks_pbkdf2(int hash, const uint8_t *pw, size_t pw_len,
                   const uint8_t *salt, size_t salt_len, uint32_t iterations,
                   uint8_t *out, size_t out_len);
int    luks_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);
int    luks_read_raw(uint64_t lba, uint32_t count, uint8_t *buf);
int    luks_keyslot_merge(uint64_t lba,
                          const uint8_t *slot_key, size_t slot_key_len,
                          uint32_t stripes, size_t mk_len, int af_hash,
                          uint8_t *mk_out);
int    af_merge(const uint8_t *area, size_t area_len, uint32_t stripes,
                size_t key_size, int hash, uint8_t *out);
void   luks_set_payload(uint64_t part_lba, uint64_t payload_offset_sectors);
int    luks_set_segment(uint32_t sector_size, uint64_t iv_tweak);
int    luks_setup_crypto(const uint8_t *mk, size_t mk_len,
                         const char *cipher_spec);
int    luks_read_passphrase(const char *label, char *buf, size_t cap);
int    luks_active(void);
void   luks_suspend(int on);
int    luks_read_block(uint64_t lba, uint8_t *buf);
int    luks_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);
int    luks_get_master_key(uint8_t *out, size_t *len);
void   luks_wipe_keys(void);

#endif
