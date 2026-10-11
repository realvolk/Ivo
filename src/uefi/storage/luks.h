/* luks.h — interface shared by luks_common.c, luks1.c and luks2.c,
 * plus luks_wipe_keys() for the boot path.
 *
 * Freestanding: stdint/stddef only, so the host tests can include it.
 */

#ifndef IVO_LUKS_H
#define IVO_LUKS_H

#include <stddef.h>
#include <stdint.h>

/* Passphrase buffer size, NUL included. cryptsetup's interactive
 * limit is 512 characters; anything that fills the buffer is refused
 * rather than silently truncated. */
#define LUKS_PASS_MAX       512

/* Largest volume key: AES-256-XTS. */
#define LUKS_MAX_KEY        64

/* cryptsetup always writes 4000. Anything up to this bound is merged;
 * 64 KiB stripes of a 64-byte key is 4 MiB of key material. */
#define LUKS_AF_MAX_STRIPES 65536u

/* Hash ids for PBKDF2, AF diffusion and the volume key digest. */
#define LUKS_HASH_SHA1      1
#define LUKS_HASH_SHA256    2

int    luks_hash_id(const char *name);
size_t luks_hash_size(int hash);
int    luks_pbkdf2(int hash, const uint8_t *pw, size_t pw_len,
                   const uint8_t *salt, size_t salt_len, uint32_t iterations,
                   uint8_t *out, size_t out_len);
int    luks_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

/* Read `count` raw 512-byte sectors. */
int    luks_read_raw(uint64_t lba, uint32_t count, uint8_t *buf);

/* Read, XTS-decrypt (512-byte sectors numbered from 0) and AF-merge a
 * keyslot's key material starting at absolute sector `lba`. */
int    luks_keyslot_merge(uint64_t lba,
                          const uint8_t *slot_key, size_t slot_key_len,
                          uint32_t stripes, size_t mk_len, int af_hash,
                          uint8_t *mk_out);
int    af_merge(const uint8_t *area, size_t area_len, uint32_t stripes,
                size_t key_size, int hash, uint8_t *out);

/* Data segment geometry. Call both before luks_setup_crypto. */
void   luks_set_payload(uint64_t part_lba, uint64_t payload_offset_sectors);
int    luks_set_segment(uint32_t sector_size, uint64_t iv_tweak);
int    luks_setup_crypto(const uint8_t *mk, size_t mk_len,
                         const char *cipher_spec);

/* Prompt for a secret (passphrase, PIN). Returns its length, or -1 if
 * it was too long for `cap` (the buffer is wiped in that case). */
int    luks_read_passphrase(const char *label, char *buf, size_t cap);

int    luks_active(void);
/* While suspended, luks_active() reports 0 so filesystem drivers read
 * the raw device: used to access the plaintext ESP after unlock. */
void   luks_suspend(int on);
int    luks_read_block(uint64_t lba, uint8_t *buf);
int    luks_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);
int    luks_get_master_key(uint8_t *out, size_t *len);

/* Wipe the volume key, the XTS key schedules and the sector bounce
 * buffer. LUKS reads fail afterwards. Call right before handing
 * control to the kernel or a chainloaded image. */
void   luks_wipe_keys(void);

#endif
