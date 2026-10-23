/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. LUKS1 keyslot unlock.
 *
 * Header fields are big-endian. Keyslot material offset is absolute
 * from the partition start, not relative to payload_offset.
 *
 * hash_spec names one hash for everything: the keyslot PBKDF2, the
 * AF diffusion and the MK digest (PBKDF2 over the merged key,
 * truncated to 20 bytes). sha1 and sha256 are supported. LUKS1 never
 * uses Argon2.
 */

#ifdef CONFIG_HOST
#include "luks1-test.h"
#else
#include "core.h"
#endif
#include "storage/luks.h"
#include "security/wipe.h"

#define LUKS1_KEY_ENABLED   0x00AC71F3u
#define LUKS1_DIGEST_SIZE   20
#define LUKS1_SALT_SIZE     32
#define LUKS_MAX_PBKDF2_ITERS (16u * 1024 * 1024)

#pragma pack(push, 1)
typedef struct {
    char     magic[6];
    uint16_t version;
    char     cipher_name[32];
    char     cipher_mode[32];
    char     hash_spec[32];
    uint32_t payload_offset;
    uint32_t key_bytes;
    uint8_t  mk_digest[LUKS1_DIGEST_SIZE];
    uint8_t  mk_digest_salt[LUKS1_SALT_SIZE];
    uint32_t mk_digest_iter;
    char     uuid[40];
    struct {
        uint32_t active;
        uint32_t iterations;
        uint8_t  salt[LUKS1_SALT_SIZE];
        uint32_t key_material_offset;
        uint32_t stripes;
    } keyslot[8];
} luks1_header_t;
#pragma pack(pop)

static uint16_t be16(uint16_t v)
{
    return (uint16_t)((v >> 8) | (v << 8));
}

static uint32_t be32(uint32_t v)
{
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) <<  8) |
           ((v & 0x00FF0000u) >>  8) |
           ((v & 0xFF000000u) >> 24);
}
static int field_eq(const char *field, size_t width, const char *s)
{
    size_t n = strlen(s);
    if (n >= width || memcmp(field, s, n) != 0) return 0;
    return field[n] == '\0';
}

int luks1_unlock_with_passphrase(boot_context_t *ctx,
                                 const uint8_t *pass, size_t pass_len)
{
    uint8_t raw[1024];
    luks1_header_t hdr;
    if (hal_read_blocks(ctx->boot_lba, 2, raw) != 0) return -1;
    memcpy(&hdr, raw, sizeof(hdr));
    if (memcmp(hdr.magic, "LUKS\xBA\xBE", 6) != 0) return -1;

    hdr.version          = be16(hdr.version);
    hdr.payload_offset   = be32(hdr.payload_offset);
    hdr.key_bytes        = be32(hdr.key_bytes);
    hdr.mk_digest_iter   = be32(hdr.mk_digest_iter);
    for (int s = 0; s < 8; s++) {
        hdr.keyslot[s].active              = be32(hdr.keyslot[s].active);
        hdr.keyslot[s].iterations          = be32(hdr.keyslot[s].iterations);
        hdr.keyslot[s].key_material_offset = be32(hdr.keyslot[s].key_material_offset);
        hdr.keyslot[s].stripes             = be32(hdr.keyslot[s].stripes);
    }
    if (hdr.version != 1) return -1;
    if (!field_eq(hdr.cipher_name, sizeof(hdr.cipher_name), "aes") ||
        !field_eq(hdr.cipher_mode, sizeof(hdr.cipher_mode), "xts-plain64") ||
        (hdr.key_bytes != 32 && hdr.key_bytes != 64)) {
        con_puts("LUKS1: unsupported cipher (need aes-xts-plain64)\n");
        return -1;
    }

    int hash = -1;
    if (field_eq(hdr.hash_spec, sizeof(hdr.hash_spec), "sha256"))
        hash = LUKS_HASH_SHA256;
    else if (field_eq(hdr.hash_spec, sizeof(hdr.hash_spec), "sha1"))
        hash = LUKS_HASH_SHA1;
    if (hash < 0) {
        con_puts("LUKS1: unsupported hash (need sha1 or sha256)\n");
        return -1;
    }
    if (hdr.mk_digest_iter == 0 || hdr.mk_digest_iter > LUKS_MAX_PBKDF2_ITERS)
        return -1;
    if (hdr.payload_offset == 0) return -1;

    size_t  key_len = hdr.key_bytes;
    uint8_t slot_key[LUKS_MAX_KEY];
    uint8_t mk[LUKS_MAX_KEY];
    uint8_t dk[LUKS1_DIGEST_SIZE];
    int found = 0;

    for (int slot = 0; slot < 8 && !found; slot++) {
        const uint32_t iters   = hdr.keyslot[slot].iterations;
        const uint32_t stripes = hdr.keyslot[slot].stripes;
        const uint32_t km_off  = hdr.keyslot[slot].key_material_offset;

        if (hdr.keyslot[slot].active != LUKS1_KEY_ENABLED) continue;
        if (iters == 0 || iters > LUKS_MAX_PBKDF2_ITERS) continue;
        if (stripes == 0 || stripes > LUKS_AF_MAX_STRIPES) continue;
        uint64_t km_sectors = ((uint64_t)key_len * stripes + 511) / 512;
        if (km_off < 2) continue;
        if ((uint64_t)km_off + km_sectors > hdr.payload_offset) continue;

        if (luks_pbkdf2(hash, pass, pass_len,
                        hdr.keyslot[slot].salt, LUKS1_SALT_SIZE, iters,
                        slot_key, key_len) != 0)
            continue;

        if (luks_keyslot_merge(ctx->boot_lba + km_off, slot_key, key_len,
                               stripes, key_len, hash, mk) != 0)
            continue;

        if (luks_pbkdf2(hash, mk, key_len,
                        hdr.mk_digest_salt, LUKS1_SALT_SIZE,
                        hdr.mk_digest_iter, dk, sizeof(dk)) == 0 &&
            luks_ct_equal(dk, hdr.mk_digest, sizeof(dk)))
            found = 1;
    }

    ivo_wipe(slot_key, sizeof(slot_key));
    ivo_wipe(dk, sizeof(dk));

    int rc = -1;
    if (found) {
        rc = luks_setup_crypto(mk, key_len, "aes-xts-plain64");
        if (rc == 0) {
            luks_set_payload(ctx->boot_lba, hdr.payload_offset);
            luks_set_segment(512, 0);
        }
    }
    ivo_wipe(mk, sizeof(mk));
    return rc;
}

int luks1_unlock(boot_context_t *ctx)
{
    char passphrase[LUKS_PASS_MAX];
    int n = luks_read_passphrase("Passphrase", passphrase, sizeof(passphrase));
    if (n < 0) return -1;

    int rc = luks1_unlock_with_passphrase(ctx, (uint8_t *)passphrase,
                                          (size_t)n);
    ivo_wipe(passphrase, sizeof(passphrase));
    return rc;
}
