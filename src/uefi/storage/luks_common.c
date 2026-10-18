/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. Shared LUKS state, PBKDF2 dispatch, keyslot material
 * handling, the anti-forensic merge primitive and the data read path.
 * The per-version header parsing lives in luks1.c and luks2.c.
 */

#ifdef CONFIG_HOST
#include "luks1-test.h"
#else
#include "core.h"
#endif
#include "storage/luks.h"
#include "security/wipe.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/pbkdf2.h"
#include "crypto/xts.h"

static uint8_t master_key[LUKS_MAX_KEY];
static size_t  master_key_len;
static int     luks_initialized;

static uint64_t luks_part_lba;
static uint64_t luks_payload_offset;
static uint32_t luks_sector_size = 512;  /* crypto data unit, bytes */
static uint64_t luks_iv_tweak;           /* dm-crypt iv_offset, 512-byte units */
static struct xts_ctx luks_xts;
static int     luks_xts_ready;
static int     luks_suspended;
static uint8_t luks_unit[4096];

int luks_hash_id(const char *name)
{
    if (!name) return -1;
    if (strcmp(name, "sha256") == 0) return LUKS_HASH_SHA256;
    if (strcmp(name, "sha1") == 0)   return LUKS_HASH_SHA1;
    return -1;
}

size_t luks_hash_size(int hash)
{
    if (hash == LUKS_HASH_SHA256) return SHA256_DIGEST_SIZE;
    if (hash == LUKS_HASH_SHA1)   return SHA1_DIGEST_SIZE;
    return 0;
}

int luks_pbkdf2(int hash, const uint8_t *pw, size_t pw_len,
                const uint8_t *salt, size_t salt_len, uint32_t iterations,
                uint8_t *out, size_t out_len)
{
    if (hash == LUKS_HASH_SHA256)
        return pbkdf2_hmac_sha256(pw, pw_len, salt, salt_len,
                                  iterations, out, out_len);
    if (hash == LUKS_HASH_SHA1)
        return pbkdf2_hmac_sha1(pw, pw_len, salt, salt_len,
                                iterations, out, out_len);
    return -1;
}

int luks_ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

int luks_read_raw(uint64_t lba, uint32_t count, uint8_t *buf)
{
    return hal_read_blocks(lba, count, buf);
}

static void af_diffuse(uint8_t *buf, size_t size, int hash)
{
    size_t ds = luks_hash_size(hash);
    uint8_t d[SHA256_DIGEST_SIZE];

    for (size_t off = 0, i = 0; off < size; off += ds, i++) {
        size_t n = size - off < ds ? size - off : ds;
        uint8_t ctr[4] = {
            (uint8_t)(i >> 24), (uint8_t)(i >> 16),
            (uint8_t)(i >> 8),  (uint8_t)i
        };
        if (hash == LUKS_HASH_SHA1) {
            struct sha1_ctx c;
            sha1_init(&c);
            sha1_update(&c, ctr, 4);
            sha1_update(&c, buf + off, n);
            sha1_final(&c, d);           /* wipes c */
        } else {
            struct sha256_ctx c;
            sha256_init(&c);
            sha256_update(&c, ctr, 4);
            sha256_update(&c, buf + off, n);
            sha256_final(&c, d);         /* wipes c */
        }
        memcpy(buf + off, d, n);
    }
    ivo_wipe(d, sizeof(d));
}

int af_merge(const uint8_t *area, size_t area_len, uint32_t stripes,
             size_t key_size, int hash, uint8_t *out)
{
    if (stripes < 1 || stripes > LUKS_AF_MAX_STRIPES) return -1;
    if (key_size == 0 || key_size > LUKS_MAX_KEY) return -1;
    if (luks_hash_size(hash) == 0) return -1;
    if ((uint64_t)stripes * key_size > area_len) return -1;

    uint8_t buf[LUKS_MAX_KEY];
    memset(buf, 0, sizeof(buf));

    for (uint32_t i = 0; i + 1 < stripes; i++) {
        const uint8_t *block = area + (size_t)i * key_size;
        for (size_t j = 0; j < key_size; j++) buf[j] ^= block[j];
        af_diffuse(buf, key_size, hash);
    }

    const uint8_t *last = area + (size_t)(stripes - 1) * key_size;
    for (size_t j = 0; j < key_size; j++) out[j] = last[j] ^ buf[j];

    ivo_wipe(buf, sizeof(buf));
    return 0;
}

int luks_keyslot_merge(uint64_t lba,
                       const uint8_t *slot_key, size_t slot_key_len,
                       uint32_t stripes, size_t mk_len, int af_hash,
                       uint8_t *mk_out)
{
    if (stripes < 1 || stripes > LUKS_AF_MAX_STRIPES) return -1;
    if (mk_len == 0 || mk_len > LUKS_MAX_KEY) return -1;
    uint64_t bytes   = (uint64_t)stripes * mk_len;
    uint32_t sectors = (uint32_t)((bytes + 511) / 512);
    size_t   alloc   = (size_t)sectors * 512;

    uint8_t *m = (uint8_t *)mm_alloc(alloc);
    if (!m) return -1;

    int rc = -1;
    struct xts_ctx xts;
    if (luks_read_raw(lba, sectors, m) == 0 &&
        xts_init(&xts, slot_key, slot_key_len) == 0) {
        rc = 0;
        for (uint32_t s = 0; s < sectors && rc == 0; s++) {
            uint8_t *p = m + (size_t)s * 512;
            rc = xts_decrypt_sector(&xts, s, p, p, 512);
        }
        xts_clear(&xts);
        if (rc == 0)
            rc = af_merge(m, (size_t)bytes, stripes, mk_len, af_hash, mk_out);
    }

    ivo_wipe(m, alloc);
    mm_free(m);
    return rc;
}

#ifdef CONFIG_HOST
int luks_enabled(void) { return 1; }
#else
int luks_enabled(boot_context_t *ctx)
{
#ifdef LUKS
    if (!ctx) return 0;
    uint8_t hdr[512];
    if (hal_read_blocks(ctx->boot_lba, 1, hdr) != 0) return 0;
    return memcmp(hdr, "LUKS\xBA\xBE", 6) == 0;
#else
    (void)ctx;
    return 0;
#endif
}
#endif

int luks_read_passphrase(const char *label, char *buf, size_t cap)
{
    int n = con_read_secret(label, buf, cap, '*');
    if (n < 0 || (size_t)n + 1 >= cap) {
        ivo_wipe(buf, cap);
        con_puts("Input too long.\n");
        return -1;
    }
    return n;
}

void luks_set_payload(uint64_t part_lba, uint64_t payload_offset_sectors)
{
    luks_part_lba       = part_lba;
    luks_payload_offset = payload_offset_sectors;
}

int luks_set_segment(uint32_t sector_size, uint64_t iv_tweak)
{
    if (sector_size != 512 && sector_size != 1024 &&
        sector_size != 2048 && sector_size != 4096) return -1;
    luks_sector_size = sector_size;
    luks_iv_tweak    = iv_tweak;
    return 0;
}

int luks_setup_crypto(const uint8_t *mk, size_t mk_len, const char *cipher_spec)
{
    luks_wipe_keys();
    if (!cipher_spec || strcmp(cipher_spec, "aes-xts-plain64") != 0) {
        con_puts("LUKS: unsupported cipher (need aes-xts-plain64)\n");
        return -1;
    }
    if (mk_len != 32 && mk_len != 64) return -1;

    if (xts_init(&luks_xts, mk, mk_len) != 0) return -1;
    memcpy(master_key, mk, mk_len);
    master_key_len   = mk_len;
    luks_initialized = 1;
    luks_xts_ready   = 1;
    return 0;
}

void luks_wipe_keys(void)
{
    luks_initialized = 0;
    luks_xts_ready   = 0;
    master_key_len   = 0;
    ivo_wipe(master_key, sizeof(master_key));
    ivo_wipe(&luks_xts, sizeof(luks_xts));
    ivo_wipe(luks_unit, sizeof(luks_unit));
}

static int decrypt_unit(uint64_t unit, uint8_t *p)
{
    uint32_t spu = luks_sector_size / 512;
    uint64_t iv  = unit * spu + luks_iv_tweak;
    return xts_decrypt_sector(&luks_xts, iv, p, p, luks_sector_size);
}

int luks_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf)
{
    if (!luks_active()) return -1;

    uint32_t spu  = luks_sector_size / 512;
    uint64_t base = luks_part_lba + luks_payload_offset;

    while (count) {
        uint64_t unit = lba / spu;
        uint32_t skip = (uint32_t)(lba % spu);

        if (skip == 0 && count >= spu) {
            uint32_t n = count - count % spu;
            if (n > 8192) n = 8192;
            if (hal_read_blocks(base + lba, n, buf) != 0) return -1;
            for (uint32_t u = 0; u < n / spu; u++) {
                if (decrypt_unit(unit + u, buf + (size_t)u * luks_sector_size) != 0)
                    return -1;
            }
            lba += n; count -= n; buf += (size_t)n * 512;
        } else {
            uint32_t n = spu - skip;
            if (n > count) n = count;
            if (hal_read_blocks(base + unit * spu, spu, luks_unit) != 0) return -1;
            if (decrypt_unit(unit, luks_unit) != 0) return -1;
            memcpy(buf, luks_unit + (size_t)skip * 512, (size_t)n * 512);
            lba += n; count -= n; buf += (size_t)n * 512;
        }
    }
    return 0;
}

int luks_read_block(uint64_t lba, uint8_t *buf)
{
    return luks_read_blocks(lba, 1, buf);
}

int luks_active(void)
{
    return luks_initialized && luks_xts_ready && !luks_suspended;
}

void luks_suspend(int on)
{
    luks_suspended = on;
}

#ifndef CONFIG_HOST
int luks_unlock(boot_context_t *ctx)
{
    extern int luks2_unlock(boot_context_t *ctx);
    extern int luks1_unlock(boot_context_t *ctx);

    uint8_t hdr[512];
    if (hal_read_blocks(ctx->boot_lba, 1, hdr) != 0) return -1;
    if (memcmp(hdr, "LUKS\xBA\xBE", 6) != 0) return -1;

    uint16_t version = (uint16_t)((hdr[6] << 8) | hdr[7]);
    if (version == 2) return luks2_unlock(ctx);
    if (version == 1) return luks1_unlock(ctx);
    return -1;
}

int luks_unlock_with_passphrase(boot_context_t *ctx,
                                const uint8_t *pass, size_t pass_len)
{
    uint8_t hdr[512];
    if (hal_read_blocks(ctx->boot_lba, 1, hdr) != 0) return -1;
    if (memcmp(hdr, "LUKS\xBA\xBE", 6) != 0) return -1;

    uint16_t version = (uint16_t)((hdr[6] << 8) | hdr[7]);
    if (version == 2) return luks2_unlock_with_passphrase(ctx, pass, pass_len);
    if (version == 1) return luks1_unlock_with_passphrase(ctx, pass, pass_len);
    return -1;
}
#endif /* !CONFIG_HOST */

int luks_get_master_key(uint8_t *out, size_t *len)
{
    if (!luks_initialized || !out || !len) return -1;
    if (*len < master_key_len) return -1;
    memcpy(out, master_key, master_key_len);
    *len = master_key_len;
    return 0;
}
