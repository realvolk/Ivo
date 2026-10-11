/* Copyright (c) 2026 realvolk (Volk)
 *
 * This file is part of kiska.
 * Distributed under the terms of the CLEAR License v1.
 * See doc/LICENSE in the repository root for the full text.
 *
 * Ported to Ivo. LUKS2 keyslot unlock.
 *
 * Both header copies are read and checksummed; the valid one with the
 * higher seqid wins. Its JSON area is parsed into a tree, then the
 * populated keyslots are tried, high priority first. Binary header
 * fields are big-endian on disk; the JSON is length-delimited by the
 * first NUL and zero-padded to hdr_size - 4096.
 *
 * Every number below comes from an unauthenticated header. Sizes are
 * bounded in 64 bits before anything is narrowed, allocated or read.
 */

#include "core.h"
#include "storage/luks.h"
#include "security/wipe.h"
#include "luks/json.h"
#include "luks/base64.h"
#include "luks/endian.h"
#include "crypto/sha256.h"
#include "crypto/argon2.h"

extern int argon2id(const uint8_t *password, size_t pw_len,
                    const uint8_t *salt, size_t salt_len,
                    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                    uint8_t *output, size_t output_len);

#define LUKS2_BIN_SIZE    4096u
#define LUKS2_HDR_MIN     0x4000u      /* 16 KiB */
#define LUKS2_HDR_MAX     0x400000u    /* 4 MiB */
#define LUKS2_CSUM_OFF    448
#define LUKS2_CSUM_LEN    64
#define LUKS2_AREA_MAX    (16u * 1024 * 1024)

struct luks2_hdr {
    struct json_value *root;
    uint64_t hdr_size;
    uint64_t seqid;
};

struct luks2_seg {
    const char *id;
    uint64_t    offset;        /* bytes from the partition start */
    uint64_t    iv_tweak;      /* 512-byte sectors */
    uint32_t    sector_size;
};

static const struct json_value *jget(const struct json_value *o, const char *k)
{
    return json_object_get(o, k);
}

static int jstr_eq(const struct json_value *o, const char *k, const char *s)
{
    const char *v = json_string(json_object_get(o, k));
    return v && strcmp(v, s) == 0;
}

static int ju64(const struct json_value *o, const char *k, uint64_t *out)
{
    return json_get_u64(json_object_get(o, k), out);
}

static int base64_decode_field(const struct json_value *obj, const char *key,
                               uint8_t *out, size_t *out_len)
{
    const char *b64 = json_string(json_object_get(obj, key));
    if (!b64) return -1;
    size_t n = *out_len;
    if (base64_decode(b64, strlen(b64), out, &n) != 0) return -1;
    *out_len = n;
    return 0;
}

/* Does JSON array `arr` list the numeric id `id` (a decimal string)? */
static int array_lists(const struct json_value *arr, const char *id)
{
    uint64_t want;
    if (json_str_to_u64(id, &want) != 0) return 0;
    for (size_t i = 0; i < json_array_size(arr); i++) {
        uint64_t v;
        if (json_get_u64(json_array_get(arr, i), &v) == 0 && v == want)
            return 1;
    }
    return 0;
}

/* LUKS2 header sizes are powers of two from 16 KiB to 4 MiB. */
static int legal_hdr_size(uint64_t s)
{
    return s >= LUKS2_HDR_MIN && s <= LUKS2_HDR_MAX && (s & (s - 1)) == 0;
}

/* Read and verify one header copy `off` bytes into the partition:
 * magic, version, hdr_size, hdr_offset, csum_alg and the SHA-256
 * checksum over all hdr_size bytes with the checksum field zeroed.
 * Then parse its JSON area. */
static int luks2_read_copy(boot_context_t *ctx, uint64_t off,
                           const char *magic, struct luks2_hdr *hdr)
{
    uint8_t bin[512];
    uint64_t lba = ctx->boot_lba + off / 512;
    if (hal_read_blocks(lba, 1, bin) != 0) return -1;
    if (memcmp(bin, magic, 6) != 0 || be16(bin + 6) != 2) return -1;

    uint64_t size = be64(bin + 8);
    if (!legal_hdr_size(size)) return -1;
    if (off != 0 && size != off) return -1;   /* secondary at hdr_size */
    if (be64(bin + 256) != off) return -1;    /* hdr_offset */
    if (memcmp(bin + 72, "sha256", 7) != 0) return -1;

    uint8_t *buf = (uint8_t *)mm_alloc((size_t)size + 1);
    if (!buf) return -1;

    int rc = -1;
    if (luks_read_raw(lba, (uint32_t)(size / 512), buf) == 0) {
        uint8_t want[SHA256_DIGEST_SIZE], got[SHA256_DIGEST_SIZE];
        memcpy(want, buf + LUKS2_CSUM_OFF, sizeof(want));
        memset(buf + LUKS2_CSUM_OFF, 0, LUKS2_CSUM_LEN);
        sha256(buf, (size_t)size, got);

        if (luks_ct_equal(want, got, sizeof(got))) {
            char *json = (char *)buf + LUKS2_BIN_SIZE;
            size_t max = (size_t)size - LUKS2_BIN_SIZE, len = 0;
            while (len < max && json[len] != '\0') len++;
            if (json_parse(json, len, &hdr->root) == 0) {
                hdr->hdr_size = size;
                hdr->seqid    = be64(bin + 16);
                rc = 0;
            }
        }
    }
    mm_free(buf);
    return rc;
}

static void luks2_free_header(struct luks2_hdr *hdr)
{
    if (hdr->root) json_free(hdr->root);
    hdr->root = 0;
}

static int luks2_load_header(boot_context_t *ctx, struct luks2_hdr *hdr)
{
    struct luks2_hdr pri = { 0, 0, 0 }, sec = { 0, 0, 0 };
    int ok_pri = luks2_read_copy(ctx, 0, "LUKS\xBA\xBE", &pri) == 0;

    /* The secondary sits hdr_size bytes in. Without a usable primary,
     * probe every legal size, as cryptsetup does. Its magic has the
     * four letters reversed: "SKUL\xBA\xBE". */
    int ok_sec = 0;
    for (uint64_t s = LUKS2_HDR_MIN; s <= LUKS2_HDR_MAX && !ok_sec; s <<= 1) {
        if (ok_pri && s != pri.hdr_size) continue;
        ok_sec = luks2_read_copy(ctx, s, "SKUL\xBA\xBE", &sec) == 0;
    }

    if (ok_pri && ok_sec && sec.seqid > pri.seqid) {
        luks2_free_header(&pri);
        ok_pri = 0;
    }
    if (ok_pri) {
        luks2_free_header(&sec);
        *hdr = pri;
        return 0;
    }
    if (ok_sec) {
        *hdr = sec;
        return 0;
    }
    con_puts("LUKS2: no valid header\n");
    return -1;
}

/* The data segment. Exactly one is accepted: more means a reencryption
 * was interrupted, which Ivo doesn't resume. */
static int luks2_get_segment(const struct json_value *root,
                             struct luks2_seg *seg)
{
    const struct json_value *segs = jget(root, "segments");
    if (json_object_count(segs) != 1) {
        con_puts("LUKS2: need exactly one data segment\n");
        return -1;
    }
    const struct json_value *s = json_object_value_at(segs, 0);
    seg->id = json_object_key_at(segs, 0);

    uint64_t ss = 0;
    if (!jstr_eq(s, "type", "crypt") ||
        !jstr_eq(s, "encryption", "aes-xts-plain64")) {
        con_puts("LUKS2: unsupported segment (need aes-xts-plain64)\n");
        return -1;
    }
    if (ju64(s, "offset", &seg->offset) != 0 || seg->offset % 512 != 0)
        return -1;
    if (ju64(s, "iv_tweak", &seg->iv_tweak) != 0) return -1;
    if (ju64(s, "sector_size", &ss) != 0 ||
        (ss != 512 && ss != 1024 && ss != 2048 && ss != 4096)) return -1;
    seg->sector_size = (uint32_t)ss;
    return 0;
}

/* Is `mk` the volume key? Some pbkdf2 digest that lists both this
 * keyslot and the segment must match it exactly. */
static int luks2_verify_digest(const struct json_value *root,
                               const char *slot_id, const char *seg_id,
                               const uint8_t *mk, size_t mk_len)
{
    const struct json_value *digests = jget(root, "digests");
    int verified = 0;

    for (size_t i = 0; i < json_object_count(digests) && !verified; i++) {
        const struct json_value *d = json_object_value_at(digests, i);
        if (!jstr_eq(d, "type", "pbkdf2")) continue;
        if (!array_lists(jget(d, "keyslots"), slot_id)) continue;
        if (!array_lists(jget(d, "segments"), seg_id)) continue;

        int hash = luks_hash_id(json_string(jget(d, "hash")));
        size_t hlen = luks_hash_size(hash);
        uint64_t iters = 0;
        if (hlen == 0) continue;
        if (ju64(d, "iterations", &iters) != 0 ||
            iters == 0 || iters > 0xFFFFFFFFu) continue;

        uint8_t salt[64];
        size_t salt_len = sizeof(salt);
        if (base64_decode_field(d, "salt", salt, &salt_len) != 0) continue;

        /* The stored digest is exactly one HMAC output. Accepting a
         * shorter one would let a header weaken the check to a few
         * bits. */
        uint8_t expected[64], computed[64];
        size_t expected_len = sizeof(expected);
        if (base64_decode_field(d, "digest", expected, &expected_len) != 0)
            continue;
        if (expected_len != hlen) continue;

        if (luks_pbkdf2(hash, mk, mk_len, salt, salt_len, (uint32_t)iters,
                        computed, hlen) == 0 &&
            luks_ct_equal(computed, expected, hlen))
            verified = 1;
        ivo_wipe(computed, sizeof(computed));
    }
    return verified ? 0 : -1;
}

/* Derive the keyslot key from the passphrase. */
static int luks2_kdf(const struct json_value *kdf,
                     const uint8_t *pass, size_t pass_len,
                     uint8_t *out, size_t out_len)
{
    uint8_t salt[64];
    size_t salt_len = sizeof(salt);
    if (base64_decode_field(kdf, "salt", salt, &salt_len) != 0) return -1;
    if (salt_len < 8) return -1;

    if (jstr_eq(kdf, "type", "argon2id")) {
        uint64_t t, m, p;
        if (ju64(kdf, "time", &t) || ju64(kdf, "memory", &m) ||
            ju64(kdf, "cpus", &p)) return -1;
        if (t > 0xFFFFFFFFu || m > 0xFFFFFFFFu || p > 0xFFFFFFFFu ||
            argon2id_check_params((uint32_t)t, (uint32_t)m, (uint32_t)p) != 0) {
            con_puts("LUKS2: argon2id parameters out of range\n");
            return -1;
        }
        return argon2id(pass, pass_len, salt, salt_len,
                        (uint32_t)t, (uint32_t)m, (uint32_t)p, out, out_len);
    }
    if (jstr_eq(kdf, "type", "pbkdf2")) {
        int hash = luks_hash_id(json_string(jget(kdf, "hash")));
        uint64_t iters;
        if (hash < 0 || ju64(kdf, "iterations", &iters) != 0 ||
            iters == 0 || iters > 0xFFFFFFFFu) return -1;
        return luks_pbkdf2(hash, pass, pass_len, salt, salt_len,
                           (uint32_t)iters, out, out_len);
    }
    return -1;   /* argon2i and anything else */
}

/* Try one keyslot. On success the volume key is in mk_out. */
static int luks2_try_keyslot(boot_context_t *ctx, const struct luks2_hdr *hdr,
                             const struct luks2_seg *seg,
                             const char *slot_id,
                             const struct json_value *slot,
                             const uint8_t *pass, size_t pass_len,
                             uint8_t *mk_out, size_t *mk_len_out)
{
    const struct json_value *area = jget(slot, "area");
    const struct json_value *kdf  = jget(slot, "kdf");
    const struct json_value *af   = jget(slot, "af");
    uint64_t key_size, area_ks, area_off, area_size, stripes;

    if (!jstr_eq(slot, "type", "luks2")) return -1;
    if (ju64(slot, "key_size", &key_size) != 0 ||
        (key_size != 32 && key_size != 64)) return -1;

    /* The keyslot area is encrypted with its own cipher and key size,
     * independent of the segment's. Only aes-xts-plain64 here too. */
    if (!jstr_eq(area, "type", "raw") ||
        !jstr_eq(area, "encryption", "aes-xts-plain64")) return -1;
    if (ju64(area, "key_size", &area_ks) != 0 ||
        (area_ks != 32 && area_ks != 64)) return -1;
    if (ju64(area, "offset", &area_off) != 0 ||
        ju64(area, "size", &area_size) != 0) return -1;
    if (area_off % 512 != 0 || area_size > LUKS2_AREA_MAX) return -1;
    /* Keyslot areas live after both header copies. */
    if (area_off < 2 * hdr->hdr_size || area_off > (1ull << 40)) return -1;

    int af_hash = luks_hash_id(json_string(jget(af, "hash")));
    if (!jstr_eq(af, "type", "luks1") || af_hash < 0) return -1;
    if (ju64(af, "stripes", &stripes) != 0 ||
        stripes == 0 || stripes > LUKS_AF_MAX_STRIPES) return -1;
    if (stripes * key_size > area_size) return -1;

    uint8_t slot_key[LUKS_MAX_KEY], mk[LUKS_MAX_KEY];
    int rc = luks2_kdf(kdf, pass, pass_len, slot_key, (size_t)area_ks);
    if (rc == 0)
        rc = luks_keyslot_merge(ctx->boot_lba + area_off / 512,
                                slot_key, (size_t)area_ks,
                                (uint32_t)stripes, (size_t)key_size,
                                af_hash, mk);
    ivo_wipe(slot_key, sizeof(slot_key));

    if (rc == 0)
        rc = luks2_verify_digest(hdr->root, slot_id, seg->id,
                                 mk, (size_t)key_size);
    if (rc == 0) {
        memcpy(mk_out, mk, (size_t)key_size);
        *mk_len_out = (size_t)key_size;
    }
    ivo_wipe(mk, sizeof(mk));
    return rc;
}

/* LUKS2 keyslot priority: 0 ignore, 1 normal (default), 2 high. */
static uint64_t slot_priority(const struct json_value *slot)
{
    uint64_t p;
    if (!jget(slot, "priority")) return 1;
    if (json_get_u64(jget(slot, "priority"), &p) != 0 || p > 2) return 0;
    return p;
}

int luks2_unlock_with_passphrase(boot_context_t *ctx,
                                 const uint8_t *pass, size_t pass_len)
{
    struct luks2_hdr hdr;
    struct luks2_seg seg;
    if (luks2_load_header(ctx, &hdr) != 0) return -1;
    if (luks2_get_segment(hdr.root, &seg) != 0) {
        luks2_free_header(&hdr);
        return -1;
    }

    const struct json_value *keyslots = jget(hdr.root, "keyslots");
    uint8_t mk[LUKS_MAX_KEY];
    size_t  mk_len = 0;
    int rc = -1;

    size_t n = json_object_count(keyslots);
    for (uint64_t prio = 2; prio >= 1 && rc != 0; prio--) {
        for (size_t i = 0; i < n && rc != 0; i++) {
            const struct json_value *slot = json_object_value_at(keyslots, i);
            if (slot_priority(slot) != prio) continue;
            rc = luks2_try_keyslot(ctx, &hdr, &seg,
                                   json_object_key_at(keyslots, i), slot,
                                   pass, pass_len, mk, &mk_len);
        }
    }
    luks2_free_header(&hdr);

    if (rc == 0) {
        luks_set_payload(ctx->boot_lba, seg.offset / 512);
        rc = luks_set_segment(seg.sector_size, seg.iv_tweak);
    }
    if (rc == 0)
        rc = luks_setup_crypto(mk, mk_len, "aes-xts-plain64");
    ivo_wipe(mk, sizeof(mk));
    return rc;
}

int luks2_unlock(boot_context_t *ctx)
{
    char passphrase[LUKS_PASS_MAX];
    int n = luks_read_passphrase("Passphrase", passphrase, sizeof(passphrase));
    if (n < 0) return -1;

    int rc = luks2_unlock_with_passphrase(ctx, (uint8_t *)passphrase,
                                          (size_t)n);
    ivo_wipe(passphrase, sizeof(passphrase));
    return rc;
}
