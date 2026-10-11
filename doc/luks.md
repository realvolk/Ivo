# LUKS — Reader Notes

Reader is `src/uefi/storage/luks1.c`, `luks2.c`, `luks_common.c`.
Crypto in `src/uefi/crypto/`. JSON parser in `src/uefi/luks/json.c`.

The on-disk format is documented by cryptsetup. This file is about
how Ivo parses it.

## Where LUKS sits

```
EFI Block I/O
    │
    ▼
lvm_read_blocks    (if LVM active)
    │
    ▼
luks_read_blocks   (if LUKS active)
    │
    ▼
ext4_read_block / btrfs_read_phys / fat32 read_sectors
```

Dispatch in the filesystem drivers:

```
if (lvm_active()) return lvm_read_blocks(...);
if (luks_active()) return luks_read_blocks(...);
return hal_read_blocks(...);
```

LVM first because the sector number has to be translated before LUKS
sees it. `lvm_raw_read` calls `luks_read_blocks` for its own reads.

## LUKS1 header

592 bytes at the start of the partition. Multi-byte fields
big-endian. Read into a 1024-byte buffer, first 592 copied into
`luks1_header_t`.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 6 | `magic` = `"LUKS\xba\xbe"` |
| 6 | 2 | `version` = 1 |
| 8 | 32 | `cipher_name` |
| 40 | 32 | `cipher_mode` |
| 72 | 32 | `hash_spec` |
| 104 | 4 | `payload_offset` (sectors) |
| 108 | 4 | `key_bytes` |
| 112 | 20 | `mk_digest` |
| 132 | 32 | `mk_digest_salt` |
| 164 | 4 | `mk_digest_iter` |
| 168 | 40 | `uuid` |
| 208 | 8×48 | keyslot array |

Each keyslot:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | `active` (`0x00AC71F3`) |
| 4 | 4 | `iterations` |
| 8 | 32 | `salt` |
| 40 | 4 | `key_material_offset` (absolute sectors) |
| 44 | 4 | `stripes` (1..65536; cryptsetup writes 4000) |

Multi-byte fields byte-swapped after the raw read. Magic is a byte
sequence.

`cipher_name`/`cipher_mode` must be `aes`/`xts-plain64` and
`key_bytes` 32 or 64. `hash_spec` (`sha1` or `sha256`) is the one
hash LUKS1 uses for everything: keyslot PBKDF2, AF diffusion and the
MK digest. LUKS1 keyslots are always PBKDF2, never Argon2.

All eight slots tried in order; first successful derivation wins.

## LUKS2 header

4096 bytes minimum. Binary part big-endian, JSON area ASCII.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 6 | `magic` |
| 6 | 2 | `version` = 2 |
| 8 | 8 | `hdr_size` (>= 4096, typical 16384) |
| 16 | 8 | `seqid` |
| 24 | 48 | label |
| 72 | 32 | `csum_alg` (must be `"sha256"`) |
| 104 | 64 | `salt` |
| 168 | 40 | `uuid` |
| 208 | 48 | subsystem |
| 256 | 8 | `hdr_offset` (0 primary, `hdr_size` secondary) |
| 448 | 64 | `csum` |

`hdr_size` must be a power of two from 16 KiB to 4 MiB. The whole
`hdr_size` bytes (binary header plus JSON area) are read and the
checksum verified: SHA-256 over them with the `csum` field zeroed must
equal the first 32 bytes of `csum`. JSON area is bytes 4096 to
`hdr_size`.

### Secondary header

LUKS2 stores two copies. Primary at sector 0 of the partition;
secondary at `hdr_size` past the primary, sector `hdr_size / 512`. The
secondary's binary header matches the primary's except for the magic:
the four ASCII letters are reversed, `"SKUL\xba\xbe"` instead of
`"LUKS\xba\xbe"`. The trailing two bytes are not swapped. That is how
cryptsetup tells which one is being read.

Both copies are read and verified (magic, version, `hdr_size`,
`hdr_offset`, checksum, JSON parse). If both are valid the one with
the higher `seqid` wins, as in cryptsetup. If the primary is unusable
the secondary is probed at every legal `hdr_size`, so a corrupt
primary binary header is recoverable too.

JSON parser is `src/uefi/luks/json.c`. Objects, arrays, strings,
numbers, bools, null, all standard escapes. Bounded: depth 32, 16384
values, 64 KiB per string. API: `json_object_get`,
`json_object_value_at`, `json_object_count`, `json_object_key_at`,
`json_array_size`, `json_array_get`, `json_string`, `json_get_u64`
(strict: integer number or decimal string, overflow is an error),
`json_type`.

## LUKS2 metadata

```json
{
  "keyslots": {
    "0": {
      "type": "luks2",
      "key_size": 64,
      "area": { "type": "raw", "offset": "32768",
                "size": "258048", "key_size": 64 },
      "kdf": { "type": "argon2id", "salt": "...",
               "time": 4, "memory": 16384, "cpus": 4 },
      "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" }
    }
  },
  "segments": {
    "0": { "offset": "16777216", "sector_size": 512 }
  },
  "digests": {
    "0": { "keyslots": ["0"], "iterations": 1000,
           "salt": "...", "digest": "..." }
  }
}
```

Extracted fields:

- The single segment: `type` `"crypt"`, `encryption`
  `"aes-xts-plain64"`, `offset` (bytes, 512-aligned; divided by 512
  for `luks_set_payload`), `iv_tweak`, `sector_size` (512, 1024, 2048
  or 4096). More than one segment (interrupted reencryption) is
  refused.
- From the keyslot: `type` `"luks2"`, `key_size` (32/64, volume key),
  `priority`, `area.{type,encryption,key_size,offset,size}`,
  `kdf.{type,salt}`, `af.{type,stripes,hash}`.
- Argon2id KDF: `kdf.time`, `kdf.memory` (KiB), `kdf.cpus`, checked
  against `argon2id_check_params` before anything is allocated.
- PBKDF2 KDF: `kdf.hash` (`sha1`/`sha256`), `kdf.iterations`.
- From a digest whose `keyslots` lists the keyslot and whose
  `segments` lists the segment: `hash`, `salt`, `digest`,
  `iterations`.

Master key verification: PBKDF2-`hash`(mk, salt, iterations) must
equal the decoded `digest`, which must be exactly one hash output long
(32 bytes for SHA-256). Compared in constant time.

## Unlock sequence

1. Read both header copies (`hdr_size` bytes each) and verify them.
2. Keep the valid one with the higher `seqid`; parse its JSON.
3. Validate the data segment.
4. Locate keyslot. Populated slots tried in order, priority 2
   ("high") first, then 1; priority 0 ("ignore") skipped.
5. Extract and bound `key_size`, `area.*`, `kdf.*`, `af.*`.
6. Prompt for the passphrase (up to 510 characters; longer input is
   refused, not truncated).
7. Derive the keyslot key (`area.key_size` bytes):
   - Argon2id with `time`, `memory`, `cpus`
   - Or PBKDF2-HMAC-`hash` with `iterations`
8. Read `stripes * key_size` bytes (rounded up to a sector) of keyslot
   material — not the whole area.
9. AES-XTS decrypt with the derived key, 512-byte sectors, counter
   from 0.
10. TKS1 AF merge. Result is the candidate master key.
11. Verify against the digest.
12. `luks_set_payload`, `luks_set_segment(sector_size, iv_tweak)`.
13. `luks_setup_crypto(mk, key_size, "aes-xts-plain64")`.
14. Wipe the passphrase, derived key, material and candidates with
    `ivo_wipe`.

LUKS1 is the same shape. Header parsed as fixed-offset binary. MK
digest is PBKDF2-`hash_spec` truncated to 20 bytes.

## AF merge

```
buf = zeros(key_size)
for i in 0..stripes-2:
    buf ^= area[i * key_size : (i+1) * key_size]
    buf = sha256_diffuse(buf)
out = area[(stripes-1) * key_size : stripes * key_size] ^ buf
```

`sha256_diffuse`: for each digest-sized chunk of the block, the hash
of a 4-byte BE counter followed by the chunk. Final partial chunk
hashed with the counter plus the remaining bytes; same number of
bytes copied. Done in place in a 64-byte stack buffer; no
allocation.

`af.hash` (LUKS2) / `hash_spec` (LUKS1) must be `"sha256"` or
`"sha1"`. Any other hash refused.

## AES-XTS

`xts_init(ctx, key, key_size)` takes a 32- or 64-byte key. First half
is the AES key, second half the tweak key.

`xts_decrypt_sector(ctx, tweak, src, dst, sector_size)`. The data
unit is the segment's `sector_size` (LUKS1: always 512). The tweak
(plain64, little-endian) is dm-crypt's: the **512-byte** sector number
within the segment plus `iv_tweak`, even for 4096-byte units —
cryptsetup does not use `iv_large_sectors` for LUKS. So 4 KiB unit
*n* uses tweak `8n + iv_tweak`. Verified against a volume encrypted by
`cryptsetup reencrypt --encrypt --sector-size 4096` (cryptsetup 2.8
defaults to 4096 for new LUKS2 volumes on 4K devices and files).

## Keyslot material offsets

LUKS1: `keyslot[i].key_material_offset` is an absolute sector offset
from the partition start, not relative to `payload_offset`.

```c
uint64_t material_offset = (uint64_t)hdr.keyslot[slot].key_material_offset * 512;
uint32_t material_blocks = (dk_len * hdr.keyslot[slot].stripes + 511) / 512;
hal_read_blocks(ctx->boot_lba + material_offset / 512 + done, chunk, ...);
```

LUKS2: `area.offset` is a byte offset from the partition start.

```c
uint64_t area_lba = ctx->boot_lba + area_offset / 512;
```

## Read path after unlock

Callers still address 512-byte sectors. `luks_read_blocks` reads
whole data units straight into the caller's buffer and decrypts them
in place; a request that starts or ends inside a larger unit reads
that unit into a 4 KiB bounce buffer, decrypts all of it and copies
the requested part. Chunks: 8192 sectors. No caching or read-ahead.

`luks_wipe_keys()` (`src/uefi/storage/luks.h`) wipes the volume key, the XTS key
schedules and the bounce buffer; LUKS reads fail afterwards. The boot
path calls it right before handing over to the kernel or a
chainloaded image.

## Refused

- Not LUKS (bad magic).
- Version not 1 or 2.
- Any cipher other than `aes-xts-plain64`, any key size other than
  256/512 bits (LUKS1 header, LUKS2 segment, LUKS2 keyslot area).
- Hash other than `sha1`/`sha256` (LUKS1 `hash_spec`, PBKDF2,
  `af.hash`, digest `hash`).
- LUKS2 `hdr_size` not a power of two in 16 KiB..4 MiB, `hdr_offset`
  wrong, `csum_alg` not `sha256`, checksum mismatch, JSON parse
  failure — for both copies.
- LUKS2: not exactly one segment; `sector_size` not 512..4096 power
  of two; offsets not 512-aligned; keyslot area inside the header
  copies; `area.size > 16 MiB`; `stripes * key_size > area.size`.
- `stripes` 0 or above 65536; zero iterations.
- Argon2id: `cpus` 0 or above 64, `memory` below `8 * cpus` or above
  4 GiB, `time` 0 or above 2^20, `time * memory` above 2^32; salt
  shorter than 8 bytes.
- KDF not `"argon2id"` or `"pbkdf2"`.
- Numbers that aren't plain non-negative integers or overflow 64 bits.
- Digest not exactly one hash output long, or not listing both the
  keyslot and the segment.
- Digest verification failure (wrong passphrase).
- Passphrase longer than 510 characters.

## Not supported

- **Detached headers.**
- **LUKS2 tokens.**
- **Ciphers other than aes-xts-plain64**, `argon2i`, hashes other than
  SHA-1/SHA-256.
- **Reencryption in progress** (more than one segment).
- **Segment `size`.** Only `"dynamic"` volumes are expected; a fixed
  size is not enforced on reads.
- **Recovery keyslots, `--key-file` offsets, keyslots above 16 MiB.**

## Verification

Verified against real `cryptsetup luksFormat` volumes, both versions,
both KDFs.

Host tests:

```bash
printf testpass > key
truncate -s 20M luks1-test.img
cryptsetup luksFormat --type luks1 --batch-mode --disable-locks \
    --pbkdf-force-iterations 1000 --key-file key luks1-test.img
make tests/luks1-test tests/luks2-test
tests/luks1-test luks1-test.img testpass

truncate -s 40M luks2-test.img
cryptsetup luksFormat --type luks2 --batch-mode --disable-locks \
    --pbkdf argon2id --pbkdf-memory 32768 --pbkdf-force-iterations 4 \
    --key-file key luks2-test.img
LUKS_TEST_LBA=0 tests/luks2-test luks2-test.img testpass
```

None of this needs root. Compare against `cryptsetup luksDump
--dump-volume-key --batch-mode --key-file key`.

Data path: encrypt a file of known plaintext offline (also no root),
then dump the first N decrypted sectors with `LUKS_TEST_DUMP=N` and
compare:

```bash
cp plain.img enc.img
cryptsetup reencrypt --encrypt --type luks2 --sector-size 4096 \
    --reduce-device-size 16M --batch-mode --disable-locks \
    --force-offline-reencrypt --key-file key enc.img
LUKS_TEST_LBA=0 LUKS_TEST_DUMP=2000 tests/luks2-test enc.img testpass \
    > out.bin
cmp out.bin <(head -c $((2000 * 512)) plain.img)
```

`LUKS_TEST_LBA` overrides the partition offset. Default 2048; use 0
for a raw image. The tests pass `${L}pN` as the image path when the
LUKS header is inside a partition — in that case `LUKS_TEST_LBA=0`
reads from the start of the partition, where the header lives.

Secondary-header fallback verified by corrupting the primary JSON
area (checksum mismatch) and, separately, the primary magic; both
recovered the same master key via the secondary. Corrupting both
copies is refused.

`tests/fuzz-json.c` is a libFuzzer target for the JSON parser; its
header has the build lines (libFuzzer/ASan, or a standalone driver
linked against `luks/mem.c`).

QEMU tests: the LUKS+LVM+ext4 test image (see `devnotes.md`)
exercises the reader end-to-end.

SSE2 alignment: Argon2id's SSE2 path uses `__m128i_u` (unaligned) so
the compiler emits `movdqu`. Aligned `movdqa` faults on 16-byte
misalignment.

## Reference

LUKS1 and LUKS2 formats:
`gitlab.com/cryptsetup/cryptsetup/-/blob/main/docs/`. The cryptsetup
source (`lib/luks1/`, `lib/luks2/`) parses the same structures.
`cryptsetup luksDump --debug` shows what cryptsetup thinks the header
contains.

Argon2: `github.com/P-H-C/phc-winner-argon2`. Ivo's
`crypto/argon2.c` and `argon2_sse2.c` implement argon2id.