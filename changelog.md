# Ivo Bootloader Changelog

## [v1.1.5]

### Changed

- `menu.c`: timeout boots the selected entry, not `default`.
- `menu.c`: text mode honors `timeout` and `ESC` to shell.
- `password.c`: `password_proven` cleared on every return to menu.
- `fs.c`: removed dead `fs_register`, `fs_readlink`, `fs_mount`.
  NULL method guards on every dispatch.

### Fixed

- `boot.c`: `boot_failed` returned after one non-blocking
  `hal_getchar`. Blocks now.
- `boot.c`: `load_kernel`, `load_initrd` left dangling `entry->kernel`
  / `entry->initrd` on failure.
- `boot.c` / `hal/uefi.c`: `hal_chainload` reported `StartImage` failure
  as success. `boot_chainload` printed "Chainloaded image returned" and
  rebooted on a failed target. Both `LoadImage` and `StartImage` failures
  now surface.
- `config.c`: `parse_uint` overflowed before the bound check.
- `con.c`: `con_read_secret` off-by-one on `cap - 1`, silent truncation
  at `cap`, busy loop on `hal_getchar`.
- `hal/uefi.c`: `hal_boot_uefi` silently booted with no cmdline if
  `AllocatePool` failed. Now halts. `ConOut` method pointers derefed
  without NULL checks; guarded.
- `efivars.c`: `ivo_configver_get` returned `-1` for corrupt store,
  inconsistent with `ivo_fwver_get`'s `-2`. The `-2` branch in
  `main.c`'s rollback check was dead; corrupt store panicked as
  "missing" instead of "corrupt". `ivo_var_get` guards `*DataSize >
  cap` from misbehaving firmware.
- `main.c`: config rollback passed with the version store missing
  after a prior boot.
- `luks1.c`, `luks2.c`: PBKDF2 iterations, segment offset, `iv_tweak`
  unbounded from header. Bound at 16M, `2 × hdr_size`, `2^48`.
- `luks2.c`: keyslot and digest counts unbounded from header. Capped
  at 32 each.
- `luks_common.c`: `xts_clear` skipped on `xts_init` failure;
  `af_merge`, `luks_read_blocks` NULL and range guards; `master_key`
  host-only.
- `tpm.c`: `tcg2_event` missing `EFI_TCG2_EVENT_HEADER.HeaderSize`;
  outer `HeaderSize` read 14 instead of 12. TCG event log entries
  malformed; PCR values unaffected.
- `lvm.c`: `\n` in quoted strings read as `n`; `\` rejected.
  Chunk-loop and base-addition wrap windows.
- `tpm_cmd.c` / `tpm_seal_create.c`: `cmd_load` and `cmd_create_primary`
  read `parameterSize` as the object handle (missing `tr_params`).
  `cmd_create_primary`'s template size 26→24 and exponent encoding
  `tw_u32`→`tw_u16`. Object handles were wrong on spec-compliant TPMs;
  likely masked by swtpm leniency.
- `tpm_seal.c`: `tpm_seal_write_blob` NULL/length guards;
  `tpm_seal_try_unlock` validates blob header before prompting for PIN;
  policy buffer wiped after seal.
- `fat32.c`: `fat32_write` freed the old chain before the new one was
  durable. Now writes new, swaps entry, frees old. Cluster leak on
  partial write fixed. Empty path components and uint32 cluster-run
  overflow guarded.
- `ext4.c`: `ext4_fs_opendir` NULL guards; `ext4_readdir` skips
  dx_root blocks; `itable * block_size` and `(rel + blocks_per_group
  - 1)` overflow guards.
- `btrfs.c`: RAID5/RAID6 profiles misread parity as data. Rejected
  alongside RAID0/RAID10. `btrfs_read_phys` and `btrfs_read_file`
  offset-add overflow guards. NULL guards on `read`, `readlink`,
  `stat`, `opendir`.
- `iso9660.c`: `iso9660_mount` and `iso9660_mount_memory` left
  `iso.dev`/`iso.memory` set after a failed scan. `iso_read_logical_
  sector` derefed `iso.dev` unconditionally and dispatched through
  LUKS/LVM, discarding `iso.dev->lba_start` — `iso-boot` with config
  on LUKS read decrypted garbage and failed. Raw reads only now.
- `aes.c`: `aes_init` left `ctx->nr` uninitialized on invalid key
  length; wiped on failure. `aes_cfb128_encrypt` removed — dead code,
  header comment claimed caller's IV advanced when it didn't. NULL
  guards on `aes_init`, `aes_encrypt_block`, `aes_decrypt_block`.
- `xts.c`: NULL guards on `xts_init`, `xts_encrypt_sector`,
  `xts_decrypt_sector`. `xts_init` clears `ctx` on partial failure.
- `hmac.c` / `hmac_sha1.c`: NULL guards on `ctx`, `key`, `data`, `out`
  in init/update/final. Unreachable with current callers.
- `pbkdf2.c`: `pbkdf2_hmac_sha1` bound on `out_len` matching the
  SHA-256 variant.
- `sha512.c`: state not wiped after `final` (SHA-256/SHA-1 both wipe);
  added. NULL guards on `update`, `final`.
- `sha256.c`, `sha1.c`: NULL guards. `sha1_zeroize` replaced by
  `ivo_wipe` for the compiler barrier.
- `blake2b.c`: NULL guards on `blake2b_init`, `blake2b_update`,
  `blake2b_final`, `blake2b`. `blake2b_init` wipes `ctx` on invalid
  `outlen`.
- `argon2.c`: `initialize` and `finalize` ignored `argon2_hprime`'s
  return. On failure (unreachable with current params), `buf` / `out`
  were used uninitialized. Propagated to `argon2id_hash`.
  `instance` struct zeroed after use.
- `mm.c`: `mm_free` wiped only the payload, leaving stale `size` /
  `next` / `free` bytes in block headers; a merge left the second
  block's header inside the merged payload. Whole block wiped now.
  `mm_alloc` guards `total + 4095` overflow.
## [v1.1.4]

### Changed

- `boot.c`: hash and read failures print the file path. Chainload
  prints the target on mismatch.
- `tpm_seal.c`: enrollment confirmation waits three seconds.
- `con.c`: `con_read_secret` collapsed to one path; prompts
  advance the cursor.
- `tpm_cmd.c`: TPM command failures serial only.
- Removed dead code from the boot path: `partition_find_boot`,
  `try_gpt`, helpers.

### Removed

- `tpm_session.c`, `rsa.c`, `rsa.h`, `tpm_kdfa`. Salted
  `StartAuthSession` failed on swtpm (`0x2C4`).

## [v1.1.3] — 2026-10-15

### Fixed

- `hal_get_disk_info` reported the active partition size. Shell
  `disk` shows the whole disk.
- TPM firmware-version store distinguishes corrupt from absent.

### Changed

- Removed dead code: `partition_find_boot`, `try_gpt`, helpers.
  Replaced by `hal_init`'s enumeration.

## [v1.1.2] — 2026-10-14

### Added

- TPM-sealed LUKS unlock. `/EFI/ivo/seal-request` marker triggers
  enrollment; passphrase sealed to PCR 4+7 with optional PIN.
  Fallback to LUKS prompt on any failure.
- Firmware rollback protection. `IVO_RELEASE` in TPM NV counter or
  `Ivo/FirmwareVer`. NV path untested under QEMU.
- `store-health` shell command.

### Fixed

- `PolicyGetDigest` command code `0x17E` → `0x189`.
- PCR 4 extension on enrollment boot broke the policy.
- `boot_status_begin` redraws the full panel.
- Kernel cmdline editor clears the screen on exit.
- Shell clears the screen on exit.

## [v1.1.1] — 2026-10-12

### Added

- UEFI variable namespace. `Ivo/BootCount`, `Ivo/LastEntry`.
- `config.toml` rollback protection via `version` and
  `Ivo/ConfigVer`.
- Conditional entries: `if = "exists(/path)"`.
- Kernel cmdline editor (`e`). Gated on passphrase proof this boot.
- Text-mode fallback when no usable GOP.
- Per-entry password: `password_hash = "pbkdf2-sha256:..."`.
- `ivo-keygen --password-hash`.

### Changed

- `fs_write` refuses any path except `/EFI/ivo/sealed.bin`.

### Fixed

- `RT_SetVariable` vtable offset `0x50` → `0x58`.
- `ivo-sign --hash` prompts to bump version. `--no-bump` skips.

## [v1.1.0] — 2026-10-12

### Changed

- Menu arrow-key redraw is two rows plus footer.
- `gfx_fill_rect`, `gfx_clear`, `gfx_vgradient` use 64-bit stores.
- `gfx_blit_glyph` fast path for opaque coverage.
- `text_draw` blits one coverage buffer per glyph.
- `con_clear` anchors top-left.
- Redrawn lines erase first. No ghost characters.
- Shell clears screen on entry.
- `con_putc(' ')` no longer used for erase. `con_clear_row` added.

## [v1.0.0] — 2026-10-09

### Features

- UEFI x86_64 boot
- LUKS1 and LUKS2: PBKDF2, Argon2id
- LVM: linear segments, multiple LVs
- FAT32 r/w; ext4 ro; BTRFS ro with subvolumes; ISO9660 ro with
  Rock Ridge, Joliet, El Torito
- GPT partition scanning
- Framebuffer UI, five themes, real font
- Read-only recovery shell
- Ed25519-signed config; SHA-512 kernel, initrd, chainload hashes
- Manual PE/COFF kernel handoff
- Live ISO boot from a raw partition
- Chainload with hash verification
- TPM 2.0 measurement via `EFI_TCG2_PROTOCOL`
- TPM-sealed LUKS passphrase, optional PIN
- TPM enrollment from a trigger file
- Crypto: AES-256, AES-XTS, SHA-1/256/512, HMAC-SHA1/256,
  PBKDF2, BLAKE2b, Argon2id, Ed25519

### Security

- Config read once; verified bytes are parsed bytes.
- `SECURE_BOOT=1`: entries missing hashes refused.
- Config grammar shared by bootloader and tools.
- TPM seal to PCR 4+7. PCR 4 capped after unlock. Enrollment
  requires typed confirmation, never overwrites `sealed.bin`.
- Shell asks for passphrase before filesystem access when unlocked
  from TPM.
- ESP parsed with FAT32 only.
- Bounds and overflow fixes across all parsers.
- Keys, passphrases, KDF state wiped. Keys wiped before handoff.
- LUKS volume must be on ESP's disk. 512-byte sectors only.
- Tools: no shell in `ivo-install`; keys written 0600 with
  `O_EXCL`; atomic writes; symlinks and `..` refused when hashing.

### Tools

- `ivo-keygen`, `ivo-sign`, `ivo-convert`, `ivo-install`,
  `ivo-config`, `ivo-doctor`, `mkinitivo`, `keymap_compiler`

### Known limitations

- No TPM attestation.
- No TPM parameter encryption.
- Table-based AES (cache timing).
- No rollback protection.
- Non-ASCII passphrases refused.
- Manual PE handoff doesn't apply relocations.
- No LVM striping.
- No LUKS inside an LV.
- Wrapped LVM metadata areas refused.
- LUKS1 backup header not read.
- No GOP fallback.

### License

CLEAR License v1.