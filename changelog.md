# Ivo Bootloader Changelog

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