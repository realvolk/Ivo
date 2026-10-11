# Ivo Bootloader Changelog

## v1.1.0 — 2026-10-12

UI fixes.

### Changed

- Menu arrow-key redraw is two rows plus the footer, not the whole
  screen. Panel background filled once, not twice. `gfx_fill_rect`,
  `gfx_clear`, and `gfx_vgradient` use 64-bit stores. `gfx_blit_glyph`
  fast-path for opaque coverage. `text_draw` blits one coverage buffer
  per glyph instead of one per glyph row.
- `con_clear` anchors to the top-left padding instead of screen
  center-left. Shell and passphrase prompts are top-left. `panic`
  block is centered on both axes.
- Redrawn lines erase first: shell input, footer countdown, boot
  progress values, LUKS/TPM prompt. No more ghost characters on
  backspace or overlapped digits on the timeout.
- Shell clears the screen on entry.
- `con_putc(' ')` no longer relied on for erase (it advances the
  cursor but paints nothing). `con_clear_row` added.

## v1.0.0 — 2026-10-09

First stable release.

### Features

- UEFI x86_64 boot
- LUKS1 and LUKS2 unlock: PBKDF2, Argon2id
- LVM: linear segments, multiple LVs
- FAT32 read/write; ext4 read-only; BTRFS read-only with subvolumes;
  ISO9660 read-only with Rock Ridge, Joliet, El Torito
- GPT partition scanning
- Framebuffer UI (GOP), five compile-time themes, real font
- Read-only recovery shell
- Ed25519-signed config; SHA-512 kernel, initrd, chainload hashes
- Manual PE/COFF kernel handoff
- Live ISO boot from a raw partition
- Chainload with hash verification
- TPM 2.0 measurement via `EFI_TCG2_PROTOCOL`
- TPM-sealed LUKS passphrase, optional PIN
- TPM enrollment from a trigger file on the ESP
- Crypto: AES-256, AES-XTS, SHA-1/256/512, HMAC-SHA1/256,
  PBKDF2, BLAKE2b, Argon2id, Ed25519

### Security

- Config read once; the verified bytes are the parsed bytes.
- `SECURE_BOOT=1`: entries missing `kver`/`iver`/`cver` refused.
  Hashes checked in every build.
- Config grammar shared by bootloader and tools. `ivo-sign --sign`
  refuses a config the bootloader would reject.
- TPM seal to PCR 4 + 7 (mask `0x90`). PCR 4 capped after unlock. No
  self-measurement. Object without `noDA`/`userWithAuth`. Enrollment
  requires typed confirmation, offers a PIN, never overwrites
  `sealed.bin`. Command and response marshalling bounded.
- Shell asks for the LUKS passphrase before `ls`/`cat`/`stat` when
  the disk was unlocked from the TPM. Console output sanitized.
- ESP parsed with FAT32 only.
- Bounds and overflow fixes across ext4, FAT32, BTRFS, ISO9660, GPT,
  LVM, LUKS1/2, Argon2, JSON, the PE loader, the allocator, and the
  kernel loader (hash before any copy, size limits).
- Master key, passphrases, KDF state wiped with non-elidable stores.
  Keys wiped before kernel handoff and chainload.
- UEFI: LUKS volume must be on the ESP's disk. 512-byte sectors only.
  `IoAlign` honoured. Kernel runs from `EfiLoaderCode` pages.
- Tools: no shell in `ivo-install`; USB install refuses partitions,
  mounted or busy devices, overlapping layouts; keys written 0600
  with `O_EXCL`; atomic writes; symlinks and `..` refused when
  hashing.

### Tools

- `ivo-keygen` — Ed25519 keypair
- `ivo-sign` — hash, sign, verify, check
- `ivo-convert` — GRUB, Limine, rEFInd → config.toml
- `ivo-install` — ESP or USB
- `ivo-config` — write a config.toml from /boot
- `ivo-doctor` — read-only diagnostic
- `mkinitivo` — embed a config as a C header
- `keymap_compiler` — keymap → C header

### Known limitations

- No TPM attestation. PCRs measured, nothing reads them.
- No TPM parameter encryption. Unsealed secret crosses the bus in
  clear.
- Table-based AES (cache timing).
- No rollback protection.
- Non-ASCII passphrases refused.
- Manual PE handoff doesn't apply relocations.
- No LVM striping (`stripe_count > 1` refused).
- No LUKS inside an LV. LUKS on a raw partition, LVM inside LUKS.
- Wrapped LVM metadata areas refused.
- LUKS1 backup header not read. LUKS2 falls back to secondary.
- No GOP fallback. Firmware without a usable framebuffer halts.

### License

CLEAR License v1.