# Ivo Bootloader Changelog

## [v1.1.3] — 2026-10-15

### Fixed

- `hal_get_disk_info` reported the active partition's size as the
  disk size. The shell's `disk` command now shows the whole disk.
- TPM firmware-version store: a corrupt NV counter or UEFI variable
  is now distinguished from an absent one. A corrupt store is left
  alone; the next boot retries.

### Changed

- Removed dead code from the boot path: `partition_find_boot`,
  `try_gpt`, and their helpers. The LUKS probe they performed is
  done by `hal_init`'s block-device enumeration.

## [v1.1.2] — 2026-10-14

TPM was made by masochists

### Added

- TPM-sealed LUKS unlock. On-device enrollment via a
  `/EFI/ivo/seal-request` marker on the ESP; the passphrase typed at
  the prompt is sealed to a policy bound to PCR 4+7, with an optional
  PIN. Unseal at boot hands the result to the same LUKS code path the
  keyboard uses. Any failure falls through to the LUKS prompt. See
  `doc/tpm.md`.
- Firmware rollback protection. `IVO_RELEASE` is stored in a TPM NV
  monotonic counter when a TPM is present, else in
  `Ivo/FirmwareVer`. Refuses to boot a binary whose release number
  is lower than the stored value. Requires Secure Boot for security
  value. The TPM NV path is untested under QEMU; see `devnotes.md`.
- `store-health` shell command: read-only report of which store is
  authoritative and both stored values.

### Fixed

- `PolicyGetDigest` was sent with command code `0x17E` (PCR_Read),
  failing with `TPM_RC_SIZE` on a session handle. Correct code is
  `0x189`. Oops
- `main.c` extended PCR 4 with `"ivo: unseal window closed"` on the
  enrollment boot, changing the PCR value after the sealed object
  was created and breaking the policy on every subsequent boot.
- `boot_status_begin` redraws the full panel.
- Kernel cmdline editor clears the screen on exit.
- Shell clears the screen on exit.

## [v1.1.1] — 2026-10-12

New features! (+ Bug fixes)

### Added

- UEFI variable namespace for Ivo's own state, under a dedicated
  vendor GUID. `Ivo/BootCount` written on each boot, cleared on
  successful kernel handoff. `Ivo/LastEntry` written when an entry
  is chosen with Enter or a number key, read on menu entry to
  preselect that entry.
- Rollback protection for `config.toml`: a top-level `version = N`
  key is compared against `Ivo/ConfigVer` on every load; a config
  older than the last accepted version refuses to boot. Configs
  without a `version` key are unchanged. Best-effort: the variable
  can be deleted by anything with ESP write access. A TPM NV
  counter would be the real fix.
- Conditional entries: `if = "exists(/path)"` on an entry hides it
  from the menu when the path is not present on the mounted
  filesystem.
- Kernel cmdline editor (`e` on a menu entry). In-memory edit only;
  the config on disk is not touched. Gated on the user having
  proven the LUKS passphrase this boot, so a TPM-sealed unlock
  cannot be bypassed into a shell.
- Text-mode fallback when no usable GOP framebuffer is present. Uses
  the firmware's ConOut/ConIn directly: numbered menu, plain
  passphrase prompt, no theme, no panel. No timeout in text mode.
- Per-entry password protection: `password_hash = "pbkdf2-sha256:..."`
  in an entry. PBKDF2-HMAC-SHA256, per-entry random salt, verified
  before boot and before the cmdline editor. Once proven in a boot,
  the entry is unlocked for the rest of that boot.
- `ivo-keygen --password-hash` produces a `password_hash` string
  from a passphrase typed at the terminal.

### Changed

- `fs_write` refuses any path except `/EFI/ivo/sealed.bin`. The
  bootloader no longer has a general-purpose write path.

### Fixed

- `RT_SetVariable` was read from the RuntimeServices vtable at the
  wrong offset (0x50, which is `GetNextVariableName`; `SetVariable`
  is at 0x58).
  `Ivo/BootCount`, `Ivo/LastEntry`, and `Ivo/ConfigVer` now
  actually survive across boots.
- `ivo-sign --hash` prompts to bump the config version before
  rewriting. `--no-bump` skips the prompt.

## [v1.1.0] — 2026-10-12

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

## [v1.0.0] — 2026-10-09

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