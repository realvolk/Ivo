# Ivo Bootloader Specification v1.0.0

## 1. Name and Meaning

**Ivo** — a Slavic given name, the diminutive of Ivan. The project is
named after Ivo Andrić, whose line sits at the top of the Makefile:
*"It is easy to beat nettles with someone else's dick."*

## 2. Design Philosophy

- **Assembly where it matters, C where it must.** No other languages
  at runtime.
- **Minimalism as security.** Less code, smaller attack surface.
- **Compile-time tailoring.** Drivers, crypto, and themes selected at
  build time. No runtime probing.
- **Read-only, mostly.** No disk writes during normal boot. The one
  exception is the ESP, where TPM enrollment writes `sealed.bin`.
- **Explicit errors, never silent failure.**
- **Separation of concerns.** The bootloader unlocks encrypted
  partitions and loads a kernel + initramfs. Complex storage topology
  beyond LUKS and linear LVM is the initramfs's job.
- **Modern firmware, first-class.** UEFI x86_64 only. Legacy BIOS is
  not supported.
- **One codebase, feature flags.** Linked set selected by `LUKS`,
  `LVM`, `TPM`, `SECURE_BOOT`. No profile axis.

## 3. Architecture Overview

One architecture, one firmware interface.

- **UEFI.** Single binary. Firmware loads `\EFI\BOOT\BOOTX64.EFI`,
  calls `efi_main`. `efi_main` builds a `boot_context_t`, calls
  `hal_init`, calls `ivo_main`. Everything above the HAL runs in
  64-bit long mode.

## 4. Build Flags

No profiles. Per-module flags in `config.mk`:

- `LUKS` — LUKS1 and LUKS2 unlock.
- `LUKS_USE_ARGON2` — accepted for compatibility, no effect: LUKS2
  always supports Argon2id and PBKDF2, LUKS1 is always PBKDF2.
- `LVM` — LVM2 PV/label/metadata reader.
- `TPM` — TPM 2.0 measurement and TPM-sealed LUKS unlock.
- `SECURE_BOOT` — Ed25519 config verification, per-entry hash checks.
- `THEME` — `default`, `nord`, `gruvbox`, `solarized`,
  `highcontrast`.
- `GFX_FMT` — `bgrx` (default) or `rgbx`. Controls how the GOP
  pixel format is mapped to memory. QEMU/OVMF lies; firmware that
  reports honestly needs `rgbx`.

All `?=` in `config.mk`.

### 4.1 Inert flags

One flag no source file reads:

- `KEYMAP` — defines `us`, never reaches `CFLAGS_EFI`.
  `tools/keymap_compiler.c` works, output not consumed.
  `src/keymaps/*.h` hand-written.

Source size at v1.0.0: ~18,000 lines C, ~2,800 headers, ~220
Makefile. About 21,000 lines of non-prose source. Markdown ~3,600
lines.

## 5. Platform Support

- **UEFI (64-bit)** native. Single PE32+ application.
- **UEFI (32-bit)** not targeted.
- **BIOS (Legacy CSM)** dropped. Two boot paths meant two HALs, two
  boot-protocol stacks, two sets of firmware quirks, and two of
  everything at every layer above them. The code was smaller with one
  path and the testing burden was half.

## 6. Boot Flow

### 6.1 UEFI

1. Firmware loads `\EFI\BOOT\BOOTX64.EFI`, calls `efi_main`.
2. `efi_main` stores system table and image handle, builds
   `boot_context_t`, calls `ivo_main`, which calls `hal_init`.
3. `hal_init` locates `ConIn`, `ConOut`, GOP, loaded-image, block
   I/O. Captures the ESP's block I/O before LUKS scan. Retargets
   `g_block_io` at the LUKS partition if one is found; otherwise
   stays on the ESP.
4. `ivo_main` calls `gfx_init`. If GOP is missing or unusable, halt
   with a serial message. Otherwise `frame_init` and `con_clear`
   set up the framebuffer UI.
5. `ivo_main` calls `tpm_init`. Ivo does not measure itself:
   firmware already measured `ivo.efi` into PCR 4. Boot does not fail
   if the TPM is absent.
6. If `TPM=1` and boot partition is LUKS, `tpm_seal_try_unlock`
   mounts the ESP, reads `/EFI/ivo/sealed.bin`, prompts for a TPM PIN
   if required, unseals via `SubmitCommand`, hands the result to
   `luks_unlock_with_passphrase`. Any failure falls through to the
   keyboard prompt.
7. LVM runs if enabled; filesystem probed and mounted.
8. `config.toml` verified (if `SECURE_BOOT=1`), parsed, entry
   selected.
9. `boot_entry` loads kernel and initrd, verifies hashes if
   `SECURE_BOOT=1`, measures into PCRs 8 and 9, calls
   `hal_boot_uefi`.
10. `hal_boot_uefi` parses the kernel PE header, places the image,
    installs `EFI_LOADED_IMAGE_PROTOCOL` on a fresh handle, installs
    LoadFile2 for the initrd, calls the kernel entry as a function
    pointer. `LoadImage` not used; firmware SB never sees the kernel.
11. Kernel EFI stub calls `ExitBootServices`, builds `boot_params`,
    retrieves initrd via LoadFile2, jumps to the decompressed kernel.

## 7. Source Tree

Root of `src/uefi/`:

- `core.h` — shared types, prototypes.
- `main.c` — `ivo_main` (entry), `panic`.
- `mm.c` — allocator. 1 MiB small heap in `.bss` with a free list;
  larger requests fall through to `hal_allocate_pages` with a page
  free list. `mm_free` zeroes the payload before returning the block.
- `string.c` — `memcpy`, `memset`, `memcmp`, `strlen`, `strcpy`,
  `strncpy`, `strcmp`, `strncmp`, `strstr`.

`boot/`:

- `boot.c` — kernel loader, per-entry hash verify, measurement,
  handoff.
- `config.c` / `config.h` — TOML subset parser, produces `entry_t`.
- `embedded_config.h` — compile-time config, generated by
  `tools/mkinitivo`.
- `partition.c` — GPT. `partition_find_boot()`,
  `partition_find_iso()`.

`ui/`:

- `con.c` — console. Same public API as the old character-cell
  version; now backed by the framebuffer renderer.
- `frame.c` / `frame.h` — panel drawing: title bar, rows, selection
  highlight, footer.
- `menu.c` — boot menu with timeout and default.
- `shell.c` — read-only CLI.
- `theme.h` / `theme.c` — theme selector and single definition of
  `theme_current`.
- `gfx.c` / `gfx.h` — framebuffer primitives: fill, alpha blend,
  vertical gradient, rounded rectangles, glyph blit.
- `text.c` / `text.h` — text drawing on top of `gfx` and `font`.
- `font.c` / `font.h` / `font_data.h` — pre-rasterized glyph tables.
  `font_data.h` is generated by `tools/font_rasterize`.

`hal/`:

- `hal.h` — platform contract.
- `uefi.c` — `hal_init`, block I/O, console, memory, chainload.
- `uefi_internal.h` — UEFI types, GUIDs, shared state.
- `uefi_kernel.c` — manual PE/COFF handoff.

`fs/`:

- `fs.c` / `fs.h` — filesystem dispatcher. `fs_probe_mount()`
  mounts the first match.
- `fat32.c` — FAT32 with VFAT long names.
- `ext4.c` / `ext4.h` — ext4 read-only. Extents depth 0–1, 64-bit,
  flex_bg, linear dirs, htree dirs, HALF_MD4, metadata_csum-aware.
- `btrfs.c` / `btrfs.h` — BTRFS read-only, single-device,
  subvolumes.
- `iso9660.c` — ISO9660 read-only with Rock Ridge, Joliet, El
  Torito. `iso9660_read_label` for `partition_find_iso`.

`storage/`:

- `luks.h`, `luks1.c`, `luks2.c`, `luks_common.c` — LUKS unlock.
- `lvm.c` / `lvm.h` — linear LVM extent mapping.
- `partition.h` — GPT constants.

`luks/`:

- `json.c` / `json.h` — LUKS2 JSON area parser.
- `base64.c` / `base64.h` — keyslot field decoder.
- `mem.c` — allocator shims for `json.c`.
- `endian.h` — big-endian readers.

`security/`:

- `secure_boot.c` / `secure_boot.h` — Ed25519 config verify, hash
  helpers.
- `secure_boot_pubkey.h` — generated by `tools/ivo-keygen`.
- `stack_chk.c` — `__stack_chk_guard`, `__stack_chk_fail`.
- `wipe.h` — `ivo_wipe`.

`security/tpm/`:

- `tpm.c` — TCG2 protocol, PCR extension.
- `tpm_cmd.c` — TPM2 command marshalling.
- `tpm_internal.h` — writers, readers, constants.
- `tpm_seal.c` — sealed-blob read, unseal, LUKS handoff.
- `tpm_seal_create.c` — SRK creation, policy build, sealed-object
  create, blob assembly.

`crypto/`:

- `aes.c` / `aes.h` — AES-256.
- `xts.c` / `xts.h` — AES-XTS.
- `sha1.c`, `sha256.c`, `sha512.c` with headers.
- `hmac.c`, `hmac_sha1.c` with headers.
- `pbkdf2.c` / `pbkdf2.h`.
- `blake2b.c` / `blake2b.h`.
- `argon2.c`, `argon2id.c`, `argon2_sse2.c`, `argon2_internal.h`.
- `ed25519.h`, `ed25519_verify.c`, `ed25519_sign.c`,
  `ed25519_keypair.c`, `ed25519_seed.c`.
- `fe.c`, `ge.c`, `sc.c` with headers, `precomp_data.h`.

`include/`:

- `string.h` — freestanding string prototypes.

Outside `src/uefi/`:

- `src/themes/{default,nord,gruvbox,solarized,highcontrast}.h` —
  theme headers. Each defines `static const struct theme
  theme_values`; `theme.c` exports the single `theme_current`.
- `src/keymaps/{us,de}.h` — keymaps.
- `assets/NotoSansMono-Regular.ttf` — the font rasterized into
  `font_data.h`.

## 8. HAL

```c
typedef struct {
    uint8_t  drive;
    uint64_t boot_lba;
    uint32_t boot_partition_guid[4];
    void    *memory_map;
    uint64_t memory_map_size;
    void    *firmware_data;
} boot_context_t;

typedef struct {
    uint32_t *framebuffer;
    uint32_t  width;
    uint32_t  height;
    uint32_t  pitch;
    uint32_t  bpp;
    uint32_t  format;
    uint64_t  size;
} video_mode_t;
```

`boot_lba` — sector offset of the filesystem within the block device.
UEFI: always 0. `EFI_BLOCK_IO_PROTOCOL` on the loaded-image handle
points at the partition directly.

`format` — `GFX_FMT_RGBX`, `GFX_FMT_BGRX`, `GFX_FMT_BITMASK`,
`GFX_FMT_BLTONLY`. `size` — framebuffer bytes.

Interface:

- `hal_init`
- `hal_read_blocks`, `hal_write_blocks`
- `hal_get_e820`
- `hal_get_video_mode`, `hal_get_text_mode`, `hal_set_video_mode`
- `hal_clear_screen`, `hal_set_attr`, `hal_set_cursor`
- `hal_getchar`, `hal_getchar_timeout`, `hal_putchar`
- `hal_puts_serial`
- `hal_allocate_pages`, `hal_allocate_pages_below`, `hal_free_pages`
- `hal_reboot`, `hal_get_disk_info`
- `hal_chainload`
- `hal_sse2_available`
- `hal_boot_uefi` (`noreturn`)

TPM-specific:

- `hal_esp_available`
- `hal_esp_sector_count`
- `hal_block_io_push_esp`, `hal_block_io_pop`

`hal_sse2_available` returns 1.

`hal_read_blocks` only serves 512-byte-sector devices, and bounces
through a page-aligned buffer when the caller's buffer does not meet
the device's `IoAlign`. The LUKS scan only considers devices on the
same disk as the ESP (device-path prefix match).

### UEFI HAL

64-bit C, `x86_64-w64-mingw32-gcc`. UEFI protocols declared inline,
no `gnu-efi`.

Boot services offsets: `AllocatePages` 0x28, `FreePages` 0x30,
`GetMemoryMap` 0x38, `HandleProtocol` 0x98, `InstallProtocolInterface`
0x80, `LoadImage` 0xC8, `StartImage` 0xD0, `LocateProtocol` 0x140,
`Stall` 0xF8.

- `hal_read_blocks`: `EFI_BLOCK_IO_PROTOCOL.ReadBlocks`, 128-sector
  chunks, cached `MediaId` and `BlockSize`.
- `hal_get_e820`: `GetMemoryMap`, `EFI_MEMORY_TYPE` translated.
- `hal_boot_uefi`: manual PE handoff.
- `hal_putchar`: `ConOut->OutputString`.
- `hal_getchar`: `ConIn->ReadKeyStroke`, non-blocking.

**Block device retargeting.** `hal_init` captures the ESP block I/O
from `li->DeviceHandle`, enumerates all block handles, probes each
for the LUKS magic. On match, `g_block_io` retargeted,
`hal_boot_partition_decided` set. No match, `g_block_io` stays on
the ESP.

**Enumeration details.** `Media->BlockSize != 512` skipped. Probe
read requests exactly `BlockSize` bytes; OVMF rejects non-multiples
with `EFI_INVALID_PARAMETER`.

**GOP pixel format.** QEMU/OVMF reports `PixelFormat == 0` (RGBX)
but lays out the framebuffer BGRX. The default mapping assumes this.
Build with `GFX_FMT=rgbx` on firmware that reports honestly.

`EFI_GRAPHICS_OUTPUT_PROTOCOL` is four function pointers followed by
`Mode *`. `EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE` carries `MaxMode`,
`Mode`, `Info *`, `SizeOfInfo`, `FrameBufferBase`, `FrameBufferSize`.
`Info` is a separate allocation holding the resolution and pixel
format.

## 9. Memory Layout

All dynamic through `AllocatePages`. Boot files read into pages from
`hal_allocate_pages_below`, capped at `0x7FFFFFFF`. Argon2id
workspace from `mm_alloc`, which pulls from the `.bss` small heap for
small requests and falls through to `hal_allocate_pages` for larger
ones.

## 10. Kernel Handoff

### UEFI

`hal_boot_uefi` manual PE handoff:

1. Parse PE header, place image.
2. Install `EFI_LOADED_IMAGE_PROTOCOL` on a fresh handle.
3. Install `EFI_LOAD_FILE2_PROTOCOL` for the initrd on both a
   private-on-image-handle GUID and the global
   `LINUX_EFI_INITRD_MEDIA_GUID` singleton.
4. Call the entry point as a function pointer.

`LoadImage` unused. Firmware SB never sees the kernel.

**Initrd delivery.** Private GUID (6.4+) or global singleton
(5.7-era). Both installed unconditionally when an initrd is present.
`LoadFile` returns `EFI_BUFFER_TOO_SMALL` with the size on a small
buffer, fills on the second call.

## 11. Crypto

- AES-256, AES-XTS — C
- SHA-1, SHA-256, SHA-512 — C
- HMAC-SHA1, HMAC-SHA256 — C
- PBKDF2-HMAC-SHA1, PBKDF2-HMAC-SHA256 — C
- BLAKE2b — C
- Argon2id — C, SSE2 path selected at compile time. Workspace from
  `mm_alloc`.
- Ed25519 — verify ported from orlp/ref10. Sign and keygen in
  `crypto/`, host-only.
- ECDSA / P-256 — not implemented.

All stateless. Stack buffers, no dynamic allocation except Argon2.

**SSE2 flag split.** `argon2_sse2.c` compiled with `-msse2`. SSE2
`fill_block` uses `__m128i_u *` (unaligned), emits `movdqu`/`movups`.
Aligned variant produces `movdqa`/`movaps`, faults with #GP on
16-byte misalignment.

Constant-time not claimed.

## 12. Filesystem

`fs.h` vtable. `fs.c` dispatches. `fs_probe_mount()` mounts the first
match. Probe order: ext4, btrfs, fat32, iso9660.

### FAT32

VFAT long names. FAT loaded into memory at mount. Write path used by
TPM enrollment to write `sealed.bin` to the ESP.

### ext4

Read-only. Extents depth 0–1, 64-bit, flex_bg, linear dirs, htree
dirs with HALF_MD4. Refuses `bigalloc`, `meta_bg`, `inline_data`,
`encrypt`, `casefold`, `verity`.

htree skip gated on `EXT4_INDEX_FL`, not signature alone.

### BTRFS

Read-only, single-device, uncompressed, subvolumes. Refuses
compressed extents and striped RAID profiles.

### ISO9660

Read-only, Rock Ridge, Joliet, El Torito. `iso9660_read_label` for
`partition_find_iso`. Two mount modes: block-device and memory.

## 13. LUKS

### LUKS1

- 592-byte header, spans two sectors. Multi-byte fields big-endian.
- `keyMaterialOffset` absolute from partition start.
- AES-XTS, 512-byte sectors, tweak counter from 0.
- TKS1 anti-forensic merge (sequential XOR-and-diffuse).
- MK digest `PBKDF2-HMAC-SHA256(mk, mk_digest_salt, mk_digest_iter,
  key_bytes)` truncated to 20.
- Iterates all eight slots.

### LUKS2

- Primary JSON header. Falls back to byte-swapped secondary on parse
  failure.
- Argon2id or PBKDF2.
- AES-XTS keyslot area decrypt.
- Anti-forensic split merge.
- Digest verify against JSON digests.
- Iterates populated keyslots, priority 2 before 1, skipping 0.
- Excluded: external tokens, multiple data segments, AEGIS/MORUS,
  non-`aes-xts`.

### Common

- `luks_enabled(ctx)` — probes for LUKS magic.
- `luks_unlock(ctx)` — dispatches by version field.
- `luks_unlock_with_passphrase(ctx, pass, pass_len)` — TPM path.
- `luks_wipe_keys()` — wipes the master key and key schedules right
  before kernel handoff or chainload.
- `luks_setup_crypto()` — stores MK, inits XTS.
- `luks_set_payload(part_lba, payload_offset_sectors)`.
- `luks_read_block`, `luks_read_blocks` — decrypt.
- `luks_get_master_key()` — host tests.
- `af_merge()` — anti-forensic merge.

## 14. LVM

Optional (`LVM=1`). PV label, MDA header, text metadata. Linear
extents for a named LV. No striping, mirroring, thin pools. Multiple
LVs per VG supported by `lvm_lv_count` / `lvm_lv_select` /
`lvm_lv_select_by_name`.

`LUKS=1 LVM=1`: LUKS first, LVM second. `luks_read_block` yields
plaintext PV sectors; `lvm.c` maps LV extents over those.

`lvm_init` idempotent.

`lvm_read_blocks` coalesces contiguous PV sectors, cap 8192. Per-
segment walk.

Wrapped MDAs refused (`RAW_LOCN_WRAPPED`). Ignored MDAs
(`RAW_LOCN_IGNORED`) refused.

## 15. Configuration

TOML subset. `/ivo/config.toml` on the boot filesystem.

```toml
timeout = 5
default = "linux"

[entries.linux]
kernel = "/boot/vmlinuz-linux"
initrd = "/boot/initramfs-linux.img"
options = "root=/dev/sda2 rw quiet"

[entries.AlpineLive]
kernel = "/alpine/vmlinuz-lts"
initrd = "/alpine/initramfs-lts"
options = "modules=loop,squashfs,sd-mod,usb-storage quiet"

[entries.Windows]
type = "efi-chainload"
path = "/EFI/Microsoft/Boot/bootmgfw.efi"
```

Per-entry fields: `kernel`, `initrd`, `options`, `type`
(`efi-chainload` or `iso-boot`), `path`, `iso_label`, `subvol`,
`kver`, `iver`, `cver`.

`tools/ivo-config` generates config. `tools/ivo-doctor` reads install
state. Every tool that reads or writes a config links
`boot/config.c` (`-DCONFIG_HOST`) and re-parses its own output.

`ivo-sign`: `--hash` hashes every file an entry boots (`kver` kernel,
`iver` non-empty initrd, `cver` chainload) beneath `--root`, refusing
`..` and symlinks (`O_NOFOLLOW` per component); `subvol` entries
beneath `--subvol-root/<subvol>`; `iso-boot` entries inside the
`--iso` image whose volume label equals `iso_label`, read with
`fs/iso9660.c`. Skips the rewrite when every hash already matches.
Rewrites only `kver`/`iver`/`cver` lines, re-parses, writes via temp
file + fsync + rename. `--sign` parses the bytes it signs; refuses on
parse error or any entry failing `config_entry_hashes_complete`.
Signs with the expanded key derived from the `.sec` seed and verifies
before writing. `.sec` is `seed[32] || pk[32]`; the old
`pk || scalar` layout is refused.

## 16. Shell

Read-only. ESC at menu. Commands: `ls`, `cat`, `stat`, `entries`,
`boot`, `disk`, `clear`, `reboot`, `halt`, `exit`, `help`. No write
path. `cat` refuses files above 32 KB and refuses binary by scanning
the first 256 bytes for a NUL.

## 17. Boot Menu

Title, entry list, countdown. Arrow keys move selection. Enter boots.
ESC enters shell. Digits 1–9 jump. Always draws, even with one entry.

Countdown: `Stall(10000)` per iteration, 10 ms per. Reset on selection
move, Enter, or shell return.

Menu items drawn with `frame_row_sel`; the selection highlight is a
rounded rectangle under the text. Footer right-aligned countdown.

## 18. UI

Framebuffer renderer on top of GOP. No character-cell layer, no CP437
font. `con.c` retains the public API of the old console (`con_puts`,
`con_putc`, `con_clear`, `con_set_fg`, `con_read_secret`, `halt`) and
is backed by `gfx` + `text` + `font`.

- **Panel.** Centred, `content_width` (default 720 px) wide, capped
  to screen minus margins. Background, 1 px border, 8 px corner
  radius, subtle drop shadow. Title bar at the top with a vertical
  gradient, centred title text.
- **Text.** Pre-rasterized glyphs, hinted (no subpixel variants).
  Noto Sans Mono Regular, em 24, baseline 19. All glyphs drawn on a
  common baseline.
- **Theme.** `struct theme` in `ui/theme.h`, one `theme_current`
  defined in `ui/theme.c`. Each theme file defines `theme_values`,
  and `theme.c` includes the one selected by the compile-time macro.
  Colours are 32-bit RGBA in the API; the gfx layer packs to the
  framebuffer format.
- **Glyph generation.** `tools/font_rasterize.c` reads a TTF via
  `stb_truetype`, produces `src/uefi/ui/font_data.h` with a
  fixed-advance cell per glyph. Regenerate with
  `make -B src/uefi/ui/font_data.h` after changing the font, size,
  or baseline. `assets/NotoSansMono-Regular.ttf` is committed.

No fallback when GOP is unavailable: `gfx_init` fails, a message goes
to serial, and the bootloader halts.

## 19. TPM

TPM 2.0 via `EFI_TCG2_PROTOCOL`.

**Measurement.** `tpm_measure` extends PCRs 8, 9 with kernel, initrd,
cmdline hashes via `HashLogExtendEvent`. Firmware extends PCRs 0–7.
Ivo does not measure itself; firmware measures `ivo.efi` into PCR 4.
After the unlock stage, `ivo_main` extends PCR 4 with the string
`ivo: unseal window closed`, so nothing later in the boot can unseal a
blob bound to PCR 4.

PCR 9 extended twice: initrd, then cmdline. `TPM_PCR_INITRD` and
`TPM_PCR_CMDLINE` are both 9.

Best-effort. No TCG2: `tpm_init` returns non-zero, `tpm_measure`
no-op. Boot does not fail.

**Sealing.** `tpm_cmd.c` marshals `Load`, `StartAuthSession`,
`PolicyPCR`, `PolicyPassword`, `Unseal`, `FlushContext`.
`tpm_seal.c` mounts ESP, reads `KNTP` blob from
`/EFI/ivo/sealed.bin`, optionally prompts for PIN, unseals against
PCR policy, hands to `luks_unlock_with_passphrase`. Failure falls
through to keyboard prompt.

Sealed secret is a 64-byte LUKS passphrase, not the master key.
Any populated keyslot works as fallback.

**Blob format.** Little-endian. Magic `KNTP`, version 2, flags byte
(bit 0 = PIN), PCR mask, parent handle, priv/pub lengths and bodies.
Length must exactly match. Full layout in `doc/tpm.md`.

**Enrollment.** `tpm_seal_create.c` creates the SRK at `0x81000001`
if absent, builds auth policy via trial session, creates the sealed
object, emits the blob. Triggered by zero-byte
`/EFI/ivo/seal-request` on the ESP.

**PIN.** flags bit 0 set: prompt `TPM PIN: `, pass bytes as
`TPM2_Unseal` auth hmac. Policy chain: `PolicyPCR`, then
`PolicyPassword`. Mismatch → `TPM_RC_AUTH_FAIL` (0x98E), falls
through to LUKS passphrase prompt. Both PIN and PCR policy must pass.

## 20. Secure Boot

`SECURE_BOOT=1`:

- `config.toml` and `config.toml.sig`. Ed25519 against
  `secure_boot_pubkey.h`.
- `kver` / `iver` / `cver` SHA-512 hex. `verify_entry` computes and
  compares.
- Fail-closed.

`sb_read_config` reads `config.toml` once; with `SECURE_BOOT` it
verifies the signature over that buffer, and `config_parse` parses the
same buffer. Entries missing a hash for any file they boot are
refused (`config_entry_hashes_complete`).

No `SECURE_BOOT`: the config is read unverified; hashes present in an
entry are still checked.

Six layers:

| Layer | Mechanism | Verified by |
|---|---|---|
| Firmware → Ivo | PE/COFF Authenticode | OVMF, X.509 RSA-2048 in `db` |
| Ivo → `config.toml` | Ed25519 signature | Ivo |
| Ivo → cmdline | inside signed config | Ivo |
| Ivo → kernel | SHA-512 (`kver`) | Ivo |
| Ivo → initrd | SHA-512 (`iver`) | Ivo |
| Ivo → chainload | SHA-512 + Authenticode | Ivo + OVMF |

Kernel verified by hash only. Manual PE handoff bypasses firmware SB.
Chainload verified by both: it goes through `LoadImage`.

Keys independent. `db` X.509 RSA-2048; `ivo_pubkey` Ed25519.

## 21. UEFI Chainloading

`LoadImage` / `StartImage`. Target read from filesystem, `cver`
verified if `SECURE_BOOT=1`, bytes passed to firmware. Target must be
signed against `db`. Same-volume only: outer Ivo's volume path plus a
synthetic `\ivo-chain` file path node. Path never read.

Verified with nested Ivo. Each chainloaded Ivo fresh: own globals,
own `hal_init`, own LUKS prompt.

## 22. Keymaps and Themes

`tools/keymap_compiler.c` converts `SCANCODE CHARACTER` text to C
header. Mappings: `us`, `de`. Output not consumed; `src/keymaps/*.h`
hand-written. §4.1.

Themes are C headers in `src/themes/`. `THEME=name` picks one.
Provided: `default`, `nord`, `gruvbox`, `solarized`,
`highcontrast`. New theme: header in `src/themes/`, `#elif
defined(IVO_THEME_<NAME>)` in both `src/uefi/ui/theme.h` (for the
macro chain) and `src/uefi/ui/theme.c` (for the include chain).

## 23. Build System

Single `Makefile`. `config.mk`.

**UEFI:** `nasm -f win64`, `x86_64-w64-mingw32-gcc`. `-DIVO_UEFI`,
`-fshort-wchar`, `-mno-stack-arg-probe`. Linked with `-nostdlib
-Wl,-subsystem,10 -Wl,-e,efi_main -Wl,-dll`. Output `ivo.efi`.

`CFLAGS_EFI` carries `-DIVO_THEME_<NAME>` and `-DIVO_GFX_FMT_<NAME>`
derived from `THEME` and `GFX_FMT`. Both flags are re-evaluated per
invocation; `make clean` is required when either changes.

`-MMD -MP`.

Source filtering:

- `STAGE2_C_SRC` wildcards `src/uefi/*.c`, `boot/*.c`, `ui/*.c`,
  `hal/*.c`, `fs/*.c`, `storage/*.c`, `crypto/*.c`, `luks/*.c`,
  `security/*.c`, `security/tpm/*.c`.
- `ed25519_sign.c`, `ed25519_keypair.c`, `ed25519_seed.c` filtered
  out — host-only.

`src/uefi/ui/font_data.h` is generated by
`tools/font_rasterize`, which is built as part of `make tools`.

**Tools:** `mkinitivo`, `keymap_compiler`, `ivo-sign`, `ivo-keygen`,
`ivo-convert`, `ivo-install`, `ivo-config`, `ivo-doctor`,
`font_rasterize`.

**Tests:** `sha512-test`, `ed25519-test`, `luks1-test`, `luks2-test`,
`btrfs-test`.

No `nm` symbol check. No profile system.

## 24. Security Principles

- **`.bss` zeroed by the linker/firmware before C runs.**
- **Fixed-size stack buffers, length-checked string operations.**
- **Read-only, mostly.** One write path: `fs_write` to the ESP, used
  by TPM enrollment.
- **Measured boot.** Firmware measures Ivo into PCR 4; Ivo caps PCR 4
  after unlock; kernel, initrd and cmdline go into PCRs 8 and 9.
- **Sealed unlock.** LUKS passphrase sealed to PCR state, unsealed at
  boot. Optional PIN. Fallback to prompt on any failure.
- **Stack protector.** `-fstack-protector-strong`, freestanding
  `__stack_chk_guard` seeded from RDRAND with a TSC fallback.
- **Wipe on panic.** `panic()` calls `luks_wipe_keys()` before
  halting.

Constant-time not claimed for C crypto.

## 25. Non-Goals

- Networking (PXE, HTTP boot).
- RAID assembly.
- Advanced LVM (striping, mirroring, thin pools).
- ZFS, NTFS, ReiserFS, JFFS, UBIFS, XFS.
- Sound, splash, games.
- GRUB compatibility or theme formats.
- TUI widget library.
- Dynamic kernel modules.
- Userspace tool compatibility.
- **General write path.** Recovery tooling out of scope. One
  exception: TPM enrollment to the ESP.
- **LUKS inside an LVM logical volume.** LUKS headers on a raw
  partition. Supported: LVM inside LUKS.
- **BIOS support.** UEFI x86_64 only.
- **ISO as virtual `EFI_BLOCK_IO_PROTOCOL`** backed by memory.
- **Direct CRB MMIO for TPM.** Under SMM the CRB region is
  intercepted by the SMI handler.
- **Fallback UI when GOP is unavailable.** Halts with a serial
  message.

## 26. Testing

Primary: QEMU OVMF, OVMF+SB, OVMF+SB+TPM. Secondary: H310M/i5-9400F
desktop.

Test loops in `devnotes.md`. Essentials:

```bash
make clean && make LUKS=1 LUKS_USE_ARGON2=1 LVM=1
make clean && make SECURE_BOOT=1 TPM=1 LUKS=1 LVM=1 LUKS_USE_ARGON2=1
make tools
tests/luks1-test /path/to/luks1.img testpass
tests/luks2-test /path/to/luks2.img testpass
```

Compare against `cryptsetup luksDump --dump-master-key --batch-file=-`.

## 27. Repository Layout

```
ivo/
├── README.md
├── LICENSE
├── example.toml
├── config.mk
├── config.mk.example
├── Makefile
├── devnotes.md
├── assets/
│   └── NotoSansMono-Regular.ttf
├── contrib/
│   └── initcpio/
│       ├── ivo-sign.hook
│       └── sign.conf
├── doc/
│   ├── spec.md
│   ├── uefi.md
│   ├── internals.md
│   ├── lvm.md
│   ├── btrfs.md
│   ├── ext4.md
│   ├── luks.md
│   ├── tpm.md
│   └── changelog.md
├── src/
│   ├── keymaps/{us,de}.h
│   ├── themes/{default,nord,gruvbox,solarized,highcontrast}.h
│   └── uefi/
│       ├── core.h
│       ├── main.c
│       ├── mm.c
│       ├── string.c
│       ├── boot/
│       │   ├── boot.c
│       │   ├── config.c
│       │   ├── config.h
│       │   ├── embedded_config.h
│       │   └── partition.c
│       ├── ui/
│       │   ├── con.c
│       │   ├── frame.c
│       │   ├── frame.h
│       │   ├── menu.c
│       │   ├── shell.c
│       │   ├── theme.c
│       │   ├── theme.h
│       │   ├── gfx.c
│       │   ├── gfx.h
│       │   ├── text.c
│       │   ├── text.h
│       │   ├── font.c
│       │   ├── font.h
│       │   └── font_data.h
│       ├── hal/
│       │   ├── hal.h
│       │   ├── uefi.c
│       │   ├── uefi_internal.h
│       │   └── uefi_kernel.c
│       ├── fs/
│       │   ├── fs.c
│       │   ├── fs.h
│       │   ├── fat32.c
│       │   ├── ext4.c
│       │   ├── ext4.h
│       │   ├── btrfs.c
│       │   ├── btrfs.h
│       │   └── iso9660.c
│       ├── storage/
│       │   ├── luks.h
│       │   ├── luks1.c
│       │   ├── luks2.c
│       │   ├── luks_common.c
│       │   ├── lvm.c
│       │   ├── lvm.h
│       │   └── partition.h
│       ├── luks/
│       │   ├── json.c
│       │   ├── json.h
│       │   ├── base64.c
│       │   ├── base64.h
│       │   ├── mem.c
│       │   └── endian.h
│       ├── security/
│       │   ├── secure_boot.c
│       │   ├── secure_boot.h
│       │   ├── secure_boot_pubkey.h
│       │   ├── stack_chk.c
│       │   ├── wipe.h
│       │   └── tpm/
│       │       ├── tpm.c
│       │       ├── tpm_cmd.c
│       │       ├── tpm_internal.h
│       │       ├── tpm_seal.c
│       │       └── tpm_seal_create.c
│       ├── crypto/
│       │   ├── aes.c, aes.h
│       │   ├── xts.c, xts.h
│       │   ├── sha1.c, sha1.h
│       │   ├── sha256.c, sha256.h
│       │   ├── sha512.c, sha512.h
│       │   ├── hmac.c, hmac.h
│       │   ├── hmac_sha1.c, hmac_sha1.h
│       │   ├── pbkdf2.c, pbkdf2.h
│       │   ├── blake2b.c, blake2b.h
│       │   ├── argon2.c, argon2.h, argon2_internal.h
│       │   ├── argon2id.c
│       │   ├── argon2_sse2.c
│       │   ├── ed25519.h
│       │   ├── ed25519_verify.c, ed25519_sign.c
│       │   ├── ed25519_keypair.c, ed25519_seed.c
│       │   ├── fe.c, fe.h
│       │   ├── ge.c, ge.h
│       │   ├── sc.c, sc.h
│       │   └── precomp_data.h
│       └── include/
│           └── string.h
├── tests/
│   ├── btrfs-test.c
│   ├── ed25519-test.c
│   ├── fuzz-json.c
│   ├── luks1-test.c
│   ├── luks1-test.h
│   ├── luks2-test.c
│   ├── sha512-test.c
│   └── sha512-vendor-gen.c
└── tools/
    ├── mkinitivo.c
    ├── keymap_compiler.c
    ├── font_rasterize.c
    ├── ivo-sign.c
    ├── ivo-sign-host.c
    ├── ivo-keygen.c
    ├── ivo-convert.c
    ├── ivo-install.c
    ├── ivo-config.c
    ├── ivo-doctor.c
    ├── ivo-util.c
    ├── ivo-util.h
    └── third_party/
        └── stb_truetype.h
```

## 28. License

CLEAR License v1.