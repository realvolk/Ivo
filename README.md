<h1 align="center">Ivo</h1>

<p align="center">
  <strong>A UEFI bootloader in C</strong><br>
  UEFI x86_64 • LUKS • LVM • TPM • Secure Boot
</p>

<p align="center">
  Small enough to audit. Complete enough to use.
</p>

<p align="center">
  <a href="#what-it-is">What it is</a>
  •
  <a href="#features">Features</a>
  •
  <a href="#tools">Tools</a>
  •
  <a href="#quick-start">Quick start</a>
  •
  <a href="#trust-model">Trust model</a>
  •
  <a href="#requirements">Requirements</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v1.1.1-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/license-CLEAR_v1-yellow?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/C-98%25-555555?style=flat-square&logo=c" alt="C">
  <img src="https://img.shields.io/badge/make-1%25-6E4C13?style=flat-square" alt="Make">
  <img src="https://img.shields.io/badge/targets-UEFI_x86__64-informational?style=flat-square" alt="Targets">
</p>

---

## What it is

Ivo boots Linux on UEFI x86_64. It unlocks LUKS volumes, reads the
filesystem inside them, verifies the kernel and initrd against a
signed config, and hands control to the kernel. No scripting engine,
no runtime modules, no writes to disk.

Targets UEFI, GPT, full-disk LUKS2. BIOS is not supported.

The config, kernel, initrd, and any chainload target are verified
against a public key compiled into the bootloader. The kernel is
loaded via a manual PE/COFF handoff, so firmware Secure Boot doesn't
need to accept the kernel's signature. An unsigned distribution kernel
boots under Secure Boot without being re-signed.

**UBI — Unified Bootloader Image.** The signed artifact is the
bootloader, not the kernel. Firmware verifies Ivo; Ivo verifies a
signed config; the config names the SHA-512 hashes of every file the
entry boots. Kernel, initrd, and cmdline are authenticated as a unit.
Where a Unified Kernel Image signs the payload and hands it to
`systemd-stub`, Ivo signs the loader and hands the payload to the
kernel directly.

## Features

- UEFI (PE/COFF) boot path
- GOP framebuffer UI. No CP437, no character cells.
- FAT32 read/write with VFAT long names
- ext4 read: extents, 64-bit, htree
- BTRFS read: single-device, subvolumes, uncompressed
- ISO9660 read: Rock Ridge, Joliet, El Torito
- LUKS1 and LUKS2, PBKDF2 and Argon2id, AES-XTS
- LVM2 linear volumes
- GPT partitions
- TOML config, no scripting
- Conditional entries (`if = "exists(/path)"`)
- Per-entry password hashes (PBKDF2-HMAC-SHA256)
- Kernel cmdline editor at boot
- Text-mode fallback when GOP is unavailable
- Ed25519-signed config, SHA-512-verified kernel/initrd/chainload
- Best-effort rollback protection (`version` key vs UEFI variable)
- Firmware Secure Boot (signed PE/COFF, `db`-enrolled)
- Manual PE/COFF kernel handoff that bypasses `LoadImage`
- Live ISO boot from a raw partition
- TPM 2.0 measurement (PCRs 4, 8, 9)
- TPM-sealed LUKS unlock, optional PIN
- Chainload with hash verification
- Read-only recovery shell
- Compile-time theme and keymap selection
- Single Makefile

## Tools

- **`ivo-install`** — install to an ESP or a USB stick.
- **`ivo-config`** — scan `/boot` and write a `config.toml`.
- **`ivo-sign`** — hash, check, sign, verify a config.
- **`ivo-keygen`** — Ed25519 keypair; `--password-hash` for
  per-entry passwords.
- **`ivo-convert`** — GRUB, Limine, rEFInd → `config.toml`.
- **`ivo-doctor`** — read-only diagnostic.

Plus `contrib/initcpio/`: a mkinitcpio post hook that re-hashes the
config after every kernel or initramfs rebuild. See
`contrib/initcpio/README.md`.

## Quick start

### Build

```sh
cp config.mk.example config.mk
# edit config.mk
make
```

Output: `ivo.efi`.

```sh
make clean && make
make clean && make LUKS=1 LUKS_USE_ARGON2=1 LVM=1
make clean && make SECURE_BOOT=1 TPM=1 LUKS=1 LVM=1 LUKS_USE_ARGON2=1
make clean && make THEME=nord LUKS=1 LVM=1
make tools
make tests
```

`make clean` after any flag change.

### Install

```sh
sudo make install ESP=/boot/efi
```

Writes `<esp>/EFI/BOOT/BOOTX64.EFI`. Doesn't touch NVRAM.
`sudo make uninstall ESP=/boot/efi` removes it.

Or `tools/ivo-install --target uefi --esp /boot/efi` — same effect.

Generate a config, hash it, optionally sign it:

```sh
tools/ivo-config -o config.toml
tools/ivo-keygen --out-prefix /path/to/key
cp /path/to/key.h src/uefi/security/secure_boot_pubkey.h
# rebuild ivo.efi
tools/ivo-sign --hash --config config.toml --root /boot
tools/ivo-sign --sign --config config.toml --key /path/to/key.sec
sudo cp config.toml config.toml.sig /boot/efi/ivo/

sudo sbctl sign -s ivo.efi    # if SECURE_BOOT=1
```

`--root` is where the boot filesystem is mounted. Symlinks and `..`
are refused. `subvol` entries resolve beneath `--subvol-root`.
`iso-boot` entries need `--iso IMAGE`, matched by volume label.
`--hash` rewrites the config atomically and does nothing when every
hash already matches. `--sign` refuses a config the bootloader would
reject.

`ivo-keygen` writes `key.sec` (mode 0600, `seed[32] || pk[32]`),
`key.pub`, and `key.h`. Refuses to overwrite without `--force`. Older
key layouts are refused by `ivo-sign`; rotate if you have one.

`ivo-doctor` reads the install. `--pub key.pub` verifies the
signature.

`TPM=1` needs no setup at install time. Ivo locates
`EFI_TCG2_PROTOCOL` at boot. To seal a LUKS passphrase, see
`doc/tpm.md`.

### Install (USB)

```sh
sudo tools/ivo-install --target usb --device /dev/sdX --iso alpine.iso
```

Partitions the device, formats the ESP, extracts kernel and initrd
from the ISO, writes a minimal config, copies the ISO to a raw
partition. Device must be a whole disk with nothing mounted.
Boot with Secure Boot off, CSM off.

### Converting an existing config

```sh
tools/ivo-convert --from grub   /boot/grub/grub.cfg -o config.toml
tools/ivo-convert --from limine /boot/limine.cfg     -o config.toml
tools/ivo-convert --from refind /boot/refind.conf    -o config.toml
tools/ivo-sign --hash --config config.toml --root /boot
```

### Configuration

```toml
version = 1
timeout = 5
default = "linux"

[entries.linux]
kernel = "/boot/vmlinuz-linux"
initrd = "/boot/initramfs-linux.img"
options = "root=/dev/mapper/vg0-root rw"
subvol = "@"
kver = "<filled by ivo-sign --hash>"
iver = "<filled by ivo-sign --hash>"

[entries.Windows]
type = "efi-chainload"
path = "/EFI/Microsoft/Boot/bootmgfw.efi"
cver = "<filled by ivo-sign --hash>"
```

Strict TOML subset: global keys, then `[entries.<name>]` sections.
No arrays, nested tables, inline tables, multi-line strings, or
scripting. Tools and bootloader share the parser.

### Themes

```sh
make clean && make THEME=nord LUKS=1 LVM=1
```

Provided: `default`, `nord`, `gruvbox`, `solarized`, `highcontrast`.
New theme: header in `src/themes/`, an `#elif defined(...)` branch in
`src/uefi/ui/theme.h`, and the same branch in `src/uefi/ui/theme.c`.

### Colors look swapped

QEMU/OVMF reports GOP `PixelFormat` one way but lays out the
framebuffer the other way. The default matches QEMU. If reds and
blues are interchanged on your firmware:

```sh
make clean && make GFX_FMT=rgbx ...
```

## Keeping hashes fresh

Kernel, initramfs, chainload target, or `ivo.efi` changes invalidate
a hash in `config.toml`. The bootloader refuses entries with stale
hashes. A `pacman -Syu` that replaces the kernel leaves the machine
unable to boot until the config is re-hashed.

Two mitigations:

1. **Fallback entry.** A second `[entries.<name>-fallback]` pointing
   at the previous kernel. Stale primary, working fallback.

2. **mkinitcpio post hook.** Install
   `contrib/initcpio/ivo-sign.hook` to `/etc/initcpio/post/ivo` and
   configure `/etc/ivo/sign.conf`. Every initramfs rebuild runs
   `ivo-sign --hash` (and `--sign` if a key is set). Failure prints
   a boxed error and exits non-zero, so pacman shows the hook failed.

   ```sh
   sudo install -Dm644 contrib/initcpio/sign.conf /etc/ivo/sign.conf
   sudo install -Dm755 contrib/initcpio/ivo-sign.hook /etc/initcpio/post/ivo
   ```

Edit `/etc/ivo/sign.conf` first: `CONFIG`, `ROOT`, `IVO_SIGN`.

## Trust model

| Layer | Mechanism | Verified by | Key |
|---|---|---|---|
| Firmware → Ivo | PE/COFF Authenticode | firmware | X.509 RSA-2048 in `db` |
| Ivo → `config.toml` | Ed25519 | `secure_boot.c` | Ed25519 pubkey in `secure_boot_pubkey.h` |
| Ivo → cmdline | inside signed config | `secure_boot.c` | same Ed25519 sig |
| Ivo → kernel | SHA-512 hash | `boot.c` (`kver`) | hash in signed config |
| Ivo → initrd | SHA-512 hash | `boot.c` (`iver`) | hash in signed config |
| Ivo → chainload target | SHA-512 + Authenticode | `boot.c` (`cver`) + firmware | hash in signed config; Authenticode in db |

`db` is X.509 RSA-2048, enrolled in firmware. `ivo_pubkey` is raw
Ed25519, compiled in. Independent keys.

Kernel verified by hash only; the manual handoff bypasses firmware
SB. Chainload verified by both hash and Authenticode.

The config commits to kernel path, initrd path, cmdline, subvol,
chainload path, and the SHA-512 hash of each referenced file, inside
one Ed25519 signature. Ivo reads `config.toml` once and parses
exactly the bytes it verified. With `SECURE_BOOT=1` every hash is
mandatory. Without it, hashes are still checked where present.

Ivo measures kernel, initrd, and cmdline into TPM PCRs 8 and 9.
PCR 4 holds the firmware's measurement of `ivo.efi`; after LUKS
unlock, Ivo extends PCR 4 with a separator. A passphrase sealed to
PCR 4 + 7 unseals only before the separator. Measurement is a record,
not a gate.

Rollback protection for signed configs is best-effort: Ivo compares a
`version` key in the config against a value stored in a UEFI variable,
and refuses to boot an older config. Anyone with ESP write access can
delete the variable and reset the check. A TPM NV counter is the real
fix and is not implemented. Cold-boot and DMA attacks on DRAM are out
of scope. Firmware-owned memory that Ivo does not clear survives
handoff. So does the kernel's own in-memory copy of anything it later
loads.

The recovery shell (Esc) reads the boot filesystem. If the disk was
unlocked from the TPM, it asks for the LUKS passphrase before any
`ls`, `cat`, or `stat`.

## Requirements

Always:

- `make`
- `nasm`
- `binutils` (`ld`, `objcopy`)
- `x86_64-w64-mingw32-gcc`

By feature:

| Feature | Extra tools |
|---|---|
| `SECURE_BOOT=1` | `sbctl` |
| TPM enrollment | `swtpm`, `tpm2-tools` |
| QEMU testing | `qemu-system-x86_64`, OVMF |
| Live ISO boot prep | `xorriso` or loopback mount |
| Enrolling keys in OVMF | `virt-fw-vars` (from `virt-firmware`) |

Target: x86_64 UEFI. Legacy BIOS, AArch64, and 32-bit UEFI are not
supported.

## Documentation

- [Specification](doc/spec.md)
- [Internals](doc/internals.md)
- [UEFI](doc/uefi.md)
- [LVM](doc/lvm.md)
- [TPM sealing](doc/tpm.md)
- [Changelog](doc/changelog.md)
- [Development notes](devnotes.md)

## License

CLEAR License v1. See [LICENSE](LICENSE).