<h1 align="center">Ivo</h1>

<p align="center">
  <strong>A UEFI bootloader in C</strong><br>
  WIP.
</p>

---

## What it is

Boots Linux on UEFI x86_64. Unlocks LUKS volumes, reads the
filesystem inside, verifies the kernel and initrd against a signed
config, hands control to the kernel.

Targets UEFI, GPT, full-disk LUKS2. BIOS is not supported.

Config, kernel, initrd, and chainload target are verified against a
compiled-in public key. Kernel loaded via manual PE/COFF handoff;
firmware Secure Boot doesn't need to accept the kernel's signature.
Unsigned distribution kernels boot under Secure Boot.

## Features

- UEFI (PE/COFF) boot path
- GOP framebuffer UI
- FAT32 r/w with VFAT long names
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
- Rollback protection: TPM NV counter when present, else UEFI variable
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

- **`ivo-install`** — install to an ESP or USB stick
- **`ivo-config`** — scan `/boot`, write `config.toml`
- **`ivo-sign`** — hash, check, sign, verify a config
- **`ivo-keygen`** — Ed25519 keypair; `--password-hash`
- **`ivo-convert`** — GRUB, Limine, rEFInd → `config.toml`
- **`ivo-doctor`** — read-only diagnostic

`contrib/initcpio/`: mkinitcpio post hook. Re-hashes the config after
kernel or initramfs rebuild.

## Install

### Build

```sh
cp config.mk.example config.mk
# edit config.mk
make
```

Output: `ivo.efi`.

```sh
make clean && make
make clean && make LUKS=1 LVM=1
make clean && make SECURE_BOOT=1 TPM=1 LUKS=1 LVM=1
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

Or `tools/ivo-install --target uefi --esp /boot/efi`.

Generate config, hash, optionally sign:

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

`--root`: boot filesystem mount point. Symlinks and `..` refused.
`subvol` resolves beneath `--subvol-root`. `iso-boot` needs
`--iso IMAGE`, matched by volume label. `--hash` rewrites
atomically, no-op if every hash matches. `--sign` refuses a config
the bootloader would reject.

`ivo-keygen` writes `key.sec` (0600, `seed[32] || pk[32]`),
`key.pub`, `key.h`. Refuses overwrite without `--force`.

`ivo-doctor --pub key.pub` verifies the signature.

### Install (USB)

```sh
sudo tools/ivo-install --target usb --device /dev/sdX --iso alpine.iso
```

Partitions the device, formats the ESP, extracts kernel and initrd
from the ISO, writes a config, copies the ISO to a raw partition.
Device must be an unmounted whole disk. Boot with Secure Boot off,
CSM off.

### Convert an existing config

```sh
tools/ivo-convert --from grub   /boot/grub/grub.cfg -o config.toml
tools/ivo-convert --from limine /boot/limine.cfg     -o config.toml
tools/ivo-convert --from refind /boot/refind.conf    -o config.toml
tools/ivo-sign --hash --config config.toml --root /boot
```

## Configuration

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

Strict TOML subset: global keys, then `[entries.<name>]` sections. No
arrays, nested tables, inline tables, multi-line strings, scripting.
Tools and bootloader share the parser.

### Themes

```sh
make clean && make THEME=nord LUKS=1 LVM=1
```

Provided: `default`, `nord`, `gruvbox`, `solarized`, `highcontrast`.

### Colors look swapped

QEMU/OVMF reports GOP `PixelFormat` one way, lays out the framebuffer
the other. Default matches QEMU. If reds and blues are interchanged:

```sh
make clean && make GFX_FMT=rgbx ...
```

### Keeping hashes fresh

Kernel, initramfs, chainload target, or `ivo.efi` changes invalidate
a hash. The bootloader refuses entries with stale hashes. A
`pacman -Syu` that replaces the kernel leaves the machine unable to
boot until the config is re-hashed.

Two mitigations:

1. **Fallback entry.** Second `[entries.<name>-fallback]` pointing
   at the previous kernel.

2. **mkinitcpio post hook.** Install
   `contrib/initcpio/ivo-sign.hook` to `/etc/initcpio/post/ivo`,
   configure `/etc/ivo/sign.conf`. Every initramfs rebuild runs
   `ivo-sign --hash` (and `--sign` if a key is set). Failure prints
   a boxed error and exits non-zero, so pacman shows the hook failed.

   ```sh
   sudo install -Dm644 contrib/initcpio/sign.conf /etc/ivo/sign.conf
   sudo install -Dm755 contrib/initcpio/ivo-sign.hook /etc/initcpio/post/ivo
   ```

Edit `/etc/ivo/sign.conf` first: `CONFIG`, `ROOT`, `IVO_SIGN`.

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

Target: x86_64 UEFI. No BIOS, AArch64, 32-bit UEFI.

## License

CLEAR License v1. See [LICENSE](LICENSE).