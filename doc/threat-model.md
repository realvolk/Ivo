# Ivo Threat Model

## Trust chain

| Layer | Mechanism | Verified by | Key |
|---|---|---|---|
| Firmware → Ivo | PE/COFF Authenticode | firmware | X.509 RSA-2048 in `db` |
| Ivo → `config.toml` | Ed25519 | `secure_boot.c` | Ed25519 pubkey in `secure_boot_pubkey.h` |
| Ivo → cmdline | inside signed config | `config.c` | same sig |
| Ivo → kernel | SHA-512 (`kver`) | `boot.c` | hash in signed config |
| Ivo → initrd | SHA-512 (`iver`) | `boot.c` | hash in signed config |
| Ivo → chainload | SHA-512 + Authenticode | `boot.c` + firmware | hash in signed config; Authenticode in `db` |

`db` and `ivo_pubkey` are independent.

## Firmware → Ivo

`ivo.efi` signed with `db`; firmware refuses to start it otherwise.
Without SB, firmware loads any executable from the ESP. Everything
below assumes SB is on.

## Ivo → config.toml

`sb_read_config` reads `/ivo/config.toml` and
`/ivo/config.toml.sig`, verifies with `ivo_pubkey`. `config_load`
parses exactly the verified buffer. No re-read.

Verification failure → `CONFIG_ERR_SIGNATURE` →
`panic("config.toml signature invalid")`. No fallback to unverified
config when a signature is present but wrong.

Without `SECURE_BOOT=1`, `sb_read_config` returns the file unverified.
Hashes in the config are still checked; missing hashes are tolerated.
Development mode.

## Ivo → cmdline

Field in the signed config. No external source. The cmdline editor
modifies the in-memory copy after verification; the modification does
not persist.

## Ivo → kernel

`load_kernel` reads the kernel, computes SHA-512, compares against
`kver`. Mismatch → `BAD HASH`, entry does not proceed.

`hal_boot_uefi` parses the PE header, copies sections into
`hal_allocate_code_pages_below` pages, installs
`EFI_LOADED_IMAGE_PROTOCOL` on a fresh handle, calls the stub entry
via MS x64 ABI. `LoadImage` is not used.

Firmware SB never sees the kernel. Trust anchor is the config's
Ed25519 signature plus `kver`. No separate kernel signature — a signed
kernel would require a signing key on every update.

## Ivo → initrd

`load_initrd` reads, hashes, compares against `iver`.

Handoff installs the initrd via `EFI_LOAD_FILE2_PROTOCOL` under
`LINUX_EFI_INITRD_LF2_PROTOCOL_GUID` (private) and
`LINUX_EFI_INITRD_MEDIA_GUID` (global).

`li.DeviceHandle` is Ivo's own image handle, not the ESP volume. The
Linux stub's `initrd=` fallback opens files on `DeviceHandle`'s
filesystem; pointing it at the ESP would allow an unhashed initrd.
With `DeviceHandle = g_image` the fallback finds no filesystem and
the initrd arrives only through the installed protocol.

## Ivo → chainload target

`boot_chainload` reads the target, hashes, compares against `cver`.
On match, `hal_chainload` calls `LoadImage` + `StartImage`. Firmware
SB applies: target must be signed against `db`.

Hash binds the target to the config. Firmware SB binds it to the
machine's trust store.

## Rollback protection

`IVO_RELEASE` compared against a stored value at boot. Higher stored
value → refuse.

Two stores:

- **TPM NV counter** (`0x01800000`). Authoritative when present.
  Not resettable without TPM owner authorization.
- **UEFI variable `Ivo/FirmwareVer`.** Fallback when the NV counter
  is unavailable or the TPM is absent.

Config `version` uses `Ivo/ConfigVer` in the same scheme. A config
without a `version` key does not participate.

Not defended against:

- Attacker replaces both the running binary and the stored value.
  NV counter blocks this; UEFI variable does not.
- Attacker writes the ESP and deletes the UEFI variable.
- Attacker modifies `ivo.efi` without changing its measured hash.

## TPM-sealed unlock

Seals the LUKS passphrase to a policy bound to PCR 4 (bootloader
measurement) and PCR 7 (Secure Boot policy). Unseal requires both.

The seal is a convenience. The passphrase is the key.

Not defended against:

- **Attacker on the TPM bus.** Sessions unsalted, parameters
  unencrypted. PIN and secret cross the bus in cleartext. Under SMM
  with a CRB trapped by the SMI handler, the "bus" is CPU-to-TPM
  traffic an OS cannot read; a hardware probe between CPU and TPM
  can. See `tpm.md` § "Salted sessions (not implemented)".
- **TPM reset.** fTPM firmware update, motherboard swap, owner
  reset. Blob permanently undecryptable. The LUKS passphrase still
  works if a human passphrase is enrolled.
- **Attacker with the same firmware state and the PIN.** PCR-only
  sealing does not stop this. The PIN does.
- **The TPM itself.** Secret stored under the SRK at `0x81000001`,
  protected by the TPM's key hierarchy. TPM firmware and silicon
  vulnerabilities are out of scope.

Enroll a second LUKS keyslot with a memorized passphrase before
enabling TPM unlock. The passphrase is the recovery path.

## Recovery

One artifact: a USB stick with a working `ivo.efi`.

Not a security feature. A second bootloader firmware can start when
the ESP's does not. Same OS, same config, same trust chain. Firmware
boot menu selects.

`tools/ivo install usb` produces one.

For LUKS: a second keyslot, `cryptsetup luksAddKey`. Fallback when the
TPM path is unavailable. Ivo does not manage LUKS fallback keys.

Lost `/tmp/tpm_state` (swtpm development): storage seed gone, every
sealed blob undecryptable. Re-enroll. Hardware equivalent is a cleared
TPM.

## Out of scope

- Cold-boot DRAM attacks.
- DMA attacks.
- Firmware-owned memory Ivo does not clear.
- The kernel's own in-memory copies.
- `sealed.bin` tampering by a chainloaded OS. Beyond the per-entry
  hash check on the next boot, Ivo does not detect it. If `sealed.bin`
  is deleted or replaced, the TPM path fails and the passphrase prompt
  appears. No compromise.
- A chainloaded OS writing `Ivo/FirmwareVer` or `Ivo/ConfigVer` to
  reset rollback protection. Both are UEFI variables; every loaded
  image has write access.

## Compile-time modes

| Flag | Effect |
|---|---|
| `SECURE_BOOT=1` | Config signature verified; entries missing hashes refused. |
| unset | Config read unverified; present hashes checked; missing hashes tolerated. |
| `TPM=1` | Measurement and sealed unlock compiled in. |
| unset | Every TPM entry point is a stub. |
| `LUKS=1` | LUKS unlock compiled in. |
| `LVM=1` | LVM reader compiled in. |

Default build (`make`): no `SECURE_BOOT`, no `TPM`, no `LUKS`, no
`LVM`. Plain FAT32 ESP bootloader. Not a secure configuration; exists
for development.