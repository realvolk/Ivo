# UEFI Internals — Reader Notes

Platform notes for the UEFI (64-bit) build. Platform-neutral notes in
`internals.md`.

## Boot chain

1. Firmware loads `\EFI\BOOT\BOOTX64.EFI` from the ESP, calls
   `efi_main` with the image handle and system table.
2. `efi_main` stashes both in globals, builds a zero-initialized
   `boot_context_t` with `firmware_data = system_table`, calls
   `ivo_main`. `ivo_main` calls `hal_init`.
3. `hal_init` locates `ConIn`, `ConOut`, GOP, the loaded-image
   protocol on the loaded image handle, block I/O on the device handle
   behind it. Then enumerates every block device and retargets the
   boot device at the LUKS partition if one is found.
4. `ivo_main` unlocks LUKS if enabled, mounts the filesystem,
   verifies `config.toml` if `SECURE_BOOT=1`, parses, shows the menu.
5. `boot_entry` loads `vmlinuz` and initrd, verifies hashes against
   the signed config, calls `hal_boot_uefi`.
6. `hal_boot_uefi` parses the PE header, places the image, installs
   `EFI_LOADED_IMAGE_PROTOCOL` on a fresh handle, calls the stub
   entry as a function pointer.

Single PE32+ application.

## Binary format

Output is `ivo.efi`, PE32+ for EFI (subsystem `10`):

```
x86_64-w64-mingw32-gcc -nostdlib -Wl,-subsystem,10 -Wl,-e,efi_main \
    -Wl,-dll -Wl,--image-base,0 -Wl,-file-alignment,512 \
    -o ivo.efi *.o
```

`efi_main` is `__attribute__((ms_abi))`. MinGW's default ABI is
already Microsoft x64; the attribute is documentation.

Flags that matter:

- `-fshort-wchar` — `wchar_t` is 16 bits, matches `CHAR16`.
- `-mno-stack-arg-probe` — suppresses the `___chkstk_ms` call GCC
  emits for large stack frames. MinGW's runtime isn't linked; the
  symbol would be undefined.
- `-fstack-protector-strong` — stack smashing protection.
  `__stack_chk_guard` seeded from RDRAND with a TSC fallback in
  `stack_chk.c`.
- `-mno-red-zone`.
- `-DIVO_UEFI` — selects UEFI paths in `boot.c`, `main.c`, `hal.h`.
- `-DLUKS` — set by the Makefile when `LUKS=1`. Without it,
  `luks_enabled()` returns 0 and the LUKS path is compiled out,
  including block-device retargeting.
- `-DSECURE_BOOT` — set by the Makefile when `SECURE_BOOT=1`.

## Signing

Firmware Secure Boot requires `ivo.efi` signed against the enrolled
`db` key. `sbctl` appends an Authenticode certificate to the PE
image's certificate table.

```
sudo sbctl sign -s ivo.efi
```

`-s` records the file in `/var/lib/sbctl/files.json` for
`sbctl sign-all`. After any rebuild the binary is unsigned and must
be re-signed.

Signing modifies the binary. A `cver` hash pointing at a
previously-signed `ivo.efi` goes stale; regenerate with
`ivo-sign --hash`.

`sbctl sign` reports success but firmware refuses: run `sbctl verify
<path>` (`sudo` — reads the private key). Signature present but OVMF
still refuses: check the OVMF VARS file has `db` enrolled —
`virt-fw-vars --output-json`, or OVMF setup.

## Boot Services offsets

UEFI 2.10, section 4.2.

| Offset  | Function                    |
|---------|-----------------------------|
| `0x28`  | `AllocatePages`             |
| `0x30`  | `FreePages`                 |
| `0x38`  | `GetMemoryMap`              |
| `0x40`  | `AllocatePool`              |
| `0x48`  | `FreePool`                  |
| `0x80`  | `InstallProtocolInterface`  |
| `0x98`  | `HandleProtocol`            |
| `0xB8`  | `LocateDevicePath`          |
| `0xC8`  | `LoadImage`                 |
| `0xD0`  | `StartImage`                |
| `0xF8`  | `Stall`                     |
| `0x138` | `LocateHandleBuffer`        |
| `0x140` | `LocateProtocol`            |

Runtime Services, section 8.1:

| Offset  | Function                    |
|---------|-----------------------------|
| `0x68`  | `ResetSystem`               |

## Protocol GUIDs

| GUID                                | Value                                  |
|-------------------------------------|----------------------------------------|
| `EFI_LOADED_IMAGE_PROTOCOL_GUID`    | `5B1B31A1-9562-11D2-8E3F-00A0C969723B` |
| `EFI_BLOCK_IO_PROTOCOL_GUID`        | `964E5B21-6459-11D2-8E39-00A0C969723B` |
| `EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID` | `9042A9DE-23DC-4A38-96FB-7ADED080516A` |
| `EFI_DEVICE_PATH_PROTOCOL_GUID`     | `09576E91-6D3F-11D2-8E39-00A0C969723B` |
| `EFI_LOAD_FILE2_PROTOCOL_GUID`      | `4006C0C1-FCB3-403E-996D-4A6C8724E06D` |
| `LINUX_EFI_INITRD_MEDIA_GUID`       | `5568E427-68FC-4F3D-AC74-CA555231CC68` |
| `LINUX_EFI_INITRD_LF2_PROTOCOL_GUID`| `F9E3378E-B3B1-423A-BD9A-2D0860287F72` |

**`EFI_LOAD_FILE2_PROTOCOL_GUID` ends in `E06D`, not `E0DE`.**
Kernel source (`include/linux/efi.h`) and tianocore
(`MdePkg/Include/Protocol/LoadFile2.h`) both say `E06D`. An earlier
revision of Ivo had `E0DE`; every LoadFile2 lookup failed on both
sides. `EFI_NOT_FOUND` for a protocol install that seems correct:
check this byte first.

`LINUX_EFI_INITRD_LF2_PROTOCOL_GUID` is the private-on-image-handle
path added in kernel 6.4. Ivo installs it as a courtesy for kernels
that carry the code. Stock Artix 7.1.8 does not; the
global-singleton install below works on that kernel.

## HAL initialization

`hal_init`, in order:

1. Sets `ctx->boot_lba = 0`. On UEFI the block device is the
   partition read from; the LUKS header or filesystem starts at LBA
   0 of that partition.
2. Caches `ConOut`, `ConIn`.
3. `HandleProtocol(g_image, &GUID_LOADED_IMAGE)` for the loaded
   `EFI_LOADED_IMAGE_PROTOCOL`.
4. From `li->DeviceHandle`, `HandleProtocol(..., &GUID_BLOCK_IO)` for
   the block device. That is the ESP. Cached as the initial
   `g_block_io`; replaced by the enumeration below if a LUKS
   partition is present.
5. Caches `MediaId`, `BlockSize`.
6. Enumerates every handle exposing `EFI_BLOCK_IO_PROTOCOL` via
   `LocateHandleBuffer(ByProtocol, &GUID_BLOCK_IO, NULL, ...)`. For
   each handle other than `li->DeviceHandle`, reads one block,
   checks for the LUKS magic. First match replaces `g_block_io`,
   `g_media_id`, `g_block_size`.    `hal_boot_partition_decided` set so
   `main.c` skips `partition_find_boot`.
7. `LocateProtocol(&GUID_GOP)`. Cached for `hal_get_video_mode`.
8. `GetMemoryMap` with a zero-size buffer to learn descriptor size
   and current map size. Not used for E820 translation —
   `hal_get_e820` does its own `GetMemoryMap`.
9. Initializes the `LoadFile2` vtable's `LoadFile` pointer.

### Block device enumeration

How Ivo finds the LUKS partition. Firmware loads `BOOTX64.EFI` from
the ESP; kernel, initrd, and config may live on a separate LUKS
volume. The enumeration finds that volume by probing the first block
of each partition for the LUKS magic.

`Media->BlockSize != 512` skipped. Firmware requires `ReadBlocks`
byte counts to be a multiple of `BlockSize`; the HAL assumes
512-byte sectors. A native 4 KB device would need a shim.

The probe read must request exactly `BlockSize` bytes. An earlier
version requested 8; OVMF rejected with `EFI_INVALID_PARAMETER` for
a non-multiple. Silent until debug prints.

## Disk I/O

`hal_read_blocks` reads from `g_block_io` (ESP or LUKS partition).

Chunked to 128 sectors per `ReadBlocks` call. Keeps buffer-size
arithmetic in 32-bit range and matches the device-agnostic cap used
by the filesystem and LUKS layers.

`hal_write_blocks` calls `WriteBlocks` with the cached `MediaId`,
checks `Media->ReadOnly` first.

## Memory map extraction

`EFI_MEMORY_TYPE` to E820:

| EFI type | E820 type | Meaning      |
|----------|-----------|--------------|
| `1` `EfiLoaderCode`         | 1 | usable       |
| `2` `EfiLoaderData`         | 1 | usable       |
| `3` `EfiBootServicesCode`   | 1 | usable       |
| `4` `EfiBootServicesData`   | 1 | usable       |
| `7` `EfiConventionalMemory` | 1 | usable       |
| `9` `EfiACPIReclaimMemory`  | 3 | ACPI reclaim |
| `10` `EfiACPIMemoryNVS`     | 4 | ACPI NVS     |
| anything else               | 2 | reserved     |

Types `1`–`4` and `7` map to usable — the kernel maps them as RAM
after `ExitBootServices`, and firmware releases loader and
boot-services memory there.

Output is 20-byte E820 entries. `boot_params.e820_table` populated by
the kernel's own EFI stub, not by Ivo.

## Allocation helpers

`hal_allocate_pages` — `AllocatePages(AllocateAnyPages)`.

`hal_allocate_pages_below` — `AllocatePages(AllocateMaxAddress)` with
the cap; falls back to `AllocateAnyPages` if no contiguous region
below the cap.

`crypto/argon2.c` uses `mm_alloc`, which pulls from the `.bss` small
heap for small requests and falls through to `hal_allocate_pages` for
larger ones. Argon2id workspace for a default
`cryptsetup luksFormat --type luks2` volume is 1 GiB; the `.bss` heap
is 1 MiB.

## Console and keyboard

`hal_putchar` calls `ConOut->OutputString` one character at a time.
`\n` becomes `\r\n` before the call. Not batched.

`hal_getchar` polls `ConIn->ReadKeyStroke` once, returns immediately.
No key → 0.

Printable ASCII (`UnicodeChar < 0x80`, nonzero) passes through.
Extended keys translated from UEFI scan codes to the convention
`0x80 | scan_code`, so `menu.c` sees identical values:

| Key      | Returned byte | UEFI ScanCode |
|----------|---------------|---------------|
| Up       | `0xC8`        | `0x01`        |
| Down     | `0xD0`        | `0x02`        |
| Right    | `0xCD`        | `0x03`        |
| Left     | `0xCB`        | `0x04`        |
| PageUp   | `0xC9`        | `0x05`        |
| PageDown | `0xD1`        | `0x06`        |
| Esc      | `0x1B`        | `0x17` → `0x1B` |

`hal_getchar_timeout` polls with `Stall(10000)`, accumulates elapsed
time in 10 ms steps, returns 0 on timeout.

An earlier UEFI implementation had `hal_getchar` spin forever, which
made `hal_getchar_timeout`'s timeout a lie and hung the menu
countdown. An earlier version returned raw `UnicodeChar` for extended
keys (0 for arrows), making arrow key input invisible to the menu.

## Kernel handoff

Firmware SB refuses `LoadImage` on unsigned PE/COFF, so an ISO's
kernel can't be booted through the normal protocol. Ivo parses the
PE header itself, places the image, installs
`EFI_LOADED_IMAGE_PROTOCOL` on a fresh handle, installs `LoadFile2`
for the initrd, calls the stub entry as a function pointer.

`hal_boot_uefi` lives in `uefi_kernel.c`. The manual handoff
bypasses firmware SB for the kernel — trust anchor is the config's
Ed25519 signature plus `kver`, both checked in `boot_entry` before
the call.

Initrd LoadFile2 install and cmdline UTF-16 conversion live in
`uefi.c`.

### Device path requirement

The kernel's EFI stub opens its own volume by reading
`EFI_LOADED_IMAGE_PROTOCOL.DeviceHandle` on its image handle. Ivo
constructs that protocol by hand; the device path has to be correct.

The stub also uses the loaded image's volume to resolve `initrd=`. If
the device handle is missing, that lookup silently fails and the
kernel proceeds without an initrd.

Current `hal_boot_uefi` sets `li.DeviceHandle = g_image` (Ivo's own
image handle), not a real volume device path. Works on Artix 7.1.8
because the initrd is delivered via LoadFile2, which doesn't need a
device path. Would not work for a kernel that resolves `initrd=`
against the volume.

### Secure Boot policy on handoff

Firmware SB bypassed for the kernel. Applies to the chainload path
(real `LoadImage`).

Exception: `SECURE_BOOT=0` → `boot_entry` doesn't check `kver` or
`iver`, `hal_boot_uefi` boots whatever bytes are at the path.
Deliberate configuration choice.

### Command line

`config.toml` cmdline → UTF-16 via `AllocatePool`, stored in
`li->LoadOptions` with size in `li->LoadOptionsSize`. Kernel stub
reads this as its boot command line.

### Initrd delivery

Two mechanisms, both installed by Ivo before calling the stub. The
kernel's EFI stub picks whichever it supports.

**LoadFile2.** Two installs.

*Global singleton.* A vendor media device path node carrying
`LINUX_EFI_INITRD_MEDIA_GUID` installed on a fresh handle, an
`EFI_LOAD_FILE2_PROTOCOL` on the same handle. The kernel's EFI stub
finds this via `LocateDevicePath(&EFI_LOAD_FILE2_PROTOCOL_GUID,
&initrd_dev_path, &handle)` — `initrd_dev_path` is the same bare
`[vendor][END]` node — then `HandleProtocol` on the returned handle,
`LoadFile`. 5.7-era path; works on any kernel with LoadFile2 support.

*Private on image handle.* `EFI_LOAD_FILE2_PROTOCOL` on the kernel's
own image handle under `LINUX_EFI_INITRD_LF2_PROTOCOL_GUID`. Kernel
6.4+ checks the image handle for this private GUID before falling
back to `LocateDevicePath`. If present, used directly. If not, falls
through to the global singleton.

Both installs unconditional when the initrd is present and non-empty.
Installing the private GUID on a kernel that doesn't know about it is
harmless.

`LoadFile` returns `EFI_BUFFER_TOO_SMALL` with the size in
`BufferSize` on a too-small (or `NULL`) buffer, copies the initrd on
a large enough buffer. Kernel calls `LoadFile` twice: once with
`Buffer = NULL` to learn the size, allocates, then fills.

**`initrd=` cmdline directive.** Kernel stub resolves the path
relative to the loaded image's volume. Not used on Ivo today — the
loaded image's device handle isn't a real volume (see above).

**Not required when LoadFile2 works.** Kernel's stub finds Ivo's
`LoadFile2`, calls twice, receives the initrd from inside the LUKS
volume, boots. Initrd need not exist on the ESP. The two paths are
independent.

If the `LoadFile2` install is malformed or installs under the wrong
GUID, the kernel's `LocateDevicePath` returns `EFI_NOT_FOUND` and the
stub falls through to `initrd=`. That path resolves against the
loaded image's volume; if the file isn't there, the kernel boots with
no initrd. Silent: kernel reaches `prepare_namespace`, tries to mount
`root=`, panics with `VFS: Unable to mount root fs on
unknown-block(0,0)`.

**GUID byte.** Both sides must agree on
`EFI_LOAD_FILE2_PROTOCOL_GUID`. Correct value ends in `E06D`. A
one-byte error is invisible until the kernel panics.

### Chainload

`hal_chainload` loads a second EFI binary via `LoadImage` +
`StartImage`. Called from `boot_chainload` in `boot.c`, which has
already read the target and verified its hash against `cver`.

Same-volume only. Device path: the outer Ivo's volume device path
plus a synthetic `FilePathDevicePath` node. File path is `\ivo-chain`,
doesn't exist on disk, never read. `LoadImage` receives the image
bytes directly; the path only constructs the new image's
`DeviceHandle` and `FilePath`.

Secure Boot policy applies. Target must be signed against `db` or
`LoadImage` returns `EFI_ACCESS_DENIED`. Signing the outer `ivo.efi`
does not sign the target.

**Each chainloaded Ivo is a fresh process.** Own `g_st`, `g_image`,
`g_block_io`. Own `hal_init`. On LUKS, prompts for the passphrase a
second time. No shared LUKS state.

`StartImage` may return if the chainloaded image exits or returns
normally. `hal_chainload` returns 0; `boot_entry` falls through to
the shell.

### Debugging the handoff

Kernel reaches its entry point but never calls Ivo's `LoadFile`: the
fault is on the kernel's side, not observable from Ivo alone. Three
tools:

1. **Firmware debug output.** Debug OVMF with
   `-D DEBUG_ON_SERIAL_PORT` prints every `InstallProtocolInterface`,
   `LocateDevicePath`, `LoadImage`.

2. **Custom kernel with stub instrumentation.** COM1 markers (LSR
   `0x3FD`, data `0x3F8`) inside `efi_load_initrd` and
   `efi_load_initrd_dev_path` in
   `drivers/firmware/efi/libstub/efi-stub-helper.c` show which calls
   the stub makes and what each returns. This is how the GUID error
   was located.

3. **`efi=debug` and `earlycon=` cmdline.** Requires
   `CONFIG_EFI_EARLYCON=y`. Stock Artix 7.1.8 does not enable it;
   custom 7.2.9 does.

Do not byte-grep a compiled binary for a GUID. `-O2` splits 16-byte
constants across `movabs` immediates. Compare against source headers.

## Secure Boot

Two independent layers on UEFI:

1. **Firmware → Ivo.** OVMF verifies the Authenticode signature on
   `ivo.efi` against `db` before calling `efi_main`. Missing or wrong
   signature: `efi_main` never reached.

2. **Ivo → config + kernel + initrd + chainload.** With
   `SECURE_BOOT=1`, Ivo verifies `config.toml` against the
   compiled-in Ed25519 pubkey before parsing, verifies SHA-512 of
   kernel, initrd, chainload target against `kver`, `iver`, `cver` in
   that signed config.

Different keys, independent. `db` X.509 signs PE/COFF binaries,
checked by firmware. `ivo_pubkey` Ed25519 signs the config, checked
by Ivo.

Six-layer table in `internals.md`.

## Known limitations

- **`-Werror` off.** MinGW headers and code generation produce
  warnings GCC on the host doesn't. Warnings printed, not promoted.
- **Requires at least 2 GB guest RAM.** 200 MB initrd + ESP + live
  rootfs must fit in usable memory. 512 MB guest: `AllocatePages`
  fails.
- **No GOP fallback.** Firmware that doesn't expose a usable linear
  framebuffer halts with a serial message. No text-mode fallback.