# Ivo — Development Notes

Environment the code was built and tested in.

## Hardware

- **Acer N3060 laptop.** InsydeH2O CSM crashes on `int 0x13` before
  stage 2. UEFI works.
- **H310M / i5-9400F desktop.** AMI Aptio, standard H310M. UEFI only.

QEMU covers the rest: stock Arch OVMF, and a debug OVMF with
SB + SMM + TPM.

## Build

Feature flags must reach `CFLAGS_EFI`. `LUKS=1` also enables the
block-device retarget in `hal_init`; without it a LUKS install is
unreachable.

`-Werror` is off. MinGW headers and codegen produce warnings GCC on
the host doesn't; promoting them fails the build on unrelated header
churn.

## QEMU notes

- `-enable-kvm -cpu host` on any run with Argon2id. Without KVM a
  64 MiB keyslot takes minutes.
- `sleep 1` after `losetup -P`. Partition device nodes are async.
- OVMF with SB refuses an unsigned `ivo.efi` and drops to shell with
  "Access Denied". Sign before every boot.
- `losetup -a` may show `(deleted)` entries. `sudo losetup -D`.
- QEMU holds a write lock on the image. Detach between runs.
- At least 2 GB guest RAM. 200 MB initrd + ESP + live rootfs must
  fit in usable memory. 512 MB guest: `AllocatePages` fails.

## Kernel handoff

`EFI_LOAD_FILE2_PROTOCOL_GUID` is
`4006C0C1-FCB3-403E-996D-4A6C8724E06D`. Kernel
(`include/linux/efi.h`) and tianocore
(`MdePkg/Include/Protocol/LoadFile2.h`) both say `E06D`. Ivo had
`E0DE` for a while; every `LocateDevicePath` searched for the wrong
value, and the kernel's EFI stub silently fell through to `initrd=`
with no initrd. One byte.

`li.DeviceHandle` on the synthetic LoadedImage is `g_image`, not the
ESP volume. The kernel stub's `initrd=` fallback opens files on
`DeviceHandle`'s filesystem; pointing it at the ESP would allow an
unhashed initrd. With `g_image`, the fallback finds no filesystem
and the initrd arrives only through `EFI_LOAD_FILE2_PROTOCOL`.

## LUKS2

**Secondary header magic.** `"SKUL\xba\xbe"` — the four ASCII letters
reversed, trailing two bytes not swapped. That is how `cryptsetup`
tells primary from secondary.

**XTS tweak for 4 KiB sectors.** dm-crypt uses the 512-byte sector
number within the segment plus `iv_tweak`, even when the segment's
`sector_size` is 4096. Cryptsetup does not set `iv_large_sectors`
for LUKS. A 4 KiB unit *n* uses tweak `8n + iv_tweak`.

**Keyslot material offset.** LUKS1 `keyslot[i].key_material_offset`
is absolute from the partition start. LUKS2 `area.offset` is byte
offset from the partition start. Different in each version.

**LUKS1 keyslot material size.** `stripes * key_size`, rounded up to
a sector. Not `area.size`.

## TPM: PCR 4 changes when ivo.efi changes

Enrollment seals the passphrase under a policy bound to PCR 4 and
PCR 7. PCR 4 contains firmware's measurement of `ivo.efi`. Every
rebuild produces a different PCR 4, therefore a sealed object the
next boot cannot unseal.

Correct behavior. The passphrase prompt is the recovery path. Do not
rebuild between enrollment and the following unseal boot. A firmware
update, a bootloader rebuild, or any change to the boot chain
invalidates the seal.

## TPM: PCR 4 extension after the unlock stage

`main.c` extends PCR 4 with `"ivo: unseal window closed"` after the
LUKS unlock block. Skipped on the enrollment boot: extending PCR 4
after the sealed object was created changes the PCR value, and every
subsequent `PolicyPCR` fails with `TPM_RC_POLICY_FAIL` (0x99D).

`main.c` tracks this with a `sealed_this_boot` flag.

## TPM: salted StartAuthSession fails on swtpm

The TPM path uses a plain policy session: `StartAuthSession` with
`tpmKey` and `bind` both `TPM_RH_NULL`, symmetric `TPM_ALG_NULL`, no
encrypted salt.

A salted session was attempted (RSA-OAEP-SHA256 salt, `"SECRET"`
label, KDFa session key, AES-128-CFB parameters). Under swtpm this
fails with `TPM_RC_VALUE | param 2` (0x2C4) on `StartAuthSession`.
Parameter 2 is `encryptedSalt`.

The wire command is well-formed. `tpm2-tools` starts a salted session
against the same SRK on the same swtpm instance without error. The
SRK has `restricted|decrypt`. Failure is in swtpm's handling of the
RSA-OAEP ciphertext.

Code removed: `tpm_session.c`, `rsa.c`, `rsa.h`, the KDFa helper in
`tpm_cmd.c`. swtpm state at `/media/hdd/testing/tpm_state`.

With SMM and a CRB trapped by the SMI handler, the unsealed
passphrase does not cross the TPM bus in a form an external observer
can read. On QEMU+swtpm the bus is a local socket. Parameter
encryption is an optimization. Revisit if the threat model changes.

## TPM NV counters cannot be tested under QEMU

`tpm_nv.c` defines an NV monotonic counter at `0x01800000` for
`IVO_RELEASE`. Works on real hardware. Under QEMU it does not, and
the failure is not in Ivo's code.

Reproduce with `tpm2-tools` against a fresh swtpm:

```bash
pkill -TERM swtpm
sleep 2
rm -rf /tmp/tpm_state
mkdir -p /tmp/tpm_state
chmod 700 /tmp/tpm_state
swtpm_setup --tpmstate /tmp/tpm_state --tpm2 --lock-nvram

swtpm socket \
    --tpmstate dir=/tmp/tpm_state \
    --ctrl type=tcp,port=2322 \
    --tpm2 --flags not-need-init \
    --server type=tcp,port=2321 --daemon

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
tpm2_startup -c
tpm2_nvdefine -C o -s 8 -a "ownerread|ownerwrite|authread|nt=counter" 0x01800000
tpm2_nvincrement 0x01800000
```

`tpm2_nvdefine` succeeds. `tpm2_nvincrement` fails:

```
ERROR: Esys_NV_Increment(0x12F) - tpm:error(2.0): NV Index or
       persistent object already defined
```

`0x12F` is `TPM_RC_ATTRIBUTES | RC_NV_Increment_nvIndex`. TCG
reference `NV_Increment.c`:

```c
if(nvIndex.publicArea.attributes.TPMA_NV_COUNTER != SET)
    return TPM_RC_ATTRIBUTES + RC_NV_Increment_nvIndex;
```

The counter bit does not survive `NV_DefineSpace` under swtpm's
libtpms. The index exists, reads back uninitialized (0x14A), refuses
to increment.

Ivo serial output, first boot:

```
nv ensure: enter
tpm nvread rc=0x0000018b         ; index absent
nv ensure: read failed, defining
tpm nvdefine rc=0x00000000       ; define ok
nv ensure: define ok
tpm nvread rc=0x0000014a         ; counter at 0
nv ensure: current=0
tpm nvincrement rc=0x0000012f    ; not a counter
nv ensure: increment failed
```

Same command, same error as `tpm2-tools`.

### Consequence

`main.c` falls back to the UEFI variable tier when
`tpm_nv_fwver_ensure` returns non-zero. Under QEMU the NV tier is
never authoritative; every rollback test exercises the variable tier
only.

The NV tier requires hardware whose TPM implements
`TPM_NT_COUNTER`. Test on real hardware before trusting it.

`tpm2_nvdefine` on a swtpm state where Ivo already defined the
counter returns `0x14C` (`NV Index already defined`). Wipe state or
use a different index.

## TPM: swtpm process lifetime

swtpm exits when its last client disconnects. QEMU closing the
control socket kills it. State on disk survives; restart between
boots if QEMU has exited.

`startup-clear` resets PCRs to zero on swtpm start. Without it, PCRs
persist across restarts and OVMF extends them from their previous
values. Any test that compares PCR values across boots needs
`startup-clear`.

## TPM: enrollment and unseal test procedure

Enrollment writes to the ESP; unseal reads from it. Between the two
boots, only `seal-request` is removed. The `ivo.efi` on the ESP must
be byte-identical between the two boots.

```bash
pkill -TERM swtpm 2>/dev/null
sleep 2
rm -rf /media/hdd/testing/tpm_state
mkdir -p /media/hdd/testing/tpm_state
chmod 700 /media/hdd/testing/tpm_state
swtpm_setup --tpmstate /media/hdd/testing/tpm_state --tpm2 --lock-nvram

LOOP=$(sudo losetup -f)
sudo losetup -P "$LOOP" /media/hdd/VMS/ivo-mmt-test.img
sleep 1
sudo mount "${LOOP}p1" /mnt/luks-esp
sudo cp ivo.efi /mnt/luks-esp/EFI/ivo/ivo.efi
sudo cp ivo.efi /mnt/luks-esp/EFI/BOOT/BOOTX64.EFI
sudo rm -f /mnt/luks-esp/EFI/ivo/sealed.bin
sudo touch /mnt/luks-esp/EFI/ivo/seal-request
sync
sudo umount /mnt/luks-esp
sudo losetup -d "$LOOP"

swtpm socket \
    --tpmstate dir=/media/hdd/testing/tpm_state \
    --ctrl type=unixio,path=/media/hdd/testing/swtpm-ctrl \
    --tpm2 --flags not-need-init,startup-clear --daemon
```

Boot A (enroll):

```bash
qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 8192 \
    -machine q35,smm=on \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive if=pflash,format=raw,readonly=on,file=/media/hdd/edk2-debug-tpm/OVMF_CODE.secboot.4m.fd \
    -drive if=pflash,format=raw,file=/media/hdd/testing/OVMF_VARS.tpm.fd \
    -drive file=/media/hdd/VMS/ivo-mmt-test.img,format=raw,if=ide \
    -chardev socket,id=chrtpm,path=/media/hdd/testing/swtpm-ctrl \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-crb,tpmdev=tpm0 \
    -serial stdio 2>&1 | tee /tmp/ivo-serial-a.log
```

LUKS passphrase, `seal`, PIN twice. Wait for
`Sealed to the TPM (PCR 4+7)`. Quit QEMU.

Between boots:

```bash
pkill -TERM swtpm 2>/dev/null
sleep 2
swtpm socket \
    --tpmstate dir=/media/hdd/testing/tpm_state \
    --ctrl type=unixio,path=/media/hdd/testing/swtpm-ctrl \
    --tpm2 --flags not-need-init,startup-clear --daemon

LOOP=$(sudo losetup -f)
sudo losetup -P "$LOOP" /media/hdd/VMS/ivo-mmt-test.img
sleep 1
sudo mount "${LOOP}p1" /mnt/luks-esp
sudo rm -f /mnt/luks-esp/EFI/ivo/seal-request
sync
sudo umount /mnt/luks-esp
sudo losetup -d "$LOOP"
```

Do not run `make` between A and B.

Boot B (unseal): same QEMU command, `-b.log`. PIN only. Boot menu
appears without a LUKS passphrase prompt. Serial shows only the NV
counter lines under `tpm`:

```
grep -E '^tpm ' /tmp/ivo-serial-b.log
tpm nvread rc=0x0000014a
tpm nvincrement rc=0x0000012f
```

Anything else under `tpm` means the TPM path hit an error. A
`Passphrase:` prompt means unseal failed and fell through; the cause
is the serial line above it.

Wrong-PIN test: boot B with a wrong PIN. Expect `tpm unseal
rc=0x98E` (`TPM_RC_AUTH_FAIL`), fall through to the LUKS prompt.

## QEMU recipes

**UEFI with Secure Boot.**

```bash
sudo sbctl create-keys
sudo openssl x509 -in /var/lib/sbctl/keys/PK/PK.pem  -outform DER -out /tmp/PK.der
sudo openssl x509 -in /var/lib/sbctl/keys/KEK/KEK.pem -outform DER -out /tmp/KEK.der
sudo openssl x509 -in /var/lib/sbctl/keys/db/db.pem  -outform DER -out /tmp/db.der
sudo chown $USER /tmp/PK.der /tmp/KEK.der /tmp/db.der

cp /usr/share/edk2/x64/OVMF_VARS.4m.fd /tmp/OVMF_VARS.fd
python -m venv /tmp/virt-fw-venv
/tmp/virt-fw-venv/bin/pip install virt-firmware
/tmp/virt-fw-venv/bin/virt-fw-vars \
    --input /tmp/OVMF_VARS.fd --output /tmp/OVMF_VARS.fd \
    --set-pk  8be4df61-93ca-11d2-aa0d-00e098032b8c /tmp/PK.der \
    --add-kek 8be4df61-93ca-11d2-aa0d-00e098032b8c /tmp/KEK.der \
    --add-db  d719b2cb-3d3a-4596-a3bc-dad00e67656f /tmp/db.der
sudo sbctl sign -s ivo.efi

cp /tmp/OVMF_VARS.fd /tmp/OVMF_VARS.run.fd
qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 8192 -machine q35 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
    -drive if=pflash,format=raw,file=/tmp/OVMF_VARS.run.fd \
    -drive file=esp.img,format=raw,if=ide \
    -drive file=luks-lvm-test.img,format=raw,if=ide \
    -serial stdio
```

**UEFI with TPM.** Stock Arch firmware has SB but not SMM. A debug
OVMF built with `-D SECURE_BOOT_ENABLE -D TPM_ENABLE -D TPM2_ENABLE
-D SMM_REQUIRE` is required. Point `-drive ...OVMF_CODE...` at that
build's `OVMF_CODE.secboot.4m.fd`.

```bash
mkdir -p /tmp/tpm_state
chmod 700 /tmp/tpm_state
swtpm_setup --tpmstate /tmp/tpm_state --tpm2 --lock-nvram

swtpm socket \
    --tpmstate dir=/tmp/tpm_state \
    --ctrl type=unixio,path=/tmp/swtpm-ctrl \
    --tpm2 --flags not-need-init --daemon

cp /tmp/OVMF_VARS.fd /tmp/OVMF_VARS.tpm.fd
qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 8192 \
    -machine q35,smm=on \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.secboot.4m.fd \
    -drive if=pflash,format=raw,file=/tmp/OVMF_VARS.tpm.fd \
    -drive file=esp.img,format=raw,if=ide \
    -drive file=luks-lvm-test.img,format=raw,if=ide \
    -chardev socket,id=chrtpm,path=/tmp/swtpm-ctrl \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-crb,tpmdev=tpm0 \
    -serial stdio
```

`tpm2-tools` against the same TPM: restart swtpm with a TCP data
channel.

```bash
swtpm socket \
    --tpmstate dir=/tmp/tpm_state \
    --ctrl type=tcp,port=2322 \
    --tpm2 --flags not-need-init \
    --server type=tcp,port=2321 --daemon
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
tpm2_startup -c
```

Read PCRs from the guest (Alpine live has sysfs):

```bash
cat /sys/class/tpm/tpm0/pcr-sha256/4
cat /sys/class/tpm/tpm0/pcr-sha256/8
```

## TPM enrollment notes

- `tpm2-tools` and QEMU can't share a Unix-socket swtpm. Restart
  between phases. The state file carries the persistent primary and
  PCR values.
- `tpm2_flushcontext -t` and `-s` before `tpm2_create`. swtpm has few
  volatile object slots.
- `pkill -TERM swtpm`, not `-KILL`. SIGKILL doesn't flush state, and
  the next start won't see the primary.
- Verify the same blob unseals on host and in guest before trusting
  the enrollment.

## Per-entry password hashes

`password_hash` in an entry accepts one format:

    pbkdf2-sha256:<iterations>:<salt-hex-32>:<hash-hex-64>

Salt is 16 bytes, hash is 32. Per-entry, random. Part of the signed
config.

Generate one:

    tools/ivo-keygen --password-hash
    # Password: <type, no echo>
    # pbkdf2-sha256:200000:<hex>:<hex>

Drop the output into the entry. Rehash + re-sign the config. The
prompt is required before booting or before the cmdline editor; once
proven in a boot the entry stays unlocked for that boot.

## Test image

LUKS+LVM+ext4 with an ISO partition.

- p1: FAT32 ESP, 512 MB.
- p2: LUKS2 → LVM `vg0` → LV `root` → ext4.
- p3: raw ISO9660, 1 GB.

```bash
IMG=luks-lvm-test.img
qemu-img create -f raw "$IMG" 9G
LOOP=$(sudo losetup -f)
sudo losetup -P "$LOOP" "$IMG"
sleep 1
sudo parted -s "$LOOP" mklabel msdos
sudo parted -s "$LOOP" mkpart primary fat32 1MiB 513MiB
sudo parted -s "$LOOP" set 1 boot on
sudo parted -s "$LOOP" mkpart primary 513MiB 8GiB
sudo parted -s "$LOOP" mkpart primary 8GiB 100%
sudo partprobe "$LOOP"
sleep 1
sudo mkfs.vfat -F 32 -n IVO_ESP "${LOOP}p1"
printf 'ivopass\n' | sudo cryptsetup luksFormat --type luks2 --batch-mode \
    --pbkdf argon2id --pbkdf-memory 16384 --pbkdf-parallel 4 \
    --pbkdf-force-iterations 4 "${LOOP}p2"
printf 'ivopass\n' | sudo cryptsetup open "${LOOP}p2" ivo-root
sudo pvcreate -ff -y /dev/mapper/ivo-root
sudo vgcreate vg0 /dev/mapper/ivo-root
sudo lvcreate -L 6G -n root vg0
sudo mkfs.ext4 -F -L IVO_ROOT /dev/vg0/root
sudo dd if=alpine-standard-3.21.3-x86_64.iso of="${LOOP}p3" bs=1M status=progress
sudo sync
sudo mkdir -p /mnt/etx
sudo mount /dev/vg0/root /mnt/etx
sudo mkdir -p /mnt/etx/boot /mnt/etx/ivo /mnt/etx/sbin /mnt/etx/alpine
sudo mkdir -p /mnt/alpine-iso
sudo mount -o ro "${LOOP}p3" /mnt/alpine-iso
sudo cp /mnt/alpine-iso/boot/vmlinuz-lts   /mnt/etx/alpine/vmlinuz-lts
sudo cp /mnt/alpine-iso/boot/initramfs-lts /mnt/etx/alpine/initramfs-lts
sudo umount /mnt/alpine-iso
sudo tee /mnt/etx/ivo/config.toml >/dev/null <<'EOF'
timeout = 5
default = "AlpineLive"

[entries.AlpineLive]
kernel = "/alpine/vmlinuz-lts"
initrd = "/alpine/initramfs-lts"
options = "modules=loop,squashfs,sd-mod,usb-storage quiet"
EOF
sudo umount /mnt/etx
sudo vgchange -an vg0 2>/dev/null
sudo cryptsetup close ivo-root
sudo losetup -d "$LOOP"
```

Then `ivo-sign --hash`, `--sign`, `make install ESP=<mounted esp>`.

btrfs subvolume test: plain image, no LUKS/LVM. p1 FAT32 ESP, p2
btrfs. Create `@`, `@home`, `@snapshots`. Kernel and initrd in
`@/alpine/`, config in `@/ivo/`, entry with `subvol = "@"`. Set a
default subvolume or the config path won't resolve. Boot partition
selection must pick p2, not the ESP.

## USB

Test sticks: `ivo-install --target usb`. Real installs to real disks:
`ivo-install --target uefi`. Not exercised outside QEMU.

## Post-config-update procedure

Invalidates a hash in `config.toml`:

- Kernel package update
- Initramfs regeneration
- Chainload target update
- Extracted kernel or initrd update
- `ivo.efi` rebuild (`cver`)

Recovery, config filesystem at `/mnt/ivo-root`:

```bash
sudo tools/ivo-sign --hash   --config /mnt/ivo-root/ivo/config.toml --root /mnt/ivo-root
sudo tools/ivo-sign --sign   --config /mnt/ivo-root/ivo/config.toml --key /tmp/ivo-test.sec
sudo tools/ivo-sign --verify --config /mnt/ivo-root/ivo/config.toml --pub /tmp/ivo-test.pub
```

## Key rotation

Lost `/tmp/ivo-test.sec`:

1. `tools/ivo-keygen --out-prefix /tmp/ivo-test`
2. `cp /tmp/ivo-test.h src/uefi/security/secure_boot_pubkey.h`
3. Rebuild `ivo.efi`
4. `sbctl sign -s ivo.efi`
5. Copy to the ESP
6. Re-sign `config.toml`

Lost `/var/lib/sbctl/keys/`: re-enroll PK/KEK/db in OVMF_VARS,
re-sign every binary.

Lost `/tmp/tpm_state`: storage seed gone. Every sealed blob
undecryptable. Re-enroll from scratch.