# Ivo — Development Notes

The environment the code was built and tested in. The code and its
comments are the truth.

## Hardware

- **Acer N3060 laptop.** Its InsydeH2O CSM crashes on `int 0x13`
  before stage 2 loads, so BIOS testing on it was QEMU only. UEFI
  works.
- **H310M / i5-9400F desktop.** AMI Aptio, standard H310M. UEFI only.

QEMU covers the rest: stock Arch OVMF, and a debug OVMF with
SB + SMM + TPM.

## Build

Feature flags must reach `CFLAGS_EFI`. `LUKS=1` also enables the
block-device retarget in `hal_init`; without it a LUKS install is
unreachable. `LVM=1`, `SECURE_BOOT=1`, `TPM=1` gate the obvious.

Full matrix in `spec.md` §23.

## QEMU notes

- `-enable-kvm -cpu host` on any run with Argon2id. Without KVM a
  64 MiB keyslot takes minutes.
- `sleep 1` after `losetup -P`. Partition device nodes are async.
- OVMF with SB refuses an unsigned `ivo.efi` and drops to shell with
  "Access Denied". Sign before every boot.
- `losetup -a` may show `(deleted)` entries. `sudo losetup -D`.
- QEMU holds a write lock on the image. Detach between runs.

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

Read PCRs from the guest (Alpine live has sysfs, no `tpm2-tools`):

```bash
cat /sys/class/tpm/tpm0/pcr-sha256/4
cat /sys/class/tpm/tpm0/pcr-sha256/8
```

## TPM enrollment

Procedure in `doc/tpm.md`. The parts not there:

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

Salt is 16 bytes, hash is 32. Per-entry, random. The string is part
of the signed config, so it is authenticated by ivo-sign.

Generate one:

    tools/ivo-keygen --password-hash
    # Password: <type, no echo>
    # pbkdf2-sha256:200000:<hex>:<hex>

Drop the output into the entry. Rehash + re-sign the config the
usual way. The prompt is required before booting or before the
cmdline editor; once proven in a boot the entry stays unlocked for
that boot.

Text mode uses the same hash and the same prompt. Nothing else
changes.

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
selection must pick p2, not the ESP — see `doc/btrfs.md`.

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