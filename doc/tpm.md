# TPM sealing — Reader Notes

`src/uefi/security/tpm/tpm_seal.c`, `tpm_seal_create.c`, `tpm_cmd.c`.
Unlocks LUKS by unsealing a secret from the TPM and handing it to
`luks_unlock_with_passphrase`. Compiled in only with `TPM=1`.

## Flow

```
ivo_main
    ├── tpm_seal_maybe_enroll   (LUKS enabled)
    ├── tpm_seal_try_unlock     (LUKS enabled)
    │     ├── swap g_block_io → ESP, mount FAT32
    │     ├── read /EFI/ivo/sealed.bin, restore g_block_io → LUKS
    │     ├── prompt PIN (if blob flags say so)
    │     ├── unseal via TPM
    │     └── luks_unlock_with_passphrase
    ├── luks_unlock             (fallthrough, keyboard)
    └── extend PCR 4 with separator
```

Every failure falls through to the passphrase prompt.

`hal_read_blocks` goes through `g_block_io`, which `hal_init` retargeted
at LUKS. The ESP read requires `hal_block_io_push_esp`/`pop` and
`luks_suspend(1)`. The ESP is mounted with `fs_mount_as(&fs_fat32, …)`,
never `fs_probe_mount` (ext4 probes first and would parse a
FAT/ext4 polyglot).

PCR 4 covers `ivo.efi`'s Authenticode hash. Rebuilding `ivo.efi` after
enrollment invalidates the seal. By design.

The PCR 4 extension after unlock closes the unseal window: nothing
later in the boot can unseal the same secret. Skipped on the
enrollment boot — PCR 4 at seal time must match the value the next
boot sees.

## What gets sealed

LUKS passphrase, not the master key. Either the on-device passphrase,
or 64 random bytes enrolled as an additional keyslot. Maximum 128 bytes
(`TPM2B_SENSITIVE_DATA` = `MAX_SYM_DATA`).

`/EFI/ivo/sealed.bin` on the plaintext ESP. The blob is ciphertext
under the PCR policy; copying it is useless without the enrolled
state.

## On-disk format

Little-endian.

```
offset  size  field
0       4     magic "KNTP"
4       1     version (2)
5       1     flags (bit 0 = PIN required; other bits 0)
6       3     reserved (0)
9       4     pcr_mask
13      4     parent_handle
17      2     private_len (1..1024)
19      2     public_len  (1..1024)
21      N     private bytes
21+N    M     public bytes
```

`pcr_mask` — bitmap. Bit *n* = PCR *n*. Default `0x90` = PCR 4 + 7.
Bits 24–31 must be clear. `parent_handle` — persistent,
`0x81000000`–`0x81FFFFFF`. `private`/`public` — from `tpm2_create`,
2-byte size prefix stripped.

Not authenticated. The TPM enforces the sealed policy. A blob whose
`pcr_mask` or PIN flag disagrees with that policy fails to unseal.
Version 1 blobs rejected.

## Which PCRs

**4+7.** PCR 4 breaks on firmware update, `ivo.efi` rebuild, boot-chain
change. PCR 7 breaks on SB key rotation. Neither breaks on kernel
update.

Don't use PCR 8 — OVMF's TCG2 driver extends it during firmware boot;
unseal returns `TPM_RC_POLICY_FAIL` (0x99D). Don't use PCR 23 or 16 —
application-resettable.

PCR 4+7 must be captured from a real boot at the point Ivo unseals.
On-device enrollment does this.

## PIN

Optional `authValue` on the sealed object, max 32 characters. Flags
bit 0 set → prompt `TPM PIN: `, pass as `TPM2_Unseal` auth hmac.
Mismatch → `TPM_RC_AUTH_FAIL` (0x98E), falls through. Object does not
have `noDA` set; wrong PINs count toward DA lockout.

Enrollment policy chain:

```
StartAuthSession (trial)
PolicyPCR           — current PCR selection
PolicyPassword      — if PIN required
PolicyGetDigest     — read resulting digest
```

TPM computes the digest. Trial session — same policy engine produces
it as at unseal. Client-side computation risks format mismatch that
only shows as `TPM_RC_POLICY_FAIL`.

`PolicyPassword` internally extends with `TPM_CC_PolicyAuthValue`
(0x16B), not `TPM_CC_PolicyPassword` (0x18C). Digest is what matters.

PIN and PCR policy both required. PIN stops an attacker who can
replicate the PCR state; PCR policy stops an attacker who knows the
PIN.

## Commands

Seven, hand-marshalled over `EFI_TCG2_PROTOCOL.SubmitCommand`:

| Code | Command |
|---|---|
| 0x00000157 | TPM2_Load |
| 0x00000176 | TPM2_StartAuthSession |
| 0x0000017F | TPM2_PolicyPCR |
| 0x0000018C | TPM2_PolicyPassword |
| 0x00000189 | TPM2_PolicyGetDigest |
| 0x0000015E | TPM2_Unseal |
| 0x00000165 | TPM2_FlushContext |

`SubmitCommand` is vtable entry 4. Under SMM it's the only transport;
direct CRB MMIO at `0xFED40000` is intercepted by the SMI handler.

## Wire format gotchas

**`StartAuthSession` response.** `sessionHandle` then `nonceTPM`, not
the reverse. Wrong order → `TPM_RC_HANDLE`.

**`TPM_ST_SESSIONS` responses.** Response tag `0x8002` has a 4-byte
`parameterSize` between header and parameters. Parsing as
`TPM_ST_NO_SESSIONS` reads the top 2 bytes as the first parameter's
size (0).

**`TPM_ST_SESSIONS` requests.** 4-byte `authorizationSize` between
handles and auth blocks. Omitting → `TPM_RC_SIZE`.

**`TPMT_SYM_DEF` in `StartAuthSession`.** `algorithm ==
TPM_ALG_NULL` (0x0010) means `keyBits` and `mode` absent on the wire.
Sending them → `TPM_RC_SYMMETRIC` on parameter 4.

**`nonceCaller` size.** Non-empty required. 32 bytes for SHA-256.
Zero → `TPM_RC_SIZE` on parameter 1.

**`PolicyPCR`/`PolicyPassword` tag.** `TPM_ST_NO_SESSIONS`, no auth
area. Sending an auth block → `TPM_RC_HANDLE`.

**`PolicyGetDigest` code.** `0x00000189`, not `0x0000017E` (PCR_Read).
`0x17E` with a session handle → `TPM_RC_SIZE` on parameter 1.

**`Unseal` session attributes.** `continueSession` (bit 0, `0x01`)
required. Otherwise session flushed as a side effect;
`TPM_RC_POLICY_FAIL`.

**`Unseal` auth with PIN.** PIN goes in `hmac` as plaintext. That is
what `TPM2_PolicyPassword` sets up. `TPM2_PolicyAuthValue` requires an
HMAC; wrong one → `TPM_RC_POLICY_FAIL`.

**`TPM_SE_POLICY`.** `0x01`, not `0x03` (`TPM_SE_TRIAL`).

## Sealed object attributes

`fixedTPM | fixedParent | adminWithPolicy` (`0x92`), nameAlg SHA-256,
`authPolicy` = PolicyPCR(4,7) [+ PolicyPassword].

- `userWithAuth` clear: Unseal requires a policy session; PCR policy
  can't be bypassed by authValue.
- `adminWithPolicy` set: ADMIN actions also go through the policy.
- `sensitiveDataOrigin` clear: caller supplies the secret. Real TPMs
  reject `sensitiveDataOrigin` with supplied data
  (`TPM_RC_ATTRIBUTES`).
- `noDA` clear: PIN guessing rate-limited by DA lockout.

## Enrollment

### On device (preferred)

1. Create `/EFI/ivo/seal-request` on the ESP. `sealed.bin` must not
   exist — Ivo never overwrites.
2. Reboot. Enter the LUKS passphrase.
3. Type `seal` at the confirmation screen. Anything else skips.
4. Optionally set a PIN (twice; empty = none).
5. Ivo creates the SRK at `0x81000001` if needed, opens a trial
   session, runs PolicyPCR [+ PolicyPassword], reads the digest via
   `PolicyGetDigest`, passes it to `Create`. Writes `sealed.bin`.
   Delete `seal-request`.

Anyone with write access to the ESP can create the request file and
bring up the confirmation screen. That is why the screen exists.

### Host-side (development, swtpm)

Enrollment (TCP TCTI) and boot (Unix socket) can't share one swtpm
process. Round-trip through the state file.

**1. Start swtpm on TCP.**

```bash
swtpm socket \
    --tpmstate dir=/tmp/tpm_state \
    --ctrl type=tcp,port=2322 \
    --tpm2 --flags not-need-init \
    --server type=tcp,port=2321 --daemon

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
tpm2_startup -c
```

**2. Persistent parent.**

```bash
tpm2_createprimary -C o -G rsa2048 -c primary.ctx
tpm2_evictcontrol -C o -c primary.ctx 0x81000001
```

**3. Policy and sealed passphrase.**

```bash
PIN=1234  # optional

head -c 64 /dev/urandom > /tmp/ivo-tpm-pass
chmod 600 /tmp/ivo-tpm-pass

tpm2_flushcontext -t
tpm2_flushcontext -s

# pcrs.bin: SHA-256 values of PCR 4 and PCR 7 as they are when Ivo
# unseals — PCR 4 before Ivo's separator. Replay the event log up to
# the separator, or use on-device enrollment instead.
tpm2_startauthsession -S session.ctx
tpm2_policypcr -S session.ctx -l sha256:4,7 -f pcrs.bin -L /dev/null
tpm2_policypassword -S session.ctx -L /dev/null
tpm2_getpolicydigest -S session.ctx -o pol.bin
tpm2_flushcontext session.ctx

tpm2_create \
    -C 0x81000001 \
    -u seal.pub \
    -r seal.priv \
    -i /tmp/ivo-tpm-pass \
    -L pol.bin \
    -p "$PIN" \
    -a "fixedtpm|fixedparent|adminwithpolicy"
```

PIN-less: omit `tpm2_policypassword` and `-p "$PIN"`. Don't add
`userwithauth`, `sensitivedataorigin`, or `noda`.

The flush before `create` is required — swtpm has few volatile object
slots. Stale session or primary → "out of memory for object contexts".

**4. Enroll in LUKS.**

```bash
L=$(sudo losetup -fP --show /path/to/luks.img)

echo -n ivopass | sudo cryptsetup luksAddKey --key-file=- \
    --new-keyfile=/tmp/ivo-tpm-pass ${L}p2

sudo losetup -d $L
```

**5. Write the blob.**

```python
import struct
priv_full = open('/tmp/seal.priv','rb').read()
pub_full  = open('/tmp/seal.pub', 'rb').read()
priv_body = priv_full[2:]
pub_body  = pub_full[2:]
flags = 0x01  # 0x00 for PIN-less
hdr  = b'KNTP' + bytes([2, flags, 0, 0, 0])
hdr += struct.pack('<I', (1 << 4) | (1 << 7))
hdr += struct.pack('<I', 0x81000001)
hdr += struct.pack('<H', len(priv_body))
hdr += struct.pack('<H', len(pub_body))
open('/tmp/sealed.bin','wb').write(hdr + priv_body + pub_body)
```

```
mmd -i /tmp/esp.img ::/EFI/ivo 2>/dev/null || true
mcopy -o -i /tmp/esp.img /tmp/sealed.bin ::/EFI/ivo/sealed.bin
```

`pcr_mask` must match the policy's PCR selection. `sha256:4,7` == `0x90`.

**6. Shut swtpm down cleanly.**

```bash
pkill -TERM swtpm
sleep 2
```

SIGTERM flushes state. SIGKILL does not.

**7. Boot.**

```bash
swtpm socket \
    --tpmstate dir=/tmp/tpm_state \
    --ctrl type=unixio,path=/tmp/swtpm-ctrl \
    --tpm2 --flags not-need-init --daemon

qemu-system-x86_64 ... \
    --chardev socket,id=chrtpm,path=/tmp/swtpm-ctrl \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-crb,tpmdev=tpm0
```

## Recovery

TPM is convenience. The passphrase is the real key.

**Unseal fails.** Falls through to the prompt.
`luks2_unlock_with_passphrase` iterates every populated keyslot.

**Blob lost.** Re-enroll. On-device secret is the human passphrase;
host-side secret is random — add a new slot, kill the old one with
`cryptsetup luksKillSlot`.

**PCR state changed** (firmware update, SB rotation, `ivo.efi`
rebuild). Delete `sealed.bin`, re-enroll.

**PIN forgotten.** Blob useless. Passphrase path still works if a
human passphrase is enrolled.

**`/tmp/tpm_state` lost.** Storage seed and primary gone; every blob
permanently undecryptable.

## Refused

- Bad magic, unknown version, v1 (no flags byte).
- Unknown flag bits, non-zero reserved.
- Size outside 21..4096.
- `private_len`/`public_len` zero, >1024, or not summing to the body.
- Empty `pcr_mask` or bits above 23.
- Parent outside `0x81xxxxxx` or absent from the TPM.
- Response size <10 or >buffer, or a field past the response.
- `TPM_RC_POLICY_FAIL` (0x99D).
- `TPM_RC_AUTH_FAIL` (0x98E).

All fall through to the passphrase prompt.

## Trust boundary

Blob on the plaintext ESP.

Not protected against:

- Attacker who can boot the same firmware + SB state **and** knows the
  PIN.
- Attacker who controls the PCR measurement code (`ivo.efi` modification
  that preserves its measured hash).
- Attacker on the TPM bus. Sessions unsalted, parameters unencrypted;
  PIN and unsealed secret cross in the clear.
- Blobs sealed to PCR 23 by older revisions.

The blob is not covered by the `config.toml` signature. It doesn't
need to be — the TPM policy is stricter. A tampered blob fails to load
or unseal; a blob the attacker sealed yields bytes that fail the LUKS
digest check. The blob is parsed before any signature check, so it's
bounds-checked as hostile input.

Full threat model in `threat-model.md`.

## Verified

- Unseal succeeds with matching PCR state. Same swtpm state, same
  OVMF vars, same `ivo.efi`, `startup-clear` between boots. Menu
  reached with only the TPM PIN prompt.
- Wrong PCR state falls through. `ivo.efi` rebuilt between enrollment
  and unseal → `TPM_RC_POLICY_FAIL` (0x99D), LUKS prompt.
- Host-side enrollment produces a blob the bootloader unseals with
  the digest `tpm2_getpolicydigest` reports.

## Not verified

- Key rotation (LUKS keyslot, parent handle, PCR set).
- Wrong-PIN fallthrough. Wrong PCR fails first at
  `TPM_RC_POLICY_FAIL`; never reaches the PIN check.
- Sharing one swtpm between `tpm2-tools` and QEMU. They can't run
  simultaneously. Round-trip required.

## NV monotonic counter (rollback protection)

`tpm_nv.c`. NV counter at `0x01800000`, stores `IVO_RELEASE`.
Authoritative tier for firmware rollback when a TPM is present; UEFI
variable `Ivo/FirmwareVer` is the fallback.

| Code | Command |
|---|---|
| 0x0000012A | TPM2_NV_DefineSpace |
| 0x00000134 | TPM2_NV_Increment |
| 0x0000014E | TPM2_NV_Read |

`NV_DefineSpace` parameters: `(auth: TPM2B_AUTH, publicInfo:
TPM2B_NV_PUBLIC)`. `auth` is empty and must still be sent — omitting
makes the TPM read `publicInfo`'s size prefix as `auth`'s size and
fails with `TPM_RC_SIZE`.

At least one write attribute required. `OWNERWRITE` matches the
`TPM_RH_OWNER` auth used by `NV_Increment`. Counters forbid `ORDERLY`
and `NO_DA`.

`NV_Read` on an unwritten counter → `TPM_RC_NV_UNINITIALIZED` (0x14A).
That is "at 0", not failure. First `NV_Increment` initializes and sets
`WRITTEN`.

`last_tpm_rc()` exposes the most recent transaction's rc.
`read_counter` uses it to distinguish `0x14A` from a real failure.

### Cannot be tested under QEMU

swtpm's libtpms accepts the define but doesn't preserve
`TPMA_NV_COUNTER`. `NV_Increment` returns `TPM_RC_ATTRIBUTES |
RC_NV_Increment_nvIndex` (0x12F). `tpm2-tools` fails identically —
swtpm limitation, not Ivo.

Ivo serial, fresh state:

```
nv ensure: enter
tpm nvread rc=0x0000018b
nv ensure: read failed, defining
tpm nvdefine rc=0x00000000
nv ensure: define ok
tpm nvread rc=0x0000014a
nv ensure: current=0
tpm nvincrement rc=0x0000012f
nv ensure: increment failed
```

Falls through to the UEFI variable tier. Both tiers write
`IVO_RELEASE`; feature works under QEMU via fallback only. NV tier
needs real hardware with `TPM_NT_COUNTER`. Test there.

`tpm2_nvdefine` on a swtpm state where Ivo already defined the counter
returns `0x14C`. Wipe or pick a different index.

## Salted sessions (not implemented)

Unseal uses an unsalted policy session: `StartAuthSession` with
`tpmKey` and `bind` both `TPM_RH_NULL`, symmetric `TPM_ALG_NULL`, no
encrypted salt. Parameters not encrypted.

A salted session was attempted (RSA-OAEP-SHA256 salt to SRK, `"SECRET"`
OAEP label, SP800-108 KDFa, AES-128-CFB parameters). Under swtpm this
fails with `TPM_RC_VALUE | param 2` (0x2C4) on `StartAuthSession`.
Parameter 2 is `encryptedSalt`. Wire command is well-formed;
`tpm2-tools` starts a salted session against the same SRK without
error. Failure is in swtpm's RSA-OAEP handling.

Code removed (`tpm_session.c`, `rsa.c`, `rsa.h`, KDFa helper). May
return if the threat model changes.

With SMM and a CRB trapped by the SMI handler, the unsealed passphrase
does not cross the TPM bus in a form an external observer can read. On
QEMU+swtpm the "bus" is a local socket. Neither is a practical
cleartext exposure.