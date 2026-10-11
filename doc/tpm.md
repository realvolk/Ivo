# TPM sealing — Reader Notes

Reader is `src/uefi/security/tpm/tpm_seal.c` and `tpm_seal_create.c`,
commands in `src/uefi/security/tpm/tpm_cmd.c`. Unlocks a LUKS volume by unsealing a secret
from the TPM and handing it to the same LUKS code path the keyboard
uses. Opt-in, not default. Compiled in only with `TPM=1` (`-DTPM`);
without it every entry point is a stub that does nothing.

## Where TPM sealing sits

```
ivo_main
    │
    ├── hal_init          — g_block_io points at LUKS partition
    ├── tpm_init          — locate EFI_TCG2_PROTOCOL
    │
    ├── tpm_seal_maybe_enroll (if LUKS enabled; see "Enrollment")
    │
    ├── tpm_seal_try_unlock   (if LUKS enabled)
    │       │
    │       ├── swap g_block_io → ESP, mount it as FAT32
    │       ├── read /EFI/ivo/sealed.bin, restore g_block_io → LUKS
    │       ├── prompt for PIN (if blob flags say so)
    │       ├── unseal via TPM
    │       └── luks_unlock_with_passphrase(unsealed_bytes)
    │
    ├── luks_unlock       (fallthrough, keyboard)
    │
    └── extend PCR 4 with a separator (main.c)
```

Every failure mode falls through to the prompt. A broken TPM does not
brick the boot.

The block-IO swap is required: `hal_read_blocks` goes through
`g_block_io`, which `hal_init` already retargeted at the LUKS
partition. Without the push/pop, the ESP read hits LUKS. LUKS is also
suspended (`luks_suspend`) while the ESP is open, so the FAT driver
reads the raw ESP even after the volume is unlocked.

The ESP is plaintext and attacker-writable. It is mounted with
`fs_mount_as(&fs_fat32, ...)`, never `fs_probe_mount`: the probe
chain tries ext4 first, and a FAT/ext4 polyglot would otherwise be
parsed by the ext4 driver.

The separator closes the unseal window: once the unlock stage is over,
PCR 4 no longer holds the value the policy was sealed against, so the
kernel, initrd and userspace of this boot can't unseal the secret
again. PCR 4 is measured by firmware (it covers `ivo.efi`'s
Authenticode hash); Ivo does not measure itself.

## What gets sealed

The LUKS passphrase, not the master key.

Either the passphrase typed during on-device enrollment, or (host-side
flow) 64 random bytes from `/dev/urandom` enrolled as a keyslot on the
LUKS2 volume. At most 128 bytes: `TPM2B_SENSITIVE_DATA` is
`MAX_SYM_DATA` on common TPMs. The master key is what comes out of a
successful unlock; the passphrase is what gets there. Sealing the
passphrase leaves the LUKS code path unchanged —
`luks_unlock_with_passphrase` runs the keyslot KDF on whatever bytes
it is handed, from a keyboard or a TPM.

The blob lives at `/EFI/ivo/sealed.bin` on the ESP. The ESP is
plaintext — firmware loads `ivo.efi` from it — but the blob is sealed
to a PCR policy. Copying the file gives ciphertext; unsealing requires
the enrolled PCR state.

## On-disk format

Little-endian, unlike the TPM wire format.

```
offset  size  field
0       4     magic "KNTP"
4       1     version (2)
5       1     flags (bit 0 = PIN required; other bits must be 0)
6       3     reserved (0)
9       4     pcr_mask
13      4     parent_handle
17      2     private_len (1..1024)
19      2     public_len  (1..1024)
21      N     private bytes (TPM2B_PRIVATE body)
21+N    M     public bytes  (TPM2B_PUBLIC body)
```

`pcr_mask` — bitmap of the SHA-256 PCRs the policy is bound to: bit
*n* set means PCR *n*. It is a bitmap, not a PCR number: `0x90`
(`(1<<4)|(1<<7)`) is PCR 4 + PCR 7, the default; `0x100` is PCR 8;
the value `8` would be PCR 3. Only PCRs 0–23 exist, so bits 24–31
must be clear. `parent_handle` — persistent handle of the sealed
object's parent, `0x81000000`–`0x81FFFFFF`, e.g. `0x81000001`.
`private` / `public` — the two halves from `tpm2_create`, 2-byte size
prefix stripped.

The blob is not authenticated. The TPM enforces the policy stored in
the sealed object. A blob whose `pcr_mask` or PIN flag disagrees with
that policy fails to unseal. The PIN flag only decides whether Ivo
prompts for a PIN.

Version 1 blobs (no flags byte) rejected. Re-enroll after upgrading.

## Which PCRs

The blob carries a `pcr_mask`. The value is a design choice.

- **PCR 4** — firmware and boot manager, including `ivo.efi`'s
  Authenticode hash. Breaks on firmware update, or on any rebuild of
  `ivo.efi` that changes its bytes.
- **PCR 7** — Secure Boot policy: PK, KEK, db, dbx. Breaks on SB key
  rotation.
- **PCR 8** — the kernel. Breaks on every kernel update.
- **PCR 9** — initrd and cmdline. Breaks on every initrd or cmdline
  change.

Ivo seals to **4+7**. That survives kernel updates, breaks on firmware
update, `ivo.efi` update or SB key rotation. Sealing to 8+9 breaks on
every kernel install, and those PCRs aren't extended yet when Ivo
unseals anyway.

**Sealing to PCR 8 is broken on OVMF.** OVMF's TCG2 driver extends
PCR 8 during firmware boot, so its boot-time value differs from its
host-side enrollment value (zero). Policy digests don't match and
unseal returns `TPM_RC_POLICY_FAIL` (0x99D).

**Never seal to PCR 23** (or 16, the debug PCR). PCR 23 is
application-resettable: the running OS can `TPM2_PCR_Reset` it and
extend it to any value, so a policy on it is no policy. Older
revisions of this document recommended it for development; a blob
sealed that way unseals for anyone who can boot anything.

PCR 4+7 must be captured from a real boot, at the point where Ivo
unseals. The on-device enrollment below does exactly that.

## PIN

The sealed object can carry an `authValue` (PIN, at most 32
characters — the `authValue` can't exceed the SHA-256 digest size) in
addition to the PCR policy. Blob flags byte bit 0 set: Ivo prompts
`TPM PIN: ` at boot, passes the input to `TPM2_Unseal` as the auth
area's hmac field. Mismatch returns `TPM_RC_AUTH_FAIL` (0x98E), falls
through to the LUKS passphrase prompt. The sealed object does not
have `noDA` set, so wrong PINs count toward the TPM's
dictionary-attack lockout.

Policy chain at enrollment:

```
StartAuthSession (policy)
PolicyPCR       → digest := H(digest || TPM_CC_PolicyPCR || pcrs || pcrDigest)
PolicyPassword  → digest := H(digest || TPM_CC_PolicyAuthValue)
GetDigest       → read the final digest
Create          → authPolicy = final digest, authValue = PIN
```

`PolicyPassword` is the command sent; the TPM internally extends the
digest with `TPM_CC_PolicyAuthValue` (0x16B), not
`TPM_CC_PolicyPassword` (0x18C). Both sides must agree. The reference
TPM implementation and tpm2-tools do. The wire command code differs
from the digest-extended code; the digest is what matters.

PIN and PCR policy both required. PIN protects against an attacker
who can replicate the PCR state; PCR policy protects against an
attacker who knows the PIN but can't replicate the firmware state.

## TPM commands

Six, hand-marshalled over `EFI_TCG2_PROTOCOL.SubmitCommand`:

| Code | Command | Purpose |
|---|---|---|
| 0x00000157 | TPM2_Load | Load the sealed object under its parent |
| 0x00000176 | TPM2_StartAuthSession | Create a policy session |
| 0x0000017F | TPM2_PolicyPCR | Bind the session to the PCR policy |
| 0x0000018C | TPM2_PolicyPassword | Require a PIN when the session is used |
| 0x0000015E | TPM2_Unseal | Release the sealed bytes |
| 0x00000165 | TPM2_FlushContext | Free the session and object |

`SubmitCommand` is the fourth entry in the `EFI_TCG2_PROTOCOL`
vtable (`GetCapability`, `GetEventLog`, `HashLogExtendEvent`,
`SubmitCommand`, ...). Under SMM — required for TPM support in OVMF —
it is the only transport from boot services. Direct CRB MMIO at
`0xFED40000` is intercepted by the SMI handler and reads as `0` or
`0xFFFFFFFF`.

## Wire format gotchas

Each of these cost a boot cycle. Byte-level details the spec
summaries omit.

**`StartAuthSession` response.** `sessionHandle` (4 bytes) *then*
`nonceTPM` (`TPM2B_NONCE`), not the other way around. Reading the
session handle from offset 12 instead of 10 gives a garbage handle;
next command rejects with `TPM_RC_HANDLE`.

**`TPM_ST_SESSIONS` responses.** Response tag `0x8002`: a 4-byte
`parameterSize` field sits between the header and the parameters.
Parsing as `TPM_ST_NO_SESSIONS` reads the top 2 bytes of
`parameterSize` as the first parameter's size field and gets 0.

**`TPM_ST_SESSIONS` requests.** Commands with an auth area have a
4-byte `authorizationSize` field between the handles and the auth
blocks. Omitting it: TPM reads the first auth block's handle as
`authorizationSize`, rejects with `TPM_RC_SIZE`.

**`TPMT_SYM_DEF` in `StartAuthSession`.** When `algorithm ==
TPM_ALG_NULL` (0x0010, not 0x0000), `keyBits` and `mode` are absent
on the wire. Sending them: TPM reads `keyBits` as the start of
`authHash`, rejects with `TPM_RC_SYMMETRIC` on parameter 4.

**`nonceCaller` size.** `StartAuthSession` requires non-empty.
Zero length fails with `TPM_RC_SIZE` on parameter 1. 32 bytes for a
SHA-256 session.

**`PolicyPCR` and `PolicyPassword` tag.** Both have "Auth Index:
None" for the policy session handle. Handle in the handle area, tag
`TPM_ST_NO_SESSIONS`, no auth area. Sending an auth block: TPM
rejects with `TPM_RC_HANDLE`.

**`Unseal` session attributes.** The policy session's auth block must
have `continueSession` set (bit 0, value `0x01`). Without it, the
session is flushed as a side effect of the unseal; response is
`TPM_RC_POLICY_FAIL`.

**`Unseal` auth area with PIN.** PIN goes in the auth area's `hmac`
field as plaintext, not as an HMAC. That is what `TPM2_PolicyPassword`
sets up. `TPM2_PolicyAuthValue` requires an HMAC; using the wrong one
produces `TPM_RC_POLICY_FAIL`.

**`TPM_SE_POLICY` value.** `0x01`, not `0x03`. `0x03` is
`TPM_SE_TRIAL`; trial sessions can't authorize a policy-sealed object.

## Sealed object attributes

`fixedTPM | fixedParent | adminWithPolicy` (`0x92`), name algorithm
SHA-256, `authPolicy` = PolicyPCR(4,7) [+ PolicyPassword].

- `userWithAuth` clear: Unseal (USER role) needs a policy session, so
  the PCR policy can't be bypassed with the authValue alone.
- `adminWithPolicy` set: ADMIN actions also go through the policy.
- `sensitiveDataOrigin` clear: the secret is supplied by the caller;
  real TPMs reject `sensitiveDataOrigin` with supplied data
  (`TPM_RC_ATTRIBUTES`).
- `noDA` clear: PIN guessing is rate-limited by DA lockout.

## Enrollment

### On device (preferred)

1. From the running system, create `/EFI/ivo/seal-request` on the
   ESP (any content). `/EFI/ivo/sealed.bin` must not exist: Ivo
   never overwrites it, so re-enrolling means deleting it first.
2. Reboot. Ivo asks for the LUKS passphrase and unlocks with it.
3. A screen explains that this passphrase will be sealed to this
   machine's TPM, bound to PCR 4 + 7. Type `seal` to continue;
   anything else skips sealing and the boot continues normally with
   the passphrase already typed.
4. Optionally set a PIN (entered twice; empty = no PIN).
5. Ivo creates the SRK at `0x81000001` if needed, seals, and writes
   `/EFI/ivo/sealed.bin`. Delete `/EFI/ivo/seal-request` afterwards;
   while `sealed.bin` exists the request is ignored.

The request file sits on the unencrypted ESP, so anyone with write
access to it can bring up the confirmation screen. That is why the
screen exists: the file alone never causes anything to be sealed.

### Host-side (development, swtpm)

One-time, per LUKS volume.

**1. Start swtpm on the TPM state used at boot.** Same state
reachable by `tpm2-tools` (enrollment) and QEMU (boot). The two tools
can't share one swtpm process — QEMU's binding needs a Unix socket,
tpm2-tools' TCTI needs TCP, and swtpm serves one of each. Workaround:
run enrollment on TCP, shut swtpm down cleanly, restart on a Unix
socket for boot. The state file carries the persistent primary and
PCR values between runs.

```bash
swtpm socket \
    --tpmstate dir=/tmp/tpm_state \
    --ctrl type=tcp,port=2322 \
    --tpm2 --flags not-need-init \
    --server type=tcp,port=2321 --daemon

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
tpm2_startup -c
```

**2. Create and persist the parent.**

```bash
tpm2_createprimary -C o -G rsa2048 -c primary.ctx
tpm2_evictcontrol -C o -c primary.ctx 0x81000001
```

`0x81000001` becomes the persistent handle. The blob records it; Ivo
loads the sealed child under that handle at boot.

**3. Build the policy and seal the passphrase.**

```bash
PIN=1234  # optional; omit for a PIN-less blob

head -c 64 /dev/urandom > /tmp/ivo-tpm-pass
chmod 600 /tmp/ivo-tpm-pass

tpm2_flushcontext -t
tpm2_flushcontext -s

# pcrs.bin: the SHA-256 values of PCR 4 and PCR 7 (32 bytes each, in
# that order) as they are when Ivo unseals — i.e. PCR 4 before Ivo's
# separator. Not the values seen from the booted OS: PCR 4 has been
# extended past that point. Replay the event log up to the separator,
# or use on-device enrollment instead.
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

PIN-less blob: omit `tpm2_policypassword` and the `-p "$PIN"`
argument. The attributes must stay as shown (see "Sealed object
attributes"); in particular don't add `userwithauth`,
`sensitivedataorigin` or `noda`.

The flush before `create` is required — swtpm's default profile has
few volatile object slots. Stale session or primary context makes
`tpm2_create` fail with "out of memory for object contexts".

**4. Enroll the passphrase in LUKS.**

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
flags = 0x01  # bit 0 = PIN required; use 0x00 for a PIN-less blob
hdr  = b'KNTP' + bytes([2, flags, 0, 0, 0])
hdr += struct.pack('<I', (1 << 4) | (1 << 7))   # PCR 4 + 7 = 0x90
hdr += struct.pack('<I', 0x81000001)   # parent handle
hdr += struct.pack('<H', len(priv_body))
hdr += struct.pack('<H', len(pub_body))
open('/tmp/sealed.bin','wb').write(hdr + priv_body + pub_body)
```

```
mmd -i /tmp/esp.img ::/EFI/ivo 2>/dev/null || true
mcopy -o -i /tmp/esp.img /tmp/sealed.bin ::/EFI/ivo/sealed.bin
```

The blob's `pcr_mask` must match the PCRs the policy was built with.
`sha256:4,7` in `tpm2_policypcr` and `0x90` in the blob are the same
selection.

**6. Shut swtpm down cleanly.**

```bash
pkill -TERM swtpm
sleep 2
```

SIGTERM flushes state to `/tmp/tpm_state`. SIGKILL does not.

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

**Unseal fails at boot.** Falls through to the passphrase prompt.
`luks2_unlock_with_passphrase` iterates every populated keyslot, so
both the human and TPM passphrases work as fallbacks if both are
enrolled.

**Blob lost.** Re-enroll. With on-device enrollment the sealed
secret is the human passphrase, so nothing else changes. With the
host-side flow the random passphrase is inside the lost blob: add a
new one via the procedure, remove the old slot with
`cryptsetup luksKillSlot`.

**PCR state changed** (firmware update, SB key rotation, rebuild of
`ivo.efi`). Unseal fails, prompt appears. Delete
`/EFI/ivo/sealed.bin` and re-enroll against the new PCR state.

**PIN forgotten.** Blob useless. The passphrase path still works if a
human passphrase is enrolled. Otherwise unrecoverable from Ivo.

**`/tmp/tpm_state` lost.** Storage seed gone, persistent primary
gone, every sealed blob permanently undecryptable. Back it up or
accept the loss.

## Refused

- Not a KNTP blob (magic mismatch).
- Version 1 blob (no flags byte).
- Unknown version.
- Unknown flag bits or non-zero reserved bytes.
- Blob shorter than the fixed header, or larger than 4096 bytes.
- `private_len` or `public_len` zero, above 1024, or not adding up
  to the blob length.
- `pcr_mask` empty or with bits above 23.
- Parent handle outside the persistent range `0x81xxxxxx`.
- Parent handle not present in the TPM.
- A TPM response whose size field is below 10 or larger than the
  response buffer, or a field that runs past the response.
- Policy digest mismatch (`TPM_RC_POLICY_FAIL`, 0x99D).
- PIN mismatch (`TPM_RC_AUTH_FAIL`, 0x98E).

All fall through to the LUKS passphrase prompt.

## Trust boundary

Blob on the plaintext ESP. Copying it gives ciphertext that can't be
unsealed without the PCR state the policy requires. With a PIN set,
the PIN is also required.

Not protected against:

- An attacker who can boot the same firmware and SB state **and**
  knows the PIN. PCR-only sealing does not stop this; the PIN does.
- An attacker who controls the PCR measurement code. If they can
  modify `ivo.efi` without changing its measured hash, PCR 4 stays
  the same and the seal survives.
- An attacker on the TPM bus. Sessions are unsalted and parameters
  unencrypted, so the PIN and the unsealed secret cross the bus in
  the clear.
- Blobs sealed to PCR 23 by older revisions. Delete and re-enroll.

The blob isn't covered by the Ed25519 `config.toml` signature. It
doesn't need to be. The TPM policy is a stronger check than the
signature. A tampered blob fails to load or unseal; a blob the
attacker sealed themselves yields bytes that fail the LUKS digest
check. Either way boot falls through to the prompt. The blob is
parsed before any signature check, so it is bounds-checked as
hostile input.

## Verified

The wire-format claims below are from an earlier revision of the code
(PCR 8/23, host-side enrollment only). They exercised the unseal path
and the marshalling; they did not exercise the current PCR 4+7 default
or the on-device enrollment flow. Re-verify before trusting the
defaults.

- **PIN-less sealing.** Blob bound to PCR 8, LUKS2 volume with the
  sealed passphrase in keyslot 0. Boot reaches `Ivo: Booting
  <entry>` without printing `Passphrase:`.
- **PIN sealing.** Blob bound to PCR 23 with `flags = 0x01`, LUKS2
  volume with the TPM passphrase in slot 1 and the human passphrase
  in slot 0. Boot prompts `TPM PIN: `, accepts `1234`, reaches
  `Ivo: Booting <entry>` without a LUKS prompt. Wrong PIN returns
  `TPM_RC_AUTH_FAIL` (0x98E), falls through to `Passphrase: `, which
  accepts the human passphrase.
- **Host-side unseal.** `tpm2_unseal` against the same swtpm state
  produces the same bytes and the same LUKS digest. Bootloader and
  host tools agree on the wire format.

## Not verified

- Sealing to PCR 4+7 end to end (see above).
- Key rotation. Changing the LUKS keyslot, the parent handle, or the
  PCR set requires re-running enrollment. None of those paths have
  been exercised.
- Sharing a single swtpm between tpm2-tools and QEMU. They can't run
  simultaneously against the same process. Enrollment and boot
  require a state-file round-trip.

## Reference

The TCG PC Client Platform Firmware Profile and the TPM 2.0 Library
specification (Part 3, "Commands") are the primary references for
the wire format. `tpm2-tools`' source covers the marshalling details
the spec summaries gloss over.

`swtpm`'s man pages cover the TCP vs. Unix socket split and the
state-file layout. `tpm2_getcap`, `tpm2_readpublic`, and
`tpm2_pcrread` are the corresponding user-space views into a running
swtpm.