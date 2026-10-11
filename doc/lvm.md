# LVM — Reader Notes

Reader is `src/uefi/storage/lvm.c`, API in `src/uefi/storage/lvm.h`.
Read-only.

The on-disk format is documented in Kiska's `lvm.md`. This file
documents what Ivo does with it.

## Where LVM sits

```
EFI Block I/O
    │
    ▼
luks_read_blocks   (if LUKS active)
    │
    ▼
lvm_read_blocks    (if LVM active)
    │
    ▼
ext4_read_block / btrfs_read_phys / fat32 read_sectors
    │
    ▼
fs.c → boot.c
```

Each layer dispatches on the one below.

Layouts:

- **LVM on top of LUKS.** The decrypted stream from LUKS is an LVM
  PV. `lvm_read_blocks` calls `luks_read_blocks`. Most encrypted
  Arch installs.
- **LVM on a plaintext partition.** `lvm_read_blocks` calls
  `hal_read_blocks`. Works, untested.
- **LUKS on top of LVM.** Not supported. `luks_common.c` routes its
  reads through `hal_read_blocks`. Would need the LUKS header read to
  go through `lvm_read_blocks`.
- **LUKS inside LVM inside LUKS.** Not a real layout.

`lvm_active()` gate matches `luks_active()`. Dispatch order is LVM,
LUKS, raw.

## What the reader parses

### PV label

Sector 1 of the PV. Magic `LABELONE`. CRC32 with reflected polynomial
`0xEDB88320`, initial `0xF597A6CF`, no pre- or post-XOR. Type
`LVM2 001`. PV UUID.

CRC covers bytes 20..511 of the label sector. PV header at
`label[offset_xl]`. Reader checks magic, CRC, type, `offset_xl` in
32..448.

### PV header

Two `disk_locn` lists, 16 bytes each (`offset u64`, `size u64`):

1. Data areas. Terminated by `{0, 0}`. Walked, not used.
2. Metadata areas. First entry is the MDA.

MDA must be at least 512 bytes.

### MDA header

512 bytes at `mda_offset`. Magic `" LVM2 x[5A%r0N*>"` at offset 4.
CRC at offset 0 over bytes 4..511.

`raw_locns[0]` at offset 40:

- `offset u64` — byte offset from MDA start to the current metadata
- `size u64` — length in bytes
- `crc u32`
- `flags u32` — bit 0 ignored, bit 1 wrapped

Refused if `size == 0`, `size > 65536`, ignored bit set, or wrapped
bit set.

Wrapped MDAs: LVM writes metadata texts as an append-only log inside
the MDA. When the next text would exceed the MDA's end, the buffer
wraps. Ivo refuses rather than reassembling the two halves. A 1
MiB-aligned PV takes around 600 `lvcreate`/`lvremove` cycles to wrap.
If it ever trips, read `mda_start + offset` for `mda_size - offset`
bytes, then `mda_start + 512` for the remainder.

### Metadata text

Nested key-value, line-oriented. `parse_metadata` walks the VG
section. `parse_all_lvs` walks `logical_volumes`. `parse_segment`
walks one `segmentN`.

At VG level:

- `extent_size` — 512-byte sectors, default 8192 (4 MiB)
- `physical_volumes.pvN.pe_start` — sectors, default 2048 (1 MiB)

Per LV:

- Name (from the section name)
- Each segment's `start_extent`, `extent_count`, `type`,
  `stripe_count`, first stripe's `pe_start`

Everything else skipped. Newer LVM versions add fields; unknown keys
ignored.

**Linear single-stripe segments only.** A `segmentN` is accepted only
if its `type` is `"striped"` and its `stripe_count` is 1.
Single-device linear LVs are written as one-stripe striped segments.
No separate `"linear"` type on disk.

## LV table

```c
typedef struct {
    char          name[LVM_NAME_MAX];
    uint32_t      segment_count;
    lvm_segment_t segments[LVM_MAX_SEGMENTS];
} lvm_lv_t;

static lvm_lv_t g_lvs[LVM_MAX_LVS];
static uint32_t g_lv_count;
static int32_t  g_active_lv;
```

`LVM_MAX_LVS = 16`, `LVM_MAX_SEGMENTS = 8`. Static caps.

`g_active_lv` is the selected LV. `-1` means none; `lvm_active()`
returns 0 and filesystem drivers fall through.

`lvm_init` selects LV 0. Iterate with `lvm_lv_count()` and
`lvm_lv_name(i)`, or select one with `lvm_lv_select(index)` /
`lvm_lv_select_by_name(name)`.
`lvm_lv_select(index)`, `lvm_lv_select_by_name(name)`, or iterate with
`lvm_lv_count()` / `lvm_lv_name(i)`.

The boot path iterates: for each LV, select it, try `fs_probe_mount`.
First success becomes the boot device. None succeed → fall back to
LV 0 and panic with the non-LVM message.

## Address mapping

```
byte_off = lv_lba * 512
le       = byte_off / extent_bytes
within   = byte_off % extent_bytes

for each segment:
    if le in [segment.start_extent, segment.start_extent + segment.extent_count):
        pe       = segment.pe_start + (le - segment.start_extent)
        pv_byte  = pe_start_bytes + pe * extent_bytes + within
        return pv_byte / 512
```

`extent_bytes = extent_size * 512`. `pe_start_bytes = pe_start * 512`.
Both computed once at mount.

A single-segment LV reduces to a linear map: LV sector N is PV sector
`pe_start_bytes / 512 + N`. Multi-segment LVs (from `lvextend` or
`lvcreate` on multiple PVs) partition the LV's extent space; the walk
finds the containing segment.

## Reading through the map

```c
while i < count:
    pv_start = map(lba + i)
    j = 1
    while i + j < count and j < cap:
        next_pv = map(lba + i + j)
        if next_pv != pv_start + j: break
        j++
    lvm_raw_read(pv_start, j, buf + i*512)
    i += j
```

`cap` is 8192. For a single-segment LV, a 4 KB ext4 block read (8
sectors) becomes one `hal_read_blocks` call.

`lvm_raw_read`:

```c
if (luks_active())
    return luks_read_blocks(pv_lba, count, buf);
return hal_read_blocks(g_pv_base_lba + pv_lba, count, buf);
```

With LUKS active, `pv_lba` is a sector within the decrypted stream.
Without, it is relative to the PV start.

## API

```c
int  lvm_init(struct boot_context *ctx);
int  lvm_active(void);
int  lvm_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);

int         lvm_lv_count(void);
const char *lvm_lv_name(int index);
int         lvm_lv_select(int index);
int         lvm_lv_select_by_name(const char *name);
```

`lvm_init` reads label, PV header, MDA header, MDA text, parses LVs,
selects LV 0. Idempotent.

`lvm_active` returns 1 if an LV is selected and has a segment.

`lvm_lv_name` returns the LVM-level name: `"root"`, not `"vg0/root"`.

`LVM=0` provides inline stubs. `lvm_active` returns 0,
`lvm_read_blocks` returns -1.

## Refused

- Not an LVM PV (magic, CRC, or type).
- No MDA.
- MDA size below 512.
- MDA CRC mismatch.
- MDA text above 65536 bytes.
- MDA ignored flag set.
- MDA wrapped flag set.
- Malformed metadata text (key without `=`, unterminated quote,
  missing brace).
- No LVs in `logical_volumes`.
- An LV with no segments.
- A segment whose `type` isn't `"striped"`.
- A segment whose `stripe_count` isn't 1.
- `extent_size` or `pe_start` missing or zero.

## Not supported

**Multistripe segments.** `stripe_count > 1`. Refused at parse time
as part of the segment-type check; the reader doesn't distinguish
"refused as multistripe" from "refused as unknown type".

**Thin, cache, RAID, and mirror LVs.** Segment `type` is not
`"striped"`. Refused at parse time.

**LUKS on top of LVM.** Would need `luks_common.c` to route through
`lvm_read_blocks`.

**MDAs above 64 KB of text.** Static buffer cap. Real single-VG,
single-LV filesystems are a few KB.

**Wrapped MDAs.**

**Multiple PVs.** `pe_start` taken from the first PV. An LV with
extents on a second PV maps wrong. One PV per VG works; more is
undefined.

## Verification

Tested on QEMU against a real LVM-on-LUKS layout:

- LUKS2 containing an LVM PV
- VG `vg0` with one LV `root`, 512 MiB, ext4
- Artix 7.1.8 kernel and initrd
- `LUKS=1 LUKS_USE_ARGON2=1 LVM=1`

Boot output:

```
Passphrase: *********
Ivo: Booting Artix
Loading kernel... OK
Loading initrd... OK
cmdline: console=tty0 console=ttyS0 root=/dev/mapper/vg0-root rw init=/sbin/init
<KERNEL TAKES OVER>
```

`Loading kernel... OK` proves label parse, PV header walk, MDA header
parse, metadata text parse, LV discovery, and address mapping for
`/boot/vmlinuz` on ext4 inside the LV. `Loading initrd... OK` proves
the same for a 200 MB file.

Test image built with real `cryptsetup`, `pvcreate`, `vgcreate`,
`lvcreate`. No hand-crafted metadata.

Segment-type refusal verified separately by hand-generating a striped
segment (`lvcreate -i 2`) on a scratch VG and confirming the reader
refused rather than silently mapping the first stripe. The linear case
above still boots unchanged.

## Reference

Kiska's `lvm.md` is the primary reference for the label, PV header,
MDA header, and metadata text.

LVM2 source (`lib/format_text/`, `lib/format_text/layout.h`) covers
anything Kiska doesn't. `pvck --dump headers` prints the label, PV
header, and MDA header field by field.

`pvs --units b` gives sizes in bytes. `pvdisplay`, `vgdisplay`,
`lvdisplay` are the corresponding user-space views.