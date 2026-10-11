# BTRFS — Reader Notes

The reader is `src/uefi/fs/btrfs.c`. Read-only. Reads `/boot` on a
single-device BTRFS filesystem from `mkfs.btrfs` with default options.

## Scope

Single-device, default `mkfs.btrfs` layout. Data profile `single`.
Metadata and system default to `dup`, which is one copy per device and
needs no special handling. Replicated profiles (`raid1`, `raid1c3`,
`raid1c4`) read correctly from one member — the reader picks the
stripe whose `devid` matches the superblock. Untested.

**Refused at mount.**

- Any incompat bit outside `MIXED_BACKREF`, `DEFAULT_SUBVOL`,
  `BIG_METADATA`, `EXTENDED_IREF`, `BLOCK_GROUP_TREE`,
  `SKINNY_METADATA`, `NO_HOLES`, `RAID1C34`. Extent-tree-v2, simple
  quotas, zoned, and raid56 are refused by this list.

  `BLOCK_GROUP_TREE` (bit 7) is set by default in `mkfs.btrfs` 6.19
  and later. The reader doesn't traverse the block group tree; it's a
  metadata-only optimization and the existing extent-tree walk doesn't
  need it.
- `RAID0` or `RAID10` chunk profiles. Stripes interleave across
  devices; a single-device reader can't reassemble them.
- Any chunk whose stripe list doesn't include this device's `devid`.
  A mount on the wrong member of a multi-device set fails here.
- `nodesize != 16384` or `sectorsize != 4096`. The static block buffer
  is sized for 16384.

**Refused at read time.**

- `compression != 0`. No zlib, lzo, or zstd.
- `encryption != 0`. Doesn't exist in practice.
- `other_encoding != 0`. Reserved.

## On-disk structures

Little-endian, packed.

### Superblock

Physical offset `0x10000`, 4096 bytes. First `0x1000` parsed. Mirrors
at `0x4000000` and `0x4000000000` ignored.

| Offset | Size | Field |
|--------|------|-------|
| 0x40 | 8 | `magic` = `"_BHRfS_M"` |
| 0x50 | 8 | `root` |
| 0x58 | 8 | `chunk_root` |
| 0x90 | 4 | `sectorsize` (must be 4096) |
| 0x94 | 4 | `nodesize` (must be 16384) |
| 0xA0 | 4 | `sys_chunk_array_size` |
| 0xBC | 8 | `incompat_flags` |
| 0xC6 | 1 | `root_level` |
| 0xC7 | 1 | `chunk_root_level` |
| 0xC9 | 8 | `dev_item.devid` |
| 0x32B | up to 2048 | `sys_chunk_array` |

### sys_chunk_array

List of `(btrfs_disk_key, btrfs_chunk)` pairs. The chunk tree lives in
a chunk, so the superblock carries enough chunk items to locate it.
The reader walks the array, adds each entry to the chunk map, then uses
the map to walk the chunk tree.

Entry size `17 + 48 + 32 * num_stripes`. `num_stripes` at offset 44 of
the item.

### Chunk item

Chunk struct at offset 48 of the item:

```
length        u64
owner         u64
stripe_len    u64
type          u64   block group flags | profile flags
io_align      u32
io_width      u32
sector_size   u32
num_stripes   u16
sub_stripes   u16
stripe[]      num_stripes × 32 bytes:
    devid     u64
    offset    u64   physical offset on that device
    dev_uuid  16
```

`type` checked for `RAID0` and `RAID10`, refused. Otherwise the reader
scans for the stripe whose `devid` matches, records
`(logical = key.offset, size = length, physical = stripe.offset)` in
the chunk map.

Replicated profiles: the whole chunk is at that physical offset. Any
read within the chunk comes from that offset. First matching stripe
wins; rest ignored.

### Tree block

101-byte header:

```
csum          32   CRC32C of [0x20, nodesize)
fsid          16
bytenr         u64  logical address
flags          u64
chunk_uuid    16
generation     u64
owner          u64
nritems        u32
level          u8   0 = leaf
```

Checksum not verified.

### Leaf item

Descriptors start at byte 101, 25 bytes each:

```
key       17   btrfs_disk_key
offset    u32  data offset relative to byte 101
size      u32
```

Key:

```
objectid  u64
type      u8
offset    u64
```

Keys sort by `(objectid, type, offset)` as integers. The reader
compares fields.

Item data for descriptor `i` is at `buf[101 + desc[i].offset]`.

### Internal node

Same 101-byte header, `level > 0`. Body is `btrfs_key_ptr`:

```
key           17
blockptr      u64  logical address
generation    u64
```

33 bytes. Descend to the child whose key is the largest one not
exceeding the target.

### Root item

439 bytes in the root tree. Two fields read:

| Offset | Size | Field |
|--------|------|-------|
| 0xB0 | 8 | `bytenr` |
| 0xEE | 1 | `level` |

Found by looking up `(FS_TREE_OBJECTID, ROOT_ITEM, 0)`.

### Inode item

| Offset | Size | Field |
|--------|------|-------|
| 0x10 | 8 | `size` |
| 0x34 | 4 | `mode` |

`mode & 0xF000`: `0x4000` dir, `0x8000` regular, `0xA000` symlink.

### DIR_ITEM

Key is `(dir_ino, DIR_ITEM, hash)`. Payload:

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 8 | `objectid` (target inode) |
| 0x08 | 1 | `type` (of the location key) |
| 0x11 | 8 | `transid` |
| 0x19 | 2 | `data_len` |
| 0x1B | 2 | `name_len` |
| 0x1D | 1 | `type` (FT_*) |
| 0x1E | name_len | name |

`hash = crc32c_with_seed_FFFFFFFE(name)`. The reader searches for the
exact key, checks `name_len`, reads the inode.

Name-hash CRC32C uses init `0xFFFFFFFE` and **no final XOR**. Checksum
CRC32C uses init `0xFFFFFFFF` and a final NOT. Different functions.

`location.type` at offset 8 tells subvolume entries apart from regular
ones. `ROOT_ITEM` there means the target is a subvolume tree, not an
inode.

### EXTENT_DATA

Key is `(ino, EXTENT_DATA, file_offset)`. Payload:

```
generation        u64
ram_bytes         u64
compression       u8
encryption        u8
other_encoding    u16
type              u8   0 = inline, 1 = regular, 2 = prealloc
```

Inline: data follows at offset 21, length `ram_bytes`.

Regular: fields continue:

```
disk_bytenr   u64  logical address
disk_num_bytes u64
offset        u64  offset within the allocation
num_bytes     u64  length this item covers
```

Reading at file offset `X`: find the item with the largest
`file_offset <= X`, compute `skip = X - key.offset`, copy from
`disk_bytenr + offset + skip`, up to `num_bytes - skip`.

Prealloc treated like regular. File size from the inode caps the read.

### DIR_INDEX

Key is `(dir_ino, DIR_INDEX, sequence)`. Payload matches DIR_ITEM's.

Used for directory listings. Sequence numbers give stable order and a
range-scan-friendly key. DIR_ITEM keys are hashes and would list in
hash order.

### ROOT_REF and ROOT_ITEM

Subvolumes appear in the fs tree as `ROOT_REF` entries — a `DIR_ITEM`
whose `location.type` is `ROOT_ITEM`. `location.objectid` is the
subvolume id. The root tree carries a matching
`(subvol_id, ROOT_ITEM, 0)` entry that names the tree's `bytenr` and
`level`, same layout as the fs tree's own ROOT_ITEM.

The default subvolume, if set, appears in the root tree as a
`DIR_ITEM` named `"default"` at objectid 6 (`ROOT_TREE_DIR`). Its
`location.objectid` is the subvolume id. `btrfs subvolume
set-default` writes it; deleting the item clears the default. The
lookup is exact (`btrfs_tree_lookup` with `le=0`), keyed by
`crc32c("default", seed=0xFFFFFFFE)`.

`root_dir_objectid` at superblock offset 0x80 is unrelated: it is
always 6 and is not the default subvolume id.

## Chunk map

Linear array of `(logical, size, physical)`. Resolution:

```
for each chunk c:
    if logical >= c.logical and logical < c.logical + c.size:
        return c.physical + (logical - c.logical)
```

`BTRFS_MAX_CHUNKS` is 512. A large filesystem can exceed it; mount
fails when `btrfs_nchunks` hits the cap.

Built in two passes:

1. Parse `sys_chunk_array`.
2. Walk the chunk tree for `(FIRST_CHUNK_TREE, CHUNK_ITEM, 0)` through
   `~0`, adding each item.

Pass 2 needs to resolve chunk addresses. Pass 1 gives it the system
chunk, enough to read the chunk tree's root.

## Tree walk

Two paths.

**Range walk.** `btrfs_walk` descends a tree and calls a callback for
every leaf item in a key range. The callback can stop early. Used for
the chunk map and directory listings. At internal nodes, subtrees
whose first key is past the range end are pruned.

**Single lookup.** `btrfs_tree_lookup` descends to a key. `le = 0`
requires an exact match; `le = 1` returns the largest key not
exceeding the target. Backs `lookup_dir` (exact) and `read_file`
(largest extent at or before the current offset).

Both call `btrfs_read_tree_block`, which reads one nodesize block at a
logical address.

## Path resolution

`btrfs_resolve` walks one component at a time from inode
`BTRFS_OBJ_FIRST_FREE` (256):

1. `hash = btrfs_name_hash(name, len)`.
2. Look up `(cur_ino, DIR_ITEM, hash)`.
3. Check the payload's `name_len`.
4. Read the target inode from the payload's first 8 bytes.
5. If the payload's location type is `ROOT_ITEM`, the target is a
   subvolume: look up its tree and continue from that tree's root
   inode.
6. Recurse.

Empty path resolves to 256. Leading `/` skipped.

Subvolume entries in the fs tree are `ROOT_REF` items, not `INODE_REF`
items. `btrfs_lookup_dir` only reads `DIR_ITEM` keys, which the fs
tree root does not have for its child subvolumes. So `ls /` on the fs
tree root returns nothing; a filesystem with no default subvolume set
appears empty. In practice `mkfs.btrfs` leaves the default unset, and
a fresh filesystem is only usable after `btrfs subvolume set-default`
or by naming a subvolume in `subvol =`.

## Subvolume selection

The reader supports `subvol = "..."` on a boot entry, resolved through
`btrfs_set_subvol`.

Subvolume names are **not** relative to the current default. They're
children of the fs tree, so `@` and `@home` resolve from the fs tree's
root inode regardless of what the default is. Once a subvolume is
selected, the default root switches to its tree, and everything
afterwards — including files inside it — resolves from there.

The default subvolume is detected at mount from the root tree's
`"default"` DIR_ITEM. If absent or names the fs tree itself, the fs
tree becomes the default. `mkfs.btrfs` leaves it unset. Installers
running `btrfs subvolume set-default` set it.

Three things worth knowing when testing:

- **The bootloader's config path is resolved against the current
  default.** `secure_boot.c` opens `/ivo/config.toml`. If the default
  is `@`, that's `@/ivo/config.toml`. If no default is set, it's the
  fs tree root, which has no `ivo` entry, and the boot drops to the
  shell. Set a default subvolume at install time.

- **A mount of a filesystem with a default subvolume shows that
  subvolume, not the fs tree.** If `@home` is the default,
  `/mnt/test/ivo` is `@home/ivo`, and `/mnt/test/@home` is
  `@home/@home` — a nested entry, if it exists. Creating directories
  by hand while the default is set can put files in unexpected places.

- **The kernel honours the default at mount; btrfs-progs on the raw
  image doesn't.** `btrfs inspect-internal dump-tree` sees the fs tree
  regardless. Use the dump to verify structure, the kernel's view to
  reason about path resolution.

## File read

`btrfs_read_file` walks `EXTENT_DATA` items in order:

- `file_offset = out_key.offset`
- `skip = got - file_offset` (position in the output buffer)
- Inline: copy `ram_bytes - skip` bytes from `data + 21 + skip`
- Regular/prealloc: source logical address is `disk_bytenr + offset +
  skip`; copy `num_bytes - skip` bytes
- Loop until `got == size`

The disk read re-resolves the chunk per sector, not per extent.
Correct and simple. Slower than necessary for extents that fit in one
chunk.

## Directory listing

`btrfs_opendir` resolves the path, checks it's a directory, writes
synthetic `.` and `..` at entries 0 and 1, then walks `(ino,
DIR_INDEX, 0)` through `~0`, copying names into a static array.

The handle is a single static struct. **Nested opendir is not
supported** — opening a second directory overwrites the first. The
shell opens one directory at a time.

`BTRFS_DIR_MAX` is 128. Directories larger than that are truncated.
Raise the limit if `/boot` grows.

`btrfs_readdir` returns 1 on entry, 0 at end.

## UUIDs

Nothing in BTRFS comes from firmware. The only GUID-adjacent value is
the filesystem UUID. On a single-device filesystem it's parsed and
never compared. Multi-device support would need the comparison.

## What the reader does not do

- **Verify checksums.** Tree block CRCs and data extent CRCs are
  skipped. A corrupted filesystem that happens to parse reads as if
  intact.
- **Decompress.** Refused at read.
- **Striped RAID.** Refused at mount.
- **Follow snapshots.** Snapshots are subvolumes with a parent.
  Reading one works; there's no snapshot traversal.
- **Read extended attributes.**
- **Return real permissions.** `btrfs_stat` reports the mode bits. The
  read path doesn't check them; anything in the tree is readable
  regardless of what the mode says.
- **Skip holes.** `NO_HOLES` is allowed but the reader treats every
  extent as data.
- **Read symlinks stored in extents.** Only inline symlinks.
- **Resolve hard links.** Multiple `INODE_REF` entries are not
  followed.

## What a writer would need

Beyond what the reader has: checksum computation, tree insertion and
splitting, extent allocation, free-space tree maintenance, all three
superblock mirrors updated consistently, copy-on-write transaction
semantics. Kiska's `btrfs.c` is the reference.

## Verification

Tested against `mkfs.btrfs` from `btrfs-progs` 7.1 on a 512 MiB
single-device image, default feature set.

Two subvolumes (`@` and `@home`), each with a marker file, default set
to `@home`. Reads verified from the default (`home-subvol`), from `@`
explicitly (`root-subvol`), and from `@home` explicitly
(`home-subvol`). A nonexistent subvolume name fails cleanly.

To reproduce:

```bash
IMG=/tmp/btrfs-subvol.img
truncate -s 512M "$IMG"
mkfs.btrfs -f "$IMG"

L=$(sudo losetup -fP --show "$IMG")
sudo mkdir -p /mnt/test
sudo mount "$L" /mnt/test

sudo btrfs subvolume create /mnt/test/@
sudo btrfs subvolume create /mnt/test/@home

sudo sh -c 'echo root-subvol > /mnt/test/@/marker.txt'
sudo sh -c 'echo home-subvol > /mnt/test/@home/marker.txt'

SUBVOL_ID=$(sudo btrfs subvolume list /mnt/test | awk '/path @home/ {print $2}')
sudo btrfs subvolume set-default $SUBVOL_ID /mnt/test

sudo umount /mnt/test
sudo losetup -d "$L"
```

`tests/btrfs-test /tmp/btrfs-subvol.img - /marker.txt` prints
`home-subvol`. `tests/btrfs-test /tmp/btrfs-subvol.img @ /marker.txt`
prints `root-subvol`.

For a boot test, the filesystem goes in a partition and the config
lives in the default subvolume. The `subvol = "..."` field in the
config entry is the last thing that runs before file loads.

End-to-end boot tested on UEFI with a GPT disk:

- p1 FAT32 ESP, p2 btrfs.
- Three subvolumes: `@`, `@home`, `@snapshots`. Default set to `@`.
- Kernel and initrd in `@/alpine/`, config in `@/ivo/`, entry with
  `subvol = "@"`.
- `partition_find_boot` must pick p2, not the ESP. See the "Boot
  partition selection" note below.
- Reached the Alpine menu after `ivo-install`.

To reproduce:

```bash
IMG=/tmp/btrfs-boot.img
qemu-img create -f raw "$IMG" 2G
L=$(sudo losetup -fP --show "$IMG")
sleep 1
sudo parted -s "$L" mklabel gpt
sudo parted -s "$L" mkpart ESP fat32 1MiB 257MiB
sudo parted -s "$L" set 1 esp on
sudo parted -s "$L" mkpart root btrfs 257MiB 100%
sudo partprobe "$L"
sleep 1
sudo mkfs.vfat -F 32 -n IVO_ESP "${L}p1"
sudo mkfs.btrfs -f "${L}p2"
sudo mount "${L}p2" /mnt/bt
sudo btrfs subvolume create /mnt/bt/@
sudo btrfs subvolume create /mnt/bt/@home
sudo btrfs subvolume create /mnt/bt/@snapshots
sudo umount /mnt/bt
sudo mount -o subvol=@ "${L}p2" /mnt/bt
sudo mkdir -p /mnt/bt/ivo /mnt/bt/alpine
# copy kernel+initrd into /mnt/bt/alpine/, write config to /mnt/bt/ivo/
sudo umount /mnt/bt
sudo mount -o subvolid=5 "${L}p2" /mnt/bt
sudo btrfs subvolume set-default /mnt/bt/@
sudo umount /mnt/bt
sudo mkdir -p /mnt/esp
sudo mount "${L}p1" /mnt/esp
sudo tools/ivo-install --target uefi --esp /mnt/esp --force
sudo umount /mnt/esp
sudo losetup -d "$L"
```

## Boot partition selection

`partition_find_boot` (`src/uefi/boot/partition.c`) chooses the partition
Ivo reads the config and kernels from when the ESP isn't the boot
partition.

Order of preference:

1. **A LUKS partition.** The probe reads the first sector and matches
   `"LUKS\xBA\xBE"`. This is the original design target.
2. **Any non-ESP partition.** `ext4`, `btrfs`, `xfs`, and any other
   non-ESP type GUID.
3. **The ESP.** The bootloader binary lives here, but the config
   doesn't.

First match wins within a bucket. Partitions with a start LBA of 0,
an empty size, a wrapping end, or an out-of-range end are skipped.

## Reference

The kernel's `fs/btrfs/` is definitive. Layout docs at
`Documentation/filesystems/btrfs.rst` and `btrfs.readthedocs.io`.

`btrfs inspect-internal dump-super`, `dump-tree -t <tree>`, and
`dump-tree -t chunk` dump the exact structures the reader parses.
`btrfs check --readonly` validates against the format rules.

Kiska's `btrfs.c` and `btrfs.md` were the reference for the reader.