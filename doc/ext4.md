# ext4 — Reader Notes

Reader is `src/uefi/fs/ext4.c`. Read-only. Reads `/boot` on a
typical Artix/Arch install: extents, 64-bit, flex_bg, htree
directories.

## Scope

**Required.** Refused at mount if missing:

- `EXT4_FINCOM_EXTENTS` — inode block maps are extent trees, not the
  old direct/indirect pointers.
- `EXT4_FINCOM_64BIT` — 64-bit block numbers and file sizes.

Both set on every ext4 filesystem made by `mke2fs` in the last fifteen
years.

**Supported.**

- `FILETYPE`, `RECOVER`, `FLEX_BG`, `EA_INODE`, `CSUM_SEED`,
  `LARGEDIR`, `BTREE_DIR`.
- All writer-only `ro_compat` bits: `SPARSE_SUPER`, `LARGE_FILE`,
  `HUGE_FILE`, `GDT_CSUM`, `DIR_NLINK`, `EXTRA_ISIZE`, `QUOTA`,
  `METADATA_CSUM`, `READONLY`, `PROJECT`, `ORPHAN_PRESENT`.

**Refused at mount.**

- `COMPRESSION`, `JOURNAL_DEV`, `META_BG`, `MMP`, `INLINE_DATA`,
  `ENCRYPT`, `CASEFOLD`, `DIRDATA`.
- `BIGALLOC`, `REPLICA`, `VERITY` (`ro_compat`).

Any refused bit makes `ext4_fs_mount` print `unsupported incompat
features` or `unsupported ro_compat features` and return -1.

## On-disk structures

Little-endian, packed.

### Superblock

Offset `0x400`, 1024 bytes. Parsed into `struct ext4_superblock`,
size-checked by `_Static_assert`.

| Offset | Size | Field | Use |
|--------|------|-------|-----|
| 0x00 | 4 | `s_inodes_count` | |
| 0x04 | 4 | `s_blocks_count_lo` | |
| 0x14 | 4 | `s_first_data_block` | 0 for 4 KiB block, 1 for 1 KiB |
| 0x18 | 4 | `s_log_block_size` | block size = `1024 << this` |
| 0x20 | 4 | `s_blocks_per_group` | |
| 0x28 | 4 | `s_inodes_per_group` | |
| 0x38 | 2 | `s_magic` | `0xEF53` |
| 0x58 | 2 | `s_inode_size` | |
| 0x5C | 4 | `s_feature_incompat` | |
| 0x60 | 4 | `s_feature_ro_compat` | |
| 0xEC | 16 | `s_hash_seed` | htree hash state |
| 0xFE | 2 | `s_desc_size` | 0 means 32 |
| 0x150 | 4 | `s_blocks_count_hi` | |

Block size 1024, 2048, or 4096. Above 4096 refused;
`EXT4_MAX_BLOCK_SIZE` bounds the static buffers.

`desc_size` clamps to [64, 256].

`hash_seed` copied into `ext4.hash_seed`, four `uint32_t` words.

### Group descriptor

`gdt_block = first_data_block + 1`. Offset is
`gdt_block * block_size + group * desc_size`.

Two fields read:

| Offset | Size | Field |
|--------|------|-------|
| 0x08 | 4 | `bg_inode_table_lo` |
| 0x28 | 4 | `bg_inode_table_hi` |

Inode table block: `((uint64_t)hi << 32) | lo`.

### Inode

Inode number starts at 1. Inode 2 is the filesystem root.

Position: `inode_table_block * block_size + index * inode_size`.
Refuses if the inode straddles a block. `inode_size` is always 128,
256, 512, or 1024.

`struct ext4_inode` is 160 bytes; on-disk size is typically 256. Read
copies `min(s_inode_size, 160)`.

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 2 | `i_mode` |
| 0x04 | 4 | `i_size_lo` |
| 0x20 | 4 | `i_flags` |
| 0x28 | 60 | `i_block` |
| 0x6C | 4 | `i_size_high` |

`i_size = (hi << 32) | lo`. `i_mode & 0xF000` is `0x4000` dir, `0x8000`
file, `0xA000` symlink.

### Extent tree

When `i_flags & EXT4_INODE_EXTENTS`, `i_block` is the extent root.

Header, 12 bytes:

```
eh_magic      u16   = 0xF30A
eh_entries    u16
eh_max        u16
eh_depth      u16   0 = leaf
eh_generation u32
```

Leaf entry (`eh_depth == 0`), 16 bytes:

```
ee_block      u32
ee_len        u16   > 32768 means uninit; length is ee_len - 32768
ee_start_hi   u16
ee_start_lo   u32
```

Uninit extents refused. Physical block for logical `lb`:
`(ee_start_hi << 16 | ee_start_lo) + (lb - ee_block)`.

Index entry (`eh_depth > 0`), 12 bytes:

```
ei_block      u32
ei_leaf_lo    u32
ei_leaf_hi    u16
ei_unused     u16
```

Child block: `((uint64_t)ei_leaf_hi << 32) | ei_leaf_lo`. Descend to
the child with the largest `ei_block <= target`.

`eh_depth > 5` refused. Real filesystems never get past 1.

### Directory entry (linear)

`ext4_dir_entry_2`:

```
inode      u32   0 = empty slot
rec_len    u16   length of this entry including padding
name_len   u8
file_type  u8
name       char[name_len]
```

`rec_len == 12, name_len == 0, file_type == 0xDE` is the tail record;
stop scanning the block.

Entries pack back to back. `rec_len` for a non-last entry is
`8 + name_len` rounded up to a multiple of 4. The last entry in a block
stretches to fill the block.

### Directory entry (htree index)

First block of an indexed directory:

```
dot                 ext4_dir_entry_2, name "."
dotdot              ext4_dir_entry_2, name ".."
dx_root_info        8 bytes:
    reserved_zero   u32   = 0
    hash_version    u8
    info_length     u8    = 8
    indirect_levels u8
    unused_flags    u8
dx_entry[]          array, sentinel-terminated
```

`dx_root` detection is by layout, not magic: dot's `rec_len=12,
name_len=1`, name `.`; dotdot's `rec_len=12, name_len=2`, name `..`.
This is what `mke2fs` writes. A corrupted root fails the check and the
reader falls back to a linear scan.

`dx_entry`, 8 bytes:

```
hash      u32   upper bound of hashes in the following block
block     u32   logical block of the child
```

Search: first entry with `hash >= target`.

`dx_node` (internal index block) is the same array starting at offset 8.
First 8 bytes are a fake `ext4_dir_entry_2` with `rec_len=8,
name_len=0, file_type=0xDE`.

Leaf blocks contain ordinary `ext4_dir_entry_2` entries.

`indirect_levels > 2` refused.

### Hash

Two algorithms: HALF_MD4 (version 1) and HALF_MD4_UNSIGNED (version 4).
Both are the modern default. The `_UNSIGNED` variant differs only in
signedness during input expansion; C `char` reads as `uint8_t`, so both
are the same code here.

Start with `s_hash_seed` as the four MD4 state words. Name processed in
32-byte chunks. Each chunk expanded to eight `uint32_t` via
`str2hashbuf`, then mixed by `half_md4_transform`. Result: `buf[1]`.

`str2hashbuf(msg, remaining, chunk, in)` builds words from 4 bytes
little-endian, XORed with a `pad` value derived from `remaining`. First
word of each chunk seeded with `pad`; partial words at the end of a
chunk padded with `pad`.

`half_md4_transform` is one MD4 round, not full MD4.

Legacy (`hash_version = 0, 3`) and TEA (`2, 5`) not implemented. Any
other version returns 0 from `ext4_dir_hash` for every name, so htree
lookups miss and fall through to linear scan.

## Behavior

### Mount

`ext4_probe` reads the superblock, checks `s_magic == 0xEF53`, and
sanity-checks `s_log_block_size`, `s_blocks_per_group`,
`s_inodes_per_group`.

`ext4_fs_mount` re-reads, checks feature bits, computes geometry,
copies the hash seed.

### Inode read

`ext4_read_inode(ino, out)`:

1. `group = (ino - 1) / inodes_per_group`
2. `index = (ino - 1) % inodes_per_group`
3. Read the group descriptor, compute the inode table block.
4. Read the block, copy `min(inode_size, 160)` bytes at the right offset.

### Path resolution

`ext4_resolve` walks one component at a time from inode 2:

1. `ext4_dir_lookup`.
2. If `EXT4_INDEX_FL`, try `ext4_htree_lookup` first.
3. On failure, linear scan.
4. Both fail → -1.

Empty path or `/` → inode 2.

### Lookup — linear

`ext4_leaf_scan` walks one block of directory entries, compares
`name_len` and name bytes, returns on match. Stops at the tail record.

### Lookup — htree

`ext4_htree_lookup` reads block 0, verifies the `dx_root` layout, reads
`hash_version` and `indirect_levels`, computes the hash, descends.

At each index block, find the `dx_entry` whose hash range contains the
target. When the child is a leaf, scan it linearly.

`indirect_levels > 2` refused; caller falls back to a linear scan.

### Lookup — fallback

Any htree miss falls through to a linear scan of every block, skipping
index blocks. Wrong hash version or malformed structure means O(n)
lookups, not failure.

### Directory listing

`ext4_fs_opendir` resolves the path, checks it's a directory, returns a
handle with inode number and offset. `ext4_fs_readdir` walks blocks
from that offset, skipping index blocks, scanning leaf entries.

Entries come out in storage order: hash order for htree, write order
for linear.

### File read

`ext4_fs_read` resolves, checks regular file, calls
`ext4_read_inode_data`. That walks the byte range one block at a time,
translating logical to physical per block via `ext4_bmap`.

`ext4_bmap` requires `EXT4_INODE_EXTENTS`, descends the extent tree.
Uninit extents refused.

### stat

`ext4_fs_stat` fills `st.size` and a synthesized mode: `040755` for
directories, `0100644` for files, 0 for anything else. Real `i_mode`
permissions discarded. The shell only uses the mode to decide whether
to append `/`.

## htree fallback

A hash mismatch is not fatal. Every htree miss falls through to a
linear scan. Wrong hash on a large directory is a slow lookup, not a
failed one.

On a `LEGACY` or `TEA` directory, every lookup is O(n). Acceptable for
a boot path.

The fallback is why the reader accepts `LEGACY`, `TEA`, and the
`_UNSIGNED` variants without computing them. Only HALF_MD4 and
HALF_MD4_UNSIGNED are implemented.

## What the reader doesn't do

- **htree inserts and deletes.** Read-only.
- **Journal replay.** A filesystem that wasn't cleanly unmounted reads
  as-is.
- **Extended attributes.** `i_file_acl_lo` and its high half ignored.
- **`inline_data` inodes.** Refused at mount.
- **Compression.** Refused at mount.
- **Encryption.** Refused at mount.
- **`casefold`.** Refused at mount.
- **Block-mapped inodes** (`EXT4_INODE_EXTENTS` clear). Refused.
- **Verify directory, superblock, inode, or extent tree checksums.**
- **Serve zeros from uninit extents.**

Checksums are the biggest omission. Every metadata block in a modern
ext4 has a CRC32C. Not verifying means a corrupted filesystem reads as
wrong data. For a bootloader, verifying costs one CRC32C per block, and
a filesystem corrupted on disk won't boot anyway.

## Verification

Tested against `mke2fs` 1.47.4 on a 64 MiB filesystem with 5000 empty
files in the root. `debugfs -R "stat <2>"` reports `Flags: 0x81000`
(extents + htree). Booting Ivo against the image and running `ls /`
lists all 5000 files. `stat /file1` and `stat /file4999` succeed,
exercising the descent for names at opposite ends of the hash range.

To reproduce:

```bash
IMG=/tmp/ext4-htree.img
qemu-img create -f raw "$IMG" 64M
LOOP=$(sudo losetup -f)
sudo losetup -P "$LOOP" "$IMG"
sleep 1
sudo parted -s "$LOOP" mklabel gpt
sudo parted -s "$LOOP" mkpart ESP fat32 1MiB 33MiB
sudo parted -s "$LOOP" set 1 esp on
sudo parted -s "$LOOP" mkpart root ext4 33MiB 100%
sudo partprobe "$LOOP"
sleep 1
sudo mkfs.vfat -F 32 -n IVO_ESP "${LOOP}p1"
sudo mkfs.ext4 -F -L HTREE "${LOOP}p2"
sudo mkdir -p /mnt/test
sudo mount "${LOOP}p2" /mnt/test
cd /mnt/test
for i in $(seq 1 5000); do sudo : > "file$i"; done
cd /
sudo sync
sudo debugfs -R "stat <2>" "${LOOP}p2" 2>/dev/null | grep -i flags
sudo umount /mnt/test
sudo losetup -d "$LOOP"
```

Build the ESP with `ivo.efi`, boot. `ls /` lists 5000 files.

## Reference

Kernel `fs/ext4/` is definitive. Verified against `mke2fs` 1.47.4 and
`Documentation/filesystems/ext4/`. The htree hash is a port of
`fs/ext4/hash.c`.

`debugfs -R "stat <ino>"` and `debugfs -R "dump_extents <ino>"` confirm
what the reader should see. `dumpe2fs -h` prints the superblock fields.