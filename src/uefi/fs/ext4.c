/* ext4 read-only driver.
 *
 * Requires extents and 64bit. Refuses bigalloc, meta_bg, inline_data,
 * encrypt, casefold, dirdata, verity. Handles extent trees up to depth 5
 * and HALF_MD4 htree directories. See doc/ext4.md.
 */

#include "../core.h"
#include "fs.h"

#define EXT4_MAGIC              0xEF53
#define EXT4_ROOT_INO           2
#define EXT4_EXTENT_MAGIC       0xF30A

#define EXT4_INODE_EXTENTS      0x00080000
#define EXT4_INDEX_FL           0x00001000

#define EXT4_S_IFMT             0xF000
#define EXT4_S_IFDIR            0x4000
#define EXT4_S_IFREG            0x8000

#define EXT4_NAME_LEN           255
#define EXT4_MAX_BLOCK_SIZE     4096
#define EXT4_MAX_READ_RUN       4096

#define EXT4_FINCOM_COMPRESSION (1u << 0)
#define EXT4_FINCOM_FILETYPE    (1u << 1)
#define EXT4_FINCOM_RECOVER     (1u << 2)
#define EXT4_FINCOM_JOURNAL_DEV (1u << 3)
#define EXT4_FINCOM_META_BG     (1u << 4)
#define EXT4_FINCOM_EXTENTS     (1u << 6)
#define EXT4_FINCOM_64BIT       (1u << 7)
#define EXT4_FINCOM_MMP         (1u << 8)
#define EXT4_FINCOM_FLEX_BG     (1u << 9)
#define EXT4_FINCOM_EA_INODE    (1u << 10)
#define EXT4_FINCOM_DIRDATA     (1u << 12)
#define EXT4_FINCOM_CSUM_SEED   (1u << 13)
#define EXT4_FINCOM_LARGEDIR    (1u << 14)
#define EXT4_FINCOM_INLINE_DATA (1u << 15)
#define EXT4_FINCOM_ENCRYPT     (1u << 16)
#define EXT4_FINCOM_CASEFOLD    (1u << 17)

#define EXT4_FRO_COM_SPARSE_SUPER   (1u << 0)
#define EXT4_FRO_COM_LARGE_FILE     (1u << 1)
#define EXT4_FRO_COM_BTREE_DIR      (1u << 2)
#define EXT4_FRO_COM_HUGE_FILE      (1u << 3)
#define EXT4_FRO_COM_GDT_CSUM       (1u << 4)
#define EXT4_FRO_COM_DIR_NLINK      (1u << 5)
#define EXT4_FRO_COM_EXTRA_ISIZE    (1u << 6)
#define EXT4_FRO_COM_QUOTA          (1u << 8)
#define EXT4_FRO_COM_BIGALLOC       (1u << 9)
#define EXT4_FRO_COM_METADATA_CSUM  (1u << 10)
#define EXT4_FRO_COM_REPLICA        (1u << 11)
#define EXT4_FRO_COM_READONLY       (1u << 12)
#define EXT4_FRO_COM_PROJECT        (1u << 13)
#define EXT4_FRO_COM_VERITY         (1u << 15)
#define EXT4_FRO_COM_ORPHAN_PRESENT (1u << 16)

#define EXT4_INCOMPAT_REQUIRED \
    (EXT4_FINCOM_EXTENTS | EXT4_FINCOM_64BIT)

#define EXT4_INCOMPAT_UNSUPPORTED \
    (EXT4_FINCOM_COMPRESSION | EXT4_FINCOM_JOURNAL_DEV | \
     EXT4_FINCOM_META_BG     | EXT4_FINCOM_MMP | \
     EXT4_FINCOM_INLINE_DATA | EXT4_FINCOM_ENCRYPT | \
     EXT4_FINCOM_CASEFOLD    | EXT4_FINCOM_DIRDATA)

#define EXT4_RO_COMPAT_UNSUPPORTED \
    (EXT4_FRO_COM_BIGALLOC | EXT4_FRO_COM_REPLICA | EXT4_FRO_COM_VERITY)

#define EXT4_DX_HASH_LEGACY            0
#define EXT4_DX_HASH_HALF_MD4          1
#define EXT4_DX_HASH_TEA               2
#define EXT4_DX_HASH_LEGACY_UNSIGNED   3
#define EXT4_DX_HASH_HALF_MD4_UNSIGNED 4
#define EXT4_DX_HASH_TEA_UNSIGNED      5

struct ext4_superblock {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count_lo;
    uint32_t s_r_blocks_count_lo;
    uint32_t s_free_blocks_count_lo;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_cluster_size;
    uint32_t s_blocks_per_group;
    uint32_t s_clusters_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t  s_uuid[16];
    char     s_volume_name[16];
    char     s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;
    uint8_t  s_prealloc_blocks;
    uint8_t  s_prealloc_dir_blocks;
    uint16_t s_reserved_gdt_blocks;
    uint8_t  s_journal_uuid[16];
    uint32_t s_journal_inum;
    uint32_t s_journal_dev;
    uint32_t s_last_orphan;
    uint32_t s_hash_seed[4];
    uint8_t  s_def_hash_version;
    uint8_t  s_jnl_backup_type;
    uint16_t s_desc_size;
    uint32_t s_default_mount_opts;
    uint32_t s_first_meta_bg;
    uint32_t s_mkfs_time;
    uint32_t s_jnl_blocks[17];
    uint32_t s_blocks_count_hi;
    uint32_t s_r_blocks_count_hi;
    uint32_t s_free_blocks_count_hi;
    uint16_t s_min_extra_isize;
    uint16_t s_want_extra_isize;
    uint32_t s_flags;
    uint16_t s_raid_stride;
    uint16_t s_mmp_update_interval;
    uint64_t s_mmp_block;
    uint32_t s_raid_stripe_width;
    uint8_t  s_log_groups_per_flex;
    uint8_t  s_checksum_type;
    uint8_t  s_encryption_level;
    uint8_t  s_reserved_pad;
    uint64_t s_kbytes_written;
    uint32_t s_snapshot_inum;
    uint32_t s_snapshot_id;
    uint64_t s_snapshot_r_blocks_count;
    uint32_t s_snapshot_list;
    uint32_t s_error_count;
    uint32_t s_first_error_time;
    uint32_t s_first_error_ino;
    uint64_t s_first_error_block;
    uint8_t  s_first_error_func[32];
    uint32_t s_first_error_line;
    uint32_t s_last_error_time;
    uint32_t s_last_error_ino;
    uint32_t s_last_error_line;
    uint64_t s_last_error_block;
    uint8_t  s_last_error_func[32];
    uint8_t  s_mount_opts[64];
    uint32_t s_usr_quota_inum;
    uint32_t s_grp_quota_inum;
    uint32_t s_overhead_clusters;
    uint32_t s_backup_bgs[2];
    uint8_t  s_encrypt_algos[4];
    uint8_t  s_encrypt_pw_salt[16];
    uint32_t s_lpf_ino;
    uint32_t s_prj_quota_inum;
    uint32_t s_checksum_seed;
    uint8_t  s_wtime_hi;
    uint8_t  s_mtime_hi;
    uint8_t  s_mkfs_time_hi;
    uint8_t  s_lastcheck_hi;
    uint8_t  s_first_error_time_hi;
    uint8_t  s_last_error_time_hi;
    uint8_t  s_pad[2];
    uint16_t s_encoding;
    uint16_t s_encoding_flags;
    uint32_t s_orphan_file_inum;
    uint32_t s_reserved[94];
    uint32_t s_checksum;
} __attribute__((packed));

typedef char ext4_superblock_size_check[
    sizeof(struct ext4_superblock) == 1024 ? 1 : -1];

struct ext4_group_desc {
    uint32_t bg_block_bitmap_lo;
    uint32_t bg_inode_bitmap_lo;
    uint32_t bg_inode_table_lo;
    uint16_t bg_free_blocks_count_lo;
    uint16_t bg_free_inodes_count_lo;
    uint16_t bg_used_dirs_count_lo;
    uint16_t bg_flags;
    uint32_t bg_exclude_bitmap_lo;
    uint16_t bg_block_bitmap_csum_lo;
    uint16_t bg_inode_bitmap_csum_lo;
    uint16_t bg_itable_unused_lo;
    uint16_t bg_checksum;
    uint32_t bg_block_bitmap_hi;
    uint32_t bg_inode_bitmap_hi;
    uint32_t bg_inode_table_hi;
    uint16_t bg_free_blocks_count_hi;
    uint16_t bg_free_inodes_count_hi;
    uint16_t bg_used_dirs_count_hi;
    uint16_t bg_itable_unused_hi;
    uint32_t bg_exclude_bitmap_hi;
    uint16_t bg_block_bitmap_csum_hi;
    uint16_t bg_inode_bitmap_csum_hi;
    uint32_t bg_reserved;
} __attribute__((packed));

struct ext4_inode {
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size_lo;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks_lo;
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];
    uint32_t i_generation;
    uint32_t i_file_acl_lo;
    uint32_t i_size_high;
    uint32_t i_obso_faddr;
    uint16_t i_osd2_blocks_high;
    uint16_t i_osd2_file_acl_high;
    uint16_t i_osd2_uid_high;
    uint16_t i_osd2_gid_high;
    uint16_t i_osd2_checksum_lo;
    uint16_t i_osd2_reserved;
    uint16_t i_extra_isize;
    uint16_t i_checksum_hi;
    uint32_t i_ctime_extra;
    uint32_t i_mtime_extra;
    uint32_t i_atime_extra;
    uint32_t i_crtime;
    uint32_t i_crtime_extra;
    uint32_t i_version_hi;
    uint32_t i_projid;
} __attribute__((packed));

struct ext4_extent_header {
    uint16_t eh_magic;
    uint16_t eh_entries;
    uint16_t eh_max;
    uint16_t eh_depth;
    uint32_t eh_generation;
} __attribute__((packed));

struct ext4_extent {
    uint32_t ee_block;
    uint16_t ee_len;
    uint16_t ee_start_hi;
    uint32_t ee_start_lo;
} __attribute__((packed));

struct ext4_extent_idx {
    uint32_t ei_block;
    uint32_t ei_leaf_lo;
    uint16_t ei_leaf_hi;
    uint16_t ei_unused;
} __attribute__((packed));

struct ext4_dir_entry_2 {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t  name_len;
    uint8_t  file_type;
} __attribute__((packed));

struct dx_root_info {
    uint32_t reserved_zero;
    uint8_t  hash_version;
    uint8_t  info_length;
    uint8_t  indirect_levels;
    uint8_t  unused_flags;
} __attribute__((packed));

struct dx_entry {
    uint32_t hash;
    uint32_t block;
} __attribute__((packed));

typedef struct {
    block_device_t *dev;
    uint32_t block_size;
    uint32_t blocks_per_group;
    uint32_t inodes_per_group;
    uint32_t inode_size;
    uint32_t first_data_block;
    uint32_t gdt_block;
    uint32_t desc_size;
    uint32_t groups_count;
    uint64_t total_blocks;
    uint32_t total_inodes;
    uint32_t hash_seed[4];
    int      hash_unsigned;
} ext4_fs_t;

static ext4_fs_t ext4;

static uint8_t ext4_meta_buf[EXT4_MAX_BLOCK_SIZE];
static uint8_t ext4_io_buf[EXT4_MAX_BLOCK_SIZE];

extern int luks_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);
extern int luks_active(void);
#ifdef LVM
extern int lvm_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);
extern int lvm_active(void);
#endif

static inline uint16_t rd16(const void *p) {
    uint16_t v; __builtin_memcpy(&v, p, 2); return v;
}

static int ext4_read_block(uint64_t block, void *buf)
{
    if (block >= ext4.total_blocks) return -1;
    uint64_t sector = block * (ext4.block_size / 512);
    uint32_t nsect  = ext4.block_size / 512;
#ifdef LVM
    if (lvm_active())
        return lvm_read_blocks(sector, nsect, buf);
#endif
    if (luks_active())
        return luks_read_blocks(sector, nsect, buf);
    return hal_read_blocks(ext4.dev->lba_start + sector, nsect, buf);
}

static int ext4_read_blocks_range(uint64_t pb, uint32_t count, void *buf)
{
    if (pb >= ext4.total_blocks || count > ext4.total_blocks - pb) return -1;
    uint64_t sector = pb * (ext4.block_size / 512);
    uint32_t nsect  = count * (ext4.block_size / 512);
#ifdef LVM
    if (lvm_active())
        return lvm_read_blocks(sector, nsect, buf);
#endif
    if (luks_active())
        return luks_read_blocks(sector, nsect, buf);
    return hal_read_blocks(ext4.dev->lba_start + sector, nsect, buf);
}

static int ext4_read_gd(uint32_t group, struct ext4_group_desc *out)
{
    uint64_t byte = (uint64_t)ext4.gdt_block * ext4.block_size
                  + (uint64_t)group * ext4.desc_size;
    uint64_t block = byte / ext4.block_size;
    uint32_t off   = (uint32_t)(byte % ext4.block_size);

    if (off + ext4.desc_size > ext4.block_size) return -1;
    if (ext4_read_block(block, ext4_meta_buf) != 0) return -1;
    uint32_t copy = ext4.desc_size;
    if (copy > sizeof(*out)) copy = sizeof(*out);
    memcpy(out, ext4_meta_buf + off, copy);
    return 0;
}

static int ext4_read_inode(uint32_t ino, struct ext4_inode *out)
{
    if (ino == 0 || ino > ext4.total_inodes) return -1;

    uint32_t group = (ino - 1) / ext4.inodes_per_group;
    uint32_t index = (ino - 1) % ext4.inodes_per_group;
    if (group >= ext4.groups_count) return -1;

    struct ext4_group_desc gd;
    if (ext4_read_gd(group, &gd) != 0) return -1;

    uint64_t itable = ((uint64_t)gd.bg_inode_table_hi << 32)
                    | (uint64_t)gd.bg_inode_table_lo;
    uint64_t byte = itable * ext4.block_size
                  + (uint64_t)index * ext4.inode_size;
    uint64_t block = byte / ext4.block_size;
    uint32_t off   = (uint32_t)(byte % ext4.block_size);

    if (off + ext4.inode_size > ext4.block_size) return -1;
    if (ext4_read_block(block, ext4_meta_buf) != 0) return -1;

    size_t copy = ext4.inode_size;
    if (copy > sizeof(struct ext4_inode)) copy = sizeof(struct ext4_inode);
    memset(out, 0, sizeof(*out));
    memcpy(out, ext4_meta_buf + off, copy);
    return 0;
}

static int ext4_extent_walk(const uint8_t *node, uint32_t target_lb,
                            uint64_t *pb_out, uint32_t *run_out)
{
    uint32_t cap = 60;
    int want_depth = -1;

    for (;;) {
        const struct ext4_extent_header *h =
            (const struct ext4_extent_header *)node;
        uint16_t entries = h->eh_entries;
        uint16_t depth   = h->eh_depth;
        if (h->eh_magic != EXT4_EXTENT_MAGIC) return -1;
        if (entries > h->eh_max) return -1;
        if (entries > (cap - sizeof(*h)) / 12) return -1;
        if (depth > 5) return -1;
        if (want_depth >= 0 && depth != (uint16_t)want_depth) return -1;

        if (depth == 0) {
            const struct ext4_extent *e =
                (const struct ext4_extent *)(node + sizeof(*h));
            for (uint16_t i = 0; i < entries; i++, e++) {
                uint32_t len = e->ee_len;
                int uninit = 0;
                if (len > 32768) { uninit = 1; len -= 32768; }
                if (target_lb >= e->ee_block &&
                    (uint64_t)target_lb < (uint64_t)e->ee_block + len) {
                    if (uninit) return -1;
                    uint64_t pb = ((uint64_t)e->ee_start_hi << 32)
                                | e->ee_start_lo;
                    uint32_t delta = target_lb - e->ee_block;
                    if (pb_out)  *pb_out  = pb + delta;
                    if (run_out) *run_out = len - delta;
                    return 0;
                }
            }
            return -1;
        }

        const struct ext4_extent_idx *ix =
            (const struct ext4_extent_idx *)(node + sizeof(*h));
        int chosen = -1;
        for (uint16_t i = 0; i < entries; i++) {
            if (ix[i].ei_block <= target_lb) chosen = i;
            else break;
        }
        if (chosen < 0) return -1;

        uint64_t next = ((uint64_t)ix[chosen].ei_leaf_hi << 32)
                      | (uint64_t)ix[chosen].ei_leaf_lo;

        if (ext4_read_block(next, ext4_meta_buf) != 0) return -1;
        node = ext4_meta_buf;
        cap = ext4.block_size;
        want_depth = depth - 1;
    }
}

static int ext4_bmap(const struct ext4_inode *ino, uint32_t lb,
                     uint64_t *pb_out)
{
    if (!(ino->i_flags & EXT4_INODE_EXTENTS)) return -1;
    return ext4_extent_walk((const uint8_t *)ino->i_block, lb,
                            pb_out, 0);
}

static int ext4_bmap_run(const struct ext4_inode *ino, uint32_t lb,
                         uint64_t *pb_out, uint32_t *run_out)
{
    if (!(ino->i_flags & EXT4_INODE_EXTENTS)) return -1;
    return ext4_extent_walk((const uint8_t *)ino->i_block, lb,
                            pb_out, run_out);
}

static int ext4_read_inode_data(const struct ext4_inode *ino,
                                uint64_t offset, uint8_t *dst, size_t *len)
{
    uint64_t size = ((uint64_t)ino->i_size_high << 32) | ino->i_size_lo;
    if (offset >= size) { *len = 0; return 0; }
    if ((uint64_t)*len > size - offset) *len = (size_t)(size - offset);
    /* Logical block numbers are 32-bit. */
    if ((offset + *len) / ext4.block_size > 0xFFFFFFFFull) return -1;

    size_t want = *len;

    uint32_t boff = (uint32_t)(offset % ext4.block_size);
    if (boff != 0) {
        uint32_t lb = (uint32_t)(offset / ext4.block_size);
        uint64_t pb;
        if (ext4_bmap(ino, lb, &pb) != 0) return -1;
        if (ext4_read_block(pb, ext4_io_buf) != 0) return -1;
        uint32_t take = ext4.block_size - boff;
        if (take > want) take = (uint32_t)want;
        memcpy(dst, ext4_io_buf + boff, take);
        dst    += take;
        offset += take;
        want   -= take;
    }

    while (want >= ext4.block_size) {
        uint32_t lb = (uint32_t)(offset / ext4.block_size);
        uint64_t pb;
        uint32_t run;
        if (ext4_bmap_run(ino, lb, &pb, &run) != 0) return -1;

        uint32_t want_blocks = (uint32_t)(want / ext4.block_size);
        if (run > want_blocks)      run = want_blocks;
        if (run > EXT4_MAX_READ_RUN) run = EXT4_MAX_READ_RUN;

        size_t bytes = (size_t)run * ext4.block_size;
        if (ext4_read_blocks_range(pb, run, dst) != 0) return -1;

        dst    += bytes;
        offset += bytes;
        want   -= bytes;
    }

    if (want > 0) {
        uint32_t lb = (uint32_t)(offset / ext4.block_size);
        uint64_t pb;
        if (ext4_bmap(ino, lb, &pb) != 0) return -1;
        if (ext4_read_block(pb, ext4_io_buf) != 0) return -1;
        memcpy(dst, ext4_io_buf, want);
    }

    return 0;
}

static uint32_t ext4_rotl(uint32_t x, int s)
{
    return (x << s) | (x >> (32 - s));
}

static void ext4_half_md4_transform(uint32_t buf[4], const uint32_t in[8])
{
    uint32_t a = buf[0], b = buf[1], c = buf[2], d = buf[3];

#define F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x,y,z) (((x) & (y)) + (((x) ^ (y)) & (z)))
#define H(x,y,z) ((x) ^ (y) ^ (z))
#define R(f,a,b,c,d,x,s) do { \
        (a) += f((b),(c),(d)) + (x); \
        (a) = ext4_rotl((a), (s)); \
    } while (0)

    R(F, a,b,c,d, in[0], 3);
    R(F, d,a,b,c, in[1], 7);
    R(F, c,d,a,b, in[2], 11);
    R(F, b,c,d,a, in[3], 19);
    R(F, a,b,c,d, in[4], 3);
    R(F, d,a,b,c, in[5], 7);
    R(F, c,d,a,b, in[6], 11);
    R(F, b,c,d,a, in[7], 19);

    R(G, a,b,c,d, in[1] + 0x5A827999u, 3);
    R(G, d,a,b,c, in[3] + 0x5A827999u, 5);
    R(G, c,d,a,b, in[5] + 0x5A827999u, 9);
    R(G, b,c,d,a, in[7] + 0x5A827999u, 13);
    R(G, a,b,c,d, in[0] + 0x5A827999u, 3);
    R(G, d,a,b,c, in[2] + 0x5A827999u, 5);
    R(G, c,d,a,b, in[4] + 0x5A827999u, 9);
    R(G, b,c,d,a, in[6] + 0x5A827999u, 13);

    R(H, a,b,c,d, in[3] + 0x6ED9EBA1u, 3);
    R(H, d,a,b,c, in[7] + 0x6ED9EBA1u, 9);
    R(H, c,d,a,b, in[2] + 0x6ED9EBA1u, 11);
    R(H, b,c,d,a, in[6] + 0x6ED9EBA1u, 15);
    R(H, a,b,c,d, in[1] + 0x6ED9EBA1u, 3);
    R(H, d,a,b,c, in[5] + 0x6ED9EBA1u, 9);
    R(H, c,d,a,b, in[0] + 0x6ED9EBA1u, 11);
    R(H, b,c,d,a, in[4] + 0x6ED9EBA1u, 15);

#undef F
#undef G
#undef H
#undef R

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

static void ext4_str2hashbuf(const uint8_t *msg, size_t remaining,
                             size_t chunk, uint32_t in[8], int sign)
{
    uint32_t pad = (uint32_t)remaining;
    pad |= pad << 8;
    pad |= pad << 16;
    uint32_t val = pad;
    int num = 8;
    int idx = 0;

    for (size_t i = 0; i < chunk; i++) {
        if ((i & 3) == 0) val = pad;
        uint32_t ch = sign ? (uint32_t)(int32_t)(int8_t)msg[i] : msg[i];
        val = ch + (val << 8);
        if ((i & 3) == 3) {
            in[idx++] = val;
            val = pad;
            num--;
        }
    }
    if (--num >= 0) in[idx++] = val;
    while (--num >= 0) in[idx++] = pad;
}

static uint32_t ext4_dir_hash(const char *name, size_t len,
                              uint8_t hash_version)
{
    if (hash_version != EXT4_DX_HASH_HALF_MD4 &&
        hash_version != EXT4_DX_HASH_HALF_MD4_UNSIGNED) {
        return 0;
    }
    int sign = hash_version == EXT4_DX_HASH_HALF_MD4 && !ext4.hash_unsigned;

    uint32_t buf[4] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u };
    if (ext4.hash_seed[0] | ext4.hash_seed[1] |
        ext4.hash_seed[2] | ext4.hash_seed[3]) {
        buf[0] = ext4.hash_seed[0];
        buf[1] = ext4.hash_seed[1];
        buf[2] = ext4.hash_seed[2];
        buf[3] = ext4.hash_seed[3];
    }

    const uint8_t *msg = (const uint8_t *)name;
    size_t remaining = len;

    while (remaining > 0) {
        uint32_t in[8];
        size_t chunk = remaining > 32 ? 32 : remaining;
        ext4_str2hashbuf(msg, remaining, chunk, in, sign);
        ext4_half_md4_transform(buf, in);
        remaining -= chunk;
        msg += chunk;
    }

    return buf[1];
}

static int ext4_is_dx_root(const uint8_t *b)
{
    return rd16(b + 4) == 12 && b[6] == 1 && b[8] == '.' &&
           rd16(b + 16) == ext4.block_size - 12 && b[18] == 2 &&
           b[20] == '.' && b[21] == '.';
}

static int ext4_is_dx_node(const uint8_t *b)
{
    return b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
           rd16(b + 4) == ext4.block_size && b[6] == 0 && b[7] == 0;
}

static uint64_t ext4_isize(const struct ext4_inode *ino)
{
    return ((uint64_t)ino->i_size_high << 32) | ino->i_size_lo;
}

static uint32_t ext4_dirent_ok(const uint8_t *block, uint32_t pos)
{
    if (pos + 8 > ext4.block_size) return 0;
    const struct ext4_dir_entry_2 *de =
        (const struct ext4_dir_entry_2 *)(block + pos);
    uint32_t rl = de->rec_len;
    if (rl < 8 || (rl & 3)) return 0;
    if (rl > ext4.block_size - pos) return 0;
    if (8u + de->name_len > rl) return 0;
    return rl;
}

static int ext4_leaf_scan(const uint8_t *block, const char *name,
                          size_t name_len, uint32_t *ino_out,
                          uint8_t *type_out)
{
    uint32_t pos = 0;
    while (pos + 8 <= ext4.block_size) {
        const struct ext4_dir_entry_2 *de =
            (const struct ext4_dir_entry_2 *)(block + pos);
        uint32_t rl = ext4_dirent_ok(block, pos);
        if (rl == 0) return -1;
        if (rl == 12 && de->name_len == 0 && de->file_type == 0xDE)
            break;
        if (de->inode != 0 && de->name_len == name_len) {
            const char *dn = (const char *)(block + pos + 8);
            int match = 1;
            for (size_t k = 0; k < name_len; k++) {
                if (dn[k] != name[k]) { match = 0; break; }
            }
            if (match) {
                *ino_out = de->inode;
                if (type_out) *type_out = de->file_type;
                return 0;
            }
        }
        pos += rl;
    }
    return -1;
}

static int ext4_htree_pick(const uint8_t *blk, uint32_t off, uint32_t hash,
                           uint32_t *child_out)
{
    if (off + 8 > ext4.block_size) return -1;
    uint32_t limit = rd16(blk + off);
    uint32_t count = rd16(blk + off + 2);
    if (count == 0 || count > limit) return -1;
    if (limit > (ext4.block_size - off) / sizeof(struct dx_entry)) return -1;

    const struct dx_entry *e = (const struct dx_entry *)(blk + off);
    uint32_t i = 1;
    while (i < count && e[i].hash <= hash) i++;
    *child_out = e[i - 1].block;
    return 0;
}

static int ext4_htree_lookup(const struct ext4_inode *dir,
                             const char *name, size_t name_len,
                             uint32_t *ino_out, uint8_t *type_out)
{
    uint64_t dir_blocks = ext4_isize(dir) / ext4.block_size;
    uint64_t pb;
    if (ext4_bmap(dir, 0, &pb) != 0) return -1;
    if (ext4_read_block(pb, ext4_meta_buf) != 0) return -1;
    if (!ext4_is_dx_root(ext4_meta_buf)) return -1;

    const struct dx_root_info *ri =
        (const struct dx_root_info *)(ext4_meta_buf + 24);
    if (ri->info_length != 8) return -1;
    if (ri->indirect_levels > 2) return -1;
    if (ri->hash_version != EXT4_DX_HASH_HALF_MD4 &&
        ri->hash_version != EXT4_DX_HASH_HALF_MD4_UNSIGNED)
        return -1;

    uint8_t levels = ri->indirect_levels;
    uint32_t hash = ext4_dir_hash(name, name_len, ri->hash_version) & ~1u;
    uint32_t off = 24 + 8;

    for (uint8_t lvl = 0; ; lvl++) {
        uint32_t child;
        if (ext4_htree_pick(ext4_meta_buf, off, hash, &child) != 0)
            return -1;
        if (child == 0 || child >= dir_blocks) return -1;
        if (ext4_bmap(dir, child, &pb) != 0) return -1;
        if (lvl == levels) break;
        if (ext4_read_block(pb, ext4_meta_buf) != 0) return -1;
        if (!ext4_is_dx_node(ext4_meta_buf)) return -1;
        off = 8;
    }

    if (ext4_read_block(pb, ext4_io_buf) != 0) return -1;
    return ext4_leaf_scan(ext4_io_buf, name, name_len, ino_out, type_out);
}

static int ext4_dir_lookup(const struct ext4_inode *dir,
                           const char *name, size_t name_len,
                           uint32_t *ino_out, uint8_t *type_out)
{
    if (name_len == 0 || name_len > EXT4_NAME_LEN) return -1;

    uint64_t dir_size = ext4_isize(dir);
    if (dir_size / ext4.block_size > 0xFFFFFFFFull) return -1;

    if (dir->i_flags & EXT4_INDEX_FL) {
        if (ext4_htree_lookup(dir, name, name_len, ino_out, type_out) == 0)
            return 0;
    }

    uint64_t off = 0;
    while (off < dir_size) {
        uint32_t lb = (uint32_t)(off / ext4.block_size);
        uint64_t pb;
        if (ext4_bmap(dir, lb, &pb) != 0) return -1;
        if (ext4_read_block(pb, ext4_io_buf) != 0) return -1;

        if ((dir->i_flags & EXT4_INDEX_FL) && ext4_is_dx_node(ext4_io_buf)) {
            off += ext4.block_size;
            continue;
        }

        if (ext4_leaf_scan(ext4_io_buf, name, name_len,
                           ino_out, type_out) == 0)
            return 0;
        off += ext4.block_size;
    }
    return -1;
}

static int ext4_resolve(const char *path, struct ext4_inode *out,
                        uint32_t *ino_out)
{
    uint32_t cur = EXT4_ROOT_INO;
    struct ext4_inode cur_ino;

    if (ext4_read_inode(cur, &cur_ino) != 0) return -1;

    if (path[0] == '/') path++;

    while (*path) {
        const char *slash = path;
        while (*slash && *slash != '/') slash++;
        size_t clen = (size_t)(slash - path);

        if (clen == 0) { path = slash + 1; continue; }
        if (clen > EXT4_NAME_LEN) return -1;
        if ((cur_ino.i_mode & EXT4_S_IFMT) != EXT4_S_IFDIR) return -1;

        char name[EXT4_NAME_LEN + 1];
        memcpy(name, path, clen);
        name[clen] = '\0';

        uint32_t next_ino;
        if (ext4_dir_lookup(&cur_ino, name, clen, &next_ino, 0) != 0) return -1;
        if (ext4_read_inode(next_ino, &cur_ino) != 0) return -1;
        cur = next_ino;

        path = slash + (*slash ? 1 : 0);
    }

    *out = cur_ino;
    *ino_out = cur;
    return 0;
}

static int ext4_read_superblock(block_device_t *dev, uint8_t sb_buf[1024])
{
    block_device_t *prev = ext4.dev;
    ext4.dev = dev;

    int rc;
#ifdef LVM
    if (lvm_active()) {
        rc = lvm_read_blocks(2, 2, sb_buf);
    } else
#endif
    if (luks_active()) {
        rc = luks_read_blocks(2, 2, sb_buf);
    } else {
        rc = hal_read_blocks(dev->lba_start + 2, 2, sb_buf);
    }

    ext4.dev = prev;
    return rc;
}

static int ext4_probe(block_device_t *dev)
{
    uint8_t sb_buf[1024];
    if (ext4_read_superblock(dev, sb_buf) != 0) return -1;

    const struct ext4_superblock *sb =
        (const struct ext4_superblock *)sb_buf;
    if (sb->s_magic != EXT4_MAGIC) return -1;
    if (sb->s_log_block_size > 2) return -1;
    if (sb->s_blocks_per_group == 0) return -1;
    if (sb->s_inodes_per_group == 0) return -1;
    return 0;
}

static int ext4_fs_mount(block_device_t *dev)
{
    ext4.dev = dev;

    uint8_t sb_buf[1024];
    if (ext4_read_superblock(dev, sb_buf) != 0) return -1;

    const struct ext4_superblock *sb =
        (const struct ext4_superblock *)sb_buf;
    if (sb->s_magic != EXT4_MAGIC) return -1;

    uint32_t incompat  = sb->s_feature_incompat;
    uint32_t ro_compat = sb->s_feature_ro_compat;

    if (incompat & EXT4_INCOMPAT_UNSUPPORTED) {
        con_puts("ext4: unsupported incompat features\n");
        return -1;
    }
    if (ro_compat & EXT4_RO_COMPAT_UNSUPPORTED) {
        con_puts("ext4: unsupported ro_compat features\n");
        return -1;
    }
    if ((incompat & EXT4_INCOMPAT_REQUIRED) != EXT4_INCOMPAT_REQUIRED) {
        con_puts("ext4: missing extents or 64bit\n");
        return -1;
    }

    if (sb->s_log_block_size > 2) {
        con_puts("ext4: unsupported block size\n");
        return -1;
    }
    ext4.block_size = 1024u << sb->s_log_block_size;

    ext4.blocks_per_group = sb->s_blocks_per_group;
    ext4.inodes_per_group = sb->s_inodes_per_group;
    ext4.inode_size       = sb->s_inode_size;
    ext4.first_data_block = sb->s_first_data_block;

    if (ext4.blocks_per_group == 0 ||
        ext4.blocks_per_group > ext4.block_size * 8) return -1;
    if (ext4.inodes_per_group == 0 ||
        ext4.inodes_per_group > ext4.block_size * 8) return -1;
    if (ext4.inode_size < 128 || ext4.inode_size > ext4.block_size ||
        (ext4.inode_size & (ext4.inode_size - 1))) return -1;
    if (ext4.first_data_block != (ext4.block_size == 1024 ? 1u : 0u))
        return -1;

    uint32_t dsz = sb->s_desc_size;
    if (dsz < 64 || dsz > ext4.block_size || (dsz & (dsz - 1))) return -1;
    ext4.desc_size = dsz;

    ext4.total_blocks = ((uint64_t)sb->s_blocks_count_hi << 32)
                      | sb->s_blocks_count_lo;
    ext4.total_inodes = sb->s_inodes_count;
    if (ext4.total_blocks <= ext4.first_data_block) return -1;

    uint64_t rel = ext4.total_blocks - ext4.first_data_block;
    uint64_t groups = (rel + ext4.blocks_per_group - 1)
                    / ext4.blocks_per_group;
    if (groups == 0 || groups > 0xFFFFFFFFull) return -1;
    ext4.groups_count = (uint32_t)groups;
    ext4.gdt_block = ext4.first_data_block + 1;

    uint64_t gdt_blocks = (groups * dsz + ext4.block_size - 1)
                        / ext4.block_size;
    if (gdt_blocks > ext4.total_blocks - ext4.gdt_block) return -1;
    if (ext4.total_inodes == 0 ||
        ext4.total_inodes > groups * ext4.inodes_per_group) return -1;

    memcpy(ext4.hash_seed, sb->s_hash_seed, sizeof(ext4.hash_seed));
    ext4.hash_unsigned = (sb->s_flags & 0x2) != 0;  /* UNSIGNED_HASH */

    return 0;
}

static void ext4_fs_umount(void) { }

static int ext4_fs_read(const char *path, uint8_t *buf, size_t *len)
{
    struct ext4_inode ino;
    uint32_t ino_num;
    if (ext4_resolve(path, &ino, &ino_num) != 0) return -1;
    if ((ino.i_mode & EXT4_S_IFMT) != EXT4_S_IFREG) return -1;
    return ext4_read_inode_data(&ino, 0, buf, len);
}

static int ext4_fs_stat(const char *path, struct stat *st)
{
    struct ext4_inode ino;
    uint32_t ino_num;
    if (ext4_resolve(path, &ino, &ino_num) != 0) return -1;

    st->size = ((uint64_t)ino.i_size_high << 32) | ino.i_size_lo;
    uint16_t fmt = ino.i_mode & EXT4_S_IFMT;
    if      (fmt == EXT4_S_IFDIR) st->mode = 040755;
    else if (fmt == EXT4_S_IFREG) st->mode = 0100644;
    else                          st->mode = 0;
    return 0;
}

static int ext4_fs_readlink(const char *path, char *buf, size_t len)
{
    (void)path; (void)buf; (void)len;
    return -1;
}

typedef struct {
    uint32_t ino;
    uint64_t offset;
} ext4_dir_handle_t;

static int ext4_fs_opendir(const char *path, void **handle)
{
    struct ext4_inode ino;
    uint32_t ino_num;
    if (ext4_resolve(path, &ino, &ino_num) != 0) return -1;
    if ((ino.i_mode & EXT4_S_IFMT) != EXT4_S_IFDIR) return -1;

    ext4_dir_handle_t *h = mm_alloc(sizeof(*h));
    if (!h) return -1;
    h->ino = ino_num;
    h->offset = 0;
    *handle = h;
    return 0;
}

static int ext4_fs_readdir(void *handle, char *name, size_t name_len)
{
    if (!handle || !name || name_len < 2) return -1;
    ext4_dir_handle_t *h = (ext4_dir_handle_t *)handle;

    struct ext4_inode dir;
    if (ext4_read_inode(h->ino, &dir) != 0) return -1;

    uint64_t dir_size = ext4_isize(&dir);
    if (dir_size / ext4.block_size > 0xFFFFFFFFull) return -1;
    int is_htree = (dir.i_flags & EXT4_INDEX_FL) != 0;

    while (h->offset < dir_size) {
        uint32_t lb   = (uint32_t)(h->offset / ext4.block_size);
        uint32_t boff = (uint32_t)(h->offset % ext4.block_size);
        uint64_t pb;
        if (ext4_bmap(&dir, lb, &pb) != 0) return -1;
        if (ext4_read_block(pb, ext4_io_buf) != 0) return -1;

        if (is_htree && boff == 0 && ext4_is_dx_node(ext4_io_buf)) {
            h->offset = ((h->offset / ext4.block_size) + 1) * ext4.block_size;
            continue;
        }

        if (boff + 8 > ext4.block_size) {
            h->offset = ((h->offset / ext4.block_size) + 1) * ext4.block_size;
            continue;
        }
        const struct ext4_dir_entry_2 *de =
            (const struct ext4_dir_entry_2 *)(ext4_io_buf + boff);
        uint32_t rl = ext4_dirent_ok(ext4_io_buf, boff);
        if (rl == 0) return -1;

        if (rl == 12 && de->name_len == 0 && de->file_type == 0xDE) {
            h->offset = ((h->offset / ext4.block_size) + 1) * ext4.block_size;
            continue;
        }
        if (de->inode == 0) {
            h->offset += rl;
            continue;
        }

        size_t copy = de->name_len;
        if (copy >= name_len) copy = name_len - 1;
        const char *dn = (const char *)(ext4_io_buf + boff + 8);
        memcpy(name, dn, copy);
        name[copy] = '\0';
        h->offset += rl;
        return 1;
    }
    return 0;
}

static void ext4_fs_closedir(void *handle)
{
    if (handle) mm_free(handle);
}

static int ext4_fs_write(const char *path, const uint8_t *data, size_t size)
{
    (void)path; (void)data; (void)size;
    return -1;
}

fs_driver_t fs_ext4 = {
    .probe    = ext4_probe,
    .mount    = ext4_fs_mount,
    .read     = ext4_fs_read,
    .readlink = ext4_fs_readlink,
    .stat     = ext4_fs_stat,
    .umount   = ext4_fs_umount,
    .opendir  = ext4_fs_opendir,
    .readdir  = ext4_fs_readdir,
    .closedir = ext4_fs_closedir,
    .write    = ext4_fs_write,
};