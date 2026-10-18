/* BTRFS reader. Single-device, default subvolume, no compression.
 * See doc/btrfs.md for the on-disk derivation.
 */

#include "core.h"
#include "fs/fs.h"
#include "fs/btrfs.h"

#ifdef LVM
extern int lvm_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);
extern int lvm_active(void);
#endif

extern int luks_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);
extern int luks_active(void);

#define BTRFS_SUPER_OFFSET   0x10000ULL
#define BTRFS_SUPER_SIZE     4096u
#define BTRFS_NODESIZE_MAX   16384u
#define BTRFS_SECTORSIZE     4096u
#define BTRFS_LEAF_HDR       101u
#define BTRFS_ITEM_SIZE      25u
#define BTRFS_KEY_PTR_SIZE   33u
#define BTRFS_CHUNK_HDR      48u
#define BTRFS_STRIPE_SIZE    32u
#define BTRFS_MAX_CHUNKS     512
#define BTRFS_MAX_DEPTH      8
#define BTRFS_MAX_CHILDREN   64
#define BTRFS_MAX_READ_RUN   4096

#define BTRFS_NAME_MAX       255
#define BTRFS_DIR_MAX        128

#define BTRFS_KEY_INODE_ITEM     1
#define BTRFS_KEY_INODE_REF      12
#define BTRFS_KEY_DIR_ITEM       84
#define BTRFS_KEY_DIR_INDEX      96
#define BTRFS_KEY_EXTENT_DATA    108
#define BTRFS_KEY_ROOT_ITEM      132
#define BTRFS_KEY_CHUNK_ITEM     228

#define BTRFS_OBJ_FS_TREE            5
#define BTRFS_ROOT_TREE_DIR_OBJECTID 6
#define BTRFS_OBJ_FIRST_CHUNK        256
#define BTRFS_OBJ_FIRST_FREE         256

#define BTRFS_BG_DATA     (1ULL << 0)
#define BTRFS_BG_SYSTEM   (1ULL << 1)
#define BTRFS_BG_METADATA (1ULL << 2)
#define BTRFS_BG_RAID0    (1ULL << 3)
#define BTRFS_BG_RAID10   (1ULL << 6)

#define BTRFS_FILE_EXTENT_INLINE    0
#define BTRFS_FILE_EXTENT_REG       1
#define BTRFS_FILE_EXTENT_PREALLOC  2

#define BTRFS_S_IFMT    0170000u
#define BTRFS_S_IFDIR   0040000u
#define BTRFS_S_IFREG   0100000u
#define BTRFS_S_IFLNK   0120000u

#define BTRFS_INCOMPAT_MIXED_BACKREF    (1ULL << 0)
#define BTRFS_INCOMPAT_DEFAULT_SUBVOL   (1ULL << 1)
#define BTRFS_INCOMPAT_BIG_METADATA     (1ULL << 5)
#define BTRFS_INCOMPAT_EXTENDED_IREF    (1ULL << 6)
#define BTRFS_INCOMPAT_SKINNY_METADATA  (1ULL << 8)
#define BTRFS_INCOMPAT_BLOCK_GROUP_TREE (1ULL << 7)
#define BTRFS_INCOMPAT_NO_HOLES         (1ULL << 9)
#define BTRFS_INCOMPAT_RAID1C34         (1ULL << 11)

#define BTRFS_INCOMPAT_ALLOWED (\
    BTRFS_INCOMPAT_MIXED_BACKREF |\
    BTRFS_INCOMPAT_DEFAULT_SUBVOL |\
    BTRFS_INCOMPAT_BIG_METADATA |\
    BTRFS_INCOMPAT_EXTENDED_IREF |\
    BTRFS_INCOMPAT_BLOCK_GROUP_TREE |\
    BTRFS_INCOMPAT_SKINNY_METADATA |\
    BTRFS_INCOMPAT_NO_HOLES |\
    BTRFS_INCOMPAT_RAID1C34)

static inline uint16_t rd16(const void *p) {
    uint16_t v; __builtin_memcpy(&v, p, 2); return v;
}
static inline uint32_t rd32(const void *p) {
    uint32_t v; __builtin_memcpy(&v, p, 4); return v;
}
static inline uint64_t rd64(const void *p) {
    uint64_t v; __builtin_memcpy(&v, p, 8); return v;
}

struct btrfs_key {
    uint64_t objectid;
    uint8_t  type;
    uint64_t offset;
};

static void btrfs_key_get(struct btrfs_key *k, const void *p) {
    const uint8_t *b = p;
    k->objectid = rd64(b);
    k->type     = b[8];
    k->offset   = rd64(b + 9);
}

static int btrfs_key_cmp(const struct btrfs_key *a, const struct btrfs_key *b) {
    if (a->objectid < b->objectid) return -1;
    if (a->objectid > b->objectid) return 1;
    if (a->type     < b->type)     return -1;
    if (a->type     > b->type)     return 1;
    if (a->offset   < b->offset)   return -1;
    if (a->offset   > b->offset)   return 1;
    return 0;
}

static block_device_t *btrfs_dev;
static uint32_t        btrfs_bs;
static uint64_t        btrfs_devid;
static uint32_t        btrfs_nodesize;

static uint8_t  btrfs_sb[BTRFS_SUPER_SIZE];
static uint8_t  btrfs_block[BTRFS_NODESIZE_MAX];

struct btrfs_chunk_range {
    uint64_t logical;
    uint64_t size;
    uint64_t phys;
};

static struct btrfs_chunk_range btrfs_chunks[BTRFS_MAX_CHUNKS];
static uint32_t btrfs_nchunks;

static uint64_t btrfs_base_root;
static uint32_t btrfs_base_level;
static uint64_t btrfs_default_root;
static uint32_t btrfs_default_level;
static uint64_t btrfs_fs_tree_root;
static uint32_t btrfs_fs_tree_level;
static uint64_t btrfs_fs_root;
static uint32_t btrfs_fs_level;

struct btrfs_dirent {
    char    name[BTRFS_NAME_MAX + 1];
    uint8_t type;
};

struct btrfs_dir_handle {
    uint32_t count;
    uint32_t cursor;
    struct btrfs_dirent entries[BTRFS_DIR_MAX];
};

static struct btrfs_dir_handle btrfs_dir;

static uint32_t btrfs_crc32c_table[256];
static int      btrfs_crc32c_ready;

static void btrfs_crc32c_init(void) {
    if (btrfs_crc32c_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (c >> 1) ^ 0x82F63B78u : (c >> 1);
        btrfs_crc32c_table[i] = c;
    }
    btrfs_crc32c_ready = 1;
}

static uint32_t btrfs_crc32c_update(uint32_t crc, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len--)
        crc = (crc >> 8) ^ btrfs_crc32c_table[(crc ^ *p++) & 0xFF];
    return crc;
}

static uint64_t btrfs_name_hash(const char *name, size_t len) {
    return btrfs_crc32c_update(0xFFFFFFFEu, name, len);
}

static int btrfs_read_phys(uint64_t phys, void *buf, size_t len) {
    if (len % btrfs_bs != 0) return -1;
    uint64_t sector = phys / btrfs_bs;
    uint32_t sectors = (uint32_t)(len / btrfs_bs);
#ifdef LVM
    if (lvm_active())
        return lvm_read_blocks(sector, sectors, buf);
#endif
    if (luks_active())
        return luks_read_blocks(sector, sectors, buf);
    return hal_read_blocks(btrfs_dev->lba_start + sector, sectors, buf);
}

static int btrfs_chunk_lookup_ex(uint64_t logical, uint64_t *phys_out,
                                 uint64_t *run_out)
{
    for (uint32_t i = 0; i < btrfs_nchunks; i++) {
        const struct btrfs_chunk_range *c = &btrfs_chunks[i];
        if (logical >= c->logical && logical < c->logical + c->size) {
            *phys_out = c->phys + (logical - c->logical);
            if (run_out) *run_out = c->size - (logical - c->logical);
            return 0;
        }
    }
    return -1;
}

static int btrfs_read_logical(uint64_t logical, void *buf, size_t len) {
    if (len % btrfs_bs != 0) return -1;
    uint64_t phys, run;
    if (btrfs_chunk_lookup_ex(logical, &phys, &run) < 0) return -1;
    if (run < len) return -1;
    return btrfs_read_phys(phys, buf, len);
}

static int btrfs_add_chunk(uint64_t logical, uint64_t size, uint64_t phys) {
    if (btrfs_nchunks >= BTRFS_MAX_CHUNKS) return -1;
    if (size == 0 || logical + size < logical || phys + size < phys)
        return -1;
    btrfs_chunks[btrfs_nchunks].logical = logical;
    btrfs_chunks[btrfs_nchunks].size    = size;
    btrfs_chunks[btrfs_nchunks].phys    = phys;
    btrfs_nchunks++;
    return 0;
}

static int btrfs_add_chunk_from_item(const void *item, uint32_t item_size,
                                     uint64_t logical) {
    const uint8_t *p = item;
    if (item_size < BTRFS_CHUNK_HDR) return -1;
    uint64_t size = rd64(p + 0);
    uint64_t type = rd64(p + 24);
    uint16_t num_stripes = rd16(p + 44);
    if ((uint64_t)num_stripes * BTRFS_STRIPE_SIZE >
        item_size - BTRFS_CHUNK_HDR)
        return -1;

    if (type & (BTRFS_BG_RAID0 | BTRFS_BG_RAID10)) {
        con_puts("btrfs: striped profile refused\n");
        return -1;
    }

    for (uint16_t i = 0; i < num_stripes; i++) {
        const uint8_t *s = p + BTRFS_CHUNK_HDR + (size_t)i * BTRFS_STRIPE_SIZE;
        if (rd64(s + 0) == btrfs_devid) {
            return btrfs_add_chunk(logical, size, rd64(s + 8));
        }
    }
    con_puts("btrfs: chunk has no stripe on this device\n");
    return -1;
}

static int btrfs_parse_sys_chunk_array(void) {
    uint32_t size = rd32(btrfs_sb + 0xA0);
    if (size > 2048) return -1;

    const uint8_t *p   = btrfs_sb + 0x32B;
    const uint8_t *end = p + size;

    while (p < end) {
        if ((size_t)(end - p) < 17) return -1;
        struct btrfs_key k;
        btrfs_key_get(&k, p);
        p += 17;

        if ((size_t)(end - p) < BTRFS_CHUNK_HDR) return -1;
        uint16_t ns = rd16(p + 44);
        size_t   is = BTRFS_CHUNK_HDR + (size_t)BTRFS_STRIPE_SIZE * ns;
        if ((size_t)(end - p) < is) return -1;

        if (k.type != BTRFS_KEY_CHUNK_ITEM) return -1;
        if (btrfs_add_chunk_from_item(p, (uint32_t)is, k.offset) < 0)
            return -1;

        p += is;
    }
    return 0;
}

static int btrfs_read_tree_block(uint64_t logical, uint32_t level,
                                 uint32_t *nritems_out) {
    if (level >= BTRFS_MAX_DEPTH) return -1;
    if (btrfs_read_logical(logical, btrfs_block, btrfs_nodesize) < 0)
        return -1;
    if (btrfs_block[0x64] != level) return -1;
    uint32_t nritems = rd32(btrfs_block + 0x60);
    uint32_t per = level ? BTRFS_KEY_PTR_SIZE : BTRFS_ITEM_SIZE;
    if (nritems > (btrfs_nodesize - BTRFS_LEAF_HDR) / per) return -1;
    *nritems_out = nritems;
    return 0;
}

static int btrfs_item_data(uint32_t i, const void **data, uint32_t *size) {
    const uint8_t *it = btrfs_block + BTRFS_LEAF_HDR
                      + (size_t)i * BTRFS_ITEM_SIZE;
    uint32_t doff = rd32(it + 17);
    uint32_t dsz  = rd32(it + 21);
    if ((uint64_t)doff + dsz > btrfs_nodesize - BTRFS_LEAF_HDR) return -1;
    *data = btrfs_block + BTRFS_LEAF_HDR + doff;
    *size = dsz;
    return 0;
}

typedef int (*btrfs_walk_cb)(const struct btrfs_key *k, const void *data,
                             uint32_t size, void *user);

struct btrfs_walk_ctx {
    const struct btrfs_key *lo;
    const struct btrfs_key *hi;
    btrfs_walk_cb cb;
    void  *user;
    int    stop;
    int    ret;
};

static int btrfs_walk_recursive(uint64_t bytenr, uint32_t level,
                                struct btrfs_walk_ctx *ctx)
{
    if (ctx->stop) return 0;
    uint32_t nritems;
    if (btrfs_read_tree_block(bytenr, level, &nritems) < 0) return -1;

    const uint8_t *base = btrfs_block + BTRFS_LEAF_HDR;

    if (level == 0) {
        for (uint32_t i = 0; i < nritems; i++) {
            struct btrfs_key k;
            btrfs_key_get(&k, base + (size_t)i * BTRFS_ITEM_SIZE);
            if (btrfs_key_cmp(&k, ctx->lo) < 0) continue;
            if (btrfs_key_cmp(&k, ctx->hi) > 0) return 0;
            const void *data;
            uint32_t dsz;
            if (btrfs_item_data(i, &data, &dsz) < 0) return -1;
            int r = ctx->cb(&k, data, dsz, ctx->user);
            if (r != 0) { ctx->stop = 1; ctx->ret = r; return 0; }
        }
        return 0;
    }

    struct { uint64_t bytenr; uint32_t level; } children[BTRFS_MAX_CHILDREN];
    int nch = 0;

    for (uint32_t i = 0; i < nritems; i++) {
        struct btrfs_key k, nk;
        btrfs_key_get(&k, base + (size_t)i * BTRFS_KEY_PTR_SIZE);
        if (i + 1 < nritems) {
            btrfs_key_get(&nk, base + (size_t)(i + 1) * BTRFS_KEY_PTR_SIZE);
            if (btrfs_key_cmp(&nk, ctx->lo) <= 0) continue;
        }
        if (btrfs_key_cmp(&k, ctx->hi) > 0) break;
        if (nch >= BTRFS_MAX_CHILDREN) return -1;
        children[nch].bytenr = rd64(base + (size_t)i * BTRFS_KEY_PTR_SIZE + 17);
        children[nch].level  = level - 1;
        nch++;
    }

    for (int i = 0; i < nch; i++) {
        if (btrfs_walk_recursive(children[i].bytenr, children[i].level, ctx) < 0)
            return -1;
        if (ctx->stop) return 0;
    }
    return 0;
}

static int btrfs_walk(uint64_t root, uint32_t level,
                      const struct btrfs_key *lo,
                      const struct btrfs_key *hi,
                      btrfs_walk_cb cb, void *user)
{
    struct btrfs_walk_ctx ctx = {
        .lo = lo, .hi = hi, .cb = cb, .user = user, .stop = 0, .ret = 0,
    };
    int r = btrfs_walk_recursive(root, level, &ctx);
    if (r < 0) return -1;
    if (ctx.stop) return ctx.ret;
    return 0;
}

static int btrfs_tree_lookup(uint64_t root, uint32_t root_level,
                             const struct btrfs_key *target, int le,
                             struct btrfs_key *out_key,
                             const void **out_data, uint32_t *out_size)
{
    uint64_t cur = root;
    uint32_t lvl = root_level;

    for (int iter = 0; iter < BTRFS_MAX_DEPTH; iter++) {
        uint32_t nritems;
        if (btrfs_read_tree_block(cur, lvl, &nritems) < 0) return -1;

        const uint8_t *base = btrfs_block + BTRFS_LEAF_HDR;

        if (lvl == 0) {
            int best = -1;
            for (uint32_t i = 0; i < nritems; i++) {
                struct btrfs_key k;
                btrfs_key_get(&k, base + (size_t)i * BTRFS_ITEM_SIZE);
                int c = btrfs_key_cmp(&k, target);
                if (c == 0) {
                    *out_key = k;
                    return btrfs_item_data(i, out_data, out_size);
                }
                if (le && c < 0) best = (int)i;
                if (c > 0) break;
            }
            if (le && best >= 0) {
                btrfs_key_get(out_key, base + (size_t)best * BTRFS_ITEM_SIZE);
                return btrfs_item_data((uint32_t)best, out_data, out_size);
            }
            return -1;
        }

        if (nritems == 0) return -1;

        if (le) {
            struct btrfs_key first;
            btrfs_key_get(&first, base);
            if (btrfs_key_cmp(&first, target) > 0) return -1;
        }

        int child_idx = 0;
        for (uint32_t i = 0; i < nritems; i++) {
            struct btrfs_key k;
            btrfs_key_get(&k, base + (size_t)i * BTRFS_KEY_PTR_SIZE);
            if (btrfs_key_cmp(&k, target) <= 0) child_idx = (int)i;
            else break;
        }

        cur = rd64(base + (size_t)child_idx * BTRFS_KEY_PTR_SIZE + 17);
        lvl--;
    }
    return -1;
}

static int btrfs_check_features(void) {
    uint64_t incompat = rd64(btrfs_sb + 0xBC);
    if (incompat & ~BTRFS_INCOMPAT_ALLOWED) {
        con_puts("btrfs: unsupported incompat features\n");
        return -1;
    }
    return 0;
}

static int btrfs_parse_superblock(void) {
    if (btrfs_read_phys(BTRFS_SUPER_OFFSET, btrfs_sb, BTRFS_SUPER_SIZE) < 0)
        return -1;
    if (__builtin_memcmp(btrfs_sb + 0x40, "_BHRfS_M", 8) != 0) return -1;

    if (btrfs_check_features() < 0) return -1;

    uint32_t nodesize   = rd32(btrfs_sb + 0x94);
    uint32_t sectorsize = rd32(btrfs_sb + 0x90);
    if (sectorsize != BTRFS_SECTORSIZE || nodesize < BTRFS_SECTORSIZE ||
        nodesize > BTRFS_NODESIZE_MAX || (nodesize & (nodesize - 1))) {
        con_puts("btrfs: unexpected nodesize or sectorsize\n");
        return -1;
    }
    btrfs_nodesize = nodesize;

    if (btrfs_sb[0xC6] >= BTRFS_MAX_DEPTH ||
        btrfs_sb[0xC7] >= BTRFS_MAX_DEPTH)
        return -1;

    btrfs_devid = rd64(btrfs_sb + 0xC9);
    return 0;
}

static int btrfs_collect_chunk_cb(const struct btrfs_key *k, const void *data,
                                  uint32_t size, void *user)
{
    (void)user;
    if (k->type != BTRFS_KEY_CHUNK_ITEM) return 0;
    if (btrfs_add_chunk_from_item(data, size, k->offset) < 0) return -1;
    return 0;
}

static int btrfs_build_chunk_map(void) {
    btrfs_nchunks = 0;
    if (btrfs_parse_sys_chunk_array() < 0) return -1;

    uint64_t chunk_root  = rd64(btrfs_sb + 0x58);
    uint8_t  chunk_level = btrfs_sb[0xC7];

    struct btrfs_key lo = { BTRFS_OBJ_FIRST_CHUNK, BTRFS_KEY_CHUNK_ITEM, 0 };
    struct btrfs_key hi = { BTRFS_OBJ_FIRST_CHUNK, BTRFS_KEY_CHUNK_ITEM, ~0ULL };

    if (btrfs_walk(chunk_root, chunk_level, &lo, &hi,
                   btrfs_collect_chunk_cb, NULL) != 0) {
        con_puts("btrfs: failed to walk chunk tree\n");
        return -1;
    }
    return 0;
}

static int btrfs_lookup_subvol(uint64_t subvol_id,
                               uint64_t *out_root, uint32_t *out_level);

static int btrfs_find_default_subvol_id(uint64_t *out_id) {
    uint64_t root_tree  = rd64(btrfs_sb + 0x50);
    uint8_t  root_level = btrfs_sb[0xC6];

    struct btrfs_key target;
    target.objectid = BTRFS_ROOT_TREE_DIR_OBJECTID;
    target.type     = BTRFS_KEY_DIR_ITEM;
    target.offset   = btrfs_name_hash("default", 7);

    struct btrfs_key out_key;
    const void *data;
    uint32_t sz;

    if (btrfs_tree_lookup(root_tree, root_level, &target, 0,
                          &out_key, &data, &sz) < 0)
        return -1;
    if (sz < 30) return -1;

    uint16_t nl = rd16((const uint8_t *)data + 27);
    if (nl != 7 || 30u + nl > sz) return -1;
    if (__builtin_memcmp((const uint8_t *)data + 30, "default", 7) != 0)
        return -1;

    *out_id = rd64((const uint8_t *)data + 0);
    return 0;
}

static int btrfs_find_fs_tree(void) {
    uint64_t root_tree  = rd64(btrfs_sb + 0x50);
    uint8_t  root_level = btrfs_sb[0xC6];

    struct btrfs_key target = { BTRFS_OBJ_FS_TREE, BTRFS_KEY_ROOT_ITEM, 0 };
    struct btrfs_key out_key;
    const void *data;
    uint32_t sz;

    if (btrfs_tree_lookup(root_tree, root_level, &target, 0,
                          &out_key, &data, &sz) < 0) {
        con_puts("btrfs: fs tree ROOT_ITEM not found\n");
        return -1;
    }
    if (sz < 240) return -1;

    btrfs_fs_tree_root  = rd64((const uint8_t *)data + 176);
    btrfs_fs_tree_level = ((const uint8_t *)data)[238];
    if (btrfs_fs_tree_level >= BTRFS_MAX_DEPTH) return -1;
    btrfs_default_root  = btrfs_fs_tree_root;
    btrfs_default_level = btrfs_fs_tree_level;

    uint64_t default_id = 0;
    if (btrfs_find_default_subvol_id(&default_id) == 0 &&
        default_id >= BTRFS_OBJ_FIRST_FREE) {
        uint64_t sub_root;
        uint32_t sub_level;
        if (btrfs_lookup_subvol(default_id, &sub_root, &sub_level) == 0) {
            btrfs_default_root  = sub_root;
            btrfs_default_level = sub_level;
        }
    }

    btrfs_base_root  = btrfs_default_root;
    btrfs_base_level = btrfs_default_level;
    btrfs_fs_root  = btrfs_default_root;
    btrfs_fs_level = btrfs_default_level;
    return 0;
}

static int btrfs_lookup_subvol(uint64_t subvol_id,
                               uint64_t *out_root, uint32_t *out_level)
{
    uint64_t root_tree  = rd64(btrfs_sb + 0x50);
    uint8_t  root_level = btrfs_sb[0xC6];

    struct btrfs_key target = { subvol_id, BTRFS_KEY_ROOT_ITEM, 0 };
    struct btrfs_key out_key;
    const void *data;
    uint32_t sz;

    if (btrfs_tree_lookup(root_tree, root_level, &target, 0,
                          &out_key, &data, &sz) < 0)
        return -1;
    if (sz < 240) return -1;

    *out_root  = rd64((const uint8_t *)data + 176);
    *out_level = ((const uint8_t *)data)[238];
    if (*out_level >= BTRFS_MAX_DEPTH) return -1;
    return 0;
}

static int btrfs_lookup_dir(uint64_t dir_ino, const char *name,
                            size_t name_len, uint64_t *out_ino,
                            uint8_t *out_type)
{
    struct btrfs_key target;
    target.objectid = dir_ino;
    target.type     = BTRFS_KEY_DIR_ITEM;
    target.offset   = btrfs_name_hash(name, name_len);

    struct btrfs_key out_key;
    const void *data;
    uint32_t sz;

    if (btrfs_tree_lookup(btrfs_fs_root, btrfs_fs_level, &target, 0,
                          &out_key, &data, &sz) < 0)
        return -1;
    const uint8_t *d = data;
    uint32_t off = 0;
    while (sz - off >= 30) {
        uint16_t dlen  = rd16(d + off + 25);
        uint16_t dnlen = rd16(d + off + 27);
        if ((uint64_t)off + 30 + dnlen + dlen > sz) return -1;
        if (dnlen == name_len &&
            __builtin_memcmp(d + off + 30, name, name_len) == 0) {
            *out_ino = rd64(d + off);
            if (out_type) *out_type = d[off + 8];
            return 0;
        }
        off += 30u + dnlen + dlen;
    }
    return -1;
}

static int btrfs_resolve(const char *path, uint64_t *out_ino) {
    btrfs_fs_root  = btrfs_default_root;
    btrfs_fs_level = btrfs_default_level;

    uint64_t cur = BTRFS_OBJ_FIRST_FREE;

    const char *p = path;
    while (*p == '/') p++;

    while (*p) {
        const char *start = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - start);
        while (*p == '/') p++;

        if (len == 0) continue;
        if (len > BTRFS_NAME_MAX) return -1;

        uint64_t next;
        uint8_t  loc_type;
        if (btrfs_lookup_dir(cur, start, len, &next, &loc_type) < 0)
            return -1;

        if (loc_type == BTRFS_KEY_ROOT_ITEM) {
            uint64_t sub_root;
            uint32_t sub_level;
            if (btrfs_lookup_subvol(next, &sub_root, &sub_level) < 0)
                return -1;
            btrfs_fs_root  = sub_root;
            btrfs_fs_level = sub_level;
            cur = BTRFS_OBJ_FIRST_FREE;
        } else {
            cur = next;
        }
    }

    *out_ino = cur;
    return 0;
}

static int btrfs_resolve_subvol(const char *path,
                                uint64_t *out_root, uint32_t *out_level)
{
    btrfs_fs_root  = btrfs_fs_tree_root;
    btrfs_fs_level = btrfs_fs_tree_level;

    uint64_t cur = BTRFS_OBJ_FIRST_FREE;

    const char *p = path;
    while (*p == '/') p++;

    while (*p) {
        const char *start = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - start);
        while (*p == '/') p++;

        if (len == 0) continue;
        if (len > BTRFS_NAME_MAX) return -1;

        uint64_t next;
        uint8_t  loc_type;
        if (btrfs_lookup_dir(cur, start, len, &next, &loc_type) < 0)
            return -1;

        int is_last = (*p == '\0');

        if (loc_type == BTRFS_KEY_ROOT_ITEM) {
            uint64_t sub_root;
            uint32_t sub_level;
            if (btrfs_lookup_subvol(next, &sub_root, &sub_level) < 0)
                return -1;
            btrfs_fs_root  = sub_root;
            btrfs_fs_level = sub_level;
            cur = BTRFS_OBJ_FIRST_FREE;

            if (is_last) {
                *out_root  = sub_root;
                *out_level = sub_level;
                return 0;
            }
        } else {
            cur = next;
        }
    }

    return -1;
}

int btrfs_set_subvol(const char *path) {
    if (!path || !path[0]) {
        btrfs_default_root  = btrfs_base_root;
        btrfs_default_level = btrfs_base_level;
        return 0;
    }

    uint64_t sub_root;
    uint32_t sub_level;
    if (btrfs_resolve_subvol(path, &sub_root, &sub_level) < 0)
        return -1;

    btrfs_default_root  = sub_root;
    btrfs_default_level = sub_level;
    return 0;
}

static int btrfs_read_inode(uint64_t ino, uint64_t *size, uint32_t *mode) {
    struct btrfs_key target = { ino, BTRFS_KEY_INODE_ITEM, 0 };
    struct btrfs_key out_key;
    const void *data;
    uint32_t sz;

    if (btrfs_tree_lookup(btrfs_fs_root, btrfs_fs_level, &target, 0,
                          &out_key, &data, &sz) < 0)
        return -1;
    if (sz < 160) return -1;

    if (size) *size = rd64((const uint8_t *)data + 16);
    if (mode) *mode = rd32((const uint8_t *)data + 52);
    return 0;
}

static int btrfs_read_file(uint64_t ino, uint8_t *buf, size_t *len) {
    uint64_t size;
    if (btrfs_read_inode(ino, &size, NULL) < 0) return -1;
    if (size > *len) return -1;

    size_t got = 0;
    while (got < size) {
        struct btrfs_key target = { ino, BTRFS_KEY_EXTENT_DATA, got };
        struct btrfs_key out_key;
        const void *data;
        uint32_t sz;

        if (btrfs_tree_lookup(btrfs_fs_root, btrfs_fs_level, &target, 1,
                              &out_key, &data, &sz) < 0)
            return -1;
        if (out_key.objectid != ino) return -1;
        if (out_key.type != BTRFS_KEY_EXTENT_DATA) return -1;
        if (sz < 21) return -1;

        uint64_t file_off = out_key.offset;
        if (file_off > got) return -1;
        uint64_t skip = got - file_off;

        uint8_t type = ((const uint8_t *)data)[20];

        if (rd32((const uint8_t *)data + 16) != 0) return -1;

        if (type == BTRFS_FILE_EXTENT_INLINE) {
            uint64_t ram_bytes = rd64((const uint8_t *)data + 8);
            if (ram_bytes > sz - 21) return -1;
            if (skip >= ram_bytes) return -1;
            uint64_t avail = ram_bytes - skip;
            if (avail > size - got) avail = size - got;
            if (avail == 0) return -1;
            __builtin_memcpy(buf + got,
                             (const uint8_t *)data + 21 + skip, (size_t)avail);
            got += (size_t)avail;
        } else if (type == BTRFS_FILE_EXTENT_REG ||
                   type == BTRFS_FILE_EXTENT_PREALLOC) {
            if (sz < 53) return -1;
            uint64_t disk_bytenr = rd64((const uint8_t *)data + 21);
            uint64_t ext_offset  = rd64((const uint8_t *)data + 37);
            uint64_t num_bytes   = rd64((const uint8_t *)data + 45);

            if (skip >= num_bytes) return -1;
            uint64_t take64 = num_bytes - skip;
            if (take64 > size - got) take64 = size - got;
            size_t take = (size_t)take64;
            if (take == 0) return -1;

            uint64_t src_logical = disk_bytenr + ext_offset + skip;
            size_t   done = 0;

            while (done < take) {
                uint64_t cur_phys, chunk_remaining;
                if (btrfs_chunk_lookup_ex(src_logical + done, &cur_phys,
                                          &chunk_remaining) < 0)
                    return -1;

                uint64_t sector_phys = cur_phys &
                    ~(uint64_t)(BTRFS_SECTORSIZE - 1);
                size_t offset_in_sector =
                    (size_t)(cur_phys - sector_phys);

                if (offset_in_sector != 0 ||
                    take - done < BTRFS_SECTORSIZE) {
                    uint8_t tmp[BTRFS_SECTORSIZE];
                    if (btrfs_read_phys(sector_phys, tmp,
                                        BTRFS_SECTORSIZE) < 0)
                        return -1;
                    size_t avail = BTRFS_SECTORSIZE - offset_in_sector;
                    if (avail > take - done) avail = take - done;
                    __builtin_memcpy(buf + got + done,
                                     tmp + offset_in_sector, avail);
                    done += avail;
                    continue;
                }

                size_t run = take - done;
                if (run > chunk_remaining)        run = (size_t)chunk_remaining;
                if (run > BTRFS_MAX_READ_RUN * BTRFS_SECTORSIZE)
                    run = BTRFS_MAX_READ_RUN * BTRFS_SECTORSIZE;
                run &= ~(size_t)(BTRFS_SECTORSIZE - 1);
                if (run == 0) return -1;

                if (btrfs_read_phys(sector_phys, buf + got + done, run) < 0)
                    return -1;
                done += run;
            }
            got += take;
        } else {
            con_puts("btrfs: unsupported file extent type\n");
            return -1;
        }
    }

    *len = size;
    return 0;
}

static int btrfs_readdir_cb(const struct btrfs_key *k, const void *data,
                            uint32_t size, void *user)
{
    (void)k;
    struct btrfs_dir_handle *dh = user;

    if (dh->count >= BTRFS_DIR_MAX) return -1;
    if (size < 30) return 0;

    uint16_t nl = rd16((const uint8_t *)data + 27);
    if (nl > BTRFS_NAME_MAX) return 0;
    if (30u + nl > size) return 0;

    struct btrfs_dirent *e = &dh->entries[dh->count];
    __builtin_memcpy(e->name, (const uint8_t *)data + 30, nl);
    e->name[nl] = '\0';
    e->type = ((const uint8_t *)data)[29];
    dh->count++;
    return 0;
}

static int btrfs_probe(block_device_t *dev) {
    uint8_t buf[BTRFS_SECTORSIZE];
    if (dev->block_size != 512 && dev->block_size != 4096) return -1;

    block_device_t *saved_dev = btrfs_dev;
    uint32_t saved_bs = btrfs_bs;
    btrfs_dev = dev;
    btrfs_bs  = dev->block_size;
    int rc = btrfs_read_phys(BTRFS_SUPER_OFFSET, buf, sizeof(buf));
    btrfs_dev = saved_dev;
    btrfs_bs  = saved_bs;
    if (rc < 0) return -1;
    if (__builtin_memcmp(buf + 0x40, "_BHRfS_M", 8) != 0) return -1;
    return 0;
}

static int btrfs_mount(block_device_t *dev) {
    btrfs_crc32c_init();
    if (dev->block_size != 512 && dev->block_size != 4096) return -1;
    btrfs_dev = dev;
    btrfs_bs  = dev->block_size;

    if (btrfs_parse_superblock() < 0) return -1;
    if (btrfs_build_chunk_map()  < 0) return -1;
    if (btrfs_find_fs_tree()     < 0) return -1;
    return 0;
}

static void btrfs_umount(void) {
    btrfs_nchunks = 0;
    btrfs_dev = 0;
}

static int btrfs_read(const char *path, uint8_t *buf, size_t *len) {
    uint64_t ino;
    if (btrfs_resolve(path, &ino) < 0) return -1;

    uint64_t size;
    uint32_t mode;
    if (btrfs_read_inode(ino, &size, &mode) < 0) return -1;
    if ((mode & BTRFS_S_IFMT) != BTRFS_S_IFREG) return -1;
    if (size > *len) return -1;

    size_t want = (size_t)size;
    if (btrfs_read_file(ino, buf, &want) < 0) return -1;
    *len = want;
    return 0;
}

static int btrfs_readlink(const char *path, char *buf, size_t len) {
    uint64_t ino;
    if (btrfs_resolve(path, &ino) < 0) return -1;

    uint32_t mode;
    if (btrfs_read_inode(ino, NULL, &mode) < 0) return -1;
    if ((mode & BTRFS_S_IFMT) != BTRFS_S_IFLNK) return -1;

    struct btrfs_key target = { ino, BTRFS_KEY_EXTENT_DATA, 0 };
    struct btrfs_key out_key;
    const void *data;
    uint32_t sz;

    if (btrfs_tree_lookup(btrfs_fs_root, btrfs_fs_level, &target, 0,
                          &out_key, &data, &sz) < 0)
        return -1;
    if (sz < 21) return -1;
    if (((const uint8_t *)data)[20] != BTRFS_FILE_EXTENT_INLINE) return -1;
    if (rd32((const uint8_t *)data + 16) != 0) return -1;

    uint64_t ram_bytes = rd64((const uint8_t *)data + 8);
    if (ram_bytes > sz - 21) return -1;
    if (ram_bytes >= len) return -1;

    __builtin_memcpy(buf, (const uint8_t *)data + 21, (size_t)ram_bytes);
    buf[ram_bytes] = '\0';
    return 0;
}

static int btrfs_stat(const char *path, struct stat *st) {
    uint64_t ino;
    if (btrfs_resolve(path, &ino) < 0) return -1;
    uint64_t size;
    uint32_t mode;
    if (btrfs_read_inode(ino, &size, &mode) < 0) return -1;
    st->size = size;
    st->mode = mode;
    return 0;
}

static int btrfs_opendir(const char *path, void **handle) {
    uint64_t ino;
    if (btrfs_resolve(path, &ino) < 0) return -1;

    uint64_t size;
    uint32_t mode;
    if (btrfs_read_inode(ino, &size, &mode) < 0) return -1;
    if ((mode & BTRFS_S_IFMT) != BTRFS_S_IFDIR) return -1;

    btrfs_dir.count = 0;
    btrfs_dir.cursor = 0;

    /* Synthesize "." and "..". */
    btrfs_dir.entries[0].name[0] = '.';  btrfs_dir.entries[0].name[1] = '\0';
    btrfs_dir.entries[0].type = 2;
    btrfs_dir.entries[1].name[0] = '.';  btrfs_dir.entries[1].name[1] = '.';
    btrfs_dir.entries[1].name[2] = '\0';
    btrfs_dir.entries[1].type = 2;
    btrfs_dir.count = 2;

    struct btrfs_key lo = { ino, BTRFS_KEY_DIR_INDEX, 0 };
    struct btrfs_key hi = { ino, BTRFS_KEY_DIR_INDEX, ~0ULL };

    if (btrfs_walk(btrfs_fs_root, btrfs_fs_level, &lo, &hi,
                   btrfs_readdir_cb, &btrfs_dir) < 0)
        return -1;

    *handle = &btrfs_dir;
    return 0;
}

static int btrfs_readdir(void *handle, char *name, size_t name_len) {
    struct btrfs_dir_handle *dh = handle;
    if (!dh) return 0;
    if (dh->cursor >= dh->count) return 0;

    const char *n = dh->entries[dh->cursor].name;
    size_t nl = 0;
    while (n[nl]) nl++;
    if (nl + 1 > name_len) return 0;
    __builtin_memcpy(name, n, nl + 1);
    dh->cursor++;
    return 1;
}

static void btrfs_closedir(void *handle) {
    (void)handle;
    btrfs_dir.count = 0;
    btrfs_dir.cursor = 0;
}

static int btrfs_write(const char *path, const uint8_t *data, size_t size) {
    (void)path; (void)data; (void)size;
    return -1;
}

fs_driver_t fs_btrfs = {
    .probe      = btrfs_probe,
    .mount      = btrfs_mount,
    .read       = btrfs_read,
    .readlink   = btrfs_readlink,
    .stat       = btrfs_stat,
    .umount     = btrfs_umount,
    .opendir    = btrfs_opendir,
    .readdir    = btrfs_readdir,
    .write      = btrfs_write,
    .closedir   = btrfs_closedir,
    .set_subvol = btrfs_set_subvol,
};