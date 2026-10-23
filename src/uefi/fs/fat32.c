/* FAT32 driver with VFAT long name support. Writes (8.3 names only)
 * are used to store /EFI/ivo/sealed.bin on the ESP. */

#include "../core.h"
#include "../hal/hal.h"
#include "fs.h"

#define SECTOR_SIZE           512
#define FAT32_EOC             0x0FFFFFF8
#define FAT32_MASK            0x0FFFFFFF
#define FAT32_MAX_CLUSTERS    0x0FFFFFF5u
#define ATTR_LONG_NAME        0x0F
#define ATTR_DIRECTORY        0x10
#define ATTR_VOLUME_ID        0x08

#pragma pack(push, 1)
typedef struct {
    uint8_t  jmp[3];
    char     oem[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t  num_fats;
    uint16_t root_entries;
    uint16_t total_sectors_16;
    uint8_t  media;
    uint16_t sectors_per_fat_16;
    uint16_t sectors_per_track;
    uint16_t heads;
    uint32_t hidden_sectors;
    uint32_t total_sectors_32;
    uint32_t sectors_per_fat_32;
    uint16_t flags;
    uint16_t version;
    uint32_t root_cluster;
    uint16_t fsinfo_sector;
    uint16_t backup_boot_sector;
    uint8_t  reserved[12];
    uint8_t  drive_number;
    uint8_t  reserved1;
    uint8_t  boot_signature;
    uint32_t volume_id;
    char     volume_label[11];
    char     fs_type[8];
} fat32_bpb_t;

typedef struct {
    char     name[11];
    uint8_t  attr;
    uint8_t  nt_reserved;
    uint8_t  creation_time_tenth;
    uint16_t creation_time;
    uint16_t creation_date;
    uint16_t last_access_date;
    uint16_t first_cluster_high;
    uint16_t write_time;
    uint16_t write_date;
    uint16_t first_cluster_low;
    uint32_t file_size;
} fat32_dir_entry_t;
#pragma pack(pop)

typedef struct {
    uint32_t        *fat;
    uint32_t         fat_entries;
    uint32_t         fat_load_sectors;
    uint32_t         fat_sector;
    uint32_t         sectors_per_fat;
    uint32_t         num_fats;
    uint32_t         total_sectors;
    uint32_t         cluster_size;
    uint32_t         sectors_per_cluster;
    uint32_t         root_cluster;
    uint32_t         data_start_sector;
    block_device_t  *dev;
    const uint8_t   *memory;
    size_t           memory_size;
} fat32_fs_t;

static fat32_fs_t fs;
static uint8_t fat32_sector_buf[SECTOR_SIZE];

extern int luks_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);
extern int luks_active(void);
#ifdef LVM
extern int lvm_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);
extern int lvm_active(void);
#endif

static int read_sectors(uint32_t sector, uint32_t count, void *buf)
{
    if (fs.memory) {
        uint64_t offset = (uint64_t)sector * SECTOR_SIZE;
        uint64_t bytes  = (uint64_t)count * SECTOR_SIZE;
        if (offset + bytes > fs.memory_size) return -1;
        memcpy(buf, fs.memory + offset, (size_t)bytes);
        return 0;
    }

    uint8_t *dst = (uint8_t *)buf;
    while (count > 0) {
        uint32_t chunk = count > 2032 ? 2032 : count;
        int r;
#ifdef LVM
        if (lvm_active()) {
            r = lvm_read_blocks(sector, chunk, dst);
        } else
#endif
        if (luks_active()) {
            r = luks_read_blocks(sector, chunk, dst);
        } else {
            r = hal_read_blocks(fs.dev->lba_start + sector, chunk, dst);
        }
        if (r != 0) return -1;
        sector += chunk;
        dst += chunk * SECTOR_SIZE;
        count -= chunk;
    }
    return 0;
}

static int write_sectors(uint32_t sector, uint32_t count, const void *buf)
{
    if (fs.memory || !fs.dev) return -1;
#ifdef LVM
    if (lvm_active()) return -1;
#endif
    if (luks_active()) return -1;
    if ((uint64_t)sector + count > fs.total_sectors) return -1;

    const uint8_t *src = (const uint8_t *)buf;
    while (count > 0) {
        uint32_t chunk = count > 127 ? 127 : count;
        if (hal_write_blocks(fs.dev->lba_start + sector, chunk, src) != 0)
            return -1;
        sector += chunk;
        src += chunk * SECTOR_SIZE;
        count -= chunk;
    }
    return 0;
}

static int fat_valid(uint32_t cluster)
{
    return cluster >= 2 && cluster < fs.fat_entries;
}

static uint32_t cluster_sector(uint32_t cluster)
{
    return fs.data_start_sector + (cluster - 2) * fs.sectors_per_cluster;
}

static int read_cluster(uint32_t cluster, void *buf)
{
    if (!fat_valid(cluster)) return -1;
    return read_sectors(cluster_sector(cluster), fs.sectors_per_cluster, buf);
}

static uint32_t next_cluster(uint32_t cluster)
{
    if (!fat_valid(cluster)) return 0;
    uint32_t next = fs.fat[cluster] & FAT32_MASK;
    return fat_valid(next) ? next : 0;
}

static void set_fat(uint32_t cluster, uint32_t value)
{
    fs.fat[cluster] = (fs.fat[cluster] & ~(uint32_t)FAT32_MASK)
                    | (value & FAT32_MASK);
}

static int fat32_setup(const fat32_bpb_t *bpb, uint64_t vol_sectors)
{
    uint32_t spc = bpb->sectors_per_cluster;
    uint32_t spf = bpb->sectors_per_fat_32;

    if (bpb->bytes_per_sector != SECTOR_SIZE) return -1;
    if (bpb->boot_signature != 0x29 && bpb->boot_signature != 0x28) return -1;
    if (spc == 0 || (spc & (spc - 1))) return -1;
    if (bpb->reserved_sectors == 0 || bpb->num_fats == 0) return -1;
    if (spf == 0 || bpb->root_entries != 0) return -1;

    uint64_t total = bpb->total_sectors_16 ? bpb->total_sectors_16
                                           : bpb->total_sectors_32;
    if (total == 0) return -1;
    if (vol_sectors && total > vol_sectors) return -1;

    uint64_t data_start = (uint64_t)bpb->reserved_sectors
                        + (uint64_t)bpb->num_fats * spf;
    if (data_start >= total) return -1;

    uint64_t clusters = (total - data_start) / spc;
    if (clusters == 0) return -1;
    if (clusters > FAT32_MAX_CLUSTERS) clusters = FAT32_MAX_CLUSTERS;

    uint64_t entries = clusters + 2;
    if (entries > (uint64_t)spf * (SECTOR_SIZE / 4))
        entries = (uint64_t)spf * (SECTOR_SIZE / 4);
    if (bpb->root_cluster < 2 || bpb->root_cluster >= entries) return -1;

    fs.sectors_per_fat     = spf;
    fs.num_fats            = bpb->num_fats;
    fs.fat_sector          = bpb->reserved_sectors;
    fs.total_sectors       = (uint32_t)total;
    fs.sectors_per_cluster = spc;
    fs.cluster_size        = spc * SECTOR_SIZE;
    fs.root_cluster        = bpb->root_cluster;
    fs.data_start_sector   = (uint32_t)data_start;
    fs.fat_entries         = (uint32_t)entries;
    fs.fat_load_sectors    = (uint32_t)((entries * 4 + SECTOR_SIZE - 1)
                                        / SECTOR_SIZE);
    return 0;
}

static int load_fat(void)
{
    if (fs.fat) { mm_free(fs.fat); fs.fat = 0; }
    fs.fat = mm_alloc((size_t)fs.fat_load_sectors * SECTOR_SIZE);
    if (!fs.fat) return -1;
    uint32_t done = 0;
    while (done < fs.fat_load_sectors) {
        uint32_t chunk = fs.fat_load_sectors - done;
        if (chunk > 127) chunk = 127;
        if (read_sectors(fs.fat_sector + done, chunk,
                         (uint8_t *)fs.fat + (size_t)done * SECTOR_SIZE) != 0) {
            mm_free(fs.fat);
            fs.fat = 0;
            return -1;
        }
        done += chunk;
    }
    return 0;
}

static int parse_entry_name(fat32_dir_entry_t *entries, uint32_t entry_idx,
                            char *name_out, size_t name_size)
{
    char long_name_buf[256] = {0};
    int lfn_count = 0;
    uint32_t i = entry_idx;

    while (i > 0) {
        i--;
        uint8_t first_byte = (uint8_t)entries[i].name[0];
        if (first_byte == 0x00 || first_byte == 0xE5) break;

        if ((entries[i].attr & ATTR_LONG_NAME) != ATTR_LONG_NAME) break;

        uint8_t seq = first_byte & 0x3F;
        if (seq == 0 || seq > 20) break;
        if (seq > lfn_count) lfn_count = seq;

        const uint8_t *src = (const uint8_t *)entries[i].name;
        uint8_t lo[13];
        int idx = 0;
        for (int j = 1; j < 10; j += 2) lo[idx++] = src[j];
        for (int j = 14; j < 26; j += 2) lo[idx++] = src[j];
        for (int j = 28; j < 32; j += 2) lo[idx++] = src[j];

        int offset = (seq - 1) * 13;
        for (int k = 0; k < 13 && offset + k < 255; k++)
            long_name_buf[offset + k] = (char)lo[k];
    }

    if (lfn_count > 0) {
        int end = lfn_count * 13;
        if (end > 255) end = 255;
        long_name_buf[end] = '\0';
        size_t len = strlen(long_name_buf);
        if (len >= name_size) len = name_size - 1;
        memcpy(name_out, long_name_buf, len);
        name_out[len] = '\0';
        return 0;
    }

    char short_name[13];
    int j = 0;
    for (int k = 0; k < 8 && entries[entry_idx].name[k] != ' '; k++)
        short_name[j++] = entries[entry_idx].name[k];
    if (entries[entry_idx].name[8] != ' ') {
        short_name[j++] = '.';
        for (int k = 8; k < 11 && entries[entry_idx].name[k] != ' '; k++)
            short_name[j++] = entries[entry_idx].name[k];
    }
    short_name[j] = '\0';
    strncpy(name_out, short_name, name_size);
    name_out[name_size - 1] = '\0';
    return 0;
}

static int fat32_streq(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'a' && ca <= 'z') ca -= 32;
        if (cb >= 'a' && cb <= 'z') cb -= 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

static int find_entry(uint32_t dir_cluster, const char *name,
                      uint32_t *out_cluster, uint32_t *out_size, uint8_t *out_attr,
                      uint32_t *loc_cluster, uint32_t *loc_index)
{
    uint8_t *cluster_buf = mm_alloc(fs.cluster_size);
    if (!cluster_buf) return -1;
    uint32_t cluster = dir_cluster;
    uint32_t chain_walked = 0;

    while (fat_valid(cluster) && chain_walked++ < fs.fat_entries) {
        if (read_cluster(cluster, cluster_buf) != 0) break;

        fat32_dir_entry_t *entries = (fat32_dir_entry_t *)cluster_buf;
        uint32_t entries_per_cluster = fs.cluster_size / sizeof(fat32_dir_entry_t);

        for (uint32_t i = 0; i < entries_per_cluster; i++) {
            uint8_t first_byte = (uint8_t)entries[i].name[0];
            if (first_byte == 0x00) {
                mm_free(cluster_buf);
                return -1;
            }
            if (first_byte == 0xE5) continue;

            if ((entries[i].attr & ATTR_LONG_NAME) == ATTR_LONG_NAME) continue;
            if (entries[i].attr & ATTR_VOLUME_ID) continue;

            char entry_name[256];
            if (parse_entry_name(entries, i, entry_name, sizeof(entry_name)) != 0)
                continue;
            if (fat32_streq(entry_name, name)) {
                if (out_cluster) {
                    *out_cluster = ((uint32_t)entries[i].first_cluster_high << 16) |
                                   entries[i].first_cluster_low;
                }
                if (out_size) *out_size = entries[i].file_size;
                if (out_attr) *out_attr = entries[i].attr;
                if (loc_cluster) *loc_cluster = cluster;
                if (loc_index) *loc_index = i;
                mm_free(cluster_buf);
                return 0;
            }
        }
        cluster = next_cluster(cluster);
    }
    mm_free(cluster_buf);
    return -1;
}

int fat32_probe(block_device_t *dev)
{
    union {
        fat32_bpb_t bpb;
        uint8_t raw[512];
    } buf;
    block_device_t *prev = fs.dev;
    const uint8_t *prev_mem = fs.memory;
    fs.dev = dev;
    fs.memory = NULL;

    int ok = 0;
    if (read_sectors(0, 1, &buf) == 0) {
        if (buf.bpb.bytes_per_sector == SECTOR_SIZE &&
            (buf.bpb.boot_signature == 0x29 ||
             buf.bpb.boot_signature == 0x28) &&
            buf.bpb.sectors_per_fat_32 != 0) {
            ok = 1;
        }
    }

    fs.dev = prev;
    fs.memory = prev_mem;
    return ok ? 0 : -1;
}

int fat32_mount(block_device_t *dev)
{
    union {
        fat32_bpb_t bpb;
        uint8_t raw[512];
    } buf;
    if (fs.fat) { mm_free(fs.fat); fs.fat = 0; }
    fs.fat_entries = 0;
    fs.dev = dev;
    fs.memory = NULL;
    fs.memory_size = 0;
    if (read_sectors(0, 1, &buf) != 0) return -1;
    if (fat32_setup(&buf.bpb, dev->lba_count) != 0) return -1;
    return load_fat();
}

int fat32_mount_memory(const void *data, size_t size)
{
    if (!data || size < SECTOR_SIZE) return -1;

    if (fs.fat) { mm_free(fs.fat); fs.fat = 0; }
    fs.fat_entries = 0;

    fs.dev         = NULL;
    fs.memory      = (const uint8_t *)data;
    fs.memory_size = size;

    union {
        fat32_bpb_t bpb;
        uint8_t raw[512];
    } buf;
    if (read_sectors(0, 1, &buf) != 0 ||
        fat32_setup(&buf.bpb, (uint64_t)size / SECTOR_SIZE) != 0 ||
        load_fat() != 0) {
        fs.memory = NULL;
        return -1;
    }
    return 0;
}

int fat32_read(const char *path, uint8_t *buf, size_t *len)
{
    if (!path || !buf || !len || !fs.fat) return -1;
    if (path[0] == '/') path++;

    uint32_t dir_cluster = fs.root_cluster;
    char component[256];
    const char *p = path;

    while (*p) {
        const char *slash = p;
        while (*slash && *slash != '/') slash++;
        size_t comp_len = (size_t)(slash - p);
        if (comp_len == 0 || comp_len > 255) return -1;
        memcpy(component, p, comp_len);
        component[comp_len] = '\0';

        uint32_t found_cluster = 0;
        uint8_t found_attr = 0;
        uint32_t found_size = 0;
        if (find_entry(dir_cluster, component, &found_cluster, &found_size,
                       &found_attr, 0, 0) != 0)
            return -1;

        if (*slash == '/') {
            if (!(found_attr & ATTR_DIRECTORY)) return -1;
            dir_cluster = found_cluster;
        } else {
            if (found_attr & ATTR_DIRECTORY) return -1;

            uint32_t cluster = found_cluster;
            size_t remaining = found_size < *len ? found_size : *len;
            *len = remaining;
            uint8_t *dest = buf;

            uint32_t max_clusters = 2032 / fs.sectors_per_cluster;

            while (remaining > 0) {
                if (!fat_valid(cluster)) return -1;
                uint64_t want_clusters =
                    ((uint64_t)remaining + fs.cluster_size - 1) / fs.cluster_size;
                if (want_clusters > max_clusters) want_clusters = max_clusters;
                uint32_t run_clusters = 1;
                uint32_t next = next_cluster(cluster);
                while (run_clusters < want_clusters &&
                       (uint64_t)next == (uint64_t)cluster + run_clusters) {
                    run_clusters++;
                    next = next_cluster(next);
                }

                uint32_t start_sector = cluster_sector(cluster);
                uint64_t run_bytes = (uint64_t)run_clusters * fs.cluster_size;
                if (run_bytes > remaining) run_bytes = remaining;

                uint32_t full = (uint32_t)(run_bytes / SECTOR_SIZE);
                uint32_t tail = (uint32_t)(run_bytes % SECTOR_SIZE);
                if (full && read_sectors(start_sector, full, dest) != 0)
                    return -1;
                if (tail) {
                    if (read_sectors(start_sector + full, 1,
                                     fat32_sector_buf) != 0)
                        return -1;
                    memcpy(dest + (size_t)full * SECTOR_SIZE,
                           fat32_sector_buf, tail);
                }

                dest += run_bytes;
                remaining -= (size_t)run_bytes;
                cluster = next;
            }
            return 0;
        }
        p = slash + (*slash ? 1 : 0);
    }
    return -1;
}

int fat32_stat(const char *path, struct stat *st)
{
    if (!path || !st || !fs.fat) return -1;
    if (path[0] == '/') path++;

    uint32_t dir_cluster = fs.root_cluster;
    char component[256];
    const char *p = path;
    while (*p) {
        const char *slash = p;
        while (*slash && *slash != '/') slash++;
        size_t comp_len = (size_t)(slash - p);
        if (comp_len == 0 || comp_len > 255) return -1;
        memcpy(component, p, comp_len);
        component[comp_len] = '\0';

        uint32_t found_cluster = 0;
        uint8_t found_attr = 0;
        uint32_t found_size = 0;
        if (find_entry(dir_cluster, component, &found_cluster, &found_size,
                       &found_attr, 0, 0) != 0)
            return -1;

        if (*slash == '/') {
            if (!(found_attr & ATTR_DIRECTORY)) return -1;
            dir_cluster = found_cluster;
        } else {
            st->size = found_size;
            st->mode = (found_attr & ATTR_DIRECTORY) ? 040755 : 0100644;
            return 0;
        }
        p = slash + 1;
    }
    return -1;
}

int fat32_readlink(const char *path, char *buf, size_t len)
{
    (void)path; (void)buf; (void)len;
    return -1;
}

void fat32_umount(void)
{
    if (fs.fat) {
        mm_free(fs.fat);
        fs.fat = 0;
    }
    fs.fat_entries = 0;
}

typedef struct {
    uint32_t cluster;
    uint32_t offset;
    uint32_t walked;
} fat32_dir_handle_t;

static int fat32_opendir(const char *path, void **handle)
{
    if (!path || !handle || !fs.fat) return -1;
    if (path[0] == '/' && path[1] == '\0') {
        fat32_dir_handle_t *h = mm_alloc(sizeof(fat32_dir_handle_t));
        if (!h) return -1;
        h->cluster = fs.root_cluster;
        h->offset = 0;
        h->walked = 0;
        *handle = h;
        return 0;
    }
    return -1;
}

static int fat32_readdir(void *handle, char *name, size_t name_len)
{
    if (!handle || !name || name_len == 0) return -1;
    fat32_dir_handle_t *h = (fat32_dir_handle_t *)handle;

    while (1) {
        if (!fat_valid(h->cluster) || h->walked >= fs.fat_entries) return 0;

        uint8_t *buf = mm_alloc(fs.cluster_size);
        if (!buf) return -1;
        if (read_cluster(h->cluster, buf) != 0) {
            mm_free(buf);
            return -1;
        }

        fat32_dir_entry_t *entries = (fat32_dir_entry_t *)buf;
        uint32_t entries_per_cluster = fs.cluster_size / sizeof(fat32_dir_entry_t);

        while (h->offset < entries_per_cluster) {
            uint32_t start_offset = h->offset;

            if (entries[h->offset].name[0] == 0x00) {
                mm_free(buf);
                return 0;
            }

            if ((uint8_t)entries[h->offset].name[0] == 0xE5 ||
                (entries[h->offset].attr & ATTR_VOLUME_ID)) {
                h->offset++;
                continue;
            }

            if ((entries[h->offset].attr & ATTR_LONG_NAME) == ATTR_LONG_NAME) {
                h->offset++;
                continue;
            }

            int result = parse_entry_name(entries, start_offset,
                                          name, name_len);
            h->offset++;
            mm_free(buf);
            return (result == 0) ? 1 : 0;
        }

        mm_free(buf);
        h->cluster = next_cluster(h->cluster);
        h->offset = 0;
        h->walked++;
    }
}

static int write_fat(void)
{
    for (uint32_t k = 0; k < fs.num_fats; k++) {
        uint32_t sector = fs.fat_sector + k * fs.sectors_per_fat;
        if (write_sectors(sector, fs.fat_load_sectors, fs.fat) != 0)
            return -1;
    }
    return 0;
}

static uint32_t alloc_cluster(void)
{
    for (uint32_t i = 2; i < fs.fat_entries; i++) {
        if ((fs.fat[i] & FAT32_MASK) == 0) {
            set_fat(i, FAT32_MASK);
            return i;
        }
    }
    return 0;
}

static void free_chain(uint32_t cluster)
{
    uint32_t walked = 0;
    while (fat_valid(cluster) && walked++ < fs.fat_entries) {
        uint32_t next = fs.fat[cluster] & FAT32_MASK;
        if (next == 0) break;
        set_fat(cluster, 0);
        cluster = next;
    }
}

static int fat32_make_83(const char *name, char out[11])
{
    const char *dot = 0;
    for (const char *s = name; *s; s++) {
        if ((uint8_t)*s <= ' ' || *s == '/' || *s == '\\') return -1;
        if (*s == '.') {
            if (dot) return -1;
            dot = s;
        }
    }
    size_t base = dot ? (size_t)(dot - name) : strlen(name);
    size_t ext  = dot ? strlen(dot + 1) : 0;
    if (base == 0 || base > 8 || ext > 3) return -1;
    if ((uint8_t)name[0] == 0xE5) return -1;

    memset(out, ' ', 11);
    memcpy(out, name, base);
    if (ext) memcpy(out + 8, dot + 1, ext);
    return 0;
}

static int write_dir_entry(uint32_t dir_cluster, const char name83[11],
                           uint32_t loc_cluster, uint32_t loc_index,
                           uint32_t file_cluster, uint32_t file_size)
{
    uint32_t entries_per_cluster = fs.cluster_size / sizeof(fat32_dir_entry_t);
    uint8_t *buf = mm_alloc(fs.cluster_size);
    if (!buf) return -1;
    fat32_dir_entry_t *entries = (fat32_dir_entry_t *)buf;

    int rc = -1;
    uint32_t cluster = dir_cluster;
    uint32_t slot = entries_per_cluster;

    if (fat_valid(loc_cluster)) {
        if (loc_index >= entries_per_cluster) goto out;
        if (read_cluster(loc_cluster, buf) != 0) goto out;
        cluster = loc_cluster;
        slot = loc_index;
    } else {
        int fresh = 0;
        uint32_t walked = 0;
        while (fat_valid(cluster) && walked++ < fs.fat_entries) {
            if (fresh) memset(buf, 0, fs.cluster_size);
            else if (read_cluster(cluster, buf) != 0) goto out;

            for (uint32_t i = 0; i < entries_per_cluster; i++) {
                uint8_t b = (uint8_t)entries[i].name[0];
                if (b == 0x00 || b == 0xE5) { slot = i; break; }
            }
            if (slot < entries_per_cluster) break;

            uint32_t next = next_cluster(cluster);
            if (next == 0) {
                next = alloc_cluster();
                if (!next) goto out;
                set_fat(cluster, next);
                fresh = 1;
            }
            cluster = next;
        }
        if (slot >= entries_per_cluster) goto out;
        memset(&entries[slot], 0, sizeof(entries[slot]));
        memcpy(entries[slot].name, name83, 11);
        entries[slot].attr = 0x20;
    }

    entries[slot].first_cluster_high = (file_cluster >> 16) & 0xFFFF;
    entries[slot].first_cluster_low  = file_cluster & 0xFFFF;
    entries[slot].file_size          = file_size;
    rc = write_sectors(cluster_sector(cluster), fs.sectors_per_cluster, buf);
out:
    mm_free(buf);
    return rc;
}

static int write_file_data(uint32_t first, const uint8_t *data, size_t size)
{
    uint8_t *cluster_buf = mm_alloc(fs.cluster_size);
    if (!cluster_buf) return -1;

    int rc = -1;
    uint32_t cluster = first;
    size_t remaining = size;
    for (;;) {
        size_t to_write = remaining < fs.cluster_size ? remaining : fs.cluster_size;
        memcpy(cluster_buf, data, to_write);
        if (to_write < fs.cluster_size)
            memset(cluster_buf + to_write, 0, fs.cluster_size - to_write);
        if (write_sectors(cluster_sector(cluster), fs.sectors_per_cluster,
                          cluster_buf) != 0)
            goto out;

        data += to_write;
        remaining -= to_write;
        if (remaining == 0) break;

        uint32_t next = alloc_cluster();
        if (!next) goto out;
        set_fat(cluster, next);
        cluster = next;
    }
    rc = 0;
out:
    mm_free(cluster_buf);
    return rc;
}

int fat32_write(const char *path, const uint8_t *data, size_t size)
{
    if (!path || !data || !fs.fat || fs.memory || !fs.dev) return -1;
    uint64_t size64 = size;
    if (size64 > 0xFFFFFFFFu) return -1;
    if (path[0] == '/') path++;

    uint32_t dir_cluster = fs.root_cluster;
    char component[256];
    const char *p = path;

    while (*p) {
        const char *slash = p;
        while (*slash && *slash != '/') slash++;
        size_t comp_len = (size_t)(slash - p);
        if (comp_len == 0 || comp_len > 255) return -1;
        memcpy(component, p, comp_len);
        component[comp_len] = '\0';

        if (*slash == '/') {
            uint32_t found_cluster = 0;
            uint8_t found_attr = 0;
            uint32_t found_size = 0;
            if (find_entry(dir_cluster, component, &found_cluster,
                           &found_size, &found_attr, 0, 0) != 0)
                return -1;
            if (!(found_attr & ATTR_DIRECTORY)) return -1;
            dir_cluster = found_cluster;
        } else {
            char name83[11];
            if (fat32_make_83(component, name83) != 0) return -1;

            uint32_t old_cluster = 0;
            uint32_t old_size = 0;
            uint8_t  old_attr = 0;
            uint32_t loc_cluster = 0, loc_index = 0;

            if (find_entry(dir_cluster, component, &old_cluster,
                           &old_size, &old_attr,
                           &loc_cluster, &loc_index) == 0) {
                if (old_attr & (ATTR_DIRECTORY | ATTR_VOLUME_ID)) return -1;
            }

            uint32_t file_cluster = alloc_cluster();
            if (file_cluster == 0) return -1;

            if (write_file_data(file_cluster, data, size) != 0) {
                free_chain(file_cluster);
                return -1;
            }
            if (write_dir_entry(dir_cluster, name83, loc_cluster, loc_index,
                                file_cluster, (uint32_t)size) != 0) {
                free_chain(file_cluster);
                return -1;
            }
            if (old_cluster) free_chain(old_cluster);
            return write_fat();
        }
        p = slash + (*slash ? 1 : 0);
    }
    return -1;
}

static void fat32_closedir(void *handle)
{
    if (handle) mm_free(handle);
}

fs_driver_t fs_fat32 = {
    .probe    = fat32_probe,
    .mount    = fat32_mount,
    .read     = fat32_read,
    .readlink = fat32_readlink,
    .stat     = fat32_stat,
    .umount   = fat32_umount,
    .opendir  = fat32_opendir,
    .readdir  = fat32_readdir,
    .closedir = fat32_closedir,
    .write    = fat32_write,
};
