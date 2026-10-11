/* ISO9660 read-only driver. Prefers Rock Ridge, falls back to Joliet,
 * then plain names. Block-device mode reads through the HAL, LUKS, or
 * LVM. Memory mode reads from a buffer, used by the El Torito path.
 * `iso.memory != NULL` selects memory mode.
 *
 * Logical sectors are 2048 bytes; the HAL counts 512-byte sectors.
 * See doc/chainload.md for the El Torito helpers.
 */

#ifndef CONFIG_HOST
#include "../core.h"
#else
#include <stdlib.h>
#include <string.h>
#endif
#include "fs.h"

#define ISO_SECTOR_SIZE     2048
#define ISO_PVD_SECTOR      16
#define ISO_MAX_DESCRIPTORS 64
#define ISO_FLAG_DIRECTORY  0x02
#define ISO_MAX_NAME        255

#define ISO_NO_CACHE        0xFFFFFFFFu

#define SUSP_ENTRY_MIN      4
#define SUSP_NM_CONTINUE    0x01
#define SUSP_NM_CURRENT     0x02
#define SUSP_NM_PARENT      0x04

#ifndef CONFIG_HOST
extern int luks_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);
extern int luks_active(void);
#ifdef LVM
extern int lvm_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);
extern int lvm_active(void);
#endif
#else
void *mm_alloc(size_t n);
void  mm_free(void *p);
void  con_puts(const char *s);
#endif

typedef struct {
    block_device_t *dev;
    const uint8_t  *memory;
    size_t          memory_size;
    uint32_t        root_lba;
    uint32_t        root_size;
    int             use_joliet;
    int             use_rock_ridge;
    int             susp_skip;
} iso9660_fs_t;

static iso9660_fs_t iso;

/* Every read is bounded by the image: the memory buffer, or the
 * device's lba_count when it is known. Sector numbers come straight
 * from directory records, so they are taken as 64-bit to avoid wrap. */
static int iso_read_logical_sector(uint64_t sector, void *buf)
{
    if (sector >= (1ull << 40)) return -1;
    if (iso.memory) {
        uint64_t offset = sector * ISO_SECTOR_SIZE;
        if (offset + ISO_SECTOR_SIZE > iso.memory_size) return -1;
        memcpy(buf, iso.memory + offset, ISO_SECTOR_SIZE);
        return 0;
    }

    uint64_t hal_lba   = sector * (ISO_SECTOR_SIZE / 512);
    uint32_t hal_count = ISO_SECTOR_SIZE / 512;
    if (iso.dev->lba_count && hal_lba + hal_count > iso.dev->lba_count)
        return -1;
#ifdef CONFIG_HOST
    (void)hal_lba; (void)hal_count;
    return -1;
#else
#ifdef LVM
    if (lvm_active())
        return lvm_read_blocks(hal_lba, hal_count, buf);
#endif
    if (luks_active())
        return luks_read_blocks(hal_lba, hal_count, buf);
    return hal_read_blocks(iso.dev->lba_start + hal_lba, hal_count, buf);
#endif
}

static void iso_read_record(const uint8_t *rec,
                            uint32_t *lba_out,
                            uint32_t *size_out,
                            uint8_t  *flags_out)
{
    *lba_out = (uint32_t)rec[2]  | ((uint32_t)rec[3]  << 8)
             | ((uint32_t)rec[4]  << 16) | ((uint32_t)rec[5]  << 24);
    *size_out = (uint32_t)rec[10] | ((uint32_t)rec[11] << 8)
              | ((uint32_t)rec[12] << 16) | ((uint32_t)rec[13] << 24);
    if (flags_out) *flags_out = rec[25];
}

static size_t iso_extract_name(const uint8_t *name_ptr, size_t name_len,
                               char *out, size_t out_size)
{
    size_t idx = 0;
    if (iso.use_joliet) {
        size_t chars = name_len / 2;
        for (size_t i = 0; i < chars && idx + 1 < out_size; i++) {
            uint16_t ch = ((uint16_t)name_ptr[i * 2] << 8)
                        | name_ptr[i * 2 + 1];
            out[idx++] = (ch < 0x80) ? (char)ch : '?';
        }
    } else {
        for (size_t i = 0; i < name_len && idx + 1 < out_size; i++) {
            char c = (char)name_ptr[i];
            if (c == ';') break;
            out[idx++] = c;
        }
    }
    out[idx] = '\0';
    return idx;
}

static int iso_name_eq(const char *a, const char *b)
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

/* A directory record must hold its fixed part and its whole name. */
static int iso_record_ok(const uint8_t *rec)
{
    return rec[0] >= 34 && 33u + rec[32] <= rec[0];
}

static int iso_is_dot_entry(const uint8_t *name_ptr, size_t name_len)
{
    if (name_len != 1) return 0;
    return name_ptr[0] == 0x00 || name_ptr[0] == 0x01;
}

/* Parse the SUSP entries in a directory record's System Use area and
 * return the Rock Ridge alternate name. Returns 1 on success. The
 * caller has checked the record with iso_record_ok, and every SUSP
 * entry is bounded by the System Use area.
 *
 * Continuation Entry (CE) entries are not followed. For short names —
 * kernel filenames, initrd filenames — the whole entry fits in one
 * record, so CE never appears. */
static int iso_get_rock_ridge_name(const uint8_t *rec,
                                   char *out, size_t out_size)
{
    size_t rec_len  = rec[0];
    size_t name_len = rec[32];
    size_t su_off   = 33 + name_len;
    if (su_off & 1) su_off++;
    su_off += iso.susp_skip;
    if (su_off >= rec_len) return 0;

    const uint8_t *p = rec + su_off;
    size_t remaining = rec_len - su_off;
    size_t out_len = 0;

    while (remaining >= SUSP_ENTRY_MIN) {
        uint8_t len = p[2];
        if (len < SUSP_ENTRY_MIN || len > remaining) break;
        if (p[0] == 'S' && p[1] == 'T') break;

        if (p[0] == 'N' && p[1] == 'M' && p[3] == 1 && len >= 5) {
            uint8_t flags = p[4];
            if (flags & (SUSP_NM_CURRENT | SUSP_NM_PARENT)) {
                p += len;
                remaining -= len;
                continue;
            }
            size_t nb = len - 5;
            for (size_t i = 0; i < nb && out_len + 1 < out_size; i++)
                out[out_len++] = (char)p[5 + i];

            /* NM_CONTINUE: the name continues in the next NM entry of
             * this area. Appends stay bounded by out_size. */
            if (!(flags & SUSP_NM_CONTINUE)) break;
        }

        p += len;
        remaining -= len;
    }

    if (out_len == 0) return 0;
    out[out_len] = '\0';
    return 1;
}

/* Return the best name for a record: Rock Ridge, then Joliet, then
 * the plain ISO9660 name. */
static size_t iso_record_name(const uint8_t *rec, char *out, size_t out_size)
{
    if (iso.use_rock_ridge &&
        iso_get_rock_ridge_name(rec, out, out_size))
        return strlen(out);

    return iso_extract_name(rec + 33, rec[32], out, out_size);
}

/* Check the root directory's `.` record for an SP entry. Presence
 * means the volume has Rock Ridge. The SP entry carries a skip value
 * that applies at the start of every System Use area; it's almost
 * always zero. */
static int iso_check_rock_ridge(uint32_t root_lba)
{
    uint8_t buf[ISO_SECTOR_SIZE];
    if (iso_read_logical_sector(root_lba, buf) != 0) return 0;

    if (buf[0] < 40) return 0;
    if (buf[32] != 1 || buf[33] != 0) return 0;

    size_t su_off = 33 + buf[32];
    if (su_off & 1) su_off++;
    if (su_off + 7 > buf[0]) return 0;

    const uint8_t *sp = buf + su_off;
    if (sp[0] != 'S' || sp[1] != 'P') return 0;
    if (sp[2] < 7) return 0;
    if (sp[3] != 1) return 0;
    if (sp[4] != 0xBE || sp[5] != 0xEF) return 0;

    iso.susp_skip = sp[6];
    return 1;
}

/* Pick a root directory. Rock Ridge takes priority, then Joliet,
 * then plain ISO9660 from the PVD. */
static int iso_scan_descriptors(void)
{
    uint8_t buf[ISO_SECTOR_SIZE];
    int      have_pvd     = 0;
    int      have_joliet  = 0;
    uint32_t pvd_lba = 0, pvd_size = 0;
    uint32_t joliet_lba = 0, joliet_size = 0;

    for (int i = 0; i < ISO_MAX_DESCRIPTORS; i++) {
        if (iso_read_logical_sector(ISO_PVD_SECTOR + i, buf) != 0) break;

        uint8_t type = buf[0];
        if (type == 255) break;
        if (buf[1] != 'C' || buf[2] != 'D' || buf[3] != '0' ||
            buf[4] != '0' || buf[5] != '1') continue;

        const uint8_t *root = buf + 156;
        uint32_t root_lba, root_size;

        if (type == 1) {
            iso_read_record(root, &root_lba, &root_size, 0);
            pvd_lba  = root_lba;
            pvd_size = root_size;
            have_pvd = 1;
        } else if (type == 2 && !have_joliet) {
            if (buf[88] == 0x25 && buf[89] == 0x2F &&
                (buf[90] == 0x40 || buf[90] == 0x43 || buf[90] == 0x45)) {
                iso_read_record(root, &root_lba, &root_size, 0);
                joliet_lba  = root_lba;
                joliet_size = root_size;
                have_joliet = 1;
            }
        }
    }

    if (!have_pvd) return -1;

    iso.use_joliet     = 0;
    iso.use_rock_ridge = 0;
    iso.susp_skip      = 0;
    iso.root_lba       = pvd_lba;
    iso.root_size      = pvd_size;

    if (iso_check_rock_ridge(pvd_lba)) {
        iso.use_rock_ridge = 1;
        return 0;
    }

    if (have_joliet) {
        iso.use_joliet = 1;
        iso.root_lba   = joliet_lba;
        iso.root_size  = joliet_size;
    }
    return 0;
}

int iso9660_probe(block_device_t *dev)
{
    block_device_t *prev = iso.dev;
    const uint8_t  *prev_mem = iso.memory;
    iso.dev = dev;
    iso.memory = NULL;

    uint8_t buf[ISO_SECTOR_SIZE];
    int ok = 0;
    if (iso_read_logical_sector(ISO_PVD_SECTOR, buf) == 0) {
        if (buf[0] == 1 && buf[1] == 'C' && buf[2] == 'D' &&
            buf[3] == '0' && buf[4] == '0' && buf[5] == '1') {
            ok = 1;
        }
    }

    iso.dev = prev;
    iso.memory = prev_mem;
    return ok ? 0 : -1;
}

int iso9660_mount(block_device_t *dev)
{
    iso.dev        = dev;
    iso.memory     = NULL;
    iso.memory_size = 0;
    return iso_scan_descriptors();
}

int iso9660_mount_memory(const void *data, size_t size)
{
    if (!data || size < ISO_PVD_SECTOR * ISO_SECTOR_SIZE + ISO_SECTOR_SIZE)
        return -1;
    iso.dev         = NULL;
    iso.memory      = (const uint8_t *)data;
    iso.memory_size = size;
    return iso_scan_descriptors();
}

void iso9660_umount(void)
{
    iso.memory      = NULL;
    iso.memory_size = 0;
    iso.dev         = NULL;
}

int iso9660_get_boot_catalog(uint32_t *lba_out)
{
    if (!lba_out) return -1;
    uint8_t buf[ISO_SECTOR_SIZE];
    for (int i = 0; i < ISO_MAX_DESCRIPTORS; i++) {
        if (iso_read_logical_sector(ISO_PVD_SECTOR + i, buf) != 0) return -1;
        if (buf[0] == 255) break;
        if (buf[1] != 'C' || buf[2] != 'D' || buf[3] != '0' ||
            buf[4] != '0' || buf[5] != '1') continue;
        if (buf[0] == 0) {
            *lba_out = (uint32_t)buf[71] | ((uint32_t)buf[72] << 8)
                     | ((uint32_t)buf[73] << 16) | ((uint32_t)buf[74] << 24);
            return 0;
        }
    }
    return -1;
}

static int iso_read_catalog_entry(const uint8_t *e,
                                  uint32_t *image_lba,
                                  uint32_t *image_sectors)
{
    uint8_t boot_ind = e[0];
    if (boot_ind != 0x88 && boot_ind != 0x00) return -1;

    if (image_lba) {
        *image_lba = (uint32_t)e[8]  | ((uint32_t)e[9]  << 8)
                   | ((uint32_t)e[10] << 16) | ((uint32_t)e[11] << 24);
    }
    if (image_sectors) {
        *image_sectors = (uint32_t)e[6] | ((uint32_t)e[7] << 8);
    }
    return 0;
}

/* Walk the El Torito boot catalog and return the LBA and size of the
 * UEFI boot image, if present. The catalog can carry an x86 BIOS
 * initial entry with a UEFI section header, or the UEFI entry can be
 * initial. Alpine, Arch, and dual-boot ISOs use the former. */
int iso9660_get_boot_image(uint32_t catalog_lba,
                           uint32_t *image_lba,
                           uint32_t *image_sectors,
                           uint8_t  *platform_out)
{
    uint8_t buf[ISO_SECTOR_SIZE];
    if (iso_read_logical_sector(catalog_lba, buf) != 0) return -1;

    if (buf[0] != 1) return -1;
    if (buf[30] != 0x55 || buf[31] != 0xAA) return -1;

    uint8_t initial_platform = buf[1];

    if (initial_platform == 0xEF) {
        if (iso_read_catalog_entry(buf + 32, image_lba, image_sectors) != 0)
            return -1;
        if (platform_out) *platform_out = 0xEF;
        return 0;
    }

    uint32_t off = 64;
    while (off + 32 <= ISO_SECTOR_SIZE) {
        const uint8_t *hdr = buf + off;
        uint8_t indicator = hdr[0];
        if (indicator != 0x90 && indicator != 0x91) break;

        uint8_t  section_platform = hdr[1];
        uint16_t n_entries = (uint16_t)hdr[2] | ((uint16_t)hdr[3] << 8);

        if (section_platform == 0xEF && n_entries >= 1) {
            if (off + 64 > ISO_SECTOR_SIZE) return -1;
            const uint8_t *e = hdr + 32;
            if (iso_read_catalog_entry(e, image_lba, image_sectors) != 0)
                return -1;
            if (platform_out) *platform_out = 0xEF;
            return 0;
        }

        off += 32 + (uint32_t)n_entries * 32;
        if (indicator == 0x91) break;
    }

    return -1;
}

static int iso_find_in_dir(uint32_t dir_lba, uint32_t dir_size,
                           const char *name,
                           uint32_t *lba_out, uint32_t *size_out,
                           uint8_t *flags_out)
{
    uint8_t buf[ISO_SECTOR_SIZE];
    uint32_t offset = 0;

    while (offset < dir_size) {
        uint32_t sector_idx     = offset / ISO_SECTOR_SIZE;
        uint32_t offset_in_sec  = offset % ISO_SECTOR_SIZE;

        if (iso_read_logical_sector((uint64_t)dir_lba + sector_idx, buf) != 0)
            return -1;

        uint8_t rec_len = buf[offset_in_sec];
        if (rec_len == 0) {
            offset = (sector_idx + 1) * ISO_SECTOR_SIZE;
            continue;
        }
        if (offset_in_sec + rec_len > ISO_SECTOR_SIZE ||
            !iso_record_ok(buf + offset_in_sec))
            return -1;

        const uint8_t *rec      = buf + offset_in_sec;
        uint8_t        name_len = rec[32];
        const uint8_t *name_ptr = rec + 33;

        if (!iso_is_dot_entry(name_ptr, name_len)) {
            char entry[ISO_MAX_NAME + 1];
            iso_record_name(rec, entry, sizeof(entry));
            if (iso_name_eq(entry, name)) {
                iso_read_record(rec, lba_out, size_out, flags_out);
                return 0;
            }
        }
        offset += rec_len;
    }
    return -1;
}

static int iso_resolve(const char *path,
                       uint32_t *lba_out, uint32_t *size_out,
                       uint8_t *flags_out)
{
    uint32_t cur_lba   = iso.root_lba;
    uint32_t cur_size  = iso.root_size;
    uint8_t  cur_flags = ISO_FLAG_DIRECTORY;

    if (path[0] == '/') path++;

    while (*path) {
        const char *slash = path;
        while (*slash && *slash != '/') slash++;
        size_t clen = (size_t)(slash - path);

        if (clen == 0) { path = slash + (*slash ? 1 : 0); continue; }
        if (clen > ISO_MAX_NAME) return -1;
        if (!(cur_flags & ISO_FLAG_DIRECTORY)) return -1;

        char name[ISO_MAX_NAME + 1];
        memcpy(name, path, clen);
        name[clen] = '\0';

        uint32_t next_lba, next_size;
        uint8_t  next_flags;
        if (iso_find_in_dir(cur_lba, cur_size, name,
                            &next_lba, &next_size, &next_flags) != 0)
            return -1;

        cur_lba   = next_lba;
        cur_size  = next_size;
        cur_flags = next_flags;
        path = slash + (*slash ? 1 : 0);
    }

    *lba_out   = cur_lba;
    *size_out  = cur_size;
    if (flags_out) *flags_out = cur_flags;
    return 0;
}

int iso9660_read(const char *path, uint8_t *buf, size_t *len)
{
    uint32_t lba, size;
    uint8_t  flags;
    if (!path || !buf || !len) return -1;
    if (iso_resolve(path, &lba, &size, &flags) != 0) return -1;
    if (flags & ISO_FLAG_DIRECTORY) return -1;

    size_t want = size < *len ? size : *len;
    *len = want;

    uint8_t sector[ISO_SECTOR_SIZE];
    uint64_t cur_sector = lba;
    size_t remaining = want;

    while (remaining > 0) {
        if (iso_read_logical_sector(cur_sector, sector) != 0) return -1;
        size_t take = remaining < ISO_SECTOR_SIZE ? remaining : ISO_SECTOR_SIZE;
        memcpy(buf, sector, take);
        buf += take;
        remaining -= take;
        cur_sector++;
    }
    return 0;
}

int iso9660_stat(const char *path, struct stat *st)
{
    uint32_t lba, size;
    uint8_t  flags;
    if (!path || !st) return -1;
    if (iso_resolve(path, &lba, &size, &flags) != 0) return -1;

    st->size = size;
    st->mode = (flags & ISO_FLAG_DIRECTORY) ? 040755 : 0100644;
    return 0;
}

int iso9660_readlink(const char *path, char *buf, size_t len)
{
    (void)path; (void)buf; (void)len;
    return -1;
}

typedef struct {
    uint32_t dir_lba;
    uint32_t dir_size;
    uint32_t offset;
    uint32_t cached_sector;
    uint8_t  cache[ISO_SECTOR_SIZE];
} iso_dir_handle_t;

int iso9660_opendir(const char *path, void **handle)
{
    if (!path || !handle) return -1;

    uint32_t lba, size;
    uint8_t  flags;
    if (iso_resolve(path, &lba, &size, &flags) != 0) return -1;
    if (!(flags & ISO_FLAG_DIRECTORY)) return -1;

    iso_dir_handle_t *h = mm_alloc(sizeof(*h));
    if (!h) return -1;
    h->dir_lba       = lba;
    h->dir_size      = size;
    h->offset        = 0;
    h->cached_sector = ISO_NO_CACHE;
    *handle = h;
    return 0;
}

int iso9660_readdir(void *handle, char *name, size_t name_len)
{
    if (!handle || !name || name_len < 2) return -1;
    iso_dir_handle_t *h = (iso_dir_handle_t *)handle;

    while (h->offset < h->dir_size) {
        uint32_t sector_idx    = h->offset / ISO_SECTOR_SIZE;
        uint32_t offset_in_sec = h->offset % ISO_SECTOR_SIZE;

        if (h->cached_sector != sector_idx) {
            if (iso_read_logical_sector((uint64_t)h->dir_lba + sector_idx,
                                        h->cache) != 0)
                return -1;
            h->cached_sector = sector_idx;
        }

        uint8_t rec_len = h->cache[offset_in_sec];
        if (rec_len == 0) {
            h->offset = (sector_idx + 1) * ISO_SECTOR_SIZE;
            continue;
        }
        if (offset_in_sec + rec_len > ISO_SECTOR_SIZE ||
            !iso_record_ok(h->cache + offset_in_sec))
            return -1;

        const uint8_t *rec      = h->cache + offset_in_sec;
        uint8_t        len      = rec[32];
        const uint8_t *name_ptr = rec + 33;

        h->offset += rec_len;

        if (iso_is_dot_entry(name_ptr, len)) continue;

        iso_record_name(rec, name, name_len);
        return 1;
    }
    return 0;
}

void iso9660_closedir(void *handle)
{
    if (handle) mm_free(handle);
}

int iso9660_write(const char *path, const uint8_t *data, size_t size)
{
    (void)path; (void)data; (void)size;
    return -1;
}

int iso9660_read_label(block_device_t *dev, char *out, size_t out_size)
{
    if (!dev || !out || out_size < 2) return -1;

    block_device_t *prev = iso.dev;
    const uint8_t *prev_mem = iso.memory;

    iso.dev = dev;
    iso.memory = NULL;

    uint8_t buf[ISO_SECTOR_SIZE];
    int ok = -1;

    if (iso_read_logical_sector(ISO_PVD_SECTOR, buf) == 0 &&
        buf[0] == 1 &&
        buf[1] == 'C' && buf[2] == 'D' && buf[3] == '0' &&
        buf[4] == '0' && buf[5] == '1') {
        size_t n = 32;
        while (n > 0 && buf[40 + n - 1] == ' ') n--;
        if (n >= out_size) n = out_size - 1;
        for (size_t i = 0; i < n; i++) out[i] = (char)buf[40 + i];
        out[n] = '\0';
        ok = 0;
    }

    iso.dev = prev;
    iso.memory = prev_mem;
    return ok;
}

fs_driver_t fs_iso9660 = {
    .probe    = iso9660_probe,
    .mount    = iso9660_mount,
    .read     = iso9660_read,
    .readlink = iso9660_readlink,
    .stat     = iso9660_stat,
    .umount   = iso9660_umount,
    .opendir  = iso9660_opendir,
    .readdir  = iso9660_readdir,
    .closedir = iso9660_closedir,
    .write    = iso9660_write,
};