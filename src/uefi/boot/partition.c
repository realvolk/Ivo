#include "core.h"
#include "storage/partition.h"

/* GPT partition type GUIDs, in on-disk byte order. */
static const uint8_t GPT_TYPE_ESP[16] = {
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
    0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B
};
static const uint8_t GPT_TYPE_BASIC[16] = {
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
};
static const uint8_t GPT_TYPE_LINUX_FS[16] = {
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
    0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4
};

#define GPT_MAX_ENTRIES      1024
#define GPT_SCAN_ENTRIES     128

static int guid_eq(const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 16; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static uint32_t rd32(const uint8_t *p) {
    uint32_t v; memcpy(&v, p, 4); return v;
}
static uint64_t rd64(const uint8_t *p) {
    uint64_t v; memcpy(&v, p, 8); return v;
}

/* Disk size in 512-byte sectors, or 0 when the HAL can't tell. */
static uint64_t disk_sectors(void)
{
    return hal_get_disk_sectors();
}

/* Is [lba, lba + count) a non-empty range inside the disk? */
static int range_ok(uint64_t lba, uint64_t count, uint64_t disk)
{
    if (lba == 0 || count == 0 || lba + count < lba) return 0;
    return disk == 0 || lba + count <= disk;
}

/* Validate the GPT header at LBA 1 and return the entry array. Entry
 * sizes are 128 * 2^n up to 512, so an entry never straddles the
 * 512-byte sector buffer. At most GPT_SCAN_ENTRIES are scanned. */
static int gpt_read_header(uint64_t *entries_lba, uint32_t *num_entries,
                           uint32_t *entry_size)
{
    uint8_t h[512];
    if (hal_read_disk_blocks(1, 1, h) != 0) return -1;
    if (memcmp(h, "EFI PART", 8) != 0) return -1;
    if (rd32(h + 8) != 0x00010000u) return -1;
    if (rd32(h + 12) < 92 || rd32(h + 12) > 512) return -1;

    uint64_t lba = rd64(h + 72);
    uint32_t n   = rd32(h + 80);
    uint32_t es  = rd32(h + 84);
    if (es < 128 || es > 512 || (es & (es - 1))) return -1;
    if (n == 0 || n > GPT_MAX_ENTRIES) return -1;
    if (lba < 2) return -1;
    if (!range_ok(lba, ((uint64_t)n * es + 511) / 512, disk_sectors()))
        return -1;

    *entries_lba = lba;
    *num_entries = n > GPT_SCAN_ENTRIES ? GPT_SCAN_ENTRIES : n;
    *entry_size  = es;
    return 0;
}

static int try_gpt(boot_context_t *ctx)
{
    uint64_t entries_lba;
    uint32_t num_entries, entry_size;
    if (gpt_read_header(&entries_lba, &num_entries, &entry_size) != 0)
        return -1;

    uint64_t esp_lba = 0, other_lba = 0;
    uint32_t esp_guid[4] = {0, 0, 0, 0};
    uint32_t other_guid[4] = {0, 0, 0, 0};

    for (uint32_t i = 0; i < num_entries; i++) {
        uint64_t byte_off = (uint64_t)i * entry_size;
        uint64_t sector   = entries_lba + (byte_off / 512);
        uint32_t off      = (uint32_t)(byte_off % 512);

        uint8_t entry[512];
        if (hal_read_disk_blocks(sector, 1, entry) != 0) return -1;

        uint8_t *e = entry + off;
        int is_esp   = guid_eq(e, GPT_TYPE_ESP);
        int is_basic = guid_eq(e, GPT_TYPE_BASIC);
        int is_linux = guid_eq(e, GPT_TYPE_LINUX_FS);
        if (!is_esp && !is_basic && !is_linux) continue;

        uint64_t first_lba = rd64(e + 32);
        uint64_t last_lba  = rd64(e + 40);
        if (last_lba < first_lba) continue;
        if (first_lba == 0 || last_lba == 0) continue;

        uint8_t probe_sector[512];
        const uint8_t *probe = probe_sector;
        if (hal_read_disk_blocks(first_lba, 1, probe_sector) == 0 &&
            probe[0] == 'L' && probe[1] == 'U' &&
            probe[2] == 'K' && probe[3] == 'S' &&
            probe[4] == 0xBA && probe[5] == 0xBE) {
            ctx->boot_lba = first_lba;
            for (int k = 0; k < 4; k++) {
                ctx->boot_partition_guid[k] = rd32(e + 16 + k * 4);
            }
            return 0;
        }

        /* ESP is where the loader lives, not where the config does. */
        if (is_esp) {
            if (esp_lba == 0) {
                esp_lba = first_lba;
                for (int k = 0; k < 4; k++)
                    esp_guid[k] = rd32(e + 16 + k * 4);
            }
        } else {
            if (other_lba == 0) {
                other_lba = first_lba;
                for (int k = 0; k < 4; k++)
                    other_guid[k] = rd32(e + 16 + k * 4);
            }
        }
    }

    if (other_lba != 0) {
        ctx->boot_lba = other_lba;
        for (int k = 0; k < 4; k++) ctx->boot_partition_guid[k] = other_guid[k];
        return 0;
    }
    if (esp_lba != 0) {
        ctx->boot_lba = esp_lba;
        for (int k = 0; k < 4; k++) ctx->boot_partition_guid[k] = esp_guid[k];
        return 0;
    }
    return -1;
}

/* The block_device_t handed to the ISO reader is partition-scoped:
 * lba_start is the partition LBA, reads go through hal_read_blocks. */
int partition_find_iso(boot_context_t *ctx, const char *label,
                       uint64_t *iso_lba, uint32_t *iso_count)
{
    if (!ctx || !iso_lba || !iso_count) return -1;

    uint64_t entries_lba;
    uint32_t num_entries, entry_size;

    if (gpt_read_header(&entries_lba, &num_entries, &entry_size) != 0)
        return -1;

    for (uint32_t i = 0; i < num_entries; i++) {
        uint64_t byte_off = (uint64_t)i * entry_size;
        uint64_t sector   = entries_lba + (byte_off / 512);
        uint32_t off      = (uint32_t)(byte_off % 512);

        uint8_t entry[512];
        if (hal_read_disk_blocks(sector, 1, entry) != 0) return -1;
        uint8_t *e = entry + off;

        int all_zero = 1;
        for (int k = 0; k < 16; k++) {
            if (e[k] != 0) { all_zero = 0; break; }
        }
        if (all_zero) continue;

        uint64_t first_lba = rd64(e + 32);
        uint64_t last_lba  = rd64(e + 40);
        if (last_lba < first_lba) continue;
        /* iso_count is 32-bit; larger partitions can't be an ISO
         * we would boot anyway. */
        if (last_lba - first_lba >= 0xFFFFFFFFull) continue;
        uint32_t size = (uint32_t)(last_lba - first_lba + 1);

        block_device_t dev = {
            .lba_start = first_lba,
            .lba_count = size,
            .block_size = 512,
            .private = 0,
        };

        char vol[33];
        if (iso9660_read_label(&dev, vol, sizeof(vol)) == 0) {
            if (!label || !label[0] || strcmp(vol, label) == 0) {
                *iso_lba   = first_lba;
                *iso_count = size;
                return 0;
            }
        }
    }
    return -1;
}

int partition_find_boot(boot_context_t *ctx)
{
    if (try_gpt(ctx) == 0) {
        return 0;
    }

    ctx->boot_lba = 2048;
    for (int k = 0; k < 4; k++) ctx->boot_partition_guid[k] = 0;
    return -1;
}