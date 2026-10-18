#include "core.h"
#include "storage/partition.h"

#define GPT_MAX_ENTRIES      1024
#define GPT_SCAN_ENTRIES     128

static uint32_t rd32(const uint8_t *p) {
    uint32_t v; memcpy(&v, p, 4); return v;
}
static uint64_t rd64(const uint8_t *p) {
    uint64_t v; memcpy(&v, p, 8); return v;
}

static uint64_t disk_sectors(void)
{
    return hal_get_disk_sectors();
}

static int range_ok(uint64_t lba, uint64_t count, uint64_t disk)
{
    if (lba == 0 || count == 0 || lba + count < lba) return 0;
    return disk == 0 || lba + count <= disk;
}

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