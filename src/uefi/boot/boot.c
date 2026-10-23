#include "core.h"
#include "security/secure_boot.h"
#include "storage/partition.h"
#include "ui/theme.h"
#include "ui/gfx.h"
#include "ui/text.h"
#include "ui/frame.h"
#include "storage/luks.h"
#include "security/efivars.h"
#include "security/password.h"

static uint32_t value_color(const char *v)
{
    if (!v) return theme_current.fg;
    if (strcmp(v, "OK") == 0)     return theme_current.ok_fg;
    if (strcmp(v, "FAILED") == 0) return theme_current.error_fg;
    return theme_current.error_fg;
}

static void status_row(int row, const char *label, const char *value)
{
    uint32_t vc = value ? value_color(value) : theme_current.fg;
    frame_row_clear(row);
    frame_row_2col(row, label ? label : "", value, theme_current.fg, vc);
}

static void boot_status_begin(const char *entry_name)
{
    frame_begin(theme_current.header);
    frame_content_clear();

    char buf[128];
    int i = 0;
    const char *pre = "Booting: ";
    for (const char *p = pre; *p && i < 100; p++) buf[i++] = *p;
    for (const char *p = entry_name; *p && i < 120; p++) buf[i++] = *p;
    buf[i] = '\0';
    frame_row(0, buf, theme_current.fg);
    frame_sep(FRAME_ROWS - 2);
}

static int hash_ok(const uint8_t *data, size_t len, const char *expected)
{
    if (!expected || !expected[0]) return 1;
    char got[SB_HASH_HEX_BUF];
    sb_hash_buffer(data, len, got);
    return sb_hash_matches(got, expected);
}

static int mount_entry_iso(boot_context_t *ctx, entry_t *entry)
{
    if (!entry->is_iso_boot) return 0;
    if (fs_current == &fs_iso9660) {
        con_puts("ISO boot from an ISO9660 boot filesystem unsupported\n");
        return -1;
    }
    con_puts("Scanning for ISO... ");
    uint64_t iso_lba = 0;
    uint32_t iso_count = 0;
    if (partition_find_iso(ctx, entry->iso_label, &iso_lba, &iso_count) != 0) {
        con_puts("not found\n");
        return -1;
    }
    block_device_t iso_dev = {
        .lba_start = iso_lba, .lba_count = iso_count,
        .block_size = 512, .private = 0,
    };
    if (iso9660_mount(&iso_dev) != 0) {
        con_puts("mount failed\n");
        return -1;
    }
    con_puts("OK\n");
    fs_current = &fs_iso9660;
    return 0;
}

static int load_initrd(entry_t *entry)
{
    if (!entry->initrd_path || !entry->initrd_path[0]) {
        entry->initrd = 0;
        entry->initrd_size = 0;
        return 0;
    }
    entry->initrd = 0;
    entry->initrd_size = 0;
    size_t initrd_size = 0;
    if (fs_stat(entry->initrd_path, &initrd_size) != 0) {
        status_row(9, "Loading initrd...", "FAILED");
        frame_row(10, entry->initrd_path, theme_current.fg_dim);
        return -1;
    }
    size_t pages = (initrd_size + 4095) / 4096;
    uint8_t *buf = pages ? hal_allocate_pages_below(pages, 0x7FFFFFFF) : 0;
    if (!buf) {
        status_row(9, "Loading initrd...", "FAILED");
        return -1;
    }
    size_t rd = initrd_size;
    const char *why = 0;
    if (fs_read(entry->initrd_path, buf, &rd) != 0 || rd != initrd_size)
        why = "FAILED";
    else if (!hash_ok(buf, initrd_size, entry->initrd_hash))
        why = "BAD HASH";
    if (why) {
        hal_free_pages(buf, pages);
        entry->initrd = 0;
        entry->initrd_size = 0;
        status_row(9, "Loading initrd...", why);
        frame_row(10, entry->initrd_path, theme_current.fg_dim);
        return -1;
    }
    status_row(9, "Loading initrd...", "OK");
    entry->initrd = buf;
    entry->initrd_size = initrd_size;
    return 0;
}

static int load_kernel(entry_t *entry)
{
    size_t kernel_size = 0;
    if (fs_stat(entry->kernel_path, &kernel_size) != 0) {
        status_row(8, "Loading kernel...", "FAILED");
        frame_row(10, entry->kernel_path, theme_current.fg_dim);
        return -1;
    }
    size_t kernel_pages = (kernel_size + 4095) / 4096;
    uint8_t *tmp = kernel_pages
        ? hal_allocate_pages_below(kernel_pages, 0x7FFFFFFF) : 0;
    if (!tmp) {
        status_row(8, "Loading kernel...", "FAILED");
        return -1;
    }
    size_t rd_size = kernel_size;
    const char *why = 0;
    if (fs_read(entry->kernel_path, tmp, &rd_size) != 0 || rd_size != kernel_size)
        why = "FAILED";
    else if (!hash_ok(tmp, kernel_size, entry->kernel_hash))
        why = "BAD HASH";
    else if (kernel_size < 2 || tmp[0] != 'M' || tmp[1] != 'Z')
        why = "NOT PE";
    if (why) {
        hal_free_pages(tmp, kernel_pages);
        status_row(8, "Loading kernel...", why);
        frame_row(10, entry->kernel_path, theme_current.fg_dim);
        return -1;
    }
    status_row(8, "Loading kernel...", "OK");
    entry->kernel = tmp;
    entry->kernel_size = kernel_size;
    if (load_initrd(entry) != 0) {
        hal_free_pages(tmp, kernel_pages);
        entry->kernel = 0;
        entry->kernel_size = 0;
        return -1;
    }
    return 0;
}

static int boot_failed(const char *msg)
{
    status_row(11, msg, "FAILED");
    frame_row(12, "Press any key to return to the menu.", theme_current.fg_dim);
    while (hal_getchar_timeout(10) == 0) { }
    return 0;
}

static int boot_chainload(entry_t *entry)
{
    if (!entry->chainload_path || !entry->chainload_path[0]) {
        con_puts("chainload: no path\n");
        return -1;
    }
    con_puts("Loading EFI image... ");
    size_t efi_size = 0;
    if (fs_stat(entry->chainload_path, &efi_size) != 0 || efi_size < 2) {
        con_puts("stat FAILED\n");
        return -1;
    }
    size_t pages = (efi_size + 4095) / 4096;
    uint8_t *buf = hal_allocate_pages_below(pages, 0x7FFFFFFF);
    if (!buf) { con_puts("alloc FAILED\n"); return -1; }
    size_t rd = efi_size;
    if (fs_read(entry->chainload_path, buf, &rd) != 0 || rd != efi_size) {
        hal_free_pages(buf, pages);
        con_puts("read FAILED\n");
        return -1;
    }
    if (!hash_ok(buf, efi_size, entry->chainload_hash)) {
        hal_free_pages(buf, pages);
        con_puts("hash mismatch: ");
        con_puts(entry->chainload_path);
        con_puts("\n");
        return -1;
    }
    con_puts("OK\nStarting ");
    con_puts(entry->chainload_path);
    con_puts("...\n");
    ivo_bootcount_clear();
    luks_wipe_keys();
    if (hal_chainload(buf, efi_size) != 0) {
        con_puts("chainload failed\n");
        return -1;
    }
    con_puts("Chainloaded image returned. Rebooting.\n");
    hal_reboot();
    return -1;
}

static int entry_failed(fs_driver_t *saved_fs, int subvol_set, const char *msg)
{
    if (subvol_set && fs_current && fs_current->set_subvol)
        fs_current->set_subvol(0);
    fs_current = saved_fs;
    boot_failed(msg);
    return -1;
}

static int prepare_entry(boot_context_t *ctx, entry_t *entry)
{
    fs_driver_t *saved_fs = fs_current;
    int subvol_set = 0;
    if (mount_entry_iso(ctx, entry) != 0)
        return entry_failed(saved_fs, 0, "ISO mount failed");
    if (entry->subvol && entry->subvol[0]) {
        if (!fs_current || !fs_current->set_subvol)
            return entry_failed(saved_fs, 0, "Filesystem has no subvolume support");
        if (fs_current->set_subvol(entry->subvol) != 0)
            return entry_failed(saved_fs, 0, "Subvolume not found");
        subvol_set = 1;
    }
    if (load_kernel(entry) != 0)
        return entry_failed(saved_fs, subvol_set, "Load failed");
    return 0;
}

int boot_entry(boot_context_t *ctx, entry_t *entry)
{
    if (entry_password_check(entry) != 0) {
        return 0;
    }
    con_clear();

    boot_status_begin(entry->name);
#ifdef SECURE_BOOT
    if (!config_entry_hashes_complete(entry))
        return boot_failed("Entry has no kver/iver/cver");
#endif
    if (entry->is_chainload) {
        if (boot_chainload(entry) != 0)
            return boot_failed("Chainload failed");
        return 0;
    }
    if (prepare_entry(ctx, entry) != 0)
        return 0;
    tpm_measure(TPM_PCR_KERNEL, entry->kernel, entry->kernel_size);
    if (entry->initrd && entry->initrd_size)
        tpm_measure(TPM_PCR_INITRD, entry->initrd, entry->initrd_size);
    if (entry->cmdline && entry->cmdline[0])
        tpm_measure_string(TPM_PCR_CMDLINE, entry->cmdline);

    status_row(11, "Handing off to kernel...", 0);
    ivo_bootcount_clear();
    luks_wipe_keys();
    hal_boot_uefi(entry->kernel, entry->kernel_size,
                  entry->cmdline,
                  entry->initrd, entry->initrd_size);
    return 0;
}