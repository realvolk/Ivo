#include "core.h"
#include "ui/frame.h"
#include "storage/partition.h"
#include "ui/theme.h"
#include "security/secure_boot.h"
#include "ui/gfx.h"
#include "ui/text.h"
#include "security/efivars.h"
extern int luks_enabled(boot_context_t *ctx);
extern int luks_unlock(boot_context_t *ctx);
#ifdef LVM
extern int lvm_init(boot_context_t *ctx);
extern int lvm_lv_count(void);
extern int lvm_lv_select(int index);
#endif

extern int hal_boot_partition_decided;

/* Set when the LUKS volume was opened from a TPM-sealed secret, i.e.
 * nobody at the keyboard has proven they know the passphrase. The
 * shell checks it before exposing the decrypted filesystem. */
static int unlocked_without_passphrase;

int core_unlocked_without_passphrase(void)
{
    return unlocked_without_passphrase;
}

void core_passphrase_proven(void)
{
    unlocked_without_passphrase = 0;
}

void ivo_main(boot_context_t *ctx)
{
    stack_chk_init();
    hal_init(ctx);
    if (gfx_init() != 0) {
        gfx_force_text_mode();
        hal_puts_serial("Ivo: no usable GOP framebuffer; text mode\n");
    }
    frame_init();
    con_clear();
    mm_init(ctx);
    tpm_init();
    int bc = ivo_bootcount_get();
    ivo_bootcount_set(bc + 1);

    /* No self-measurement: firmware already measured ivo.efi into
     * PCR 4 when it loaded it. Hashing the in-memory image would mix
     * relocations and runtime .data/.bss into PCR 4 and make it
     * unpredictable across boots. */

    if (!hal_boot_partition_decided) {
        ctx->boot_lba = 0;
    }

    block_device_t dev;
    dev.lba_start  = ctx->boot_lba;
    dev.lba_count  = 0;
    dev.block_size = 512;
    dev.private    = 0;

    if (luks_enabled(ctx)) {
        /* Enrollment mode: if /EFI/ivo/seal-request exists, prompt
         * for the passphrase, unlock with it, and seal it to the TPM.
         * Returns 1 if it handled the unlock; falls through to the
         * normal path if the passphrase was wrong. */
        int handled = tpm_seal_maybe_enroll(ctx) == 1;
        if (!handled) {
            int unlocked = tpm_seal_try_unlock(ctx) == 0;
            if (unlocked) {
                unlocked_without_passphrase = 1;
            } else if (luks_unlock(ctx) != 0) {
                panic("LUKS unlock failed");
            }
        }
    }

    /* Close the unseal window. The sealed blob is bound to PCR 4, so
     * once this separator is in, nothing later in this boot (the
     * shell, the kernel, the OS) can unseal it again. */
    tpm_measure_string(TPM_PCR_BOOTLOADER, "ivo: unseal window closed");

#ifdef LVM
    if (lvm_init(ctx) == 0) {
        /* Try each LV. The first one whose filesystem the probe
         * recognises becomes the boot device. */
        int mounted = 0;
        int count = lvm_lv_count();
        for (int i = 0; i < count; i++) {
            if (lvm_lv_select(i) != 0) continue;
            if (fs_probe_mount(&dev) == 0) {
                mounted = 1;
                break;
            }
        }
        if (!mounted) {
            if (count > 0) lvm_lv_select(0);
            panic("no mountable filesystem found");
        }
    } else {
        panic("no mountable filesystem found");
    }
#else
    if (fs_probe_mount(&dev) != 0) {
        panic("no mountable filesystem found");
    }
#endif
    con_clear();

    int cfg_rc = config_load(ctx);
    if (cfg_rc == CONFIG_ERR_SIGNATURE) {
        panic("config.toml signature invalid");
    }
#ifdef SECURE_BOOT
    if (cfg_rc != 0) {
        panic("config.toml missing or malformed");
    }
#endif
    if (cfg_rc != 0) {
        con_puts("\nNo config loaded. Dropping to shell.\n");
        con_puts("Type 'help' for commands. 'halt' to stop.\n\n");
        shell_enter(ctx);
        halt();
    }

    /* Rollback protection: refuse a config older than the last one we
     * accepted. Best-effort; the efivar can be deleted by anyone with
     * ESP write access, which resets the check. See doc/security.md. */
    {
        int cv = config_get_version();      /* -1 if no version key */
        if (cv >= 0) {
            int stored = ivo_configver_get();
            if (stored >= 0 && cv < stored)
                panic("config.toml version is older than the last accepted one");
            if (cv > stored)
                ivo_configver_set(cv);
        }
    }

    for (;;) {
        entry_t *chosen = menu_select(ctx);
        if (!chosen) {
            con_puts("\nNo entry selected. Dropping to shell.\n");
            shell_enter(ctx);
            halt();
        }

        if (boot_entry(ctx, chosen) == 0) {
            /* boot_failed showed the reason and waited for a key.
             * Back to the menu. */
            continue;
        }
        break;
    }

    con_puts("\nBoot entry returned. Dropping to shell.\n");
    shell_enter(ctx);
    halt();
}

extern void luks_wipe_keys(void);

void panic(const char *msg)
{
    luks_wipe_keys();

    if (gfx_text_mode()) {
        con_clear();
        con_puts("Ivo: Fatal error\n");
        con_puts(msg ? msg : "");
        con_puts("\n\nSystem halted.\n");
        halt();
    }

    con_clear();

    const char *l1 = "Ivo: Fatal error";
    const char *l2 = msg ? msg : "";
    const char *l3 = "System halted.";

    int W   = gfx_width();
    int H   = gfx_height();
    int lh  = text_height();
    int gap = lh;

    int total_h = 3 * lh + gap;
    int y0 = (H - total_h) / 2;
    if (y0 < 0) y0 = 0;

    int w1 = text_width(l1);
    int w2 = text_width(l2);
    int w3 = text_width(l3);

    text_draw(((W - w1) / 2) << 2, y0,
              l1, theme_current.error_fg);
    text_draw(((W - w2) / 2) << 2, y0 + lh,
              l2, theme_current.fg);
    text_draw(((W - w3) / 2) << 2, y0 + 2 * lh + gap,
              l3, theme_current.fg);

    halt();
}