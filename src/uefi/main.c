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

static int unlocked_without_passphrase;
static int g_fwver_tier;

int core_fwver_tier(void) { return g_fwver_tier; }

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

    /* Rollback protection. TPM NV counter is the authoritative store
     * when available; the UEFI variable Ivo/FirmwareVer is the
     * fallback. A corrupt store is left alone; the next boot retries.
     * Requires SB for security value. */
    {
        int nv_ok = 0;
        int nv_v  = -1;
        int nv_corrupt = 0;

        if (tpm_available()) {
            int nv_rc = tpm_nv_fwver_ensure(IVO_RELEASE, &nv_v);
            if (nv_rc == 0) {
                nv_ok = 1;
            } else if (nv_rc == -2) {
                nv_corrupt = 1;
            }
        }

        g_fwver_tier = nv_ok ? 1 : 0;

        if (nv_corrupt) {
            hal_puts_serial("ivo: NV counter corrupt; not overwritten\n");
        } else if (nv_ok) {
            if (nv_v > IVO_RELEASE)
                panic("Ivo binary is older than the last one that ran");
            ivo_fwver_set(IVO_RELEASE);
        } else {
            int uv = ivo_fwver_get();
            if (uv == -2) {
                hal_puts_serial("ivo: FirmwareVer corrupt; not overwritten\n");
            } else if (uv < 0) {
                ivo_fwver_set(IVO_RELEASE);
            } else if (uv > IVO_RELEASE) {
                panic("Ivo binary is older than the last one that ran");
            } else if (uv < IVO_RELEASE) {
                ivo_fwver_set(IVO_RELEASE);
            }
        }
    }

    int bc = ivo_bootcount_get();
    ivo_bootcount_set(bc + 1);

    if (!hal_boot_partition_decided) {
        ctx->boot_lba = 0;
    }

    block_device_t dev;
    dev.lba_start  = ctx->boot_lba;
    dev.lba_count  = 0;
    dev.block_size = 512;
    dev.private    = 0;

    int sealed_this_boot = 0;

    if (luks_enabled(ctx)) {
        int handled = tpm_seal_maybe_enroll(ctx) == 1;
        if (handled) {
            sealed_this_boot = 1;
        } else {
            int unlocked = tpm_seal_try_unlock(ctx) == 0;
            if (unlocked) {
                unlocked_without_passphrase = 1;
            } else if (luks_unlock(ctx) != 0) {
                panic("LUKS unlock failed");
            }
        }
    }

    /* Closes the unseal window: after this, PCR 4 no longer holds the
     * value a blob was sealed against. Skipped on the enrollment boot
     * so the seal survives to the next boot. */
    if (!sealed_this_boot)
        tpm_measure_string(TPM_PCR_BOOTLOADER, "ivo: unseal window closed");

#ifdef LVM
    if (lvm_init(ctx) == 0) {
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

    /* Config rollback protection. Best-effort: the efivar can be
     * deleted by anyone with ESP write access. */
    {
        int cv = config_get_version();
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

        if (boot_entry(ctx, chosen) == 0)
            continue;
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