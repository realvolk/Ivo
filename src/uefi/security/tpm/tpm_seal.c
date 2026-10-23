/* tpm_seal.c — TPM-sealed LUKS passphrase.
 *
 * Unlock: reads the sealed blob from /EFI/ivo/sealed.bin on the ESP,
 * unseals it via the TCG2 SubmitCommand interface, and hands the
 * result to luks_unlock_with_passphrase. Any failure falls through so
 * the caller prompts for a passphrase.
 *
 * Enrollment: if /EFI/ivo/seal-request exists and sealed.bin does not,
 * the passphrase typed at the prompt is sealed to PCR 4 + PCR 7 after
 * an explicit on-screen confirmation, and written to sealed.bin.
 *
 * The ESP is plaintext and attacker-writable. Only the FAT32 driver
 * ever parses it, the blob is validated before use, and the request
 * file alone can't make Ivo seal anything: the user has to type
 * "seal". sealed.bin is never overwritten.
 */

#include "core.h"
#include "fs/fs.h"

#if defined(TPM)

#include "storage/luks.h"
#include "security/wipe.h"
#include "security/tpm/tpm_internal.h"

#define SEALED_PATH   "/EFI/ivo/sealed.bin"
#define REQUEST_PATH  "/EFI/ivo/seal-request"
#define SEAL_MAX      4096
#define SEAL_PCR_MASK ((1u << 4) | (1u << 7))
#define PIN_BUF       (IVO_SEAL_PIN_MAX + 2)
#define ST_REQUEST    1
#define ST_SEALED     2

extern fs_driver_t *fs_current;
extern void *g_tcg2;

static void esp_close(fs_driver_t *saved)
{
    hal_block_io_pop();
    fs_current = saved;
    luks_suspend(0);
}

static int esp_open(fs_driver_t **saved)
{
    if (!hal_esp_available()) return -1;
    *saved = fs_current;
    luks_suspend(1);
    hal_block_io_push_esp();

    block_device_t esp_dev = {
        .lba_start  = 0,
        .lba_count  = hal_esp_sector_count(),
        .block_size = 512,
        .private    = 0,
    };
    if (fs_mount_as(&fs_fat32, &esp_dev) != 0) {
        esp_close(*saved);
        return -1;
    }
    return 0;
}

static int esp_seal_state(void)
{
    fs_driver_t *saved;
    size_t sz = 0;
    int st = 0;
    if (esp_open(&saved) != 0) return 0;
    if (fs_stat(REQUEST_PATH, &sz) == 0) st |= ST_REQUEST;
    if (fs_stat(SEALED_PATH, &sz) == 0)  st |= ST_SEALED;
    esp_close(saved);
    return st;
}

int tpm_seal_try_unlock(boot_context_t *ctx)
{
    if (!g_tcg2) return -1;

    fs_driver_t *saved;
    if (esp_open(&saved) != 0) return -1;

    size_t   blob_len = 0;
    uint8_t *blob     = 0;
    int ok = fs_stat(SEALED_PATH, &blob_len) == 0 &&
             blob_len >= IVO_SEAL_HDR_LEN && blob_len <= SEAL_MAX &&
             (blob = mm_alloc(blob_len)) != 0;
    if (ok) {
        size_t rd = blob_len;
        ok = fs_read(SEALED_PATH, blob, &rd) == 0 && rd == blob_len;
    }
    esp_close(saved);
    if (!ok) {
        if (blob) mm_free(blob);
        return -1;
    }

    char pin[PIN_BUF];
    int  pin_len = 0;
    int  rc = -1;
    int  needs_pin = (blob[5] & IVO_SEAL_FLAG_PIN) != 0;
    if (needs_pin && (blob[6] || blob[7] || blob[8])) {
        mm_free(blob);
        return -1;
    }
    if (needs_pin)
        pin_len = luks_read_passphrase("TPM PIN", pin, sizeof(pin));

    if (pin_len >= 0) {
        uint8_t pass[256];
        size_t  pass_len = sizeof(pass);
        if (tpm2_unseal(blob, blob_len, (const uint8_t *)pin, (size_t)pin_len,
                        pass, &pass_len) == 0)
            rc = luks_unlock_with_passphrase(ctx, pass, pass_len);
        ivo_wipe(pass, sizeof(pass));
    }
    ivo_wipe(pin, sizeof(pin));
    mm_free(blob);
    return rc;
}

int tpm_seal_request_pending(void)
{
    return (esp_seal_state() & ST_REQUEST) != 0;
}

int tpm_seal_write_blob(const uint8_t *blob, size_t len)
{
    if (!blob || len == 0 || len > SEAL_MAX) return -1;
    fs_driver_t *saved;
    size_t sz = 0;
    int rc = -1;
    if (esp_open(&saved) != 0) {
        hal_puts_serial("tpm enroll: esp_open failed\n");
        return -1;
    }
    if (fs_stat(SEALED_PATH, &sz) == 0) {
        hal_puts_serial("tpm enroll: sealed.bin exists, refusing\n");
    } else if (fs_write(SEALED_PATH, blob, len) != 0) {
        hal_puts_serial("tpm enroll: fs_write failed\n");
    } else {
        rc = 0;
    }
    esp_close(saved);
    return rc;
}

static int confirm_seal(void)
{
    con_clear();
    con_puts(
        "TPM enrollment requested (/EFI/ivo/seal-request on the ESP).\n\n"
        "The passphrase just entered will be sealed to this machine's\n"
        "TPM, bound to PCR 4 (firmware-measured boot loader) and PCR 7\n"
        "(Secure Boot state), and stored in /EFI/ivo/sealed.bin. Boots\n"
        "with the same firmware, ivo.efi and Secure Boot keys will then\n"
        "unlock this disk without the passphrase (or with a PIN only).\n\n"
        "The request file is on the unencrypted ESP: anyone who could\n"
        "write to it can bring up this screen. If this was not\n"
        "requested, do not continue.\n\n"
        "Type seal and press Enter to continue; anything else skips: ");

    char buf[4];
    size_t n = 0;
    for (;;) {
        char c = hal_getchar();
        if (c == '\r' || c == '\n') break;
        if (c == '\b' || c == 0x7F) {
            if (n > 0) { n--; con_puts("\b \b"); }
            continue;
        }
        if (c < 0x20 || c > 0x7E) continue;
        if (n < sizeof(buf)) buf[n] = c;
        n++;
        con_putc(c);
    }
    con_puts("\n");
    return n == 4 && memcmp(buf, "seal", 4) == 0;
}

static int read_new_pin(char *pin)
{
    char again[PIN_BUF];
    for (int tries = 0; tries < 3; tries++) {
        int n = luks_read_passphrase(tries ? "PINs differ. New TPM PIN"
                                           : "New TPM PIN (Enter: none)",
                                     pin, PIN_BUF);
        int m = n < 0 ? -1 :
                luks_read_passphrase("Repeat TPM PIN", again, sizeof(again));
        int same = n >= 0 && m == n && memcmp(pin, again, (size_t)n) == 0;
        ivo_wipe(again, sizeof(again));
        if (same) return n;
        ivo_wipe(pin, PIN_BUF);
    }
    return -1;
}

int tpm_seal_maybe_enroll(boot_context_t *ctx)
{
    int st = esp_seal_state();
    if (!(st & ST_REQUEST)) return 0;
    if (st & ST_SEALED) {
        con_puts("TPM: seal-request ignored, /EFI/ivo/sealed.bin exists.\n"
                 "     Delete it from the running system to re-enroll.\n");
        return 0;
    }
    if (!g_tcg2) {
        con_puts("TPM: seal-request ignored, no TPM.\n");
        return 0;
    }

    char pass[LUKS_PASS_MAX];
    int n = luks_read_passphrase("Passphrase", pass, sizeof(pass));
    if (n <= 0 ||
        luks_unlock_with_passphrase(ctx, (const uint8_t *)pass, (size_t)n) != 0) {
        con_puts("Wrong passphrase; not sealing.\n");
        ivo_wipe(pass, sizeof(pass));
        return 0;
    }

    if (n > IVO_SEAL_SECRET_MAX) {
        con_puts("TPM: passphrase too long to seal (max 128 bytes).\n");
    } else if (!confirm_seal()) {
        con_puts("Not sealing.\n");
    } else {
        char pin[PIN_BUF];
        int  pin_len = read_new_pin(pin);
        uint8_t blob[SEAL_MAX];
        size_t  blob_len = 0;

        if (pin_len < 0) {
            con_puts("TPM: PIN entry failed; not sealing.\n");
            hal_puts_serial("tpm enroll: pin entry failed\n");
        } else if (tpm2_seal_create((const uint8_t *)pass, (size_t)n,
                                    (const uint8_t *)pin, (size_t)pin_len,
                                    SEAL_PCR_MASK,
                                    blob, &blob_len, sizeof(blob)) != 0) {
            con_puts("TPM: seal failed.\n");
            hal_puts_serial("tpm enroll: seal failed\n");
        } else if (tpm_seal_write_blob(blob, blob_len) != 0) {
            con_puts("TPM: could not write /EFI/ivo/sealed.bin.\n");
            hal_puts_serial("tpm enroll: write failed\n");
        } else {
            con_puts("Sealed to the TPM (PCR 4+7). Delete "
                     "/EFI/ivo/seal-request.\n");
            hal_getchar_timeout(3000);
            hal_puts_serial("tpm enroll: sealed ok\n");
        }
        ivo_wipe(pin, sizeof(pin));
    }

    ivo_wipe(pass, sizeof(pass));
    return 1;
}

#else /* !TPM */

int tpm_seal_request_pending(void)          { return 0; }
int tpm_seal_write_blob(const uint8_t *b, size_t l) { (void)b; (void)l; return -1; }
int tpm_seal_maybe_enroll(boot_context_t *c) { (void)c; return 0; }

int tpm_seal_try_unlock(boot_context_t *ctx)
{
    (void)ctx;
    return -1;
}

#endif /* TPM */
