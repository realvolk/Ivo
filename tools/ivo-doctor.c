/* ivo-doctor — read the current install and report what's wrong.
 *
 *   ivo-doctor [--config PATH] [--root DIR] [--subvol-root DIR]
 *              [--esp DIR] [--pub KEY.pub]
 *
 * Prints one line per check, exit 0 if everything is ok, 1 if any
 * check warns or fails. Read-only: does not modify anything. Nothing
 * is reported "ok" unless it was actually checked:
 *
 *   - the config is parsed with the bootloader's own parser;
 *   - the Ed25519 signature is verified only with --pub (otherwise the
 *     check is reported as not done);
 *   - every file an entry boots is hashed beneath --root the way
 *     ivo-sign does it (no symlinks, no "..") and compared;
 *   - entries missing a hash are failures: under SECURE_BOOT the
 *     bootloader refuses them.
 *
 * Firmware Secure Boot (UEFI db/dbx, checks ivo.efi) and Ivo's config
 * signature (checks config.toml) are separate and reported separately.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "config.h"
#include "ed25519.h"
#include "ivo-util.h"

#define CONFIG_MAX (64 * 1024)

void *mm_alloc(size_t size) { return malloc(size); }

static int n_ok;
static int n_warn;
static int n_fail;

static void report(const char *level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void report(const char *level, const char *fmt, ...)
{
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    printf("%s: %s\n", level, msg);
    if (strcmp(level, "ok")   == 0) n_ok++;
    if (strcmp(level, "warn") == 0) n_warn++;
    if (strcmp(level, "fail") == 0) n_fail++;
}

static void check_file(const char *root, const char *subvol_root,
                       const entry_t *e, const char *key, const char *path,
                       const char *recorded)
{
    if (e->is_iso_boot) {
        report("warn", "[%s] %s %s is inside ISO '%s'; not checked here "
               "(use ivo-sign --check --iso IMAGE)", e->name, key, path,
               e->iso_label);
        return;
    }

    const char *base = root;
    const char *sub = NULL;
    if (e->subvol && e->subvol[0]) {
        base = subvol_root ? subvol_root : root;
        sub = e->subvol;
    }

    char err[512];
    int fd = ivo_open_beneath(base, sub, path, err, sizeof(err));
    if (fd < 0) {
        report("fail", "[%s] %s: %s%s%s: %s", e->name, path,
               base[0] ? "under " : "", base, sub ? " (subvol)" : "", err);
        return;
    }

    if (!recorded || !recorded[0]) {
        close(fd);
        report("fail", "[%s] %s has no %s recorded; the bootloader refuses "
               "this entry under SECURE_BOOT", e->name, path, key);
        return;
    }

    char hex[IVO_HASH_HEX_LEN + 1];
    int rc = ivo_sha512_fd(fd, hex);
    close(fd);
    if (rc != 0) {
        report("fail", "[%s] %s: read error: %s", e->name, path, strerror(errno));
        return;
    }
    if (strcmp(hex, recorded) != 0)
        report("fail", "[%s] %s mismatch (%s)", e->name, key, path);
    else
        report("ok", "[%s] %s matches (%s)", e->name, key, path);
}

static void check_config(const uint8_t *cfg, size_t cfg_len, const char *cfg_path,
                         const char *root, const char *subvol_root)
{
    if (config_parse((const char *)cfg, cfg_len) != 0) {
        int line = config_error_line();
        if (line > 0)
            report("fail", "%s:%d: parse error; the bootloader will reject "
                   "this config", cfg_path, line);
        else
            report("fail", "%s: parse error (no entries, or the last entry "
                   "is incomplete)", cfg_path);
        return;
    }

    int n = 0;
    entry_t *entries = config_get_entries(&n);
    report("ok", "%s parses: %d entr%s, default '%s'", cfg_path, n,
           n == 1 ? "y" : "ies", config_get_default()->name);

    for (int i = 0; i < n; i++) {
        const entry_t *e = &entries[i];
        if (e->is_iso_boot && e->subvol && e->subvol[0])
            report("fail", "[%s] iso-boot entry with subvol cannot boot", e->name);
        if (e->is_chainload) {
            check_file(root, subvol_root, e, "cver", e->chainload_path,
                       e->chainload_hash);
            continue;
        }
        check_file(root, subvol_root, e, "kver", e->kernel_path, e->kernel_hash);
        if (e->initrd_path && e->initrd_path[0])
            check_file(root, subvol_root, e, "iver", e->initrd_path,
                       e->initrd_hash);
    }
}

static void check_sig(const uint8_t *cfg, size_t cfg_len, const char *cfg_path,
                      const char *pub_path)
{
    char *sig_path = NULL;
    if (asprintf(&sig_path, "%s.sig", cfg_path) < 0) {
        report("fail", "out of memory");
        return;
    }

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (ivo_read_file(sig_path, 128, &sig, &sig_len) != 0) {
        report("warn", "no config signature (%s: %s); a SECURE_BOOT build "
               "will not boot this config", sig_path, strerror(errno));
        free(sig_path);
        return;
    }
    if (sig_len != ED25519_SIGNATURE_SIZE) {
        report("fail", "%s: %zu bytes, a signature is %d", sig_path, sig_len,
               ED25519_SIGNATURE_SIZE);
        free(sig); free(sig_path);
        return;
    }
    if (!pub_path) {
        report("warn", "config signature present but NOT verified "
               "(pass --pub KEY.pub)");
        free(sig); free(sig_path);
        return;
    }

    uint8_t *pub = NULL;
    size_t pub_len = 0;
    if (ivo_read_file(pub_path, 64, &pub, &pub_len) != 0 ||
        pub_len != ED25519_PUBLIC_KEY_SIZE) {
        report("fail", "%s: not a 32-byte public key", pub_path);
        free(pub); free(sig); free(sig_path);
        return;
    }
    if (ed25519_verify(sig, cfg, cfg_len, pub))
        report("ok", "config signature verifies against %s", pub_path);
    else
        report("fail", "config signature does NOT verify against %s", pub_path);
    free(pub); free(sig); free(sig_path);
}

static void check_esp(const char *esp)
{
    struct stat st;
    if (stat(esp, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report("fail", "ESP not mounted or not a directory: %s", esp);
        return;
    }

    char *efi_path = NULL;
    if (asprintf(&efi_path, "%s/EFI/BOOT/BOOTX64.EFI", esp) < 0) {
        report("fail", "out of memory");
        return;
    }

    if (stat(efi_path, &st) != 0) {
        report("fail", "bootloader not found: %s", efi_path);
    } else {
        report("ok", "bootloader present: %s (%lld bytes; contents not "
               "verified)", efi_path, (long long)st.st_size);
    }
    free(efi_path);
}

/* Firmware Secure Boot: whether the firmware enforces db/dbx on
 * ivo.efi. Says nothing about Ivo's own config signature. */
static void check_firmware_secure_boot(void)
{
    const char *path =
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        report("warn", "firmware Secure Boot state unavailable (not booted "
               "via UEFI?)");
        return;
    }

    uint8_t buf[8];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);

    /* efivarfs: 4 attribute bytes, then the 1-byte value. */
    if (n != 5) {
        report("warn", "firmware Secure Boot state unreadable");
        return;
    }

    if (buf[4] == 1)
        report("ok", "firmware Secure Boot is enabled (firmware checks "
               "ivo.efi)");
    else
        report("warn", "firmware Secure Boot is disabled (firmware does not "
               "check ivo.efi)");
}

int main(int argc, char **argv)
{
    const char *cfg_path = NULL;
    const char *root = NULL;
    const char *subvol_root = NULL;
    const char *esp = NULL;
    const char *pub = NULL;

    for (int i = 1; i < argc; i++) {
        int v = i + 1 < argc;
        if      (strcmp(argv[i], "--config")      == 0 && v) cfg_path = argv[++i];
        else if (strcmp(argv[i], "--root")        == 0 && v) root = argv[++i];
        else if (strcmp(argv[i], "--subvol-root") == 0 && v) subvol_root = argv[++i];
        else if (strcmp(argv[i], "--esp")         == 0 && v) esp = argv[++i];
        else if (strcmp(argv[i], "--pub")         == 0 && v) pub = argv[++i];
        else {
            fprintf(stderr, "ivo-doctor: unknown argument: %s\n", argv[i]);
            fprintf(stderr, "usage: ivo-doctor [--config PATH] [--root DIR] "
                    "[--subvol-root DIR] [--esp DIR] [--pub KEY.pub]\n");
            return 1;
        }
    }

    if (!cfg_path) cfg_path = "/boot/efi/ivo/config.toml";
    if (!esp)      esp      = "/boot/efi";
    if (!root)     root     = "";

    printf("ivo-doctor: checking %s\n\n", cfg_path);

    check_esp(esp);
    check_firmware_secure_boot();

    uint8_t *cfg = NULL;
    size_t cfg_len = 0;
    if (ivo_read_file(cfg_path, CONFIG_MAX + 1, &cfg, &cfg_len) != 0) {
        report("fail", "%s: %s", cfg_path,
               errno == EFBIG ? "larger than the bootloader's 64 KiB limit"
                              : strerror(errno));
    } else if (cfg_len == 0 || cfg_len > CONFIG_MAX) {
        report("fail", "%s: %s", cfg_path, cfg_len ? "larger than the "
               "bootloader's 64 KiB limit" : "empty");
        free(cfg);
    } else {
        check_sig(cfg, cfg_len, cfg_path, pub);
        check_config(cfg, cfg_len, cfg_path, root, subvol_root);
        free(cfg);
    }

    printf("\n%d ok, %d warn, %d fail\n", n_ok, n_warn, n_fail);

    return (n_warn || n_fail) ? 1 : 0;
}
