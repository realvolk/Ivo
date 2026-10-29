#include "core.h"
#include "security/wipe.h"
#include "security/efivars.h"
#include "security/secure_boot.h"
#include "boot/config.h"
#include "storage/luks.h"
#include "storage/lvm.h"

#include <string.h>

extern int tpm_available(void);

#define SHELL_MAX_CMD   256
#define SHELL_MAX_PATH  256
#define SHELL_CAT_LIMIT (32 * 1024)

static uint8_t cat_buf[SHELL_CAT_LIMIT];

static int fs_access_allowed(boot_context_t *ctx);

static const char *skip_spaces(const char *p)
{
    while (*p == ' ') p++;
    return p;
}

static void put_safe(const char *s)
{
    for (; *s; s++) con_putc((*s < 0x20 || *s > 0x7E) ? '.' : *s);
}

static void print_uint(uint64_t n)
{
    char buf[24];
    int i = 0;
    if (n == 0) buf[i++] = '0';
    while (n > 0) { buf[i++] = '0' + (n % 10); n /= 10; }
    for (int a = 0, b = i - 1; a < b; a++, b--) {
        char t = buf[a]; buf[a] = buf[b]; buf[b] = t;
    }
    buf[i] = '\0';
    con_puts(buf);
}

static void print_size_padded(uint64_t n, int width)
{
    char buf[24];
    int i = 0;
    if (n == 0) buf[i++] = '0';
    while (n > 0) { buf[i++] = '0' + (n % 10); n /= 10; }
    for (int a = 0, b = i - 1; a < b; a++, b--) {
        char t = buf[a]; buf[a] = buf[b]; buf[b] = t;
    }
    for (int p = 0; p < width - i; p++) con_putc(' ');
    for (int k = 0; k < i; k++) con_putc(buf[k]);
}

static void print_oct(uint32_t n)
{
    char buf[16];
    int i = 0;
    if (n == 0) buf[i++] = '0';
    while (n > 0) { buf[i++] = '0' + (n & 7); n >>= 3; }
    for (int a = 0, b = i - 1; a < b; a++, b--) {
        char t = buf[a]; buf[a] = buf[b]; buf[b] = t;
    }
    buf[i] = '\0';
    con_puts(buf);
}

static void cmd_help(void)
{
    con_puts("  ls [-l] [path]   list directory (default: /)\n");
    con_puts("  cat <path>       print a text file\n");
    con_puts("  stat <path>      show file size and type\n");
    con_puts("  check            verify config file hashes\n");
    con_puts("  info             show current bootloader state\n");
    con_puts("  entries          list configured boot entries\n");
    con_puts("  boot <name>      boot an entry by name\n");
    con_puts("  disk             show boot disk size\n");
    con_puts("  store-health     firmware version store status\n");
    con_puts("  clear            clear the screen\n");
    con_puts("  reboot           reboot the machine\n");
    con_puts("  halt             halt the machine\n");
    con_puts("  exit             leave the shell\n");
    con_puts("  help             this message\n");
}

static void join_path(char *full, size_t full_cap,
                      const char *target, const char *name)
{
    size_t tp = 0, np = 0;
    while (target[tp] && tp < full_cap - 1) { full[tp] = target[tp]; tp++; }
    if (tp > 0 && full[tp - 1] != '/') {
        if (tp < full_cap - 1) full[tp++] = '/';
    }
    while (name[np] && tp + np < full_cap - 1) {
        full[tp + np] = name[np];
        np++;
    }
    full[tp + np] = '\0';
}

static void cmd_ls(const char *path)
{
    const char *target = path && *path ? path : "/";
    void *dir;
    if (fs_opendir(target, &dir) != 0) {
        con_puts("cannot open ");
        put_safe(target);
        con_puts("\n");
        return;
    }
    char name[SHELL_MAX_PATH];
    while (fs_readdir(dir, name, sizeof(name)) > 0) {
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        char full[SHELL_MAX_PATH * 2];
        join_path(full, sizeof(full), target, name);

        uint32_t mode = 0;
        struct stat st;
        if (fs_current && fs_current->stat) {
            if (fs_current->stat(full, &st) == 0) mode = st.mode;
        }
        int is_dir = (mode & 0170000) == 0040000;

        put_safe(name);
        if (is_dir) con_puts("/");
        con_puts("\n");
    }
    fs_closedir(dir);
}

static void cmd_ls_long(const char *path)
{
    const char *target = path && *path ? path : "/";
    void *dir;
    if (fs_opendir(target, &dir) != 0) {
        con_puts("cannot open ");
        put_safe(target);
        con_puts("\n");
        return;
    }
    char name[SHELL_MAX_PATH];
    while (fs_readdir(dir, name, sizeof(name)) > 0) {
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        char full[SHELL_MAX_PATH * 2];
        join_path(full, sizeof(full), target, name);

        uint32_t mode = 0;
        uint64_t size = 0;
        struct stat st;
        if (fs_current && fs_current->stat) {
            if (fs_current->stat(full, &st) == 0) {
                mode = st.mode;
                size = st.size;
            }
        }

        uint32_t fmt = mode & 0170000;
        char type_ch = '-';
        if (fmt == 0040000) type_ch = 'd';
        else if (fmt == 0120000) type_ch = 'l';

        char perms[11];
        perms[0]  = type_ch;
        perms[1]  = (mode & 0400) ? 'r' : '-';
        perms[2]  = (mode & 0200) ? 'w' : '-';
        perms[3]  = (mode & 0100) ? 'x' : '-';
        perms[4]  = (mode & 0040) ? 'r' : '-';
        perms[5]  = (mode & 0020) ? 'w' : '-';
        perms[6]  = (mode & 0010) ? 'x' : '-';
        perms[7]  = (mode & 0004) ? 'r' : '-';
        perms[8]  = (mode & 0002) ? 'w' : '-';
        perms[9]  = (mode & 0001) ? 'x' : '-';
        perms[10] = '\0';

        con_puts(perms);
        con_puts(" ");
        print_size_padded(size, 10);
        con_puts("  ");
        put_safe(name);
        if (type_ch == 'd') con_puts("/");
        con_puts("\n");
    }
    fs_closedir(dir);
}

static void cmd_cat(const char *path)
{
    if (!fs_current || !fs_current->stat) {
        con_puts("no stat support\n");
        return;
    }
    struct stat st;
    if (fs_current->stat(path, &st) != 0) {
        con_puts("not found: ");
        put_safe(path);
        con_puts("\n");
        return;
    }
    uint32_t fmt = st.mode & 0170000;
    if (fmt == 0040000) {
        con_puts("is a directory\n");
        return;
    }
    if (fmt != 0100000) {
        con_puts("not a regular file\n");
        return;
    }
    if (st.size == 0) {
        con_puts("(empty)\n");
        return;
    }
    if (st.size > SHELL_CAT_LIMIT) {
        con_puts("refusing: file is ");
        print_uint(st.size);
        con_puts(" bytes, limit is ");
        print_uint(SHELL_CAT_LIMIT);
        con_puts("\n");
        return;
    }

    size_t len = (size_t)st.size;
    uint8_t *buf = cat_buf;
    size_t got = len;
    if (fs_read(path, buf, &got) != 0) {
        con_puts("read failed\n");
        return;
    }
    if (got != len) {
        con_puts("short read\n");
        ivo_wipe(buf, len);
        return;
    }

    size_t check = got < 256 ? got : 256;
    for (size_t i = 0; i < check; i++) {
        if (buf[i] == 0) {
            con_puts("refusing: file appears to be binary\n");
            ivo_wipe(buf, len);
            return;
        }
    }

    for (size_t i = 0; i < got; i++) {
        char c = (char)buf[i];
        if ((c < 0x20 && c != '\n' && c != '\t') || c > 0x7E) c = '.';
        con_putc(c);
    }
    if (got == 0 || buf[got - 1] != '\n') con_putc('\n');

    ivo_wipe(buf, len);
}

static void cmd_stat(const char *path)
{
    struct stat st;
    if (!fs_current || !fs_current->stat) {
        con_puts("no stat support\n");
        return;
    }
    if (fs_current->stat(path, &st) != 0) {
        con_puts("not found: ");
        put_safe(path);
        con_puts("\n");
        return;
    }
    con_puts("size: ");
    print_uint(st.size);
    con_puts("\ntype: ");
    uint32_t fmt = st.mode & 0170000;
    if (fmt == 0040000)      con_puts("directory");
    else if (fmt == 0100000) con_puts("regular file");
    else if (fmt == 0120000) con_puts("symlink");
    else                     con_puts("other");
    con_puts("\nmode: 0");
    print_oct(st.mode & 07777);
    con_puts("\n");
}

static void cmd_entries(void)
{
    int count = 0;
    entry_t *entries = config_get_entries(&count);
    if (count == 0) {
        con_puts("(none)\n");
        return;
    }
    for (int i = 0; i < count; i++) {
        con_puts("  ");
        put_safe(entries[i].name);
        if (entries[i].kernel_path) {
            con_puts(" -> ");
            put_safe(entries[i].kernel_path);
        }
        con_puts("\n");
    }
}

static int cmd_boot(boot_context_t *ctx, const char *name)
{
    int count = 0;
    entry_t *entries = config_get_entries(&count);
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].name, name) == 0) {
            boot_entry(ctx, &entries[i]);
            return 0;
        }
    }
    con_puts("no entry named '");
    put_safe(name);
    con_puts("'\n");
    cmd_entries();
    return 0;
}

static void cmd_store_health(void)
{
    int nv_v = -1;
    int nv_rc = tpm_nv_fwver_read(&nv_v);
    int uv_v = ivo_fwver_get();

    con_puts("tier: ");
    con_puts(core_fwver_tier() ? "TPM NV" : "UEFI variable");
    con_puts("\nnv:   ");
    if (nv_rc == -2)        con_puts("corrupt");
    else if (nv_rc != 0)    con_puts("-");
    else                    print_uint((uint64_t)nv_v);
    con_puts("\nuvar: ");
    if (uv_v == -2)         con_puts("corrupt");
    else if (uv_v < 0)      con_puts("-");
    else                    print_uint((uint64_t)uv_v);
    con_puts("\n");
}

static void cmd_disk(void)
{
    uint64_t total_sectors = 0;
    uint32_t sector_size = 512;
    hal_get_disk_info(&total_sectors, &sector_size);
    if (total_sectors == 0) {
        con_puts("disk info not available\n");
        return;
    }
    uint64_t bytes = total_sectors * sector_size;
    uint64_t mb = bytes / (1024 * 1024);
    con_puts("disk: ");
    print_uint(mb);
    con_puts(" MB (");
    print_uint(total_sectors);
    con_puts(" sectors of ");
    print_uint(sector_size);
    con_puts(" bytes)\n");
}

static void cmd_info(void)
{
    con_puts("filesystem:    ");
    if      (fs_current == &fs_ext4)    con_puts("ext4");
    else if (fs_current == &fs_btrfs)   con_puts("btrfs");
    else if (fs_current == &fs_fat32)   con_puts("fat32");
    else if (fs_current == &fs_iso9660) con_puts("iso9660");
    else if (fs_current)                con_puts("(unknown)");
    else                                con_puts("(none)");
    con_puts("\n");

    con_puts("luks:          ");
    con_puts(luks_active() ? "active" : "inactive");
    con_puts("\n");

#ifdef LVM
    con_puts("lvm:           ");
    con_puts(lvm_active() ? "active" : "inactive");
    con_puts("\n");
#endif

#ifdef TPM
    con_puts("tpm:           ");
    con_puts(tpm_available() ? "available" : "unavailable");
    con_puts("\n");
#else
    con_puts("tpm:           not compiled in\n");
#endif

    con_puts("firmware tier: ");
    con_puts(core_fwver_tier() ? "TPM NV" : "UEFI variable");
    con_puts("\n");

    con_puts("tpm unsealed:  ");
    con_puts(core_unlocked_without_passphrase() ? "yes" : "no");
    con_puts("\n");

    con_puts("boot partition: ");
    con_puts(hal_boot_partition_decided ? "decided" : "default");
    con_puts("\n");

    uint64_t total = 0;
    uint32_t ss = 512;
    hal_get_disk_info(&total, &ss);
    con_puts("disk:          ");
    print_uint(total);
    con_puts(" sectors of ");
    print_uint(ss);
    con_puts(" bytes\n");

#ifdef SECURE_BOOT
    con_puts("secure boot:   enabled (config signed, hashes required)\n");
#else
    con_puts("secure boot:   disabled (config unverified)\n");
#endif

    int cv = config_get_version();
    con_puts("config version: ");
    if (cv < 0) con_puts("(none)");
    else print_uint((uint64_t)cv);
    con_puts("\n");
}

static int check_file(const char *path, const char *expected)
{
    if (!path || !*path) {
        con_puts("  (no path in config)\n");
        return 0;
    }
    if (!fs_current || !fs_current->stat) {
        con_puts("  ");
        put_safe(path);
        con_puts("  (no stat support)\n");
        return -1;
    }

    struct stat st;
    if (fs_current->stat(path, &st) != 0) {
        con_puts("  ");
        put_safe(path);
        con_puts("  MISSING\n");
        return -1;
    }
    if ((st.mode & 0170000) != 0100000) {
        con_puts("  ");
        put_safe(path);
        con_puts("  (not a regular file)\n");
        return -1;
    }
    if (st.size == 0) {
        con_puts("  ");
        put_safe(path);
        con_puts("  EMPTY\n");
        return -1;
    }

    if (!expected || strlen(expected) != SB_HASH_HEX_LEN) {
        con_puts("  ");
        put_safe(path);
        con_puts("  (no hash in config)\n");
        return 0;
    }

    size_t len = (size_t)st.size;
    uint8_t *buf = mm_alloc(len);
    if (!buf) {
        con_puts("  ");
        put_safe(path);
        con_puts("  NO MEMORY (");
        print_uint(len);
        con_puts(" bytes)\n");
        return -1;
    }

    size_t got = len;
    int rc = -1;
    if (fs_read(path, buf, &got) != 0 || got != len) {
        con_puts("  ");
        put_safe(path);
        con_puts("  READ FAILED\n");
    } else {
        char hex[SB_HASH_HEX_BUF];
        sb_hash_buffer(buf, len, hex);
        con_puts("  ");
        put_safe(path);
        if (sb_hash_matches(hex, expected)) {
            con_puts("  OK\n");
            rc = 0;
        } else {
            con_puts("  FAIL\n");
            con_puts("    expected ");
            con_puts(expected);
            con_puts("\n    actual   ");
            con_puts(hex);
            con_puts("\n");
        }
    }

    ivo_wipe(buf, len);
    mm_free(buf);
    return rc;
}

static void cmd_check(boot_context_t *ctx)
{
    if (!fs_access_allowed(ctx)) return;

    int count = 0;
    entry_t *entries = config_get_entries(&count);
    if (count == 0) {
        con_puts("(no entries)\n");
        return;
    }

    int checked  = 0;
    int failed   = 0;
    int missing  = 0;

    for (int i = 0; i < count; i++) {
        entry_t *e = &entries[i];
        con_puts("entry ");
        put_safe(e->name);
        con_puts(":\n");

        if (e->is_iso_boot) {
            con_puts("  iso-boot: not checked by this command\n");
            continue;
        }

        int has_all = 1;
        if (e->is_chainload) {
            if (!e->chainload_hash || !e->chainload_hash[0]) has_all = 0;
        } else {
            if (!e->kernel_hash || !e->kernel_hash[0]) has_all = 0;
            if (e->initrd_path && e->initrd_path[0] &&
                (!e->initrd_hash || !e->initrd_hash[0])) has_all = 0;
        }

#ifdef SECURE_BOOT
        if (!has_all) {
            con_puts("  missing hash: refused under SECURE_BOOT=1\n");
            missing++;
        }
#else
        (void)has_all;
#endif

        if (e->is_chainload) {
            if (e->chainload_hash && e->chainload_hash[0]) {
                checked++;
                if (check_file(e->chainload_path, e->chainload_hash) != 0)
                    failed++;
            }
            continue;
        }

        if (e->kernel_hash && e->kernel_hash[0]) {
            checked++;
            if (check_file(e->kernel_path, e->kernel_hash) != 0)
                failed++;
        }
        if (e->initrd_path && e->initrd_path[0] &&
            e->initrd_hash && e->initrd_hash[0]) {
            checked++;
            if (check_file(e->initrd_path, e->initrd_hash) != 0)
                failed++;
        }
    }

    con_puts("\n");
    if (missing > 0) {
        con_puts("missing hash: ");
        print_uint((uint64_t)missing);
        con_puts(" entr");
        con_puts(missing == 1 ? "y" : "ies");
        con_puts(" (would be refused at boot)\n");
    }
    if (failed == 0 && missing == 0) {
        con_puts("all ");
        print_uint((uint64_t)checked);
        con_puts(" file");
        if (checked != 1) con_puts("s");
        con_puts(" OK\n");
    } else if (failed > 0) {
        con_puts("FAILED: ");
        print_uint((uint64_t)failed);
        con_puts(" of ");
        print_uint((uint64_t)checked);
        con_puts(" file");
        if (checked != 1) con_puts("s");
        con_puts("\n");
    }
}

static int fs_access_allowed(boot_context_t *ctx)
{
    if (!core_unlocked_without_passphrase())
        return 1;

    char pass[512];
    int n = con_read_secret("LUKS passphrase for shell access", pass,
                            sizeof(pass), '*');
    int ok = n > 0 &&
             luks_unlock_with_passphrase(ctx, (const uint8_t *)pass,
                                         (size_t)n) == 0;
    ivo_wipe(pass, sizeof(pass));
    con_clear();
    if (!ok) {
        con_puts("Wrong passphrase. Filesystem commands stay locked.\n");
        return 0;
    }
    core_passphrase_proven();
    return 1;
}

void shell_enter(boot_context_t *ctx)
{
    char cmd[SHELL_MAX_CMD];
    int idx = 0;

    con_clear();
    con_puts("Ivo Shell. 'help' for commands, 'exit' to return.\n");

    while (1) {
        #define SHELL_REDRAW()                                                  \
            do {                                                                \
                con_putc('\r');                                                 \
                con_clear_row();                                                \
                con_puts("> ");                                                 \
                for (int _i = 0; _i < idx; _i++) con_putc(cmd[_i]);             \
            } while (0)

        con_puts("> ");
        ivo_wipe(cmd, sizeof(cmd));
        idx = 0;
        while (1) {
            char c = hal_getchar();
            if (c == '\r' || c == '\n') {
                con_putc('\n');
                cmd[idx] = '\0';
                break;
            }
            if (c == '\b' || c == 0x7F) {
                if (idx > 0) {
                    idx--;
                    SHELL_REDRAW();
                }
                continue;
            }
            if (c < 0x20 || c > 0x7E) continue;
            if (idx < SHELL_MAX_CMD - 1) {
                cmd[idx++] = c;
                SHELL_REDRAW();
            }
        }

        #undef SHELL_REDRAW

        if (cmd[0] == '\0') continue;

        if (strcmp(cmd, "help") == 0) {
            cmd_help();
        } else if (strncmp(cmd, "ls -l ", 6) == 0) {
            if (fs_access_allowed(ctx)) cmd_ls_long(skip_spaces(cmd + 6));
        } else if (strcmp(cmd, "ls -l") == 0) {
            if (fs_access_allowed(ctx)) cmd_ls_long("/");
        } else if (strncmp(cmd, "ls ", 3) == 0) {
            if (fs_access_allowed(ctx)) cmd_ls(skip_spaces(cmd + 3));
        } else if (strcmp(cmd, "ls") == 0) {
            if (fs_access_allowed(ctx)) cmd_ls("/");
        } else if (strncmp(cmd, "cat ", 4) == 0) {
            if (fs_access_allowed(ctx)) cmd_cat(skip_spaces(cmd + 4));
        } else if (strncmp(cmd, "stat ", 5) == 0) {
            if (fs_access_allowed(ctx)) cmd_stat(skip_spaces(cmd + 5));
        } else if (strcmp(cmd, "check") == 0) {
            cmd_check(ctx);
        } else if (strcmp(cmd, "info") == 0) {
            cmd_info();
        } else if (strcmp(cmd, "entries") == 0) {
            cmd_entries();
        } else if (strncmp(cmd, "boot ", 5) == 0) {
            cmd_boot(ctx, skip_spaces(cmd + 5));
        } else if (strcmp(cmd, "disk") == 0) {
            cmd_disk();
        } else if (strcmp(cmd, "store-health") == 0) {
            cmd_store_health();
        } else if (strcmp(cmd, "clear") == 0) {
            con_clear();
        } else if (strcmp(cmd, "reboot") == 0) {
            hal_reboot();
        } else if (strcmp(cmd, "halt") == 0) {
            halt();
        } else if (strcmp(cmd, "exit") == 0) {
            ivo_wipe(cmd, sizeof(cmd));
            return;
        } else {
            con_puts("unknown: ");
            put_safe(cmd);
            con_puts("\n");
        }
    }
}