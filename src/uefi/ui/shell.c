#include "core.h"
#include "security/wipe.h"

#define SHELL_MAX_CMD   256
#define SHELL_MAX_PATH  256
#define SHELL_CAT_LIMIT (32 * 1024)

static uint8_t cat_buf[SHELL_CAT_LIMIT];
static int fs_access_granted;

static const char *skip_spaces(const char *p)
{
    while (*p == ' ') p++;
    return p;
}

/* On-disk names can carry control bytes; show them as '.'. */
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

/* Octal, no prefix. Zero prints as "0". */
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
    con_puts("  ls [path]     list directory (default: /)\n");
    con_puts("  cat <path>    print a text file\n");
    con_puts("  stat <path>   show file size and type\n");
    con_puts("  entries       list configured boot entries\n");
    con_puts("  boot <name>   boot an entry by name\n");
    con_puts("  disk          show boot disk size\n");
    con_puts("  clear         clear the screen\n");
    con_puts("  reboot        reboot the machine\n");
    con_puts("  halt          halt the machine\n");
    con_puts("  exit          return to the boot menu\n");
    con_puts("  help          this message\n");
}

static void cmd_ls(const char *path)
{
    const char *target = path && *path ? path : "/";
    void *dir;
    if (fs_opendir(target, &dir) != 0) {
        con_puts("cannot open ");
        con_puts(target);
        con_puts("\n");
        return;
    }
    char name[SHELL_MAX_PATH];
    while (fs_readdir(dir, name, sizeof(name)) > 0) {
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        /* stat the entry so directories can get a trailing slash. */
        char full[SHELL_MAX_PATH * 2];
        size_t tp = 0, np = 0;
        while (target[tp] && tp < SHELL_MAX_PATH - 1) { full[tp] = target[tp]; tp++; }
        if (tp > 0 && full[tp - 1] != '/') full[tp++] = '/';
        while (name[np] && tp + np < sizeof(full) - 1) { full[tp + np] = name[np]; np++; }
        full[tp + np] = '\0';

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

static void cmd_cat(const char *path)
{
    size_t len = 0;
    if (fs_stat(path, &len) != 0) {
        con_puts("not found: ");
        con_puts(path);
        con_puts("\n");
        return;
    }
    if (len == 0) {
        con_puts("(empty)\n");
        return;
    }
    if (len > SHELL_CAT_LIMIT) {
        con_puts("refusing: file is ");
        print_uint(len);
        con_puts(" bytes, limit is ");
        print_uint(SHELL_CAT_LIMIT);
        con_puts("\n");
        return;
    }

    uint8_t *buf = cat_buf;
    size_t got = len;
    if (fs_read(path, buf, &got) != 0) {
        con_puts("read failed\n");
        return;
    }

    /* Refuse to dump binary: any NUL in the first 256 bytes. */
    size_t check = got < 256 ? got : 256;
    for (size_t i = 0; i < check; i++) {
        if (buf[i] == 0) {
            con_puts("refusing: file appears to be binary\n");
            return;
        }
    }

    /* Printable ASCII, newline and tab only: a file must not be able
     * to drive the console with escape or control sequences. */
    for (size_t i = 0; i < got; i++) {
        char c = (char)buf[i];
        if ((c < 0x20 && c != '\n' && c != '\t') || c > 0x7E) c = '.';
        con_putc(c);
    }
    if (got == 0 || buf[got - 1] != '\n') con_putc('\n');
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
        con_puts(path);
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
        con_puts(entries[i].name);
        if (entries[i].kernel_path) {
            con_puts(" -> ");
            con_puts(entries[i].kernel_path);
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
    con_puts(name);
    con_puts("'\n");
    cmd_entries();
    return 0;
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

/* If the disk was opened by the TPM, the person at the keyboard has
 * not shown they know the passphrase, and the shell must not become
 * a way to read the decrypted filesystem. Ask for it once. */
static int fs_access_allowed(boot_context_t *ctx)
{
    if (fs_access_granted || !core_unlocked_without_passphrase())
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
    fs_access_granted = 1;
    return 1;
}

void shell_enter(boot_context_t *ctx)
{
    char cmd[SHELL_MAX_CMD];
    int idx = 0;

    con_puts("\nIvo Shell. 'help' for commands, 'exit' to return.\n");

    while (1) {
        /* Redraw the prompt + typed line on every keystroke. Firmware
         * consoles (OVMF GraphicsConsoleDxe) don't repaint cells on
         * a bare cursor move, so \b alone leaves stale characters on
         * screen. Writing the whole line every time fixes that. */
        #define SHELL_REDRAW()                                                  \
            do {                                                                \
                con_putc('\r');                                                 \
                con_puts("> ");                                                 \
                for (int _i = 0; _i < idx; _i++) con_putc(cmd[_i]);             \
                for (int _i = 0; _i < 8; _i++) con_putc(' ');                   \
                con_putc('\r');                                                 \
                con_puts("> ");                                                 \
                for (int _i = 0; _i < idx; _i++) con_putc(cmd[_i]);             \
            } while (0)

        con_puts("> ");
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
        } else if (strcmp(cmd, "ls") == 0) {
            if (fs_access_allowed(ctx)) cmd_ls("/");
        } else if (strncmp(cmd, "ls ", 3) == 0) {
            if (fs_access_allowed(ctx)) cmd_ls(skip_spaces(cmd + 3));
        } else if (strncmp(cmd, "cat ", 4) == 0) {
            if (fs_access_allowed(ctx)) cmd_cat(skip_spaces(cmd + 4));
        } else if (strncmp(cmd, "stat ", 5) == 0) {
            if (fs_access_allowed(ctx)) cmd_stat(skip_spaces(cmd + 5));
        } else if (strcmp(cmd, "entries") == 0) {
            cmd_entries();
        } else if (strncmp(cmd, "boot ", 5) == 0) {
            cmd_boot(ctx, skip_spaces(cmd + 5));
        } else if (strcmp(cmd, "disk") == 0) {
            cmd_disk();
        } else if (strcmp(cmd, "clear") == 0) {
            con_clear();
        } else if (strcmp(cmd, "reboot") == 0) {
            hal_reboot();
        } else if (strcmp(cmd, "halt") == 0) {
            halt();
        } else if (strcmp(cmd, "exit") == 0) {
            return;
        } else {
            con_puts("unknown: ");
            con_puts(cmd);
            con_puts("\n");
        }
    }
}