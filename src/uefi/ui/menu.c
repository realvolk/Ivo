#include "core.h"
#include "ui/theme.h"
#include "ui/gfx.h"
#include "ui/text.h"
#include "ui/frame.h"
#include "security/efivars.h"
#include "security/password.h"

#define MENU_MAX_VISIBLE  16
#define CMDLINE_EDIT_MAX  256

static int visible_idx[MENU_MAX_VISIBLE];
static int visible_count;

static int entry_predicate_ok(const entry_t *e)
{
    if (!e->if_exists_path) return 1;
    size_t sz = 0;
    return fs_stat(e->if_exists_path, &sz) == 0;
}

static void build_visible(entry_t *entries, int count)
{
    visible_count = 0;
    for (int i = 0; i < count && visible_count < MENU_MAX_VISIBLE; i++) {
        if (entries[i].hidden) continue;
        if (!entry_predicate_ok(&entries[i])) continue;
        visible_idx[visible_count++] = i;
    }
}

static uint32_t entry_accent(const entry_t *e)
{
    if (e->is_chainload) return theme_current.accent;
    if (e->is_iso_boot)  return theme_current.warn_fg;
    return 0;
}

static void draw_entry(int row, entry_t *e, int selected, int is_default)
{
    char buf[128];
    int i = 0;
    for (const char *p = e->name; *p && i < 100; p++) buf[i++] = *p;
    if (is_default) {
        const char *s = " (default)";
        for (; *s && i < 120; s++) buf[i++] = *s;
    }
    buf[i] = '\0';
    frame_row_sel(row, buf, selected, entry_accent(e));
}

static void draw_footer(int timeout, int remaining_s)
{
    char left[64];
    const char *hints = "Arrows select   Enter boot   Esc shell";
    int i = 0;
    for (const char *p = hints; *p && i < 60; p++) left[i++] = *p;
    left[i] = '\0';

    char right[24];
    int r = 0;
    if (timeout > 0) {
        const char *pre = "Auto in ";
        for (const char *p = pre; *p; p++) right[r++] = *p;
        char num[8];
        int ni = 0;
        int n = remaining_s;
        if (n == 0) num[ni++] = '0';
        while (n > 0) { num[ni++] = '0' + (n % 10); n /= 10; }
        for (int a = 0, b = ni - 1; a < b; a++, b--) {
            char t = num[a]; num[a] = num[b]; num[b] = t;
        }
        for (int k = 0; k < ni; k++) right[r++] = num[k];
        right[r++] = 's';
    }
    right[r] = '\0';

    frame_row_clear_right(FRAME_ROWS - 1, 96);

    frame_row_2col(FRAME_ROWS - 1, left, right[0] ? right : 0,
                   theme_current.foot_fg, theme_current.foot_fg);
}

static void redraw_row(entry_t *entries, int row, int selected, entry_t *def)
{
    frame_row_clear(row);
    entry_t *e = &entries[visible_idx[row]];
    draw_entry(row, e, selected, e == def);
}

static void draw_menu(entry_t *entries, int selected,
                      entry_t *def, int timeout, int remaining_s)
{
    frame_begin(theme_current.header);
    for (int i = 0; i < MENU_MAX_VISIBLE; i++) {
        if (i < visible_count) {
            entry_t *e = &entries[visible_idx[i]];
            draw_entry(i, e, i == selected, e == def);
        }
    }
    frame_sep(FRAME_ROWS - 2);
    draw_footer(timeout, remaining_s);
    frame_end();
}

static int entry_timeout(entry_t *e)
{
    if (e->timeout >= 0) return e->timeout;
    return config_get_timeout();
}

static void set_cmdline(entry_t *e, const char *s)
{
    if (e->cmdline) mm_free(e->cmdline);
    size_t n = strlen(s);
    char *p = mm_alloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    e->cmdline = p;
}

static void cmdline_editor_fb(entry_t *e)
{
    char buf[CMDLINE_EDIT_MAX];
    size_t len = 0;
    if (e->cmdline) {
        size_t n = strlen(e->cmdline);
        if (n >= sizeof(buf)) {
            frame_content_clear();
            frame_row(1, "cmdline too long to edit; not changed.",
                      theme_current.error_fg);
            frame_row(2, "Press any key to return.",
                      theme_current.fg_dim);
            while (hal_getchar_timeout(10) == 0) { }
            return;
        }
        memcpy(buf, e->cmdline, n);
        len = n;
    }

    char title[128];
    int i = 0;
    const char *pre = "Editing: ";
    for (const char *p = pre; *p && i < 100; p++) title[i++] = *p;
    for (const char *p = e->name; *p && i < 120; p++) title[i++] = *p;
    title[i] = '\0';
    frame_title(title);

    while (1) {
        frame_content_clear();
        frame_row(0, "Enter: save    Esc: cancel", theme_current.fg_dim);

        char line[CMDLINE_EDIT_MAX + 4];
        int k = 0;
        line[k++] = '>';
        line[k++] = ' ';
        for (size_t j = 0; j < len; j++) line[k++] = buf[j];
        line[k++] = '_';
        line[k] = '\0';
        frame_row(2, line, theme_current.fg);

        char c = hal_getchar_timeout(10);
        if (c == 0) continue;

        if (c == '\r' || c == '\n') {
            buf[len] = '\0';
            set_cmdline(e, buf);
            return;
        }
        if (c == 0x1B) return;
        if (c == '\b' || c == 0x7F) {
            if (len > 0) len--;
            continue;
        }
        if (c >= 0x20 && c <= 0x7E) {
            if (len + 1 < sizeof(buf)) buf[len++] = c;
        }
    }
}

static void cmdline_editor_text(entry_t *e)
{
    int lh = text_height();
    int P  = theme_current.padding;

    con_clear();
    con_puts("Editing cmdline for: ");
    con_puts(e->name);
    con_puts("\n\n> ");

    int input_x = P + text_width("> ");
    int input_y = P + 2 * lh;

    char buf[CMDLINE_EDIT_MAX];
    size_t len = 0;
    if (e->cmdline) {
        size_t n = strlen(e->cmdline);
        if (n >= sizeof(buf)) {
            con_puts("\n\ncmdline too long to edit; not changed.\n");
            con_puts("Press any key.\n");
            while (hal_getchar_timeout(10) == 0) { }
            con_clear();
            return;
        }
        memcpy(buf, e->cmdline, n);
        len = n;
    }

    for (size_t i = 0; i < len; i++) con_putc(buf[i]);
    con_putc('_');

    con_puts("\n\nEnter: save   Esc: cancel\n");

    for (;;) {
        char c = hal_getchar_timeout(10);
        if (c == 0) continue;

        if (c == '\r' || c == '\n') {
            buf[len] = '\0';
            set_cmdline(e, buf);
            con_clear();
            return;
        }
        if (c == 0x1B) {
            con_clear();
            return;
        }

        if (c == '\b' || c == 0x7F) {
            if (len > 0) len--;
        } else if (c >= 0x20 && c <= 0x7E) {
            if (len + 1 < sizeof(buf)) buf[len++] = c;
        } else {
            continue;
        }

        con_set_pos(input_x, input_y);
        con_clear_row();
        for (size_t i = 0; i < len; i++) con_putc(buf[i]);
        con_putc('_');
    }
}

static void cmdline_editor(entry_t *e)
{
    if (gfx_available() && !gfx_text_mode())
        cmdline_editor_fb(e);
    else
        cmdline_editor_text(e);
}

static entry_t *menu_select_text(boot_context_t *ctx, entry_t *entries)
{
    (void)ctx;

    entry_t *def = config_get_default();
    int selected = -1;
    char last[IVO_LASTENTRY_MAX];
    if (ivo_lastentry_get(last, sizeof(last)) == 0) {
        for (int i = 0; i < visible_count; i++) {
            if (strcmp(entries[visible_idx[i]].name, last) == 0) {
                selected = i;
                break;
            }
        }
    }
    if (selected < 0 && def) {
        for (int i = 0; i < visible_count; i++)
            if (&entries[visible_idx[i]] == def) { selected = i; break; }
    }
    if (selected < 0) selected = 0;

    con_clear();
    con_puts("Ivo: text mode (no usable framebuffer)\n\n");
    for (int i = 0; i < visible_count; i++) {
        char num[4];
        int n = i + 1;
        num[0] = (char)('0' + n);
        num[1] = ')';
        num[2] = ' ';
        num[3] = '\0';
        con_puts(num);
        con_puts(entries[visible_idx[i]].name);
        if (&entries[visible_idx[i]] == def) con_puts(" (default)");
        con_puts("\n");
    }
    con_puts("\n");

    int timeout = entry_timeout(&entries[visible_idx[selected]]);
    if (timeout > 0) {
        char prompt[32] = "Choose [default, ";
        int n = timeout;
        char digits[8];
        int di = 0;
        if (n == 0) digits[di++] = '0';
        while (n > 0) { digits[di++] = '0' + (n % 10); n /= 10; }
        for (int a = 0, b = di - 1; a < b; a++, b--) {
            char t = digits[a]; digits[a] = digits[b]; digits[b] = t;
        }
        char *p = prompt + strlen(prompt);
        for (int k = 0; k < di; k++) *p++ = digits[k];
        *p++ = 's';
        *p++ = ']'; *p++ = ':'; *p++ = ' '; *p = '\0';
        con_puts(prompt);
    } else {
        con_puts("Choose: ");
    }

    int elapsed_ms = 0;
    int timeout_ms = timeout * 1000;
    for (;;) {
        int wait = 50;
        if (timeout > 0 && timeout_ms - elapsed_ms < wait)
            wait = timeout_ms - elapsed_ms;
        if (wait < 1) wait = 1;

        char c = hal_getchar_timeout(wait);
        if (c == 0) {
            elapsed_ms += wait;
            if (timeout > 0 && elapsed_ms >= timeout_ms) {
                con_puts("\n");
                return &entries[visible_idx[selected]];
            }
            continue;
        }

        if (c >= 0x20 && c <= 0x7E)
            con_putc(c);
        if (c == '\r' || c == '\n') {
            entry_t *chosen = &entries[visible_idx[selected]];
            ivo_lastentry_set(chosen->name);
            return chosen;
        }
        if (c == 0x1B) {
            shell_enter(ctx);
            con_clear();
            return menu_select_text(ctx, entries);
        }
        if (c >= '1' && c <= '9') {
            int idx = c - '1';
            if (idx < visible_count) {
                entry_t *chosen = &entries[visible_idx[idx]];
                ivo_lastentry_set(chosen->name);
                return chosen;
            }
        }
    }
}

entry_t *menu_select(boot_context_t *ctx)
{
    int count = 0;
    entry_t *entries = config_get_entries(&count);
    if (count == 0) return 0;
    config_clear_proven();
    build_visible(entries, count);
    if (visible_count == 0) return 0;

    if (gfx_text_mode())
        return menu_select_text(ctx, entries);

    entry_t *def = config_get_default();
    int selected = -1;

    char last[IVO_LASTENTRY_MAX];
    if (ivo_lastentry_get(last, sizeof(last)) == 0) {
        for (int i = 0; i < visible_count; i++) {
            if (strcmp(entries[visible_idx[i]].name, last) == 0) {
                selected = i;
                break;
            }
        }
    }
    if (selected < 0 && def) {
        for (int i = 0; i < visible_count; i++)
            if (&entries[visible_idx[i]] == def) { selected = i; break; }
    }
    if (selected < 0) selected = 0;

    int timeout      = entry_timeout(&entries[visible_idx[selected]]);
    int elapsed_ms   = 0;
    int timeout_ms   = timeout * 1000;
    int last_shown_s = timeout;

    draw_menu(entries, selected, def, timeout, timeout);

    while (1) {
        int wait = 50;
        if (timeout > 0 && timeout_ms - elapsed_ms < wait)
            wait = timeout_ms - elapsed_ms;
        if (wait < 1) wait = 1;

        char c = hal_getchar_timeout(wait);

        if (c == 0) {
            elapsed_ms += wait;
            if (timeout > 0) {
                int remaining = (timeout_ms - elapsed_ms + 999) / 1000;
                if (remaining != last_shown_s) {
                    last_shown_s = remaining;
                    draw_footer(timeout, remaining);
                }
                if (elapsed_ms >= timeout_ms)
                    return &entries[visible_idx[selected]];
            }
            continue;
        }

        if (c == '\r' || c == '\n') {
            entry_t *chosen = &entries[visible_idx[selected]];
            ivo_lastentry_set(chosen->name);
            return chosen;
        }

        if (c == 0x1B) {
            shell_enter(ctx);
            timeout = entry_timeout(&entries[visible_idx[selected]]);
            elapsed_ms = 0;
            last_shown_s = timeout;
            timeout_ms = timeout * 1000;
            draw_menu(entries, selected, def, timeout, timeout);
            continue;
        }

        if (c == (char)(0x80 | 0x48) || c == (char)(0x80 | 0x50)) {
            int old = selected;
            if (c == (char)(0x80 | 0x48))
                selected = (selected + visible_count - 1) % visible_count;
            else
                selected = (selected + 1) % visible_count;
            timeout = entry_timeout(&entries[visible_idx[selected]]);
            elapsed_ms = 0;
            last_shown_s = timeout;
            timeout_ms = timeout * 1000;
            redraw_row(entries, old, 0, def);
            redraw_row(entries, selected, 1, def);
            draw_footer(timeout, timeout);
            continue;
        }

        if (c == 'e') {
            if (core_unlocked_without_passphrase()) {
                continue;
            }
            entry_t *e = &entries[visible_idx[selected]];
            if (entry_password_check(e) != 0) {
                draw_menu(entries, selected, def, timeout, timeout);
                continue;
            }
            cmdline_editor(e);
            timeout      = entry_timeout(&entries[visible_idx[selected]]);
            elapsed_ms   = 0;
            last_shown_s = timeout;
            timeout_ms   = timeout * 1000;
            draw_menu(entries, selected, def, timeout, timeout);
            continue;
        }

        if (c >= '1' && c <= '9') {
            int idx = c - '1';
            if (idx < visible_count) {
                entry_t *chosen = &entries[visible_idx[idx]];
                ivo_lastentry_set(chosen->name);
                return chosen;
            }
        }
    }
}