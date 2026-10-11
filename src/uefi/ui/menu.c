#include "core.h"
#include "ui/theme.h"
#include "ui/gfx.h"
#include "ui/text.h"
#include "ui/frame.h"

#define MENU_MAX_VISIBLE 16

static int visible_idx[MENU_MAX_VISIBLE];
static int visible_count;

static void build_visible(entry_t *entries, int count)
{
    visible_count = 0;
    for (int i = 0; i < count && visible_count < MENU_MAX_VISIBLE; i++)
        if (!entries[i].hidden)
            visible_idx[visible_count++] = i;
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
    frame_row_sel(row, buf, selected);
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

    frame_row_2col(FRAME_ROWS - 1, left, right[0] ? right : 0,
                   theme_current.foot_fg, theme_current.foot_fg);
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

entry_t *menu_select(boot_context_t *ctx)
{
    int count = 0;
    entry_t *entries = config_get_entries(&count);
    if (count == 0) return 0;
    build_visible(entries, count);
    if (visible_count == 0) return 0;

    entry_t *def = config_get_default();
    int selected = 0;
    if (def) {
        for (int i = 0; i < visible_count; i++)
            if (&entries[visible_idx[i]] == def) { selected = i; break; }
    }

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
                    draw_menu(entries, selected, def, timeout, remaining);
                }
                if (elapsed_ms >= timeout_ms)
                    return def ? def : &entries[visible_idx[0]];
            }
            continue;
        }

        if (c == '\r' || c == '\n')
            return &entries[visible_idx[selected]];

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
            if (c == (char)(0x80 | 0x48))
                selected = (selected + visible_count - 1) % visible_count;
            else
                selected = (selected + 1) % visible_count;
            timeout = entry_timeout(&entries[visible_idx[selected]]);
            elapsed_ms = 0;
            last_shown_s = timeout;
            timeout_ms = timeout * 1000;
            draw_menu(entries, selected, def, timeout, timeout);
            continue;
        }

        if (c >= '1' && c <= '9') {
            int idx = c - '1';
            if (idx < visible_count)
                return &entries[visible_idx[idx]];
        }
    }
}