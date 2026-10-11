#include "core.h"
#include "ui/theme.h"
#include "ui/gfx.h"
#include "ui/text.h"
#include "ui/frame.h"

static int g_px, g_py, g_pw, g_ph;
static int g_content_x, g_content_y, g_content_w;

static int title_height(void) { return text_height() + 2 * theme_current.padding; }

void frame_init(void)
{
    int sw = gfx_width(), sh = gfx_height();
    g_pw = theme_current.content_width;
    if (g_pw > sw - 80) g_pw = sw - 80;
    if (g_pw < 200) g_pw = 200;

    int rows_h = FRAME_ROWS * theme_current.row_height;
    g_ph = title_height() + theme_current.padding + rows_h +
           theme_current.padding;
    if (g_ph > sh - 40) g_ph = sh - 40;

    g_px = (sw - g_pw) / 2;
    g_py = (sh - g_ph) / 2;

    g_content_x = g_px + theme_current.padding;
    g_content_y = g_py + title_height() + theme_current.padding;
    g_content_w = g_pw - 2 * theme_current.padding;
}

void frame_begin(const char *title)
{
    gfx_clear(theme_current.bg);

    int r = theme_current.corner_radius;
    gfx_rounded_rect(g_px + 3, g_py + 4, g_pw, g_ph, r,
                     theme_current.panel_shadow);
    gfx_rounded_rect(g_px, g_py, g_pw, g_ph, r, theme_current.panel_bg);

    /* Border: 1px stroke drawn as 4 thin lines + corner arcs is fussy;
     * for now draw a rounded outline by clearing pixels is even worse.
     * Simpler: draw filled rounded rect of border colour, then a
     * 1px-inset rounded rect of panel_bg. */
    gfx_rounded_rect(g_px, g_py, g_pw, g_ph, r, theme_current.panel_border);
    if (r > 0) {
        gfx_rounded_rect(g_px + 1, g_py + 1, g_pw - 2, g_ph - 2, r - 1,
                         theme_current.panel_bg);
    } else {
        gfx_fill_rect(g_px + 1, g_py + 1, g_pw - 2, g_ph - 2,
                      theme_current.panel_bg);
    }

    /* Title bar: gradient strip, clipped to panel content top.
     * Corners not rounded here; overlap with panel edges is minimal. */
    int th = title_height();
    gfx_vgradient(g_px + 1, g_py + 1, g_pw - 2, th,
                  theme_current.title_bg_top, theme_current.title_bg_bottom);

    if (title) {
        int tw = text_width(title);
        int tx = g_px + (g_pw - tw) / 2;
        int ty = g_py + theme_current.padding;
        text_draw(tx << 2, ty, title, theme_current.title_fg);
    }

    /* Separator between title and content. */
    gfx_hline(g_px + 1, g_py + th, g_pw - 2, theme_current.sep);
}

void frame_end(void) { }

void frame_sep(int row)
{
    int y = g_content_y + row * theme_current.row_height +
            theme_current.row_height / 2;
    gfx_hline(g_content_x, y, g_content_w, theme_current.sep);
}

void frame_row(int row, const char *s, uint32_t fg)
{
    int y = g_content_y + row * theme_current.row_height;
    text_draw(g_content_x << 2, y, s, fg);
}

void frame_row_sel(int row, const char *s, int selected)
{
    int lh   = text_height();
    int y    = g_content_y + row * theme_current.row_height;
    int ybox = y + (theme_current.row_height - lh) / 2;
    if (selected) {
        gfx_rounded_rect(g_content_x, ybox - 2, g_content_w,
                         lh + 4, 6, theme_current.sel_bg);
    }
    uint32_t col = selected ? theme_current.sel_fg : theme_current.fg;
    text_draw((g_content_x + 14) << 2, ybox, s, col);
}

void frame_row_2col(int row, const char *l, const char *r,
                    uint32_t lfg, uint32_t rfg)
{
    int y = g_content_y + row * theme_current.row_height;
    text_draw((g_content_x + 14) << 2, y, l, lfg);
    if (r) {
        int rw = text_width(r);
        text_draw((g_content_x + g_content_w - rw - 14) << 2, y, r, rfg);
    }
}