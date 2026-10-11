#include "core.h"
#include "ui/theme.h"
#include "ui/gfx.h"
#include "ui/text.h"
#include "security/wipe.h"

static int g_cx, g_cy;
static uint32_t g_fg;

static int pad(void) { return theme_current.padding; }
static int adv(void) { return text_width(" "); }

static void scroll_up(int pixels)
{
    int pitch_px = (int)(gfx_width());
    uint32_t *base = (uint32_t *)0;
    (void)base;
    /* Shove the framebuffer up by `pixels` rows. Reaches into the
     * raw video mode because gfx doesn't expose a scroll primitive. */
    video_mode_t m;
    hal_get_video_mode(&m);
    uint32_t *fb = m.framebuffer;
    uint32_t stride = m.pitch / 4;
    for (uint32_t y = 0; y < m.height - (uint32_t)pixels; y++) {
        uint32_t *d = fb + (size_t)y * stride;
        uint32_t *s = fb + (size_t)(y + pixels) * stride;
        for (uint32_t x = 0; x < m.width; x++) d[x] = s[x];
    }
    for (uint32_t y = m.height - (uint32_t)pixels; y < m.height; y++) {
        uint32_t *d = fb + (size_t)y * stride;
        uint32_t p = theme_current.bg;
        uint8_t rr = (uint8_t)(p >> 24), gg = (uint8_t)(p >> 16), bb = (uint8_t)(p >> 8);
        uint32_t px = (m.format == GFX_FMT_BGRX)
            ? (0xFF000000u | ((uint32_t)bb << 16) | ((uint32_t)gg << 8) | rr)
            : (0xFF000000u | ((uint32_t)rr << 16) | ((uint32_t)gg << 8) | bb);
        for (uint32_t x = 0; x < m.width; x++) d[x] = px;
    }
    (void)pitch_px;
}

void con_clear(void)
{
    gfx_clear(theme_current.bg);
    int W = gfx_width();
    int H = gfx_height();
    g_cx = (W - 720) / 2;
    if (g_cx < 40) g_cx = 40;
    g_cy = H / 3;
    g_fg = theme_current.fg;
}

void con_set_fg(uint32_t rgba)
{
    g_fg = rgba;
}

void con_putc(char c)
{
    if (!gfx_available()) return;
    int lh = text_height();
    int W = gfx_width();
    int H = gfx_height();
    int P = pad();
    int A = adv();

    if (c == '\n') {
        g_cx = P;
        g_cy += lh;
        if (g_cy + lh > H - P) scroll_up(lh);
        return;
    }
    if (c == '\r') { g_cx = P; return; }
    if (c == '\b') { g_cx -= A; if (g_cx < P) g_cx = P; return; }

    char buf[2] = { c, 0 };
    uint32_t fg = g_fg ? g_fg : theme_current.fg;
    text_draw(g_cx << 2, g_cy, buf, fg);
    g_cx += A;
    if (g_cx + A > W - P) {
        g_cx = P;
        g_cy += lh;
        if (g_cy + lh > H - P) scroll_up(lh);
    }
}

void con_puts(const char *s)
{
    while (*s) con_putc(*s++);
}

void halt(void)
{
    for (;;) __asm__ volatile("cli; hlt");
}

int con_read_secret(const char *label, char *out, size_t max_len, char echo)
{
    con_clear();
    int W = gfx_width();
    int lh = text_height();
    int P  = (W - 720) / 2;
    if (P < 40) P = 40;
    int y0 = gfx_height() / 3;

    size_t idx = 0;
    int redraw = 1;
    for (;;) {
        if (redraw) {
            gfx_fill_rect(P, y0 - 4, 720, lh + 8, theme_current.bg);
            int x = P;
            text_draw(x << 2, y0, label, theme_current.fg);
            x += text_width(label);
            text_draw(x << 2, y0, ": ", theme_current.fg);
            x += text_width(": ");
            for (size_t i = 0; i < idx; i++) {
                char buf[2] = { echo, 0 };
                text_draw(x << 2, y0, buf, theme_current.fg);
                x += text_width(" ");
            }
            redraw = 0;
        }
        char c = hal_getchar();
        if (c == 0) continue;
        if (c == '\r' || c == '\n') { out[idx] = '\0'; return (int)idx; }
        if (c == '\b' || c == 0x7F) { if (idx > 0) { idx--; redraw = 1; } continue; }
        if ((uint8_t)c == HAL_KEY_NON_ASCII) {
            ivo_wipe(out, max_len);
            con_puts("\nNon-ASCII characters are not supported here.\n");
            return -1;
        }
        if (c < 0x20 || c > 0x7E) continue;
        if (idx + 1 < max_len) { out[idx++] = c; redraw = 1; }
    }
}