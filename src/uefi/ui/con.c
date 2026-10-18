#include "core.h"
#include "ui/theme.h"
#include "ui/gfx.h"
#include "ui/text.h"
#include "security/wipe.h"
#include "hal/hal.h"

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
    if (gfx_text_mode()) {
        for (int i = 0; i < 3; i++) {
            hal_putchar('\r');
            hal_putchar('\n');
        }
        g_cx = 0;
        g_cy = 0;
        return;
    }
    /* Text mode behaves differently.. annoyingly */
    gfx_clear(theme_current.bg);
    g_cx = pad();
    g_cy = pad();
    g_fg = theme_current.fg;
}

void con_set_fg(uint32_t rgba)
{
    g_fg = rgba;
}

void con_set_pos(int x, int y)
{
    g_cx = x;
    g_cy = y;
}

void con_putc(char c)
{
    if (gfx_text_mode()) {
        hal_putchar(c);
        return;
    }
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

void con_clear_row(void)
{
    if (gfx_text_mode()) {
        hal_putchar('\n');
        return;
    }
    if (!gfx_available()) return;
    int W = gfx_width();
    int P = pad();
    int lh = text_height();
    if (g_cx < P) g_cx = P;
    int w = W - P - g_cx;
    if (w <= 0) return;
    gfx_fill_rect(g_cx, g_cy, w, lh, theme_current.bg);
}

void halt(void)
{
    for (;;) __asm__ volatile("cli; hlt");
}

int con_read_secret(const char *label, char *out, size_t max_len, char echo)
{
    con_puts(label);
    con_puts(": ");

    size_t idx = 0;
    for (;;) {
        char c = hal_getchar();
        if (c == 0) continue;
        if (c == '\r' || c == '\n') {
            out[idx] = '\0';
            con_puts("\n");
            return (int)idx;
        }
        if (c == '\b' || c == 0x7F) {
            if (idx > 0) { idx--; con_puts("\b \b"); }
            continue;
        }
        if ((uint8_t)c == HAL_KEY_NON_ASCII) {
            ivo_wipe(out, max_len);
            con_puts("\nNon-ASCII characters are not supported here.\n");
            return -1;
        }
        if (c < 0x20 || c > 0x7E) continue;
        if (idx + 1 < max_len) {
            out[idx++] = c;
            con_putc(echo);
        }
    }
}