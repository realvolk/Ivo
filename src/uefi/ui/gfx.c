#include "core.h"
#include "ui/gfx.h"
#include "hal/hal.h"

static video_mode_t g_fb;
static int g_ready;

int gfx_init(void)
{
    video_mode_t m;
    hal_get_video_mode(&m);

    if (!m.framebuffer ||
        m.bpp != 32 ||
        m.width < 640 || m.width > 16384 ||
        m.height < 480 || m.height > 16384 ||
        m.pitch < m.width * 4 || m.pitch > m.width * 8 ||
        m.size == 0 || m.size > (4ull << 30)) {
        hal_puts_serial("gfx: rejecting implausible mode\n");
        return -1;
    }
    if (m.format != GFX_FMT_RGBX && m.format != GFX_FMT_BGRX) return -1;
    g_fb = m;
    g_ready = 1;
    return 0;
}

static int g_text_mode;

int gfx_available(void) { return g_ready; }
int gfx_text_mode(void)  { return g_text_mode; }

void gfx_force_text_mode(void)
{
    g_text_mode = 1;
    g_ready = 0;
}
int gfx_width(void)     { return (int)g_fb.width; }
int gfx_height(void)    { return (int)g_fb.height; }

static inline uint32_t pack(uint32_t rgba)
{
    uint8_t r = (uint8_t)(rgba >> 24);
    uint8_t g = (uint8_t)(rgba >> 16);
    uint8_t b = (uint8_t)(rgba >> 8);
    if (g_fb.format == GFX_FMT_BGRX)
        return 0xFF000000u | ((uint32_t)b << 16) | ((uint32_t)g << 8) | r;
    return 0xFF000000u | ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
}

static inline uint8_t mul8(uint8_t x, uint8_t a)
{
    uint32_t t = (uint32_t)x * (uint32_t)a + 128;
    return (uint8_t)((t + (t >> 8)) >> 8);
}

void gfx_clear(uint32_t rgba)
{
    if (!g_ready) return;
    uint32_t p = pack(rgba);
    uint32_t pitch_px = g_fb.pitch / 4;
    uint64_t p2 = ((uint64_t)p << 32) | p;
    for (uint32_t y = 0; y < g_fb.height; y++) {
        uint32_t *row = g_fb.framebuffer + (size_t)y * pitch_px;
        uint32_t n = g_fb.width;
        while (n >= 2) {
            __builtin_memcpy(row, &p2, 8);
            row += 2;
            n -= 2;
        }
        if (n) *row = p;
    }
}

void gfx_fill_rect(int x, int y, int w, int h, uint32_t rgba)
{
    if (!g_ready || w <= 0 || h <= 0) return;
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > (int)g_fb.width)  w = (int)g_fb.width  - x;
    if (y + h > (int)g_fb.height) h = (int)g_fb.height - y;
    if (w <= 0 || h <= 0) return;
    uint32_t p = pack(rgba);
    uint32_t pitch_px = g_fb.pitch / 4;
    uint64_t p2 = ((uint64_t)p << 32) | p;
    for (int r = 0; r < h; r++) {
        uint32_t *row = g_fb.framebuffer + (size_t)(y + r) * pitch_px + x;
        int n = w;
        while (n >= 2) {
            __builtin_memcpy(row, &p2, 8);
            row += 2;
            n -= 2;
        }
        if (n) *row = p;
    }
}

void gfx_fill_rect_a(int x, int y, int w, int h, uint32_t rgba)
{
    if (!g_ready || w <= 0 || h <= 0) return;
    uint8_t a = (uint8_t)rgba;
    if (a == 0xFF) { gfx_fill_rect(x, y, w, h, rgba); return; }
    if (a == 0) return;
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > (int)g_fb.width)  w = (int)g_fb.width  - x;
    if (y + h > (int)g_fb.height) h = (int)g_fb.height - y;
    if (w <= 0 || h <= 0) return;
    uint8_t sr = (uint8_t)(rgba >> 24);
    uint8_t sg = (uint8_t)(rgba >> 16);
    uint8_t sb = (uint8_t)(rgba >> 8);
    uint32_t sa = a;
    uint32_t ia = 255 - a;
    int bgrx = (g_fb.format == GFX_FMT_BGRX);
    uint32_t pitch_px = g_fb.pitch / 4;
    for (int r = 0; r < h; r++) {
        uint32_t *row = g_fb.framebuffer + (size_t)(y + r) * pitch_px + x;
        for (int c = 0; c < w; c++) {
            uint32_t d = row[c];
            uint8_t dr, dg, db;
            if (bgrx) {
                db = (uint8_t)(d >> 16); dg = (uint8_t)(d >> 8); dr = (uint8_t)d;
            } else {
                dr = (uint8_t)(d >> 16); dg = (uint8_t)(d >> 8); db = (uint8_t)d;
            }
            uint8_t nr = (uint8_t)(mul8(sr, sa) + mul8(dr, (uint8_t)ia));
            uint8_t ng = (uint8_t)(mul8(sg, sa) + mul8(dg, (uint8_t)ia));
            uint8_t nb = (uint8_t)(mul8(sb, sa) + mul8(db, (uint8_t)ia));
            if (bgrx)
                row[c] = 0xFF000000u | ((uint32_t)nb << 16) | ((uint32_t)ng << 8) | nr;
            else
                row[c] = 0xFF000000u | ((uint32_t)nr << 16) | ((uint32_t)ng << 8) | nb;
        }
    }
}

void gfx_vgradient(int x, int y, int w, int h, uint32_t top, uint32_t bot)
{
    if (!g_ready || w <= 0 || h <= 0) return;
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > (int)g_fb.width)  w = (int)g_fb.width  - x;
    if (y + h > (int)g_fb.height) h = (int)g_fb.height - y;
    if (w <= 0 || h <= 0) return;
    uint32_t tr = (top >> 24) & 0xFF, tg = (top >> 16) & 0xFF, tb = (top >> 8) & 0xFF;
    uint32_t br = (bot >> 24) & 0xFF, bg = (bot >> 16) & 0xFF, bb = (bot >> 8) & 0xFF;
    uint32_t pitch_px = g_fb.pitch / 4;
    int den = h > 1 ? h - 1 : 1;
    for (int r = 0; r < h; r++) {
        uint32_t t = (uint32_t)((r * 255) / den);
        uint32_t cr = tr + ((br - tr) * t) / 255u;
        uint32_t cg = tg + ((bg - tg) * t) / 255u;
        uint32_t cb = tb + ((bb - tb) * t) / 255u;
        uint32_t px;
        if (g_fb.format == GFX_FMT_BGRX)
            px = 0xFF000000u | (cb << 16) | (cg << 8) | cr;
        else
            px = 0xFF000000u | (cr << 16) | (cg << 8) | cb;
        uint32_t *row = g_fb.framebuffer + (size_t)(y + r) * pitch_px + x;
        uint64_t px2 = ((uint64_t)px << 32) | px;
        int n = w;
        while (n >= 2) {
            __builtin_memcpy(row, &px2, 8);
            row += 2;
            n -= 2;
        }
        if (n) *row = px;
    }
}

void gfx_hline(int x, int y, int w, uint32_t rgba) { gfx_fill_rect(x, y, w, 1, rgba); }
void gfx_vline(int x, int y, int h, uint32_t rgba) { gfx_fill_rect(x, y, 1, h, rgba); }

static inline void gfx_hline_raw(int x, int y, int w, uint32_t rgba)
{
    if (w <= 0 || y < 0 || y >= (int)g_fb.height) return;
    if (x < 0) { w += x; x = 0; }
    if (x + w > (int)g_fb.width) w = (int)g_fb.width - x;
    if (w <= 0) return;
    uint32_t p = pack(rgba);
    uint32_t *row = g_fb.framebuffer + (size_t)y * (g_fb.pitch / 4) + x;
    while (w--) *row++ = p;
}

void gfx_rounded_rect(int x, int y, int w, int h, int radius, uint32_t rgba)
{
    if (radius <= 0) { gfx_fill_rect(x, y, w, h, rgba); return; }
    if (radius > w / 2) radius = w / 2;
    if (radius > h / 2) radius = h / 2;
    gfx_fill_rect(x, y + radius, w, h - 2 * radius, rgba);
    gfx_fill_rect(x + radius, y, w - 2 * radius, radius, rgba);
    gfx_fill_rect(x + radius, y + h - radius, w - 2 * radius, radius, rgba);
    for (int dy = 0; dy < radius; dy++) {
        int r = radius;
        int dy0 = r - dy - 1;
        int lim = r * r - dy0 * dy0;
        int dx = 0;
        while ((dx + 1) * (dx + 1) <= lim) dx++;
        int len = dx + 1;
        gfx_hline_raw(x + r - len, y + dy,        len, rgba);
        gfx_hline_raw(x + w - r,   y + dy,        len, rgba);
        gfx_hline_raw(x + r - len, y + h - 1 - dy, len, rgba);
        gfx_hline_raw(x + w - r,   y + h - 1 - dy, len, rgba);
    }
}

void gfx_rounded_rect_erase_gaps(int x, int y, int w, int h,
                                 int radius, uint32_t behind)
{
    if (!g_ready || radius <= 0 || w <= 0 || h <= 0) return;
    if (radius > w / 2) radius = w / 2;
    if (radius > h / 2) radius = h / 2;
    for (int dy = 0; dy < radius; dy++) {
        int dy0 = radius - dy - 1;
        int lim = radius * radius - dy0 * dy0;
        int dx = 0;
        while ((dx + 1) * (dx + 1) <= lim) dx++;
        int gap = radius - dx - 1;
        if (gap <= 0) continue;
        int ytop = y + dy;
        int ybot = y + h - 1 - dy;
        gfx_fill_rect(x, ytop, gap, 1, behind);
        gfx_fill_rect(x + w - gap, ytop, gap, 1, behind);
        gfx_fill_rect(x, ybot, gap, 1, behind);
        gfx_fill_rect(x + w - gap, ybot, gap, 1, behind);
    }
}

void gfx_blit_glyph(int x, int y, int w, int h, const uint8_t *cov, uint32_t rgba)
{
    if (!g_ready || w <= 0 || h <= 0) return;
    uint8_t cr = (uint8_t)(rgba >> 24);
    uint8_t cg = (uint8_t)(rgba >> 16);
    uint8_t cb = (uint8_t)(rgba >> 8);
    uint32_t pitch_px = g_fb.pitch / 4;
    for (int r = 0; r < h; r++) {
        int yy = y + r;
        const uint8_t *row_cov = cov + (size_t)r * w;
        if (yy < 0 || yy >= (int)g_fb.height) continue;
        uint32_t *row = g_fb.framebuffer + (size_t)yy * pitch_px;
        for (int c = 0; c < w; c++) {
            int xx = x + c;
            if (xx < 0 || xx >= (int)g_fb.width) continue;
            uint8_t a = row_cov[c];
            if (a == 0) continue;
            if (a == 255) {
                if (g_fb.format == GFX_FMT_BGRX)
                    row[xx] = 0xFF000000u | ((uint32_t)cb << 16)
                            | ((uint32_t)cg << 8) | cr;
                else
                    row[xx] = 0xFF000000u | ((uint32_t)cr << 16)
                            | ((uint32_t)cg << 8) | cb;
                continue;
            }
            uint32_t d = row[xx];
            uint8_t dr, dg, db;
            if (g_fb.format == GFX_FMT_BGRX) {
                db = (uint8_t)(d >> 16); dg = (uint8_t)(d >> 8); dr = (uint8_t)d;
            } else {
                dr = (uint8_t)(d >> 16); dg = (uint8_t)(d >> 8); db = (uint8_t)d;
            }
            uint8_t nr = (uint8_t)(mul8(cr, a) + mul8(dr, (uint8_t)(255 - a)));
            uint8_t ng = (uint8_t)(mul8(cg, a) + mul8(dg, (uint8_t)(255 - a)));
            uint8_t nb = (uint8_t)(mul8(cb, a) + mul8(db, (uint8_t)(255 - a)));
            if (g_fb.format == GFX_FMT_BGRX)
                row[xx] = 0xFF000000u | ((uint32_t)nb << 16) | ((uint32_t)ng << 8) | nr;
            else
                row[xx] = 0xFF000000u | ((uint32_t)nr << 16) | ((uint32_t)ng << 8) | nb;
        }
    }
}