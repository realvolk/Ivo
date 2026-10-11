#include <stddef.h>
#include "ui/text.h"
#include "ui/gfx.h"
#include "ui/font.h"

void text_draw(int32_t x_q4, int y, const char *s, uint32_t rgba)
{
    if (!gfx_available() || !s) return;
    for (; *s; s++) {
        uint8_t ch = (uint8_t)*s;
        if (ch < font_main.first_char ||
            ch >= font_main.first_char + font_main.glyph_count)
            ch = font_main.first_char;
        const struct font_glyph *g = &font_main.glyphs[ch - font_main.first_char];
        if (g->width == 0) { x_q4 += g->advance; continue; }
        int sp = 0;
        (void)sp;
        int xp = (int)(x_q4 >> 2) + g->bearing_x;
        int W = g->width;
        int H = font_main.height;
        const uint8_t *base = font_main.data + g->data_off;
        /* Interleaved: (row * W + col) * 4 + sp. Each glyph's bitmap
         * is exactly font_main.height rows, aligned to the line top. */
        static uint8_t scratch[256];
        int any = 0;
        for (int i = 0; i < H * W && i < (int)sizeof(scratch); i++) {
            scratch[i] = base[i];
            if (scratch[i]) any = 1;
        }
        if (any) gfx_blit_glyph(xp, y, W, H, scratch, rgba);
        x_q4 += g->advance;
    }
}

int32_t text_width_q4(const char *s)
{
    int32_t w = 0;
    for (; *s; s++) {
        uint8_t ch = (uint8_t)*s;
        if (ch < font_main.first_char ||
            ch >= font_main.first_char + font_main.glyph_count)
            ch = font_main.first_char;
        w += font_main.glyphs[ch - font_main.first_char].advance;
    }
    return w;
}

int text_width(const char *s) { return (int)(text_width_q4(s) >> 2); }
int text_height(void)          { return font_main.height; }