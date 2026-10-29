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
        int xp = (int)(x_q4 >> 2) + g->bearing_x;
        const uint8_t *base = font_main.data + g->data_off;
        gfx_blit_glyph(xp, y, g->width, font_main.height, base, rgba);
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