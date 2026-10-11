#include "ui/font.h"
#include "ui/font_data.h"

const struct font font_main = {
    .height         = FONT_HEIGHT,
    .baseline       = FONT_BASELINE,
    .subpixel_count = 4,
    .first_char     = FONT_FIRST_CHAR,
    .glyph_count    = FONT_GLYPH_COUNT,
    .glyphs         = font_glyphs_raw,
    .data           = font_data_raw,
};