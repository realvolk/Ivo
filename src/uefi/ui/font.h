#ifndef IVO_FONT_H
#define IVO_FONT_H

#include <stdint.h>

struct font_glyph {
    uint32_t data_off;
    uint8_t  width;
    uint8_t  height;
    uint8_t  advance;   /* 1/4-pixel units */
    int8_t   bearing_x;
    int8_t   bearing_y;
};

struct font {
    uint8_t  height;
    uint8_t  baseline;
    uint8_t  subpixel_count;
    uint8_t  first_char;
    uint8_t  glyph_count;
    uint8_t  pad[3];
    const struct font_glyph *glyphs;
    const uint8_t *data;
};

extern const struct font font_main;

#endif