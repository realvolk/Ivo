#ifndef IVO_THEME_H
#define IVO_THEME_H

#include <stdint.h>

struct theme {
    uint32_t bg;
    uint32_t panel_bg;
    uint32_t panel_border;
    uint32_t panel_shadow;
    uint32_t title_bg_top;
    uint32_t title_bg_bottom;
    uint32_t title_fg;
    uint32_t sep;
    uint32_t foot_fg;

    uint32_t fg;
    uint32_t fg_dim;
    uint32_t accent;
    uint32_t sel_bg;
    uint32_t sel_fg;
    uint32_t ok_fg;
    uint32_t warn_fg;
    uint32_t error_fg;

    int content_width;
    int padding;
    int corner_radius;
    int row_height;

    const char *header;
};

extern const struct theme theme_current;

#endif