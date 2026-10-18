#ifndef IVO_THEME_HIGHCONTRAST_H
#define IVO_THEME_HIGHCONTRAST_H
#include "ui/theme.h"

static const struct theme theme_values = {
    .bg              = 0x000000FFu,
    .panel_bg        = 0x000000FFu,
    .panel_border    = 0xFFFFFFFFu,
    .panel_shadow    = 0x00000000u,
    .title_bg_top    = 0x000000FFu,
    .title_bg_bottom = 0x000000FFu,
    .title_fg        = 0xFFFFFFFFu,
    .sep             = 0xFFFFFFFFu,
    .foot_fg         = 0xFFFFFFFFu,

    .fg              = 0xFFFFFFFFu,
    .fg_dim          = 0xFFFFFFFFu,
    .accent          = 0xFFFFFFFFu,
    .sel_bg          = 0xFFFFFFFFu,
    .sel_fg          = 0x000000FFu,
    .ok_fg           = 0xFFFFFFFFu,
    .warn_fg         = 0xFFFFFFFFu,
    .error_fg        = 0xFFFFFFFFu,

    .content_width   = 720,
    .padding         = 12,
    .corner_radius   = 0,
    .row_height      = 30,
    .header          = "Ivo Bootloader",
};

#endif