#ifndef IVO_THEME_SOLARIZED_H
#define IVO_THEME_SOLARIZED_H
#include "ui/theme.h"

static const struct theme theme_values = {
    .bg              = 0x002B36FFu,
    .panel_bg        = 0x073642FFu,
    .panel_border    = 0x586E75FFu,
    .panel_shadow    = 0x00000060u,
    .title_bg_top    = 0x0A4B5CFFu,
    .title_bg_bottom = 0x073642FFu,
    .title_fg        = 0xFDF6E3FFu,
    .sep             = 0x586E75FFu,
    .foot_fg         = 0x657B83FFu,

    .fg              = 0xEEE8D5FFu,
    .fg_dim          = 0x93A1A1FFu,
    .accent          = 0x268BD2FFu,
    .sel_bg          = 0x268BD2FFu,
    .sel_fg          = 0xFDF6E3FFu,
    .ok_fg           = 0x859900FFu,
    .warn_fg         = 0xB58900FFu,
    .error_fg        = 0xDC322FFFu,

    .content_width   = 720,
    .padding         = 12,
    .corner_radius   = 8,
    .row_height      = 30,
    .header          = "Ivo Bootloader",
};

#endif