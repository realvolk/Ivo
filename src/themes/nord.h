#ifndef IVO_THEME_NORD_H
#define IVO_THEME_NORD_H
#include "ui/theme.h"

static const struct theme theme_values = {
    .bg              = 0x2E3440FFu,
    .panel_bg        = 0x3B4252FFu,
    .panel_border    = 0x4C566AFFu,
    .panel_shadow    = 0x00000060u,
    .title_bg_top    = 0x434C5EFFu,
    .title_bg_bottom = 0x3B4252FFu,
    .title_fg        = 0xECEFF4FFu,
    .sep             = 0x4C566AFFu,
    .foot_fg         = 0x7B88A1FFu,

    .fg              = 0xD8DEE9FFu,
    .fg_dim          = 0x7B88A1FFu,
    .accent          = 0x88C0D0FFu,
    .sel_bg          = 0x88C0D0FFu,
    .sel_fg          = 0x2E3440FFu,
    .ok_fg           = 0xA3BE8CFFu,
    .warn_fg         = 0xEBCB8BFFu,
    .error_fg        = 0xBF616AFFu,

    .content_width   = 720,
    .padding         = 12,
    .corner_radius   = 8,
    .row_height      = 30,
    .header          = "Ivo Bootloader",
};

#endif