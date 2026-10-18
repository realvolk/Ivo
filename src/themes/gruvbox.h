#ifndef IVO_THEME_GRUVBOX_H
#define IVO_THEME_GRUVBOX_H
#include "ui/theme.h"

static const struct theme theme_values = {
    .bg              = 0x282828FFu,
    .panel_bg        = 0x3C3836FFu,
    .panel_border    = 0x504945FFu,
    .panel_shadow    = 0x00000060u,
    .title_bg_top    = 0x504945FFu,
    .title_bg_bottom = 0x3C3836FFu,
    .title_fg        = 0xFBF1C7FFu,
    .sep             = 0x504945FFu,
    .foot_fg         = 0x928374FFu,

    .fg              = 0xEBDBB2FFu,
    .fg_dim          = 0xA89984FFu,
    .accent          = 0xD79921FFu,
    .sel_bg          = 0xD79921FFu,
    .sel_fg          = 0x282828FFu,
    .ok_fg           = 0xB8BB26FFu,
    .warn_fg         = 0xFABD2FFFu,
    .error_fg        = 0xFB4934FFu,

    .content_width   = 720,
    .padding         = 12,
    .corner_radius   = 8,
    .row_height      = 30,
    .header          = "Ivo Bootloader",
};

#endif