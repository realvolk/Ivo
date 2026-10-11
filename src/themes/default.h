#ifndef IVO_THEME_DEFAULT_H
#define IVO_THEME_DEFAULT_H
#include "ui/theme.h"

static const struct theme theme_values = {
    .bg              = 0x0A0A0CFFu,
    .panel_bg        = 0x16161AFFu,
    .panel_border    = 0x2A2A2EFFu,
    .panel_shadow    = 0x00000060u,
    .title_bg_top    = 0x22222AFFu,
    .title_bg_bottom = 0x18181EFFu,
    .title_fg        = 0xFFFFFFFFu,
    .sep             = 0x2A2A2EFFu,
    .foot_fg         = 0x808088FFu,

    .fg              = 0xE4E4E8FFu,
    .fg_dim          = 0x808088FFu,
    .accent          = 0x4C9AF0FFu,
    .sel_bg          = 0x4C9AF0FFu,
    .sel_fg          = 0xFFFFFFFFu,
    .ok_fg           = 0x6FCF6FFFu,
    .warn_fg         = 0xE0C060FFu,
    .error_fg        = 0xE06060FFu,

    .content_width   = 720,
    .padding         = 12,
    .corner_radius   = 8,
    .row_height      = 30,
    .header          = "Ivo Bootloader",
};

#endif