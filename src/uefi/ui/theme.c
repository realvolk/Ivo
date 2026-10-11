#include "ui/theme.h"

#if defined(IVO_THEME_NORD)
#include "themes/nord.h"
#elif defined(IVO_THEME_SOLARIZED)
#include "themes/solarized.h"
#elif defined(IVO_THEME_GRUVBOX)
#include "themes/gruvbox.h"
#elif defined(IVO_THEME_HIGHCONTRAST)
#include "themes/highcontrast.h"
#else
#include "themes/default.h"
#endif

const struct theme theme_current = theme_values;