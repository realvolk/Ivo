#ifndef IVO_TEXT_H
#define IVO_TEXT_H

#include <stdint.h>

void    text_draw(int32_t x_q4, int y, const char *s, uint32_t rgba);
int32_t text_width_q4(const char *s);
int     text_width(const char *s);
int     text_height(void);

#endif