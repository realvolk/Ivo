#ifndef IVO_FRAME_H
#define IVO_FRAME_H

#include <stdint.h>

#define FRAME_ROWS 20

void frame_init(void);
void frame_begin(const char *title);
void frame_title(const char *title);
void frame_content_clear(void);
void frame_end(void);
void frame_sep(int row);
void frame_row(int row, const char *s, uint32_t fg);
void frame_row_clear(int row);
void frame_row_clear_right(int row, int width);
void frame_row_sel(int row, const char *s, int selected, uint32_t accent_color);
void frame_row_2col(int row, const char *l, const char *r,
                    uint32_t lfg, uint32_t rfg);

#endif