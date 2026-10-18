#ifndef IVO_GFX_H
#define IVO_GFX_H

#include <stdint.h>

#define RGBA32(r,g,b,a) (((uint32_t)(r)<<24)|((uint32_t)(g)<<16)| \
                         ((uint32_t)(b)<<8)|(uint32_t)(a))
#define RGB(r,g,b)      RGBA32(r,g,b,0xFF)

int  gfx_init(void);
int  gfx_available(void);
/* 1 if Ivo is running without a usable GOP framebuffer and should
 * use ConOut for all output. Set by ivo_main when gfx_init fails. */
int  gfx_text_mode(void);
void gfx_force_text_mode(void);
int  gfx_width(void);
int  gfx_height(void);

void gfx_clear(uint32_t rgba);
void gfx_fill_rect(int x, int y, int w, int h, uint32_t rgba);
void gfx_fill_rect_a(int x, int y, int w, int h, uint32_t rgba);
void gfx_vgradient(int x, int y, int w, int h, uint32_t top, uint32_t bot);
void gfx_hline(int x, int y, int w, uint32_t rgba);
void gfx_vline(int x, int y, int h, uint32_t rgba);
void gfx_rounded_rect(int x, int y, int w, int h, int radius, uint32_t rgba);
void gfx_rounded_rect_erase_gaps(int x, int y, int w, int h,
                                 int radius, uint32_t behind);
void gfx_blit_glyph(int x, int y, int w, int h, const uint8_t *cov, uint32_t rgba);

#endif