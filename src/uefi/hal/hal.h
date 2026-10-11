#ifndef HAL_H
#define HAL_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t  drive;
    uint64_t boot_lba;
    uint32_t boot_partition_guid[4];
    void    *memory_map;
    uint64_t memory_map_size;
    void    *firmware_data;
} boot_context_t;

#define GFX_FMT_RGBX    0
#define GFX_FMT_BGRX    1
#define GFX_FMT_BITMASK 2
#define GFX_FMT_BLTONLY 3

typedef struct {
    uint32_t *framebuffer;
    uint32_t  width;
    uint32_t  height;
    uint32_t  pitch;
    uint32_t  bpp;
    uint32_t  format;
    uint64_t  size;
} video_mode_t;

void  hal_init(boot_context_t *ctx);
int   hal_read_blocks(uint64_t lba, uint32_t count, void *buf);
int   hal_read_disk_blocks(uint64_t lba, uint32_t count, void *buf);
uint64_t hal_get_disk_sectors(void);
int   hal_write_blocks(uint64_t lba, uint32_t count, const void *buf);
int   hal_get_e820(void *buf, uint32_t max_entries);
void  hal_get_video_mode(video_mode_t *mode);
void  hal_get_text_mode(int *cols, int *rows);
void  hal_set_video_mode(uint32_t width, uint32_t height);
void  hal_clear_screen(void);
void  hal_set_attr(uint8_t fg, uint8_t bg);
void  hal_set_cursor(int x, int y);
/* hal_getchar returns ASCII, 0x80|scancode for navigation keys, or
 * HAL_KEY_NON_ASCII for a printable key outside ASCII. */
#define HAL_KEY_NON_ASCII 0xFF
char  hal_getchar(void);
char  hal_getchar_timeout(int timeout_ms);
void  hal_putchar(char c);
void hal_puts_serial(const char *s);
void *hal_allocate_pages(size_t pages);
void *hal_allocate_pages_below(size_t pages, uint64_t max_addr);
void  hal_free_pages(void *addr, size_t pages);
void  hal_reboot(void);
void  hal_get_disk_info(uint64_t *total_sectors, uint32_t *sector_size);
int   hal_chainload(void *data, size_t size);
int   hal_sse2_available(void);

int      hal_esp_available(void);
uint64_t hal_esp_sector_count(void);
void     hal_block_io_push_esp(void);
void     hal_block_io_pop(void);

void  hal_boot_uefi(const void *kernel, size_t kernel_size,
                    const char *cmdline,
                    const void *initrd, size_t initrd_size)
                    __attribute__((noreturn));

/* Set by the HAL when it has already located the boot partition.
 * partition_find_boot() is skipped if this is 1. */
extern int hal_boot_partition_decided;

#endif