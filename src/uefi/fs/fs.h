#ifndef FS_H
#define FS_H

#include <stdint.h>
#include <stddef.h>

struct stat;

typedef struct block_device block_device_t;

typedef struct {
    int  (*probe)(block_device_t *dev);
    int  (*mount)(block_device_t *dev);
    int  (*read)(const char *path, uint8_t *buf, size_t *len);
    int  (*readlink)(const char *path, char *buf, size_t len);
    int  (*stat)(const char *path, struct stat *st);
    void (*umount)(void);
    int  (*opendir)(const char *path, void **handle);
    int  (*readdir)(void *handle, char *name, size_t name_len);
    int  (*write)(const char *path, const uint8_t *data, size_t size);
    void (*closedir)(void *handle);
    int  (*set_subvol)(const char *path);
} fs_driver_t;

struct block_device {
    uint64_t lba_start;
    uint64_t lba_count;
    uint32_t block_size;
    void    *private;
};

struct stat {
    uint64_t size;
    uint32_t mode;
};

extern fs_driver_t *fs_current;
extern fs_driver_t fs_fat32;
extern fs_driver_t fs_ext4;
extern fs_driver_t fs_btrfs;
extern fs_driver_t fs_iso9660;

int fat32_mount_memory(const void *data, size_t size);

int iso9660_mount(block_device_t *dev);
int iso9660_mount_memory(const void *data, size_t size);
int iso9660_read_label(block_device_t *dev, char *out, size_t out_size);
int iso9660_get_boot_catalog(uint32_t *lba_out);
int iso9660_get_boot_image(uint32_t catalog_lba,
                           uint32_t *image_lba,
                           uint32_t *image_sectors,
                           uint8_t  *platform_out);

int  fs_probe_mount(block_device_t *dev);
int  fs_mount_as(fs_driver_t *drv, block_device_t *dev);
int  fs_read(const char *path, uint8_t *buf, size_t *len);
int  fs_stat(const char *path, size_t *size);
int  fs_opendir(const char *path, void **handle);
int  fs_readdir(void *handle, char *name, size_t name_len);
int  fs_write(const char *path, const uint8_t *data, size_t size);
void fs_closedir(void *handle);

#endif