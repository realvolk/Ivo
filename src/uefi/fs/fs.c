#include "core.h"
#include "fs/fs.h"

fs_driver_t *fs_current;

static fs_driver_t *probe_order[] = {
    &fs_ext4,
    &fs_btrfs,
    &fs_fat32,
    &fs_iso9660,
    0,
};

void fs_register(fs_driver_t *drv)
{
    fs_current = drv;
}

int fs_probe_mount(block_device_t *dev)
{
    for (int i = 0; probe_order[i]; i++) {
        fs_driver_t *d = probe_order[i];
        if (!d->probe || !d->mount) continue;
        if (d->probe(dev) != 0) continue;
        if (d->mount(dev) != 0) continue;
        fs_current = d;
        return 0;
    }
    return -1;
}

/* Mount with one specific driver, no probing of the others. Used for
 * the ESP, which is plaintext and attacker-writable: only the FAT32
 * driver should ever parse it. */
int fs_mount_as(fs_driver_t *drv, block_device_t *dev)
{
    if (!drv || !drv->probe || !drv->mount) return -1;
    if (drv->probe(dev) != 0) return -1;
    if (drv->mount(dev) != 0) return -1;
    fs_current = drv;
    return 0;
}

int fs_mount(block_device_t *dev)
{
    if (!fs_current) return -1;
    return fs_current->mount(dev);
}

int fs_read(const char *path, uint8_t *buf, size_t *len)
{
    if (!fs_current) return -1;
    return fs_current->read(path, buf, len);
}

int fs_readlink(const char *path, char *buf, size_t len)
{
    if (!fs_current) return -1;
    return fs_current->readlink(path, buf, len);
}

int fs_stat(const char *path, size_t *size)
{
    if (!fs_current) return -1;
    struct stat st;
    int ret = fs_current->stat(path, &st);
    if (ret != 0) return ret;
    /* A size that doesn't fit size_t would be
     * silently truncated by every caller. */
    if (st.size > (uint64_t)SIZE_MAX) return -1;
    *size = (size_t)st.size;
    return 0;
}

int fs_opendir(const char *path, void **handle)
{
    if (!fs_current) return -1;
    return fs_current->opendir(path, handle);
}

int fs_readdir(void *handle, char *name, size_t name_len)
{
    if (!fs_current) return -1;
    return fs_current->readdir(handle, name, name_len);
}

int fs_write(const char *path, const uint8_t *data, size_t size)
{
    if (!fs_current) return -1;
    return fs_current->write(path, data, size);
}

void fs_closedir(void *handle)
{
    if (fs_current)
        fs_current->closedir(handle);
}