#ifndef IVO_LVM_H
#define IVO_LVM_H

#include <stdint.h>
#include <stddef.h>

struct boot_context;

#ifdef LVM
int lvm_init(struct boot_context *ctx);
int lvm_active(void);
int lvm_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf);

/* Iteration over the LVs found in the VG's metadata. Call lvm_init()
 * first. Names are the LV's LVM-level name, without the VG prefix. */
int         lvm_lv_count(void);
const char *lvm_lv_name(int index);
int         lvm_lv_select(int index);
int         lvm_lv_select_by_name(const char *name);
#else
static inline int lvm_init(struct boot_context *ctx) { (void)ctx; return -1; }
static inline int lvm_active(void) { return 0; }
static inline int lvm_read_blocks(uint64_t lba, uint32_t count, uint8_t *buf)
{ (void)lba; (void)count; (void)buf; return -1; }
static inline int lvm_lv_count(void) { return 0; }
static inline const char *lvm_lv_name(int index) { (void)index; return 0; }
static inline int lvm_lv_select(int index) { (void)index; return -1; }
static inline int lvm_lv_select_by_name(const char *name)
{ (void)name; return -1; }
#endif

#endif