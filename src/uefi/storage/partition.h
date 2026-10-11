#ifndef PARTITION_H
#define PARTITION_H

#include <stdint.h>
#include "hal/hal.h"

/* Fills ctx->boot_lba and ctx->boot_partition_guid from the on-disk
 * partition table. Returns 0 on success, -1 if no suitable partition
 * is found. */
int partition_find_boot(boot_context_t *ctx);
int partition_find_iso(boot_context_t *ctx, const char *label,
                       uint64_t *iso_lba, uint32_t *iso_count);

#endif