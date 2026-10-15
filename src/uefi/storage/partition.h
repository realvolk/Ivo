#ifndef PARTITION_H
#define PARTITION_H

#include <stdint.h>
#include "hal/hal.h"

int partition_find_iso(boot_context_t *ctx, const char *label,
                       uint64_t *iso_lba, uint32_t *iso_count);

#endif