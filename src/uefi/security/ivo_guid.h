#ifndef IVO_GUID_H
#define IVO_GUID_H

#include <stdint.h>
#define IVO_GUID_STR "1c934930-1918-4354-a1ba-9d6ef5547cd4"

#ifndef CONFIG_HOST
#include "hal/uefi_internal.h"
static const efi_guid_t IVO_GUID = {
    0x1C934930, 0x1918, 0x4354,
    { 0xA1, 0xBA, 0x9D, 0x6E, 0xF5, 0x54, 0x7C, 0xD4 }
};
#endif

#endif