/* efivars.c — Ivo's slice of the UEFI variable store.
 *
 * Everything Ivo persists across boots lives here: boot count,
 * last menu selection, and anything else added later. All under the
 * IVO_GUID namespace defined in ivo_guid.h.
 *
 * The bootloader never touches BootOrder, BootNext, or any firmware
 * variable. Writing those from a bootloader is how machines get
 * bricked.
 *
 * UEFI variable names are CHAR16 (UTF-16). Names here are ASCII, so
 * the conversion is a widening of each byte. The name buffer is
 * fixed-size; longer names are refused rather than truncated. */

#include "core.h"
#include "security/efivars.h"
#include "security/ivo_guid.h"
#include "hal/uefi_internal.h"

#define EFIVAR_NAME_MAX 64

/* Runtime services offsets. These are what gnu-efi's function calls
 * resolve to under the hood; the tree already does this style for
 * BootServices in hal/uefi.c. */
#define RT_GetVariable 0x48
#define RT_SetVariable 0x58

static int to_utf16(const char *name, CHAR16 *out, size_t out_cap)
{
    size_t n = 0;
    for (; name[n]; n++) {
        if (n + 1 >= out_cap) return -1;
        out[n] = (CHAR16)(uint8_t)name[n];
    }
    out[n] = 0;
    return 0;
}

int ivo_var_get(const char *name, uint8_t *buf, size_t *len, size_t cap)
{
    if (!name || !buf || !len) return -1;
    if (!g_st || !g_st->RuntimeServices) return -1;

    CHAR16 wname[EFIVAR_NAME_MAX];
    if (to_utf16(name, wname, EFIVAR_NAME_MAX) != 0) return -1;

    void *rt = g_st->RuntimeServices;
    EFI_STATUS (*get)(CHAR16 *, const efi_guid_t *,
                      uint32_t *, size_t *, void *) =
        *(void **)((uint8_t *)rt + RT_GetVariable);

    uint32_t attrs = 0;
    size_t got = cap;
    EFI_STATUS s = get(wname, &IVO_GUID, &attrs, &got, buf);
    if (s != EFI_SUCCESS) return -1;
    *len = got;
    return 0;
}

int ivo_var_set(const char *name, const uint8_t *data, size_t len)
{
    if (!name || (!data && len)) return -1;
    if (!g_st || !g_st->RuntimeServices) return -1;

    CHAR16 wname[EFIVAR_NAME_MAX];
    if (to_utf16(name, wname, EFIVAR_NAME_MAX) != 0) return -1;

    void *rt = g_st->RuntimeServices;
    EFI_STATUS (*set)(CHAR16 *, const efi_guid_t *, uint32_t,
                      size_t, const void *) =
        *(void **)((uint8_t *)rt + RT_SetVariable);

    /* NV + BS + RT: persistent, accessible from boot services (us) and
     * runtime services (Linux via efivarfs). No other attribute bits. */
    uint32_t attrs = 0x00000007u;
    EFI_STATUS s = set(wname, &IVO_GUID, attrs, len, data);
    return (s == EFI_SUCCESS) ? 0 : -1;
}

int ivo_var_del(const char *name)
{
    if (!name) return -1;
    if (!g_st || !g_st->RuntimeServices) return -1;

    CHAR16 wname[EFIVAR_NAME_MAX];
    if (to_utf16(name, wname, EFIVAR_NAME_MAX) != 0) return -1;

    void *rt = g_st->RuntimeServices;
    EFI_STATUS (*set)(CHAR16 *, const efi_guid_t *, uint32_t,
                      size_t, const void *) =
        *(void **)((uint8_t *)rt + RT_SetVariable);

    /* Setting with len 0 and no data deletes a variable. An
     * already-absent variable returns EFI_NOT_FOUND, which we treat
     * as success: the caller wanted it gone. */
    EFI_STATUS s = set(wname, &IVO_GUID, 0, 0, 0);
    if (s == EFI_SUCCESS) return 0;
    if (s == 0x800000000000000EULL) return 0;   /* EFI_NOT_FOUND */
    return -1;
}

#define BOOTCOUNT_VAR "Ivo/BootCount"

int ivo_bootcount_get(void)
{
    uint8_t buf[4];
    size_t len = 0;
    if (ivo_var_get(BOOTCOUNT_VAR, buf, &len, sizeof(buf)) != 0)
        return 0;
    if (len != 4) return 0;
    /* Little-endian uint32. */
    return (int)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | ((uint32_t)buf[3] << 24));
}

int ivo_bootcount_set(int n)
{
    uint8_t buf[4];
    uint32_t v = (uint32_t)n;
    buf[0] = (uint8_t)v;
    buf[1] = (uint8_t)(v >> 8);
    buf[2] = (uint8_t)(v >> 16);
    buf[3] = (uint8_t)(v >> 24);
    return ivo_var_set(BOOTCOUNT_VAR, buf, 4);
}

void ivo_bootcount_clear(void)
{
    ivo_var_del(BOOTCOUNT_VAR);
}

#define LASTENTRY_VAR "Ivo/LastEntry"

int ivo_lastentry_get(char *buf, size_t cap)
{
    if (!buf || cap == 0) return -1;
    uint8_t tmp[IVO_LASTENTRY_MAX];
    size_t len = 0;
    if (ivo_var_get(LASTENTRY_VAR, tmp, &len, sizeof(tmp)) != 0)
        return -1;
    if (len == 0 || len > sizeof(tmp)) return -1;
    /* Stored with the NUL as the last byte. */
    if (tmp[len - 1] != '\0') return -1;
    size_t slen = len - 1;
    if (slen + 1 > cap) return -1;
    memcpy(buf, tmp, slen + 1);
    return 0;
}

int ivo_lastentry_set(const char *name)
{
    if (!name || !name[0]) return -1;
    size_t n = strlen(name);
    if (n + 1 > IVO_LASTENTRY_MAX) return -1;
    return ivo_var_set(LASTENTRY_VAR, (const uint8_t *)name, n + 1);
}

void ivo_lastentry_clear(void)
{
    ivo_var_del(LASTENTRY_VAR);
}

#define CONFIGVER_VAR "Ivo/ConfigVer"

int ivo_configver_get(void)
{
    uint8_t buf[4];
    size_t len = 0;
    if (ivo_var_get(CONFIGVER_VAR, buf, &len, sizeof(buf)) != 0)
        return -1;
    if (len != 4) return -1;
    int32_t v = (int32_t)(buf[0] | (buf[1] << 8) |
                          (buf[2] << 16) | ((uint32_t)buf[3] << 24));
    if (v < 0) return -1;
    return (int)v;
}

int ivo_configver_set(int v)
{
    if (v < 0) return -1;
    uint8_t buf[4];
    uint32_t u = (uint32_t)v;
    buf[0] = (uint8_t)u;
    buf[1] = (uint8_t)(u >> 8);
    buf[2] = (uint8_t)(u >> 16);
    buf[3] = (uint8_t)(u >> 24);
    return ivo_var_set(CONFIGVER_VAR, buf, 4);
}