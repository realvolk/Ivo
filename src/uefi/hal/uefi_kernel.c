/* Manual kernel handoff for UEFI.
 *
 * Firmware SB refuses to LoadImage an unsigned kernel, so an ISO's
 * kernel can't be booted that way. Ivo verifies it against the
 * config's kver, then parses the PE header, places the image, installs
 * EFI_LOADED_IMAGE_PROTOCOL on a fresh handle, and calls the stub
 * entry as a function pointer.
 *
 * Bypasses firmware SB for the kernel. The trust anchor is the
 * config's Ed25519 signature plus the kver hash. The initrd
 * LoadFile2 install and the cmdline UTF-16 conversion live in
 * uefi.c and are shared. */

#include "uefi_internal.h"
#include "../core.h"

#include <string.h>

#define PE_SIG 0x00004550u   /* "PE\0\0" */

static uint16_t pe_rd16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t pe_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int pe_parse(const uint8_t *img, size_t img_size,
                    uint32_t *image_size,
                    uint32_t *entry_rva,
                    uint32_t *section_count,
                    const uint8_t **section_headers)
{
    if (img_size < 0x40) return -1;
    if (img[0] != 'M' || img[1] != 'Z') return -1;

    uint64_t e_lfanew = pe_rd32(img + 0x3C);
    if (e_lfanew + 24 > img_size) return -1;
    if (pe_rd32(img + e_lfanew) != PE_SIG) return -1;

    uint16_t nsec     = pe_rd16(img + e_lfanew + 0x06);
    uint16_t opt_size = pe_rd16(img + e_lfanew + 0x14);

    if (nsec == 0 || nsec > 96) return -1;
    if (opt_size < 0x3C) return -1;
    if (e_lfanew + 24 + opt_size + (uint64_t)nsec * 40 > img_size) return -1;

    const uint8_t *opt = img + e_lfanew + 24;
    uint16_t magic = pe_rd16(opt);

    uint32_t entry, size;
    if (magic == 0x10B) {       /* PE32 */
        entry = pe_rd32(opt + 0x10);
        size  = pe_rd32(opt + 0x38);
    } else if (magic == 0x20B) { /* PE32+ */
        entry = pe_rd32(opt + 0x10);
        size  = pe_rd32(opt + 0x38);
    } else {
        return -1;
    }

    if (size == 0 || size > 0x40000000u) return -1;
    if (entry >= size) return -1;

    *image_size      = size;
    *entry_rva       = entry;
    *section_count   = nsec;
    *section_headers = img + e_lfanew + 24 + opt_size;
    return 0;
}

static void pe_copy_sections(const uint8_t *img, size_t img_size,
                             uint8_t *dest, uint32_t image_size,
                             const uint8_t *section_headers,
                             uint32_t nsec)
{
    for (uint32_t i = 0; i < nsec; i++) {
        const uint8_t *sh = section_headers + i * 40;
        uint32_t raw_size = pe_rd32(sh + 0x10);
        uint32_t raw_off  = pe_rd32(sh + 0x14);
        uint32_t rva      = pe_rd32(sh + 0x0C);

        if (raw_size == 0) continue;
        if ((uint64_t)raw_off + raw_size > img_size) continue;
        if ((uint64_t)rva + raw_size > image_size) continue;

        memcpy(dest + rva, img + raw_off, raw_size);
    }
}

void hal_boot_uefi(const void *kernel, size_t kernel_size,
                   const char *cmdline,
                   const void *initrd, size_t initrd_size)
{
    if (!g_st || !g_st->BootServices) {
        puts_("no boot services\n");
        for (;;) __asm__ volatile("hlt");
    }

    const uint8_t *img = (const uint8_t *)kernel;

    if (kernel_size < 0x40 || img[0] != 'M' || img[1] != 'Z') {
        puts_("kernel is not a PE/COFF image\n");
        for (;;) __asm__ volatile("hlt");
    }

    uint32_t image_size, entry_rva, nsec;
    const uint8_t *section_headers;
    if (pe_parse(img, kernel_size, &image_size, &entry_rva,
                 &nsec, &section_headers) != 0) {
        puts_("kernel PE parse failed\n");
        for (;;) __asm__ volatile("hlt");
    }

    if (image_size < 0x1000) image_size = 0x1000;
    size_t pages = (image_size + 4095) / 4096;

    uint8_t *loaded = hal_allocate_code_pages_below(pages, 0x7FFFFFFF);
    if (!loaded) {
        puts_("kernel alloc failed\n");
        for (;;) __asm__ volatile("hlt");
    }
    memset(loaded, 0, pages * 4096);

    pe_copy_sections(img, kernel_size, loaded, (uint32_t)(pages * 4096),
                     section_headers, nsec);

    uintptr_t entry_va = (uintptr_t)loaded + entry_rva;

    static EFI_LOADED_IMAGE_PROTOCOL li;
    memset(&li, 0, sizeof(li));
    li.Revision      = 0x1000;
    li.SystemTable   = g_st;
    li.DeviceHandle  = g_image;
    li.ImageBase     = loaded;
    li.ImageSize     = pages * 4096;
    li.ImageCodeType = 1;   /* EfiLoaderCode */
    li.ImageDataType = 2;   /* EfiLoaderData */

    if (cmdline && *cmdline) {
        CHAR16 *w = alloc_cmdline_utf16(cmdline);
        if (w) {
            size_t len = 0;
            while (cmdline[len]) len++;
            li.LoadOptions     = w;
            li.LoadOptionsSize = (uint32_t)((len + 1) * 2);
        }
    }

    void *bs = g_st->BootServices;
    EFI_STATUS (*install_proto)(EFI_HANDLE *, const efi_guid_t *,
                                uint64_t, void *) =
        *(void **)((uint8_t *)bs + BS_InstallProtocolInterface);

    EFI_HANDLE kernel_handle = 0;
    EFI_STATUS s = install_proto(&kernel_handle, &GUID_LOADED_IMAGE, 0, &li);
    if (s != EFI_SUCCESS) {
        puts_("install LoadedImage failed\n");
        for (;;) __asm__ volatile("hlt");
    }

    if (initrd && initrd_size > 0) {
        hal_uefi_install_initrd_protocol(kernel_handle, initrd, initrd_size);
    }

    typedef EFI_STATUS (__attribute__((ms_abi)) *entry_fn_t)
        (EFI_HANDLE, EFI_SYSTEM_TABLE *);
    entry_fn_t fn = (entry_fn_t)entry_va;
    (void)fn(kernel_handle, g_st);

    puts_("EFI stub returned\n");
    for (;;) __asm__ volatile("hlt");
}