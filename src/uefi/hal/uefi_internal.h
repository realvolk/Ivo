#ifndef HAL_UEFI_INTERNAL_H
#define HAL_UEFI_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

typedef uint64_t EFI_STATUS;
typedef void    *EFI_HANDLE;
typedef uint16_t CHAR16;
typedef uint8_t  BOOLEAN;
typedef uint64_t EFI_PHYSICAL_ADDRESS;

#define EFI_SUCCESS           0
#define EFI_NOT_READY         0x8000000000000006ULL
#define EFI_BUFFER_TOO_SMALL  0x8000000000000005ULL
#define EFI_INVALID_PARAMETER 0x8000000000000002ULL
#define EFI_UNSUPPORTED       0x8000000000000003ULL

#define BS_AllocatePool                 0x40
#define BS_InstallProtocolInterface     0x80
#define BS_LocateHandleBuffer           0x138

#define MEDIA_DEVICE_PATH               0x04
#define MEDIA_VENDOR_DP                 0x03
#define END_DEVICE_PATH_TYPE            0x7F
#define END_ENTIRE_DEVICE_PATH_SUBTYPE  0xFF

typedef struct {
    uint32_t d1;
    uint16_t d2;
    uint16_t d3;
    uint8_t  d4[8];
} __attribute__((packed)) efi_guid_t;

static const efi_guid_t GUID_LOADED_IMAGE = {
    0x5B1B31A1, 0x9562, 0x11D2,
    { 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B }
};
static const efi_guid_t GUID_DEVICE_PATH = {
    0x09576e91, 0x6d3f, 0x11d2,
    { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b }
};
static const efi_guid_t GUID_LOAD_FILE2 = {
    0x4006c0c1, 0xfcb3, 0x403e,
    { 0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d }
};
static const efi_guid_t GUID_LINUX_INITRD = {
    0x5568e427, 0x68fc, 0x4f3d,
    { 0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68 }
};
static const efi_guid_t GUID_LINUX_INITRD_LF2 = {
    0xf9e3378e, 0xb3b1, 0x423a,
    { 0xbd, 0x9a, 0x2d, 0x08, 0x60, 0x28, 0x7f, 0x72 }
};

typedef struct {
    uint8_t  Reserved[24];
    CHAR16  *FirmwareVendor;
    uint32_t FirmwareRevision;
    uint32_t _pad;
    EFI_HANDLE ConsoleInHandle;
    void *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    void *ConOut;
    EFI_HANDLE StandardErrorHandle;
    void *StdErr;
    void *RuntimeServices;
    void *BootServices;
} EFI_SYSTEM_TABLE;

typedef struct {
    uint32_t Revision;
    uint32_t _pad;
    EFI_HANDLE ParentHandle;
    EFI_SYSTEM_TABLE *SystemTable;
    EFI_HANDLE DeviceHandle;
    void *FilePath;
    void *Reserved;
    uint32_t LoadOptionsSize;
    uint32_t _pad2;
    void *LoadOptions;
    void *ImageBase;
    uint64_t ImageSize;
    uint32_t ImageCodeType;
    uint32_t ImageDataType;
    void *Unload;
} EFI_LOADED_IMAGE_PROTOCOL;

typedef struct {
    EFI_STATUS (*LoadFile)(void *This, void *FilePath, BOOLEAN BootPolicy,
                           uint64_t *BufferSize, void *Buffer);
} EFI_LOAD_FILE2_PROTOCOL;

typedef struct {
    uint8_t    Type;
    uint8_t    SubType;
    uint16_t   Length;
    efi_guid_t Guid;
} __attribute__((packed)) vendor_dp_t;

typedef struct {
    uint8_t  Type;
    uint8_t  SubType;
    uint16_t Length;
} __attribute__((packed)) end_dp_t;

typedef struct {
    vendor_dp_t vendor;
    end_dp_t    end;
} __attribute__((packed)) full_dp_t;

extern EFI_SYSTEM_TABLE *g_st;
extern EFI_HANDLE        g_image;

void     serial_puts(const char *s);
void     puts_(const char *s);
EFI_STATUS bs_handle_protocol(EFI_HANDLE h, const efi_guid_t *guid,
                              void **out);
void      *hal_allocate_code_pages_below(size_t pages, uint64_t max_addr);
CHAR16  *alloc_cmdline_utf16(const char *s);

void hal_uefi_install_initrd_protocol(EFI_HANDLE kernel_handle,
                                      const void *initrd,
                                      size_t initrd_size);

void serial_putc(char c);
#endif