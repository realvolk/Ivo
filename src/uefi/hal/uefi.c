/* UEFI HAL. Boot services and runtime services are called through
 * their vtable offsets rather than gnu-efi. Protocol GUIDs, boot
 * services offsets, and shared state live in uefi_internal.h. */

#include "hal.h"
#include "uefi_internal.h"
#include <string.h>
#define EFI_ALLOCATE_ANY_PAGES    0
#define EFI_LOADER_CODE           1
#define EFI_LOADER_DATA           2
#define EFI_RESET_COLD            0

#define BS_FreePool                     0x48
#define BS_LoadImage                    0xC8
#define BS_StartImage                   0xD0

#define MMAP_BUF_SIZE 16384

static CHAR16 cp437_to_unicode(uint8_t b)
{
    switch (b) {
    case 0x08: return 0x08;     /* backspace */
    case 0x09: return 0x09;     /* tab */
    case 0x0A: return 0x0A;     /* line feed */
    case 0x0D: return 0x0D;     /* carriage return */
    case 0x07: return 0x2022;   /* • */
    case 0x10: return 0x25BA;   /* ► */
    case 0x11: return 0x25C4;   /* ◄ */
    case 0x18: return 0x2191;   /* ↑ */
    case 0x19: return 0x2193;   /* ↓ */
    case 0x1A: return 0x2192;   /* → */
    case 0x1B: return 0x2190;   /* ← */
    case 0xB0: return 0x2591;   /* ░ */
    case 0xB1: return 0x2592;   /* ▒ */
    case 0xB2: return 0x2593;   /* ▓ */
    case 0xB9: return 0x2524;   /* ┤ single-line */
    case 0xBA: return 0x2502;   /* │ single-line */
    case 0xBB: return 0x2510;   /* ┐ single-line */
    case 0xBC: return 0x2518;   /* ┘ single-line */
    case 0xC8: return 0x2514;   /* └ single-line */
    case 0xC9: return 0x250C;   /* ┌ single-line */
    case 0xCC: return 0x251C;   /* ├ single-line */
    case 0xCD: return 0x2500;   /* ─ single-line */
    case 0xDB: return 0x2588;   /* █ */
    default:
        if (b >= 0x20 && b < 0x7F) return b;
        return '?';
    }
}

static const efi_guid_t GUID_BLOCK_IO = {
    0x964E5B21, 0x6459, 0x11D2,
    { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B }
};
static const efi_guid_t GUID_GOP = {
    0x9042A9DE, 0x23DC, 0x4A38,
    { 0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A }
};

typedef struct {
    int32_t  MaxMode;
    int32_t  Mode;
    int32_t  Attribute;
    int32_t  CursorColumn;
    int32_t  CursorRow;
    BOOLEAN  CursorVisible;
} EFI_SIMPLE_TEXT_OUTPUT_MODE;

typedef struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    void *Reset;
    EFI_STATUS (*OutputString)(struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *,
                               CHAR16 *);
    void *TestString;
    EFI_STATUS (*QueryMode)(struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *,
                            size_t, size_t *, size_t *);
    void *SetMode;
    void *SetAttribute;
    void *ClearScreen;
    void *SetCursorPosition;
    void *EnableCursor;
    EFI_SIMPLE_TEXT_OUTPUT_MODE *Mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

typedef struct {
    uint16_t ScanCode;
    uint16_t UnicodeChar;
} EFI_INPUT_KEY;

typedef struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
    void *Reset;
    EFI_STATUS (*ReadKeyStroke)(struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL *,
                                EFI_INPUT_KEY *);
    void *WaitForKey;
} EFI_SIMPLE_TEXT_INPUT_PROTOCOL;

typedef struct {
    uint32_t MediaId;
    uint8_t  RemovableMedia;
    uint8_t  MediaPresent;
    uint8_t  LogicalPartition;
    uint8_t  ReadOnly;
    uint8_t  WriteCaching;
    uint32_t BlockSize;
    uint32_t IoAlign;
    uint64_t LastBlock;
    uint64_t LowestAlignedLba;
    uint32_t LogicalBlocksPerPhysicalBlock;
    uint32_t OptimalTransferLengthGranularity;
} EFI_BLOCK_IO_MEDIA;

typedef struct EFI_BLOCK_IO_PROTOCOL {
    uint64_t Revision;
    EFI_BLOCK_IO_MEDIA *Media;
    EFI_STATUS (*Reset)(struct EFI_BLOCK_IO_PROTOCOL *, BOOLEAN);
    EFI_STATUS (*ReadBlocks)(struct EFI_BLOCK_IO_PROTOCOL *, uint32_t,
                             uint64_t, size_t, void *);
    EFI_STATUS (*WriteBlocks)(struct EFI_BLOCK_IO_PROTOCOL *, uint32_t,
                              uint64_t, size_t, const void *);
    EFI_STATUS (*FlushBlocks)(struct EFI_BLOCK_IO_PROTOCOL *);
} EFI_BLOCK_IO_PROTOCOL;

typedef struct {
    uint32_t Version;
    uint32_t HorizontalResolution;
    uint32_t VerticalResolution;
    uint32_t PixelFormat;
    uint8_t  PixelInfo[16];
    uint32_t PixelsPerScanLine;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

typedef struct {
    uint32_t MaxMode;
    uint32_t Mode;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
    uint64_t SizeOfInfo;
    EFI_PHYSICAL_ADDRESS FrameBufferBase;
    uint64_t FrameBufferSize;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

typedef struct EFI_GRAPHICS_OUTPUT_PROTOCOL {
    void *QueryMode;
    void *SetMode;
    void *Blt;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *Mode;
} EFI_GRAPHICS_OUTPUT_PROTOCOL;

typedef struct {
    uint32_t Type;
    uint32_t Pad;
    uint64_t PhysicalStart;
    uint64_t VirtualStart;
    uint64_t NumberOfPages;
    uint64_t Attribute;
} EFI_MEMORY_DESCRIPTOR;

typedef struct {
    uint64_t base;
    uint64_t len;
    uint32_t type;
} __attribute__((packed)) e820_entry_t;

EFI_SYSTEM_TABLE *g_st;
EFI_HANDLE        g_image;
static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *g_con_out;
static EFI_SIMPLE_TEXT_INPUT_PROTOCOL  *g_con_in;
static EFI_BLOCK_IO_PROTOCOL           *g_block_io;
static uint32_t          g_media_id;
static uint32_t          g_block_size;
static EFI_GRAPHICS_OUTPUT_PROTOCOL *g_gop;

static EFI_BLOCK_IO_PROTOCOL *g_esp_block_io;
static uint32_t g_esp_media_id;
static uint32_t g_esp_block_size;
static uint64_t g_esp_sectors;

static EFI_BLOCK_IO_PROTOCOL *g_disk_block_io;
static uint32_t g_disk_media_id;
static uint32_t g_disk_block_size;
static uint64_t g_disk_sectors;

static int g_cursor_x;
static int g_cursor_y;

static struct {
    EFI_BLOCK_IO_PROTOCOL *bio;
    uint32_t media_id;
    uint32_t block_size;
    int valid;
} g_block_io_saved;

static uint8_t  g_mmap_buf[MMAP_BUF_SIZE];
static uint64_t g_mmap_size;
static uint64_t g_mmap_key;
static uint64_t g_mmap_desc_size;
static uint32_t g_mmap_desc_ver;

static const void *g_initrd_data;
static size_t      g_initrd_size;

static EFI_LOAD_FILE2_PROTOCOL g_initrd_proto;
int hal_boot_partition_decided = 0;

void serial_putc(char c)
{
    uint8_t status;
    do {
        __asm__ volatile("inb %1, %0" : "=a"(status)
                         : "Nd"((uint16_t)0x3FD));
    } while ((status & 0x20) == 0);
    __asm__ volatile("outb %0, %1"
                     : : "a"((uint8_t)c), "Nd"((uint16_t)0x3F8));
}

void serial_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') serial_putc('\r');
        serial_putc(*s++);
    }
}

void hal_puts_serial(const char *s)
{
    while (s && *s) serial_putc(*s++);
}

void hal_putchar(char c)
{
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *co = g_st ? g_st->ConOut : g_con_out;
    if (!co || !co->OutputString) return;

    if (c == '\b') {
        if (g_cursor_x > 0) g_cursor_x--;
        hal_set_cursor(g_cursor_x, g_cursor_y);
        return;
    }

    CHAR16 buf[3];
    int i = 0;
    if (c == '\n') buf[i++] = '\r';
    buf[i++] = cp437_to_unicode((uint8_t)c);
    buf[i] = 0;
    co->OutputString(co, buf);

    if (c == '\n') {
        g_cursor_x = 0;
        g_cursor_y++;
    } else if (c == '\r') {
        g_cursor_x = 0;
    } else if (c >= 0x20) {
        g_cursor_x++;
        if (g_cursor_x >= 80) {
            g_cursor_x = 0;
            g_cursor_y++;
        }
    }
}

void puts_(const char *s)
{
    while (*s) hal_putchar(*s++);
}

static EFI_STATUS bs_locate_protocol(const efi_guid_t *guid, void **out)
{
    void *bs = g_st->BootServices;
    EFI_STATUS (*fn)(const efi_guid_t *, void *, void **) =
        *(void **)((uint8_t *)bs + 0x140);
    return fn(guid, 0, out);
}

EFI_STATUS bs_handle_protocol(EFI_HANDLE h, const efi_guid_t *guid,
                              void **out)
{
    void *bs = g_st->BootServices;
    EFI_STATUS (*fn)(EFI_HANDLE, const efi_guid_t *, void **) =
        *(void **)((uint8_t *)bs + 0x98);
    return fn(h, guid, out);
}

static EFI_STATUS bs_get_memory_map(void)
{
    void *bs = g_st->BootServices;
    EFI_STATUS (*fn)(uint64_t *, void *, uint64_t *, uint64_t *, uint32_t *) =
        *(void **)((uint8_t *)bs + 0x38);
    return fn(&g_mmap_size, g_mmap_buf, &g_mmap_key,
              &g_mmap_desc_size, &g_mmap_desc_ver);
}

static void bs_stall(uint64_t us)
{
    void *bs = g_st->BootServices;
    void (*fn)(uint64_t) = *(void **)((uint8_t *)bs + 0xF8);
    fn(us);
}

static EFI_STATUS efi_load_file2(void *This, void *FilePath,
                                 BOOLEAN BootPolicy,
                                 uint64_t *BufferSize, void *Buffer)
{
    (void)This;
    (void)FilePath;

    if (BootPolicy) return EFI_UNSUPPORTED;
    if (!BufferSize) return EFI_INVALID_PARAMETER;

    if (!Buffer || *BufferSize < g_initrd_size) {
        *BufferSize = g_initrd_size;
        return EFI_BUFFER_TOO_SMALL;
    }

    uint8_t *d = Buffer;
    const uint8_t *s = g_initrd_data;
    for (size_t i = 0; i < g_initrd_size; i++) d[i] = s[i];
    *BufferSize = g_initrd_size;
    return 0;
}

#define BOUNCE_SECTORS 128
static uint8_t *g_bounce;

static int needs_bounce(EFI_BLOCK_IO_PROTOCOL *bio, const void *buf)
{
    uint32_t align = bio->Media ? bio->Media->IoAlign : 0;
    if (align <= 1) return 0;
    return ((uintptr_t)buf & (align - 1)) != 0;
}

static EFI_STATUS bio_read(EFI_BLOCK_IO_PROTOCOL *bio, uint32_t media_id,
                           uint64_t lba, uint32_t count, void *buf)
{
    if (!needs_bounce(bio, buf))
        return bio->ReadBlocks(bio, media_id, lba, (size_t)count * 512, buf);
    if (!g_bounce || bio->Media->IoAlign > 4096) return EFI_UNSUPPORTED;
    uint8_t *dst = buf;
    while (count) {
        uint32_t n = count > BOUNCE_SECTORS ? BOUNCE_SECTORS : count;
        EFI_STATUS s = bio->ReadBlocks(bio, media_id, lba, (size_t)n * 512, g_bounce);
        if (s != EFI_SUCCESS) return s;
        memcpy(dst, g_bounce, (size_t)n * 512);
        dst += (size_t)n * 512;
        lba += n;
        count -= n;
    }
    return EFI_SUCCESS;
}

static size_t dp_length(const uint8_t *p)
{
    size_t len = 0;
    for (int guard = 0; guard < 64; guard++) {
        uint16_t l = (uint16_t)(p[len + 2] | (p[len + 3] << 8));
        if (l < 4) return 0;
        if (p[len] == END_DEVICE_PATH_TYPE) return len;
        len += l;
    }
    return 0;
}

static size_t disk_prefix_len(const uint8_t *esp_dp)
{
    size_t last = 0, len = 0;
    for (int guard = 0; guard < 64; guard++) {
        uint16_t l = (uint16_t)(esp_dp[len + 2] | (esp_dp[len + 3] << 8));
        if (l < 4) return 0;
        if (esp_dp[len] == END_DEVICE_PATH_TYPE) break;
        last = len;
        len += l;
    }
    if (len == 0 || esp_dp[last] != MEDIA_DEVICE_PATH || esp_dp[last + 1] != 1)
        return 0;
    return last;
}

CHAR16 *alloc_cmdline_utf16(const char *s)
{
    if (!s) return 0;

    size_t len = 0;
    while (s[len]) len++;
    size_t bytes = (len + 1) * sizeof(CHAR16);

    void *bs = g_st->BootServices;
    EFI_STATUS (*alloc_pool)(uint32_t, uint64_t, void **) =
        *(void **)((uint8_t *)bs + BS_AllocatePool);
    void *buf = 0;
    if (alloc_pool(2, bytes, &buf) != EFI_SUCCESS) return 0;

    CHAR16 *w = (CHAR16 *)buf;
    for (size_t i = 0; i < len; i++) w[i] = (CHAR16)(uint8_t)s[i];
    w[len] = 0;
    return w;
}

void hal_init(boot_context_t *ctx)
{
    if (!g_st || !g_image) return;
    if (ctx) ctx->boot_lba = 0;

    g_con_out = g_st->ConOut;
    g_con_in  = g_st->ConIn;

    if (g_con_out && g_con_out->Mode && g_con_out->QueryMode) {
        size_t c = 0, r = 0;
        EFI_STATUS s = g_con_out->QueryMode(g_con_out,
                                            (size_t)g_con_out->Mode->Mode,
                                            &c, &r);
        if (s == EFI_SUCCESS) {
            char buf[32];
            int i = 0;
            buf[i++] = 'c'; buf[i++] = 'o'; buf[i++] = 'n'; buf[i++] = 'o';
            buf[i++] = 'u'; buf[i++] = 't'; buf[i++] = ':'; buf[i++] = ' ';
            size_t n = c;
            if (n == 0) buf[i++] = '0';
            char tmp[8]; int j = 0;
            while (n > 0) { tmp[j++] = (char)('0' + (n % 10)); n /= 10; }
            while (j > 0) buf[i++] = tmp[--j];
            buf[i++] = 'x';
            n = r;
            j = 0;
            if (n == 0) tmp[j++] = '0';
            while (n > 0) { tmp[j++] = (char)('0' + (n % 10)); n /= 10; }
            while (j > 0) buf[i++] = tmp[--j];
            buf[i++] = '\n';
            buf[i] = 0;
            puts_(buf);
        }
    }

    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    (void)bs_handle_protocol(g_image, &GUID_LOADED_IMAGE, (void **)&li);
    g_bounce = hal_allocate_pages(BOUNCE_SECTORS * 512 / 4096);
    const uint8_t *esp_dp = 0;
    size_t disk_len = 0;

    if (li && li->DeviceHandle) {
        void *dp = 0;
        if (bs_handle_protocol(li->DeviceHandle, &GUID_DEVICE_PATH, &dp) == EFI_SUCCESS && dp) {
            esp_dp = (const uint8_t *)dp;
            disk_len = disk_prefix_len(esp_dp);
        }

        EFI_BLOCK_IO_PROTOCOL *bio = 0;
        if (bs_handle_protocol(li->DeviceHandle, &GUID_BLOCK_IO,
                               (void **)&bio) == EFI_SUCCESS && bio &&
            bio->Media && bio->Media->MediaPresent &&
            bio->Media->BlockSize == 512) {
            g_esp_block_io   = bio;
            g_esp_media_id   = bio->Media->MediaId;
            g_esp_block_size = bio->Media->BlockSize;
            g_esp_sectors    = bio->Media->LastBlock + 1;
            g_block_io   = bio;
            g_media_id   = bio->Media->MediaId;
            g_block_size = bio->Media->BlockSize;
        }
    }

    {
        void *bs = g_st->BootServices;
        EFI_STATUS (*locate_handle_buffer)(uint64_t, const efi_guid_t *,
                                            void *, uint64_t *,
                                            EFI_HANDLE **) =
            *(void **)((uint8_t *)bs + BS_LocateHandleBuffer);
        EFI_STATUS (*free_pool)(void *) =
            *(void **)((uint8_t *)bs + BS_FreePool);

        EFI_HANDLE *handles = 0;
        uint64_t n_handles = 0;
        EFI_BLOCK_IO_PROTOCOL *fallback_bio = 0;
        uint32_t fallback_media_id = 0;
        uint32_t fallback_block_size = 0;
        EFI_STATUS lb_s = locate_handle_buffer(2, &GUID_BLOCK_IO, 0,
                                               &n_handles, &handles);
        if (lb_s == EFI_SUCCESS && handles) {
            for (uint64_t i = 0; i < n_handles; i++) {
                EFI_HANDLE h = handles[i];
                if (li && h == li->DeviceHandle) continue;
                EFI_BLOCK_IO_PROTOCOL *bio = 0;
                if (bs_handle_protocol(h, &GUID_BLOCK_IO,
                                       (void **)&bio) != EFI_SUCCESS)
                    continue;
                if (!bio || !bio->Media || !bio->Media->MediaPresent) continue;
                if (bio->Media->BlockSize != 512) continue;

                if (disk_len) {
                    void *dp = 0;
                    if (bs_handle_protocol(h, &GUID_DEVICE_PATH, &dp) != EFI_SUCCESS || !dp)
                        continue;
                    const uint8_t *cdp = (const uint8_t *)dp;
                    size_t clen = dp_length(cdp);
                    if (bio->Media->LogicalPartition == 0 &&
                        clen >= disk_len &&
                        memcmp(cdp, esp_dp, disk_len) == 0) {
                        g_disk_block_io   = bio;
                        g_disk_media_id   = bio->Media->MediaId;
                        g_disk_block_size = bio->Media->BlockSize;
                        g_disk_sectors    = bio->Media->LastBlock + 1;
                        continue;
                    }
                    if (clen < disk_len || memcmp(cdp, esp_dp, disk_len) != 0)
                        continue;
                } else if (bio->Media->RemovableMedia) {
                    continue;
                }

                uint8_t probe[512] = {0};
                if (bio_read(bio, bio->Media->MediaId, 0, 1, probe) != EFI_SUCCESS)
                    continue;

                if (probe[0] == 'L' && probe[1] == 'U' &&
                    probe[2] == 'K' && probe[3] == 'S' &&
                    probe[4] == 0xBA && probe[5] == 0xBE) {
                    g_block_io   = bio;
                    g_media_id   = bio->Media->MediaId;
                    g_block_size = bio->Media->BlockSize;
                    hal_boot_partition_decided = 1;
                    break;
                }

                if (fallback_bio == 0) {
                    fallback_bio        = bio;
                    fallback_media_id   = bio->Media->MediaId;
                    fallback_block_size = bio->Media->BlockSize;
                }
            }
            free_pool(handles);

            if (!hal_boot_partition_decided && fallback_bio) {
                g_block_io   = fallback_bio;
                g_media_id   = fallback_media_id;
                g_block_size = fallback_block_size;
                hal_boot_partition_decided = 1;
            }
        }
    }

    void *gop = 0;
    if (bs_locate_protocol(&GUID_GOP, &gop) == EFI_SUCCESS && gop)
        g_gop = (EFI_GRAPHICS_OUTPUT_PROTOCOL *)gop;

    g_initrd_proto.LoadFile = efi_load_file2;
}

int hal_read_blocks(uint64_t lba, uint32_t count, void *buf)
{
    if (!g_block_io || !buf || g_block_size != 512) return -1;

    uint8_t *dst = (uint8_t *)buf;
    uint32_t done = 0;
    while (done < count) {
        uint32_t chunk = count - done;
        if (chunk > 128) chunk = 128;
        uint32_t mid = g_block_io->Media ? g_block_io->Media->MediaId : g_media_id;
        if (bio_read(g_block_io, mid, lba + done, chunk,
                     dst + (uint64_t)done * 512) != EFI_SUCCESS) {
            return -1;
        }
        done += chunk;
    }
    return 0;
}

int hal_read_disk_blocks(uint64_t lba, uint32_t count, void *buf)
{
    if (!g_disk_block_io || !buf || g_disk_block_size != 512) return -1;

    uint8_t *dst = (uint8_t *)buf;
    uint32_t done = 0;
    while (done < count) {
        uint32_t chunk = count - done;
        if (chunk > 128) chunk = 128;
        if (bio_read(g_disk_block_io, g_disk_media_id, lba + done, chunk,
                     dst + (uint64_t)done * 512) != EFI_SUCCESS) {
            return -1;
        }
        done += chunk;
    }
    return 0;
}

uint64_t hal_get_disk_sectors(void)
{
    return g_disk_sectors;
}

int hal_esp_available(void)
{
    return g_esp_block_io != 0;
}

uint64_t hal_esp_sector_count(void)
{
    return g_esp_sectors;
}

void hal_block_io_push_esp(void)
{
    if (!g_esp_block_io) return;
    g_block_io_saved.bio        = g_block_io;
    g_block_io_saved.media_id   = g_media_id;
    g_block_io_saved.block_size = g_block_size;
    g_block_io_saved.valid      = 1;
    g_block_io    = g_esp_block_io;
    g_media_id    = g_esp_media_id;
    g_block_size  = g_esp_block_size;
}

void hal_block_io_pop(void)
{
    if (!g_block_io_saved.valid) return;
    g_block_io    = g_block_io_saved.bio;
    g_media_id    = g_block_io_saved.media_id;
    g_block_size  = g_block_io_saved.block_size;
    g_block_io_saved.valid = 0;
}

int hal_write_blocks(uint64_t lba, uint32_t count, const void *buf)
{
    if (!g_block_io || !buf || !g_block_io->Media ||
        g_block_io->Media->ReadOnly || g_block_size != 512) return -1;

    if (!needs_bounce(g_block_io, buf)) {
        EFI_STATUS s = g_block_io->WriteBlocks(g_block_io, g_media_id, lba,
                                               (size_t)count * 512, buf);
        return (s == EFI_SUCCESS) ? 0 : -1;
    }
    if (!g_bounce || g_block_io->Media->IoAlign > 4096) return -1;
    const uint8_t *src = buf;
    while (count) {
        uint32_t n = count > BOUNCE_SECTORS ? BOUNCE_SECTORS : count;
        memcpy(g_bounce, src, (size_t)n * 512);
        if (g_block_io->WriteBlocks(g_block_io, g_media_id, lba,
                                    (size_t)n * 512, g_bounce) != EFI_SUCCESS)
            return -1;
        src += (size_t)n * 512;
        lba += n;
        count -= n;
    }
    return 0;
}

void hal_get_disk_info(uint64_t *total_sectors, uint32_t *sector_size)
{
    if (!g_disk_block_io || !g_disk_block_io->Media) {
        *total_sectors = 0;
        *sector_size = 512;
        return;
    }
    *total_sectors = g_disk_block_io->Media->LastBlock + 1;
    *sector_size = g_disk_block_io->Media->BlockSize;
}

static uint32_t uefi_to_e820_type(uint32_t t)
{
    switch (t) {
    case 1: case 2: case 3: case 4: case 7: return 1;
    case 9:  return 3;
    case 10: return 4;
    default: return 2;
    }
}

int hal_get_e820(void *buf, uint32_t max_entries)
{
    if (!buf || max_entries == 0) return -1;

    g_mmap_size = 0;
    g_mmap_key = 0;
    g_mmap_desc_size = 0;
    g_mmap_desc_ver = 0;

    EFI_STATUS s = bs_get_memory_map();
    if (s != EFI_BUFFER_TOO_SMALL && s != EFI_SUCCESS) return -1;

    g_mmap_size += 4096;
    if (g_mmap_size > MMAP_BUF_SIZE) return -1;
    if (g_mmap_desc_size < sizeof(EFI_MEMORY_DESCRIPTOR)) return -1;

    s = bs_get_memory_map();
    if (s != EFI_SUCCESS) return -1;

    uint32_t count = (uint32_t)(g_mmap_size / g_mmap_desc_size);
    e820_entry_t *out = (e820_entry_t *)buf;
    uint32_t n = 0;
    for (uint32_t i = 0; i < count && n < max_entries; i++) {
        EFI_MEMORY_DESCRIPTOR *d =
            (EFI_MEMORY_DESCRIPTOR *)(g_mmap_buf + i * g_mmap_desc_size);
        out[n].base = d->PhysicalStart;
        out[n].len  = d->NumberOfPages * 4096ULL;
        out[n].type = uefi_to_e820_type(d->Type);
        n++;
    }
    return (int)n;
}

void hal_get_video_mode(video_mode_t *mode)
{
    if (!mode) return;
    if (g_gop && g_gop->Mode && g_gop->Mode->Info &&
        (g_gop->Mode->Info->PixelFormat == 0 ||
         g_gop->Mode->Info->PixelFormat == 1)) {
        mode->framebuffer = (uint32_t *)(uintptr_t)g_gop->Mode->FrameBufferBase;
        mode->width       = g_gop->Mode->Info->HorizontalResolution;
        mode->height      = g_gop->Mode->Info->VerticalResolution;
        mode->pitch       = g_gop->Mode->Info->PixelsPerScanLine * 4;
        mode->bpp         = 32;
        /* QEMU/OVMF reports PixelFormat 0 (RGBX) but lays the
         * framebuffer out BGRX, so by default the mapping is swapped
         * from what the spec says. Build with GFX_FMT=rgbx to follow
         * the spec strictly. */
#if defined(IVO_GFX_FMT_RGBX)
        mode->format      = (g_gop->Mode->Info->PixelFormat == 1)
                            ? GFX_FMT_BGRX : GFX_FMT_RGBX;
#else
        mode->format      = (g_gop->Mode->Info->PixelFormat == 1)
                            ? GFX_FMT_RGBX : GFX_FMT_BGRX;
#endif
        mode->size        = g_gop->Mode->FrameBufferSize;
    } else {
        mode->framebuffer = 0;
        mode->width = 0;
        mode->height = 0;
        mode->pitch = 0;
        mode->bpp = 0;
        mode->format = GFX_FMT_BLTONLY;
        mode->size = 0;
    }
}

void hal_set_video_mode(uint32_t width, uint32_t height)
{
    (void)width; (void)height;
}

void hal_get_text_mode(int *cols, int *rows)
{
    *cols = 80;
    *rows = 25;
    if (!g_con_out || !g_con_out->Mode || !g_con_out->QueryMode) return;

    size_t c = 0, r = 0;
    EFI_STATUS s = g_con_out->QueryMode(g_con_out,
                                        (size_t)g_con_out->Mode->Mode,
                                        &c, &r);
    if (s == EFI_SUCCESS) {
        *cols = (int)c;
        *rows = (int)r;
    }
}

void hal_clear_screen(void)
{
    g_cursor_x = 0;
    g_cursor_y = 0;
    if (!g_con_out || !g_con_out->ClearScreen) return;
    EFI_STATUS (*fn)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *) =
        (EFI_STATUS (*)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *))
        g_con_out->ClearScreen;
    fn(g_con_out);
}

void hal_set_attr(uint8_t fg, uint8_t bg)
{
    if (!g_con_out || !g_con_out->SetAttribute) return;
    EFI_STATUS (*fn)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, size_t) =
        (EFI_STATUS (*)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, size_t))
        g_con_out->SetAttribute;
    fn(g_con_out, (size_t)((fg & 0x0F) | ((bg & 0x07) << 4)));
}

void hal_set_cursor(int x, int y)
{
    g_cursor_x = x;
    g_cursor_y = y;
    if (!g_con_out || !g_con_out->SetCursorPosition) return;
    EFI_STATUS (*fn)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, size_t, size_t) =
        (EFI_STATUS (*)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, size_t, size_t))
        g_con_out->SetCursorPosition;
    fn(g_con_out, (size_t)x, (size_t)y);
}

char hal_getchar(void)
{
    if (!g_con_in) return 0;
    EFI_INPUT_KEY key = {0, 0};
    EFI_STATUS s = g_con_in->ReadKeyStroke(g_con_in, &key);
    if (s != EFI_SUCCESS) return 0;

    if (key.UnicodeChar != 0 && key.UnicodeChar < 0x80)
        return (char)key.UnicodeChar;
    if (key.UnicodeChar >= 0x80)
        return (char)HAL_KEY_NON_ASCII;

    switch (key.ScanCode) {
    case 0x01: return (char)(0x80 | 0x48);
    case 0x02: return (char)(0x80 | 0x50);
    case 0x03: return (char)(0x80 | 0x4D);
    case 0x04: return (char)(0x80 | 0x4B);
    case 0x05: return (char)(0x80 | 0x49);
    case 0x06: return (char)(0x80 | 0x51);
    case 0x17: return 0x1B;
    default:   return 0;
    }
}

char hal_getchar_timeout(int timeout_ms)
{
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        char c = hal_getchar();
        if (c) return c;
        bs_stall(10000);
        elapsed += 10;
    }
    return 0;
}

void *hal_allocate_pages(size_t pages)
{
    if (!g_st || !g_st->BootServices) return 0;
    void *bs = g_st->BootServices;
    EFI_STATUS (*fn)(uint32_t, uint32_t, uint64_t, EFI_PHYSICAL_ADDRESS *) =
        *(void **)((uint8_t *)bs + 0x28);
    EFI_PHYSICAL_ADDRESS addr = 0;
    EFI_STATUS s = fn(EFI_ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, pages, &addr);
    return (s == EFI_SUCCESS) ? (void *)(uintptr_t)addr : 0;
}

void *hal_allocate_pages_below(size_t pages, uint64_t max_addr)
{
    if (!g_st || !g_st->BootServices) return 0;
    void *bs = g_st->BootServices;
    EFI_STATUS (*fn)(uint32_t, uint32_t, uint64_t, EFI_PHYSICAL_ADDRESS *) =
        *(void **)((uint8_t *)bs + 0x28);

    EFI_PHYSICAL_ADDRESS addr = max_addr;
    EFI_STATUS s = fn(1, EFI_LOADER_DATA, pages, &addr);
    if (s == EFI_SUCCESS) return (void *)(uintptr_t)addr;

    addr = 0;
    s = fn(0, EFI_LOADER_DATA, pages, &addr);
    return (s == EFI_SUCCESS) ? (void *)(uintptr_t)addr : 0;
}

void *hal_allocate_code_pages_below(size_t pages, uint64_t max_addr)
{
    if (!g_st || !g_st->BootServices) return 0;
    void *bs = g_st->BootServices;
    EFI_STATUS (*fn)(uint32_t, uint32_t, uint64_t, EFI_PHYSICAL_ADDRESS *) =
        *(void **)((uint8_t *)bs + 0x28);

    EFI_PHYSICAL_ADDRESS addr = max_addr;
    if (fn(1, EFI_LOADER_CODE, pages, &addr) == EFI_SUCCESS)
        return (void *)(uintptr_t)addr;
    addr = 0;
    return fn(0, EFI_LOADER_CODE, pages, &addr) == EFI_SUCCESS
         ? (void *)(uintptr_t)addr : 0;
}

void hal_free_pages(void *addr, size_t pages)
{
    if (!g_st || !g_st->BootServices || !addr) return;
    void *bs = g_st->BootServices;
    EFI_STATUS (*fn)(EFI_PHYSICAL_ADDRESS, uint64_t) =
        *(void **)((uint8_t *)bs + 0x30);
    fn((EFI_PHYSICAL_ADDRESS)(uintptr_t)addr, pages);
}

void hal_reboot(void)
{
    if (g_st && g_st->RuntimeServices) {
        void *rt = g_st->RuntimeServices;
        void (*reset)(uint32_t, uint64_t, uint64_t, void *) =
            *(void **)((uint8_t *)rt + 0x68);
        reset(EFI_RESET_COLD, 0, 0, 0);
    }
    for (;;) __asm__ volatile("cli; hlt");
}

int hal_chainload(void *data, size_t size)
{
    if (!g_st || !g_st->BootServices || !g_image || !data || size < 2)
        return -1;

    void *bs = g_st->BootServices;

    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    if (bs_handle_protocol(g_image, &GUID_LOADED_IMAGE,
                           (void **)&li) != EFI_SUCCESS || !li) {
        puts_("chainload: no LoadedImage\n");
        return -1;
    }
    void *volume_dp = 0;
    if (!li->DeviceHandle ||
        bs_handle_protocol(li->DeviceHandle, &GUID_DEVICE_PATH,
                           &volume_dp) != EFI_SUCCESS || !volume_dp) {
        puts_("chainload: no volume device path\n");
        return -1;
    }

    static const CHAR16 placeholder[] = {
        '\\', 'k', 'e', 'n', 'a', 'n', '-', 'c', 'h', 'a', 'i', 'n',
        0
    };

    uint16_t volume_dp_len = 0;
    {
        const uint8_t *p = (const uint8_t *)volume_dp;
        for (int guard = 0; guard < 256; guard++) {
            uint16_t l = *(const uint16_t *)(p + 2);
            if (l < 4) { puts_("chainload: bad volume dp\n"); return -1; }
            if (p[0] == END_DEVICE_PATH_TYPE &&
                p[1] == END_ENTIRE_DEVICE_PATH_SUBTYPE) {
                volume_dp_len = (uint16_t)(p - (const uint8_t *)volume_dp);
                break;
            }
            p += l;
        }
        if (volume_dp_len == 0) {
            puts_("chainload: no end node in volume dp\n");
            return -1;
        }
    }

    uint8_t dp_buf[512];
    size_t dp_off = 0;

    if ((size_t)volume_dp_len + 4 + sizeof(placeholder) + 4 > sizeof(dp_buf)) {
        puts_("chainload: dp too big\n");
        return -1;
    }

    for (int k = 0; k < volume_dp_len; k++)
        dp_buf[dp_off++] = ((const uint8_t *)volume_dp)[k];

    dp_buf[dp_off++] = 0x04;
    dp_buf[dp_off++] = 0x04;
    uint16_t fp_len = (uint16_t)(4 + sizeof(placeholder));
    dp_buf[dp_off++] = (uint8_t)(fp_len & 0xFF);
    dp_buf[dp_off++] = (uint8_t)(fp_len >> 8);
    for (size_t k = 0; k < sizeof(placeholder); k++)
        dp_buf[dp_off++] = ((const uint8_t *)placeholder)[k];

    dp_buf[dp_off++] = END_DEVICE_PATH_TYPE;
    dp_buf[dp_off++] = END_ENTIRE_DEVICE_PATH_SUBTYPE;
    dp_buf[dp_off++] = 0x04;
    dp_buf[dp_off++] = 0x00;

    EFI_HANDLE new_handle = 0;
    EFI_STATUS (*load_image)(BOOLEAN, EFI_HANDLE, const void *,
                             void *, uint64_t, EFI_HANDLE *) =
        *(void **)((uint8_t *)bs + BS_LoadImage);

    EFI_STATUS s = load_image(0, g_image, dp_buf, data, size, &new_handle);
    if (s != EFI_SUCCESS) {
        puts_("chainload: LoadImage failed\n");
        return -1;
    }

    EFI_STATUS (*start_image)(EFI_HANDLE, uint64_t *, CHAR16 **) =
        *(void **)((uint8_t *)bs + BS_StartImage);
    s = start_image(new_handle, 0, 0);
    if (s != EFI_SUCCESS) {
        puts_("chainload: StartImage failed\n");
        return -1;
    }

    puts_("chainload: StartImage returned\n");
    return 0;
}

int hal_sse2_available(void)
{
    return 1;
}

void hal_uefi_install_initrd_protocol(EFI_HANDLE kernel_handle,
                                      const void *initrd,
                                      size_t initrd_size)
{
    if (!g_st || !g_st->BootServices) return;
    void *bs = g_st->BootServices;

    g_initrd_data = initrd;
    g_initrd_size = initrd_size;

    EFI_STATUS (*install_proto)(EFI_HANDLE *, const efi_guid_t *,
                                uint64_t, void *) =
        *(void **)((uint8_t *)bs + BS_InstallProtocolInterface);

    (void)install_proto(&kernel_handle, &GUID_LINUX_INITRD_LF2, 0,
                        &g_initrd_proto);

    static full_dp_t initrd_dp;
    initrd_dp.vendor.Type    = MEDIA_DEVICE_PATH;
    initrd_dp.vendor.SubType = MEDIA_VENDOR_DP;
    initrd_dp.vendor.Length  = sizeof(initrd_dp.vendor);
    initrd_dp.vendor.Guid    = GUID_LINUX_INITRD;
    initrd_dp.end.Type       = END_DEVICE_PATH_TYPE;
    initrd_dp.end.SubType    = END_ENTIRE_DEVICE_PATH_SUBTYPE;
    initrd_dp.end.Length     = sizeof(initrd_dp.end);

    EFI_HANDLE initrd_handle = 0;
    (void)install_proto(&initrd_handle, &GUID_DEVICE_PATH, 0, &initrd_dp);
    (void)install_proto(&initrd_handle, &GUID_LOAD_FILE2, 0,
                        &g_initrd_proto);
}

void ivo_main(boot_context_t *ctx);

__attribute__((ms_abi))
void efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    g_st = st;
    g_image = image;

    boot_context_t ctx;
    uint8_t *p = (uint8_t *)&ctx;
    for (size_t i = 0; i < sizeof(ctx); i++) p[i] = 0;
    ctx.firmware_data = st;

    ivo_main(&ctx);

    for (;;) __asm__ volatile("hlt");
}