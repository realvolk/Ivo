/* tpm.c — TPM 2.0 measurement via EFI_TCG2_PROTOCOL.
 * Compiled in only with TPM=1 (-DTPM); otherwise every entry point is
 * a no-op stub.
 */

#include "core.h"

#if defined(TPM)

#include "hal/uefi_internal.h"

#define TCG2_PCR_INDEX_MAX     23

/* EFI_TCG2_PROTOCOL_GUID */
static const efi_guid_t GUID_TCG2 = {
    0x607f766c, 0x7455, 0x42be,
    { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }
};

#define EV_EFI_BOOT_SERVICES_APPLICATION  0x80000003

typedef EFI_STATUS (*efi_tcg2_hash_log_extend_fn)(
    void *This, uint64_t Flags, uint64_t DataToHash, uint64_t DataToHashLen,
    void *EfiTcgEvent);

struct tcg2_event {
    uint32_t Size;
    uint32_t HeaderSize;
    uint16_t HeaderVersion;
    uint32_t PCRIndex;
    uint32_t EventType;
    uint8_t  Event[1];
} __attribute__((packed));

void *g_tcg2;

static void *locate_tcg2(void)
{
    if (!g_st || !g_st->BootServices) return 0;
    void *bs = g_st->BootServices;
    EFI_STATUS (*fn)(const efi_guid_t *, void *, void **) =
        *(void **)((uint8_t *)bs + 0x140);   /* LocateProtocol */
    void *out = 0;
    if (fn(&GUID_TCG2, 0, &out) != EFI_SUCCESS) return 0;
    return out;
}

int tpm_init(void)
{
    g_tcg2 = locate_tcg2();
    if (!g_tcg2) return -1;
    return 0;
}

void tpm_measure(uint32_t pcr, const uint8_t *data, size_t len)
{
    if (!g_tcg2) return;
    if (pcr > TCG2_PCR_INDEX_MAX) return;
    if (!data || len == 0) return;

    struct tcg2_event ev;
    ev.Size          = sizeof(ev);
    ev.HeaderSize    = 14;
    ev.HeaderVersion = 1;
    ev.PCRIndex      = pcr;
    ev.EventType     = EV_EFI_BOOT_SERVICES_APPLICATION;
    ev.Event[0]      = 0;

    efi_tcg2_hash_log_extend_fn fn =
        (efi_tcg2_hash_log_extend_fn)((void **)g_tcg2)[2];

    (void)fn(g_tcg2, 0,
             (uint64_t)(uintptr_t)data, (uint64_t)len, &ev);
}

void tpm_measure_string(uint32_t pcr, const char *str)
{
    if (!str) return;
    size_t len = 0;
    while (str[len]) len++;
    tpm_measure(pcr, (const uint8_t *)str, len);
}

#else /* !TPM */

int  tpm_init(void) { return -1; }
void tpm_measure(uint32_t pcr, const uint8_t *data, size_t len)
{ (void)pcr; (void)data; (void)len; }
void tpm_measure_string(uint32_t pcr, const char *str)
{ (void)pcr; (void)str; }

#endif /* TPM */