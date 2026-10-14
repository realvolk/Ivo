/* tpm_nv.c — TPM 2.0 monotonic counter for firmware rollback.
 * Stores IVO_RELEASE, defined on first use with empty owner auth.
 * If the owner hierarchy has a non-empty auth, definition fails and
 * the caller falls back to the UEFI variable tier. TPM=1 only. */

#include "core.h"

#if defined(TPM)

#include "hal/uefi_internal.h"
#include "security/tpm/tpm_internal.h"

/* Monotonic counter slot. TPM 2.0 reserves 0x01800000-0x01BFFFFF for
 * counters. Slot 0 is unclaimed by anything Ivo knows of. */
#define IVO_NV_FWVER_INDEX 0x01800000u

/* TPMA_NV: NT=counter, AUTHREAD, OWNERWRITE. The spec requires at
 * least one write attribute on any NV index, including counters;
 * OWNERWRITE matches the TPM_RH_OWNER auth used by NV_Increment.
 * Counters forbid ORDERLY and NO_DA; WRITEALL and WRITEDEFINE are
 * meaningless here and stay clear. */
#define NV_COUNTER_ATTRS 0x00040012u

extern void *g_tcg2;

int tpm_available(void)
{
    return g_tcg2 != 0;
}

static int cmd_nv_define_counter(uint32_t index)
{
    uint8_t cmd[128], rsp[128];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_SESSIONS, TPM_CC_NV_DEFINE_SPACE);
    tw_u32(&w, TPM_RH_OWNER);
    tw_auth(&w, TPM_RS_PW, 0, 0, 0);
    tw_u16(&w, 0);          /* TPM2B_AUTH, empty */

    /* TPM2B_NV_PUBLIC: nvIndex(4) + nameAlg(2) + attributes(4)
     * + authPolicy_size(2) + dataSize(2) = 14. */
    tw_u16(&w, 14);
    tw_u32(&w, index);
    tw_u16(&w, TPM_ALG_SHA256);
    tw_u32(&w, NV_COUNTER_ATTRS);
    tw_u16(&w, 0);          /* authPolicy: empty */
    tw_u16(&w, 8);          /* dataSize: counters are 8 bytes */

    return tpm_transact(&w, rsp, sizeof(rsp), &r, "nvdefine");
}

static int cmd_nv_read(uint32_t index, uint16_t offset, uint16_t size,
                       uint8_t *out)
{
    uint8_t cmd[64], rsp[64];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_SESSIONS, TPM_CC_NV_READ);
    tw_u32(&w, index);      /* authHandle */
    tw_u32(&w, index);      /* nvIndex */
    tw_auth(&w, TPM_RS_PW, 0, 0, 0);
    tw_u16(&w, size);
    tw_u16(&w, offset);

    if (tpm_transact(&w, rsp, sizeof(rsp), &r, "nvread") != 0) return -1;

    tr_params(&r);
    uint16_t n;
    const uint8_t *data = tr_b2b(&r, &n);
    if (r.err || !data || n != size) return -1;
    memcpy(out, data, n);
    return 0;
}

static int cmd_nv_increment(uint32_t index)
{
    uint8_t cmd[64], rsp[64];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_SESSIONS, TPM_CC_NV_INCREMENT);
    tw_u32(&w, index);      /* authHandle */
    tw_u32(&w, index);      /* nvIndex */
    tw_auth(&w, TPM_RS_PW, 0, 0, 0);

    return tpm_transact(&w, rsp, sizeof(rsp), &r, "nvincrement");
}

static int read_counter(uint64_t *out)
{
    uint8_t buf[8];
    int rc = cmd_nv_read(IVO_NV_FWVER_INDEX, 0, 8, buf);
    if (rc != 0) {
        /* A freshly defined counter has TPMA_NV_WRITTEN clear and
         * returns TPM_RC_NV_UNINITIALIZED (0x14A) on read. That is
         * "counter is at 0", not a failure. */
        if (last_tpm_rc() == 0x14A) {
            *out = 0;
            return 0;
        }
        return -1;
    }
    /* Big-endian on the wire, per TPM 2.0 spec. */
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | buf[i];
    *out = v;
    return 0;
}

/* Ensure the counter is at least `target`. On success, *out is the
 * counter value after any bumping (>= target). On failure, returns
 * -1 and the counter state is unchanged. */
int tpm_nv_fwver_ensure(int target, int *out)
{
    if (!g_tcg2) return -1;
    if (target < 0 || !out) return -1;
    if (target > IVO_CEILING)
        hal_puts_serial("ivo: NV counter target above ceiling\n");

    uint64_t current;

    if (read_counter(&current) != 0) {
        if (cmd_nv_define_counter(IVO_NV_FWVER_INDEX) != 0) return -1;
        if (read_counter(&current) != 0) return -1;
    }

    if (current > 0x7FFFFFFF) return -1;

    while (current < (uint64_t)target) {
        if (cmd_nv_increment(IVO_NV_FWVER_INDEX) != 0) return -1;
        current++;
    }

    *out = (int)current;
    return 0;
}

int tpm_nv_fwver_read(int *out)
{
    if (!g_tcg2 || !out) return -1;
    uint64_t v;
    if (read_counter(&v) != 0) return -1;
    if (v > 0x7FFFFFFF) return -1;
    *out = (int)v;
    return 0;
}

#else /* !TPM */

int tpm_available(void) { return 0; }
int tpm_nv_fwver_ensure(int target, int *out)
{ (void)target; (void)out; return -1; }
int tpm_nv_fwver_read(int *out) { (void)out; return -1; }

#endif /* TPM */