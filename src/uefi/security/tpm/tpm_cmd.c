/* tpm_cmd.c — TPM 2.0 command marshalling for sealed-object unseal.
 *
 * All commands are hand-marshalled. TPM wire format is big-endian,
 * fixed field order, no padding. SubmitCommand is the fourth entry in
 * the EFI_TCG2_PROTOCOL vtable. Under SMM it's the only supported
 * transport to the TPM; direct CRB MMIO is intercepted by the SMI
 * handler. See doc/tpm.md for the field-by-field layout of every
 * command and the wire format gotchas.
 *
 * The sealed blob comes from the plaintext ESP and is attacker-
 * controlled; every length in it is bounded before use. Responses are
 * parsed only within the size the TPM reported, which is itself
 * bounded by the response buffer.
 */

#include "core.h"

#if defined(TPM)

#include "hal/uefi_internal.h"
#include "security/tpm/tpm_internal.h"
#include "security/wipe.h"

#define EFI_DEVICE_ERROR 0x8000000000000007ULL

#define TPM_HDR_LEN 10

extern void *g_tcg2;

void tw_bytes(struct tpm_wr *w, const void *p, size_t n)
{
    if (w->err || n > w->cap - w->len) { w->err = 1; return; }
    if (n) memcpy(w->buf + w->len, p, n);
    w->len += n;
}

void tw_u8(struct tpm_wr *w, uint8_t v) { tw_bytes(w, &v, 1); }

void tw_u16(struct tpm_wr *w, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    tw_bytes(w, b, 2);
}

void tw_u32(struct tpm_wr *w, uint32_t v)
{
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16),
                     (uint8_t)(v >> 8),  (uint8_t)v };
    tw_bytes(w, b, 4);
}

void tw_b2b(struct tpm_wr *w, const void *p, size_t n)
{
    if (n > 0xFFFF) { w->err = 1; return; }
    tw_u16(w, (uint16_t)n);
    tw_bytes(w, p, n);
}

void tw_begin(struct tpm_wr *w, uint8_t *buf, size_t cap,
              uint16_t tag, uint32_t cc)
{
    w->buf = buf;
    w->len = 0;
    w->cap = cap;
    w->err = 0;
    tw_u16(w, tag);
    tw_u32(w, 0);
    tw_u32(w, cc);
}

void tw_auth(struct tpm_wr *w, uint32_t session, uint8_t attrs,
             const uint8_t *hmac, size_t hmac_len)
{
    tw_u32(w, (uint32_t)(4 + 2 + 1 + 2 + hmac_len));
    tw_u32(w, session);
    tw_u16(w, 0);        /* nonceCaller: empty */
    tw_u8(w, attrs);
    tw_b2b(w, hmac, hmac_len);
}


static const uint8_t *tr_take(struct tpm_rd *r, size_t n)
{
    if (r->err || n > r->left) { r->err = 1; return 0; }
    const uint8_t *p = r->p;
    r->p += n;
    r->left -= n;
    return p;
}

uint8_t tr_u8(struct tpm_rd *r)
{
    const uint8_t *p = tr_take(r, 1);
    return p ? *p : 0;
}

uint16_t tr_u16(struct tpm_rd *r)
{
    const uint8_t *p = tr_take(r, 2);
    return p ? (uint16_t)((p[0] << 8) | p[1]) : 0;
}

uint32_t tr_u32(struct tpm_rd *r)
{
    const uint8_t *p = tr_take(r, 4);
    return p ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8)  |  (uint32_t)p[3] : 0;
}

const uint8_t *tr_b2b(struct tpm_rd *r, uint16_t *len)
{
    *len = tr_u16(r);
    const uint8_t *p = tr_take(r, *len);
    if (!p) *len = 0;
    return p;
}

void tr_params(struct tpm_rd *r)
{
    if (r->tag != TPM_ST_SESSIONS) return;
    uint32_t n = tr_u32(r);
    if (n > r->left) { r->err = 1; return; }
    r->left = n;
}

typedef EFI_STATUS (*efi_tcg2_submit_fn)(
    void *This, uint32_t in_size, uint8_t *in_buf,
    uint32_t out_size, uint8_t *out_buf);

static uint32_t g_last_tpm_rc;

uint32_t last_tpm_rc(void)
{
    return g_last_tpm_rc;
}

static void serial_err_hex(const char *what, uint32_t rc)
{
    static const char h[] = "0123456789abcdef";
    char buf[64];
    int i = 0;
    buf[i++] = 't'; buf[i++] = 'p'; buf[i++] = 'm'; buf[i++] = ' ';
    for (const char *p = what; *p && i < 48; p++) buf[i++] = *p;
    buf[i++] = ' ';
    buf[i++] = 'r'; buf[i++] = 'c'; buf[i++] = '=';
    buf[i++] = '0'; buf[i++] = 'x';
    for (int j = 7; j >= 0; j--) buf[i++] = h[(rc >> (j * 4)) & 0xF];
    buf[i++] = '\n';
    buf[i] = 0;
    hal_puts_serial(buf);
}

int tpm_transact(struct tpm_wr *w, uint8_t *rsp, size_t rsp_cap,
                 struct tpm_rd *r, const char *what)
{
    if (!g_tcg2 || w->err || w->len < TPM_HDR_LEN || rsp_cap < TPM_HDR_LEN)
        return -1;

    uint32_t n = (uint32_t)w->len;
    w->buf[2] = (uint8_t)(n >> 24);
    w->buf[3] = (uint8_t)(n >> 16);
    w->buf[4] = (uint8_t)(n >> 8);
    w->buf[5] = (uint8_t)n;
    memset(rsp, 0, rsp_cap);
    efi_tcg2_submit_fn fn = (efi_tcg2_submit_fn)((void **)g_tcg2)[3];
    EFI_STATUS s = fn(g_tcg2, n, w->buf, (uint32_t)rsp_cap, rsp);
    if (s != EFI_SUCCESS) {
        hal_puts_serial("tpm submit failed\n");
        return -1;
    }

    uint32_t size = ((uint32_t)rsp[2] << 24) | ((uint32_t)rsp[3] << 16) |
                    ((uint32_t)rsp[4] << 8)  |  (uint32_t)rsp[5];
    if (size < TPM_HDR_LEN || size > rsp_cap) {
        con_puts("tpm: bad response size\n");
        hal_puts_serial("tpm: bad response size\n");
        return -1;
    }

    r->p    = rsp;
    r->left = size;
    r->err  = 0;
    r->tag  = tr_u16(r);
    (void)tr_u32(r);
    uint32_t code = tr_u32(r);
    g_last_tpm_rc = code;
    if (code != 0) {
        serial_err_hex(what, code);
        return -1;
    }
    return 0;
}

int tpm_start_session(uint8_t type, uint32_t *session_out)
{
    static const uint8_t nonce[32];
    uint8_t cmd[128], rsp[128];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_NO_SESSIONS,
             TPM_CC_START_AUTH_SESSION);
    tw_u32(&w, TPM_RH_NULL);            /* tpmKey */
    tw_u32(&w, TPM_RH_NULL);            /* bind */
    tw_b2b(&w, nonce, sizeof(nonce));   /* nonceCaller, SHA-256 size */
    tw_u16(&w, 0);                      /* encryptedSalt, empty */
    tw_u8(&w, type);
    tw_u16(&w, TPM_ALG_NULL);
    tw_u16(&w, TPM_ALG_SHA256);         /* authHash */

    if (tpm_transact(&w, rsp, sizeof(rsp), &r, "startauth") != 0)
        return -1;
    uint32_t h = tr_u32(&r);
    if (r.err) return -1;
    *session_out = h;
    return 0;
}

int tpm_policy_pcr(uint32_t session, uint32_t pcr_mask)
{
    uint8_t cmd[64], rsp[64];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_NO_SESSIONS, TPM_CC_POLICY_PCR);
    tw_u32(&w, session);
    tw_u16(&w, 0);                      /* pcrDigest size = 0 */
    tw_u32(&w, 1);                      /* TPML_PCR_SELECTION.count */
    tw_u16(&w, TPM_ALG_SHA256);
    tw_u8(&w, 3);                       /* sizeofSelect */
    tw_u8(&w, (uint8_t)pcr_mask);       /* bit n of byte n/8 = PCR n */
    tw_u8(&w, (uint8_t)(pcr_mask >> 8));
    tw_u8(&w, (uint8_t)(pcr_mask >> 16));
    return tpm_transact(&w, rsp, sizeof(rsp), &r, "policypcr");
}

int tpm_policy_password(uint32_t session)
{
    uint8_t cmd[32], rsp[64];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_NO_SESSIONS,
             TPM_CC_POLICY_PASSWORD);
    tw_u32(&w, session);
    return tpm_transact(&w, rsp, sizeof(rsp), &r, "policypassword");
}

void tpm_flush(uint32_t handle)
{
    uint8_t cmd[16], rsp[32];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT);
    tw_u32(&w, handle);
    (void)tpm_transact(&w, rsp, sizeof(rsp), &r, "flush");
}


static int cmd_load(uint32_t parent,
                    const uint8_t *priv, uint16_t priv_len,
                    const uint8_t *pub,  uint16_t pub_len,
                    uint32_t *object_out)
{
    static uint8_t cmd[64 + 2 * IVO_SEAL_PART_MAX];
    uint8_t rsp[256];
    struct tpm_wr w;
    struct tpm_rd r;
    int rc = -1;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_SESSIONS, TPM_CC_LOAD);
    tw_u32(&w, parent);
    tw_auth(&w, TPM_RS_PW, 0, 0, 0);
    tw_b2b(&w, priv, priv_len);
    tw_b2b(&w, pub, pub_len);

    if (tpm_transact(&w, rsp, sizeof(rsp), &r, "load") == 0) {
        uint32_t h = tr_u32(&r);
        if (!r.err) { *object_out = h; rc = 0; }
    }
    ivo_wipe(cmd, sizeof(cmd));
    return rc;
}

static int cmd_unseal(uint32_t object, uint32_t policy_session,
                      const uint8_t *pin, size_t pin_len,
                      uint8_t *out, size_t *out_len)
{
    uint8_t cmd[128], rsp[512];
    struct tpm_wr w;
    struct tpm_rd r;
    int rc = -1;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_SESSIONS, TPM_CC_UNSEAL);
    tw_u32(&w, object);
    tw_auth(&w, policy_session, 0x01 /* continueSession */, pin, pin_len);

    if (tpm_transact(&w, rsp, sizeof(rsp), &r, "unseal") == 0) {
        uint16_t n;
        tr_params(&r);
        const uint8_t *data = tr_b2b(&r, &n);
        if (!r.err && data && n <= *out_len) {
            memcpy(out, data, n);
            *out_len = n;
            rc = 0;
        }
    }
    ivo_wipe(cmd, sizeof(cmd));
    ivo_wipe(rsp, sizeof(rsp));
    return rc;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Blob layout, little-endian:
 *
 *   0   4  magic  "KNTP"
 *   4   1  version (2)
 *   5   1  flags (bit 0 = PIN required; others reserved, must be 0)
 *   6   3  reserved (0)
 *   9   4  pcr_mask (bit n = PCR n, SHA-256 bank, PCRs 0-23)
 *  13   4  parent_handle (persistent, 0x81xxxxxx)
 *  17   2  private_len (1..1024)
 *  19   2  public_len  (1..1024)
 *  21   N  private
 *  21+N M  public
 *
 * The blob is not trusted.*/
int tpm2_unseal(const uint8_t *blob, size_t blob_len,
                const uint8_t *pin, size_t pin_len,
                uint8_t *out, size_t *out_len)
{
    if (!blob || !out || !out_len) return -1;
    if (blob_len < IVO_SEAL_HDR_LEN) return -1;
    if (memcmp(blob, "KNTP", 4) != 0) return -1;
    if (blob[4] != IVO_SEAL_VERSION) return -1;
    if ((blob[5] & ~IVO_SEAL_FLAG_PIN) || blob[6] || blob[7] || blob[8])
        return -1;

    uint32_t pcr_mask = le32(blob + 9);
    uint32_t parent   = le32(blob + 13);
    uint16_t priv_len = (uint16_t)(blob[17] | (blob[18] << 8));
    uint16_t pub_len  = (uint16_t)(blob[19] | (blob[20] << 8));

    if (pcr_mask == 0 || (pcr_mask & ~IVO_SEAL_PCR_VALID)) return -1;
    if (parent < TPM_HR_PERSISTENT_MIN || parent > TPM_HR_PERSISTENT_MAX)
        return -1;
    if (priv_len == 0 || priv_len > IVO_SEAL_PART_MAX ||
        pub_len  == 0 || pub_len  > IVO_SEAL_PART_MAX) return -1;
    if ((size_t)IVO_SEAL_HDR_LEN + priv_len + pub_len != blob_len) return -1;

    int needs_pin = (blob[5] & IVO_SEAL_FLAG_PIN) != 0;
    if (needs_pin && (!pin || pin_len == 0 || pin_len > IVO_SEAL_PIN_MAX))
        return -1;
    if (!needs_pin && pin_len != 0) return -1;

    const uint8_t *priv = blob + IVO_SEAL_HDR_LEN;
    const uint8_t *pub  = priv + priv_len;

    uint32_t object = 0;
    if (cmd_load(parent, priv, priv_len, pub, pub_len, &object) != 0)
        return -1;

    uint32_t session = 0;
    if (tpm_start_session(TPM_SE_POLICY, &session) != 0) {
        tpm_flush(object);
        return -1;
    }

    int rc = -1;
    if (tpm_policy_pcr(session, pcr_mask) == 0 &&
        (!needs_pin || tpm_policy_password(session) == 0))
        rc = cmd_unseal(object, session,
                        needs_pin ? pin : 0, needs_pin ? pin_len : 0,
                        out, out_len);

    tpm_flush(session);
    tpm_flush(object);
    return rc;
}

int tpm_policy_get_digest(uint32_t session, uint8_t *out, size_t *out_len)
{
    uint8_t cmd[16], rsp[64];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_NO_SESSIONS, 0x00000189u);
    tw_u32(&w, session);
    if (tpm_transact(&w, rsp, sizeof(rsp), &r, "policygetdigest") != 0)
        return -1;
    uint16_t n;
    const uint8_t *d = tr_b2b(&r, &n);
    if (r.err || !d || n == 0 || n > *out_len) return -1;
    memcpy(out, d, n);
    *out_len = n;
    return 0;
}
#else /* !TPM */

int tpm_policy_get_digest(uint32_t session, uint8_t *out, size_t *out_len)
{ (void)session; (void)out; (void)out_len; return -1; }

int tpm2_unseal(const uint8_t *blob, size_t blob_len,
                const uint8_t *pin, size_t pin_len,
                uint8_t *out, size_t *out_len)
{
    (void)blob; (void)blob_len; (void)pin; (void)pin_len;
    (void)out; (void)out_len;
    return -1;
}

#endif /* TPM */
