/* tpm_seal_create.c — TPM 2.0 enrollment: seal a passphrase to a
 * PCR policy under a persistent SRK.
 *
 * Counterpart to tpm_cmd.c's unseal path, and uses its marshalling
 * helpers. Creates the SRK at 0x81000001 if it doesn't exist, builds
 * the auth policy via a trial session, creates the sealed object, and
 * emits the IVO_SEAL v2 blob that tpm2_unseal consumes.
 *
 * TPM only. Other builds get a stub.
 */

#include "core.h"

#if defined(TPM)

#include "hal/uefi_internal.h"
#include "security/tpm/tpm_internal.h"
#include "security/wipe.h"

#define TPM_CC_CREATE_PRIMARY     0x00000131u
#define TPM_CC_EVICT_CONTROL      0x00000120u
#define TPM_CC_CREATE             0x00000153u
#define TPM_CC_READ_PUBLIC        0x00000173u
#define TPM_CC_POLICY_GET_DIGEST  0x0000017Eu

/* Standard SRK handle. systemd-cryptenroll uses the same value; the
 * Linux kernel's trusted-key subsystem does too. Persistent, not
 * transient, because transient handles are lost on TPM reset. */
#define SRK_HANDLE  0x81000001u

/* fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth |
 * restricted | decrypt */
#define SRK_ATTRS   0x00030072u

/* fixedTPM (0x02) | fixedParent (0x10) | adminWithPolicy (0x80).
 *
 * userWithAuth is clear: the USER role (Unseal) can only be satisfied
 * by a policy session, i.e. PolicyPCR [+ PolicyPassword]; the
 * authValue alone never unseals. adminWithPolicy likewise puts ADMIN
 * actions (ObjectChangeAuth, ...) behind the policy.
 * sensitiveDataOrigin is clear because the caller supplies the data;
 * real TPMs reject the combination with TPM_RC_ATTRIBUTES.
 * noDA is clear so PIN guesses count toward dictionary-attack lockout. */
#define SEALED_ATTRS 0x00000092u

extern void *g_tcg2;

/* Returns 0 if the handle is populated, -1 otherwise. Used to check
 * whether the SRK already exists at its persistent handle. */
static int cmd_read_public(uint32_t handle)
{
    uint8_t cmd[16], rsp[1024];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_NO_SESSIONS, TPM_CC_READ_PUBLIC);
    tw_u32(&w, handle);
    return tpm_transact(&w, rsp, sizeof(rsp), &r, "readpublic");
}

static int cmd_policy_get_digest(uint32_t session,
                                 uint8_t *digest, size_t *digest_len)
{
    uint8_t cmd[16], rsp[64];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_NO_SESSIONS,
             TPM_CC_POLICY_GET_DIGEST);
    tw_u32(&w, session);
    if (tpm_transact(&w, rsp, sizeof(rsp), &r, "policygetdigest") != 0)
        return -1;

    uint16_t n;
    const uint8_t *d = tr_b2b(&r, &n);
    if (r.err || !d || n == 0 || n > *digest_len) return -1;
    memcpy(digest, d, n);
    *digest_len = n;
    return 0;
}

static int cmd_create_primary(uint32_t *handle_out)
{
    uint8_t cmd[128], rsp[1024];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY);
    tw_u32(&w, TPM_RH_OWNER);
    tw_auth(&w, TPM_RS_PW, 0, 0, 0);

    /* inSensitive: empty auth, empty data */
    tw_u16(&w, 4);
    tw_u16(&w, 0);
    tw_u16(&w, 0);

    /* inPublic: TPMT_PUBLIC (RSA SRK, standard template). The size
     * prefix is the template length below. */
    tw_u16(&w, 26);
    tw_u16(&w, TPM_ALG_RSA);
    tw_u16(&w, TPM_ALG_SHA256);
    tw_u32(&w, SRK_ATTRS);
    tw_u16(&w, 0);                   /* authPolicy: empty for SRK */
    tw_u16(&w, TPM_ALG_AES);
    tw_u16(&w, 128);                 /* keyBits for AES */
    tw_u16(&w, TPM_ALG_CFB);         /* mode */
    tw_u16(&w, TPM_ALG_NULL);        /* RSA scheme */
    tw_u16(&w, 2048);                /* RSA key size */
    tw_u32(&w, 0);                   /* exponent (default) */
    tw_u16(&w, 0);                   /* unique: empty for CreatePrimary */

    tw_u16(&w, 0);                   /* outsideInfo */
    tw_u32(&w, 0);                   /* creationPCR.count */

    if (tpm_transact(&w, rsp, sizeof(rsp), &r, "createprimary") != 0)
        return -1;
    uint32_t h = tr_u32(&r);
    if (r.err) return -1;
    *handle_out = h;
    return 0;
}

static int cmd_evict_control(uint32_t object, uint32_t persistent)
{
    uint8_t cmd[64], rsp[64];
    struct tpm_wr w;
    struct tpm_rd r;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_SESSIONS, TPM_CC_EVICT_CONTROL);
    tw_u32(&w, TPM_RH_OWNER);
    tw_u32(&w, object);
    tw_auth(&w, TPM_RS_PW, 0, 0, 0);
    tw_u32(&w, persistent);
    return tpm_transact(&w, rsp, sizeof(rsp), &r, "evictcontrol");
}

static int cmd_create(uint32_t parent,
                      const uint8_t *secret, size_t secret_len,
                      const uint8_t *user_auth, size_t user_auth_len,
                      const uint8_t *auth_policy, size_t auth_policy_len,
                      uint8_t *out_priv, size_t *out_priv_len,
                      uint8_t *out_pub, size_t *out_pub_len)
{
    static uint8_t cmd[512];
    static uint8_t rsp[4096];
    struct tpm_wr w;
    struct tpm_rd r;
    int rc = -1;

    tw_begin(&w, cmd, sizeof(cmd), TPM_ST_SESSIONS, TPM_CC_CREATE);
    tw_u32(&w, parent);
    tw_auth(&w, TPM_RS_PW, 0, 0, 0);

    /* inSensitive: TPM2B_SENSITIVE_CREATE { userAuth, data } */
    tw_u16(&w, (uint16_t)(2 + user_auth_len + 2 + secret_len));
    tw_b2b(&w, user_auth, user_auth_len);
    tw_b2b(&w, secret, secret_len);

    /* inPublic: TPM2B_PUBLIC (sealed data object) */
    tw_u16(&w, (uint16_t)(2 + 2 + 4 + 2 + auth_policy_len + 2 + 2));
    tw_u16(&w, TPM_ALG_KEYEDHASH);
    tw_u16(&w, TPM_ALG_SHA256);
    tw_u32(&w, SEALED_ATTRS);
    tw_b2b(&w, auth_policy, auth_policy_len);
    tw_u16(&w, TPM_ALG_NULL);        /* TPMS_KEYEDHASH_PARMS.scheme */
    tw_u16(&w, 0);                   /* unique: empty TPM2B_DIGEST */

    tw_u16(&w, 0);                   /* outsideInfo */
    tw_u32(&w, 0);                   /* creationPCR.count */

    if (tpm_transact(&w, rsp, sizeof(rsp), &r, "create") == 0) {
        uint16_t plen, ulen;
        tr_params(&r);
        const uint8_t *priv = tr_b2b(&r, &plen);
        const uint8_t *pub  = tr_b2b(&r, &ulen);
        if (!r.err && priv && pub &&
            plen > 0 && plen <= *out_priv_len &&
            ulen > 0 && ulen <= *out_pub_len) {
            memcpy(out_priv, priv, plen);
            memcpy(out_pub, pub, ulen);
            *out_priv_len = plen;
            *out_pub_len  = ulen;
            rc = 0;
        }
    }
    ivo_wipe(cmd, sizeof(cmd));   /* held the secret and the PIN */
    return rc;
}

static void put_le32(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)v;         b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
}

int tpm2_seal_create(const uint8_t *secret, size_t secret_len,
                     const uint8_t *pin, size_t pin_len,
                     uint32_t pcr_mask,
                     uint8_t *blob_out, size_t *blob_out_len,
                     size_t blob_out_cap)
{
    if (!g_tcg2 || !blob_out || !blob_out_len) return -1;
    if (!secret || secret_len == 0 || secret_len > IVO_SEAL_SECRET_MAX)
        return -1;
    if (pin_len > 0 && (!pin || pin_len > IVO_SEAL_PIN_MAX)) return -1;
    if (pcr_mask == 0 || (pcr_mask & ~IVO_SEAL_PCR_VALID)) return -1;

    /* Ensure the SRK exists at SRK_HANDLE. */
    if (cmd_read_public(SRK_HANDLE) != 0) {
        uint32_t transient = 0;
        if (cmd_create_primary(&transient) != 0) return -1;
        int rc = cmd_evict_control(transient, SRK_HANDLE);
        tpm_flush(transient);
        if (rc != 0) return -1;
    }

    /* Build the auth policy in a trial session, against the current
     * PCR values. */
    uint32_t trial = 0;
    uint8_t  policy[32];
    size_t   policy_len = sizeof(policy);
    if (tpm_start_session(TPM_SE_TRIAL, &trial) != 0) return -1;
    int prc = tpm_policy_pcr(trial, pcr_mask);
    if (prc == 0 && pin_len > 0) prc = tpm_policy_password(trial);
    if (prc == 0) prc = cmd_policy_get_digest(trial, policy, &policy_len);
    tpm_flush(trial);
    if (prc != 0) return -1;

    /* Create the sealed object under the SRK. */
    uint8_t out_priv[IVO_SEAL_PART_MAX];
    uint8_t out_pub[IVO_SEAL_PART_MAX];
    size_t out_priv_len = sizeof(out_priv);
    size_t out_pub_len  = sizeof(out_pub);

    if (cmd_create(SRK_HANDLE,
                   secret, secret_len,
                   pin, pin_len,
                   policy, policy_len,
                   out_priv, &out_priv_len,
                   out_pub,  &out_pub_len) != 0)
        return -1;

    /* Assemble the IVO_SEAL v2 blob. Header is little-endian. */
    size_t total = IVO_SEAL_HDR_LEN + out_priv_len + out_pub_len;
    if (total > blob_out_cap) return -1;

    uint8_t *b = blob_out;
    memcpy(b, "KNTP", 4);
    b[4] = IVO_SEAL_VERSION;
    b[5] = (pin_len > 0) ? IVO_SEAL_FLAG_PIN : 0;
    b[6] = b[7] = b[8] = 0;
    put_le32(b + 9, pcr_mask);
    put_le32(b + 13, SRK_HANDLE);
    b[17] = (uint8_t)out_priv_len;
    b[18] = (uint8_t)(out_priv_len >> 8);
    b[19] = (uint8_t)out_pub_len;
    b[20] = (uint8_t)(out_pub_len >> 8);
    memcpy(b + IVO_SEAL_HDR_LEN, out_priv, out_priv_len);
    memcpy(b + IVO_SEAL_HDR_LEN + out_priv_len, out_pub, out_pub_len);

    *blob_out_len = total;
    return 0;
}

#else /* !TPM */

int tpm2_seal_create(const uint8_t *secret, size_t secret_len,
                     const uint8_t *pin, size_t pin_len,
                     uint32_t pcr_mask,
                     uint8_t *blob_out, size_t *blob_out_len,
                     size_t blob_out_cap)
{
    (void)secret; (void)secret_len; (void)pin; (void)pin_len;
    (void)pcr_mask; (void)blob_out; (void)blob_out_len; (void)blob_out_cap;
    return -1;
}

#endif /* TPM */
