/* tpm_internal.h — TPM 2.0 marshalling shared by tpm_cmd.c (unseal)
 * and tpm_seal_create.c (enrollment). UEFI + TPM builds only.
 *
 * Writers never write past their buffer: overflow sets `err` and the
 * command is not sent. Readers only see the bytes the TPM said it
 * returned (the response header's size, itself bounded by the
 * buffer); reading past them sets `err` and yields zeros.
 */

#ifndef IVO_TPM_INTERNAL_H
#define IVO_TPM_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#define TPM_ST_NO_SESSIONS 0x8001u
#define TPM_ST_SESSIONS    0x8002u

#define TPM_RH_OWNER  0x40000001u
#define TPM_RH_NULL   0x40000007u
#define TPM_RS_PW     0x40000009u

#define TPM_SE_POLICY 0x01u
#define TPM_SE_TRIAL  0x03u

#define TPM_CC_CREATE_PRIMARY      0x00000131u
#define TPM_CC_EVICT_CONTROL       0x00000120u
#define TPM_CC_CREATE              0x00000153u
#define TPM_CC_LOAD                0x00000157u
#define TPM_CC_UNSEAL              0x0000015Eu
#define TPM_CC_FLUSH_CONTEXT       0x00000165u
#define TPM_CC_READ_PUBLIC         0x00000173u
#define TPM_CC_START_AUTH_SESSION  0x00000176u
#define TPM_CC_NV_DEFINE_SPACE     0x0000012Au
#define TPM_CC_NV_INCREMENT        0x00000134u
#define TPM_CC_NV_READ             0x0000014Eu
#define TPM_CC_POLICY_GET_DIGEST   0x00000189u
#define TPM_CC_POLICY_PCR          0x0000017Fu
#define TPM_CC_POLICY_PASSWORD     0x0000018Cu

#define TPM_ALG_RSA       0x0001u
#define TPM_ALG_AES       0x0006u
#define TPM_ALG_KEYEDHASH 0x0008u
#define TPM_ALG_SHA256    0x000Bu
#define TPM_ALG_NULL      0x0010u
#define TPM_ALG_CFB       0x0043u

/* Persistent object handles: 0x81xxxxxx. */
#define TPM_HR_PERSISTENT_MIN 0x81000000u
#define TPM_HR_PERSISTENT_MAX 0x81FFFFFFu

/* IVO_SEAL v2 blob ("KNTP"), little-endian header. See tpm_cmd.c. */
#define IVO_SEAL_HDR_LEN    21
#define IVO_SEAL_VERSION    2
#define IVO_SEAL_FLAG_PIN   0x01
#define IVO_SEAL_PART_MAX   1024   /* TPM2B_PRIVATE / TPM2B_PUBLIC body */
#define IVO_SEAL_PIN_MAX    32     /* authValue <= nameAlg digest size */
#define IVO_SEAL_SECRET_MAX 128    /* TPM2B_SENSITIVE_DATA (MAX_SYM_DATA) */
#define IVO_SEAL_PCR_VALID  0x00FFFFFFu

struct tpm_wr {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
    int      err;
};

struct tpm_rd {
    const uint8_t *p;
    size_t   left;
    uint16_t tag;
    int      err;
};

void tw_begin(struct tpm_wr *w, uint8_t *buf, size_t cap,
              uint16_t tag, uint32_t cc);
void tw_u8(struct tpm_wr *w, uint8_t v);
void tw_u16(struct tpm_wr *w, uint16_t v);
void tw_u32(struct tpm_wr *w, uint32_t v);
void tw_bytes(struct tpm_wr *w, const void *p, size_t n);
void tw_b2b(struct tpm_wr *w, const void *p, size_t n);   /* TPM2B */
/* authorizationSize + one TPMS_AUTH_COMMAND. */
void tw_auth(struct tpm_wr *w, uint32_t session, uint8_t attrs,
             const uint8_t *hmac, size_t hmac_len);

uint8_t        tr_u8(struct tpm_rd *r);
uint16_t       tr_u16(struct tpm_rd *r);
uint32_t       tr_u32(struct tpm_rd *r);
const uint8_t *tr_b2b(struct tpm_rd *r, uint16_t *len);   /* TPM2B */
/* Step over parameterSize of a TPM_ST_SESSIONS response and limit the
 * reader to the parameter area. No-op for TPM_ST_NO_SESSIONS. */
void           tr_params(struct tpm_rd *r);

/* Send `w`, validate the response header. 0 on TPM_RC_SUCCESS with `r`
 * positioned after the header; -1 otherwise (rc printed as `what`). */
int  tpm_transact(struct tpm_wr *w, uint8_t *rsp, size_t rsp_cap,
                  struct tpm_rd *r, const char *what);

/* TPM error code from the most recent tpm_transact call. 0 on success. */
uint32_t last_tpm_rc(void);

int  tpm_start_session(uint8_t type, uint32_t *session_out);
int  tpm_policy_pcr(uint32_t session, uint32_t pcr_mask);
int  tpm_policy_password(uint32_t session);
void tpm_flush(uint32_t handle);

/* PolicyGetDigest. Returns the current policy digest of a trial or
 * policy session. Used at enrollment to let the TPM compute the
 * authPolicy for the sealed object. */
int  tpm_policy_get_digest(uint32_t session, uint8_t *out, size_t *out_len);

#endif
