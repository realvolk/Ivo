/* Ed25519 signing (RFC 8032 5.1.6, deterministic).
 *
 * Port of orlp/ed25519 sign.c, adapted to use Ivo's own SHA-512
 * (src/uefi/crypto/sha512.c). The ref10 field/group/scalar
 * arithmetic in fe.c, ge.c, sc.c is unchanged.
 *
 *   r = SHA-512(prefix || M) mod L      prefix = expanded_key[32..63]
 *   R = r*B
 *   S = (r + SHA-512(R || A || M) * a) mod L,   a = expanded_key[0..31]
 *
 * Host-only. Not compiled into the bootloader; ivo-sign links
 * against it. The bootloader only verifies. */

#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"
#include "../security/wipe.h"

void ed25519_sign(unsigned char signature[ED25519_SIGNATURE_SIZE],
                  const unsigned char *message, size_t message_len,
                  const unsigned char public_key[ED25519_PUBLIC_KEY_SIZE],
                  const unsigned char expanded_key[ED25519_EXPANDED_KEY_SIZE])
{
    sha512_ctx_t hash;
    unsigned char hram[64];
    unsigned char r[64];
    ge_p3 R;

    sha512_init(&hash);
    sha512_update(&hash, expanded_key + 32, 32);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash, r);

    sc_reduce(r);
    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(signature, &R);

    sha512_init(&hash);
    sha512_update(&hash, signature, 32);
    sha512_update(&hash, public_key, 32);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash, hram);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, expanded_key, r);

    /* r is the per-message nonce: anyone holding r and the signature
     * can solve for the secret scalar. */
    ivo_wipe(r, sizeof(r));
    ivo_wipe(&R, sizeof(R));
    ivo_wipe(&hash, sizeof(hash));
    ivo_wipe(hram, sizeof(hram));
}
