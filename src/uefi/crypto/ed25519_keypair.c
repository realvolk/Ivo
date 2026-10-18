/* Ed25519 keypair generation.
 *
 * Port of orlp/ed25519 keypair.c, adapted to use Ivo's own SHA-512.
 *
 * The 64-byte `expanded_key` output is SHA-512(seed) with the first
 * byte masked to 0xF8, the last scalar byte masked to 0x3F and OR'd
 * with 0x40 (RFC 8032 5.1.5). First 32 bytes are the scalar; second 32
 * bytes are the nonce prefix used by ed25519_sign. Both are secret.
 *
 * Host-only. */

#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "../security/wipe.h"

void ed25519_create_keypair(unsigned char public_key[ED25519_PUBLIC_KEY_SIZE],
                            unsigned char expanded_key[ED25519_EXPANDED_KEY_SIZE],
                            const unsigned char seed[ED25519_SEED_SIZE])
{
    ge_p3 A;
    sha512_ctx_t hash;

    sha512_init(&hash);
    sha512_update(&hash, seed, ED25519_SEED_SIZE);
    sha512_final(&hash, expanded_key);

    expanded_key[0]  &= 248;
    expanded_key[31] &= 63;
    expanded_key[31] |= 64;

    ge_scalarmult_base(&A, expanded_key);
    ge_p3_tobytes(public_key, &A);

    ivo_wipe(&hash, sizeof(hash));
    ivo_wipe(&A, sizeof(A));
}
