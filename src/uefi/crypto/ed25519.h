#ifndef IVO_ED25519_H
#define IVO_ED25519_H

#include <stddef.h>

#define ED25519_SEED_SIZE          32
#define ED25519_PUBLIC_KEY_SIZE    32
/* SHA-512(seed), clamped: bytes 0..31 are the secret scalar a, bytes
 * 32..63 are the nonce prefix. Both halves are secret and both are
 * needed to sign (RFC 8032 5.1.5). */
#define ED25519_EXPANDED_KEY_SIZE  64
#define ED25519_SIGNATURE_SIZE     64

/* Verification. Compiled into the bootloader and into host tools. */
int ed25519_verify(const unsigned char *signature,
                   const unsigned char *message,
                   size_t message_len,
                   const unsigned char *public_key);

/* Signing and key generation. Host-only; not compiled into the
 * bootloader. Buffer sizes are part of the contract. */

/* 32 bytes from the kernel CSPRNG. Returns 0 on success. */
int  ed25519_create_seed(unsigned char seed[ED25519_SEED_SIZE]);

/* Derive the expanded private key and public key from a seed. */
void ed25519_create_keypair(unsigned char public_key[ED25519_PUBLIC_KEY_SIZE],
                            unsigned char expanded_key[ED25519_EXPANDED_KEY_SIZE],
                            const unsigned char seed[ED25519_SEED_SIZE]);

/* Deterministic RFC 8032 signature. `public_key` must be the key
 * derived from `expanded_key`. */
void ed25519_sign(unsigned char signature[ED25519_SIGNATURE_SIZE],
                  const unsigned char *message, size_t message_len,
                  const unsigned char public_key[ED25519_PUBLIC_KEY_SIZE],
                  const unsigned char expanded_key[ED25519_EXPANDED_KEY_SIZE]);

#endif
