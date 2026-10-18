/* Usage: ivo-keygen --out-prefix DIR/NAME [--force]
 *
 * Produces:
 *   NAME.sec  64 bytes, seed[32] || public[32]  (mode 0600, KEEP SECRET)
 *   NAME.pub  32 raw bytes, the public key
 *   NAME.h    C header with ivo_pubkey[32] for secure_boot_pubkey.h
 *
 * The .sec layout is the libsodium/OpenSSH "seed || pk" one: ivo-sign
 * re-derives the full 64-byte expanded key from the seed and refuses
 * the file if the stored public key does not match.
 *
 * Existing files are never overwritten unless --force is given; with
 * --force they are replaced atomically (temp file + rename).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#include "ed25519.h"
#include "wipe.h"
#include "ivo-util.h"
#include "crypto/pbkdf2.h"

#include <termios.h>
#include <unistd.h>
#include <sys/random.h>
static void usage(void)
{
    fprintf(stderr,
            "usage: ivo-keygen --out-prefix DIR/NAME [--force]\n"
            "       ivo-keygen --password-hash [--iterations N]\n");
}

static char *with_suffix(const char *prefix, const char *suffix)
{
    size_t a = strlen(prefix), b = strlen(suffix);
    char *p = malloc(a + b + 1);
    if (!p) { fprintf(stderr, "ivo-keygen: out of memory\n"); exit(1); }
    memcpy(p, prefix, a);
    memcpy(p + a, suffix, b + 1);
    return p;
}

static int read_password_line(char *buf, size_t cap)
{
    if (!isatty(STDIN_FILENO)) {
        if (!fgets(buf, (int)cap, stdin)) return -1;
        size_t n = strlen(buf);
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
        return (int)n;
    }

    struct termios old, raw;
    if (tcgetattr(STDIN_FILENO, &old) != 0) return -1;
    raw = old;
    raw.c_lflag &= ~(tcflag_t)ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) return -1;

    int rc = -1;
    size_t n = 0;
    for (;;) {
        char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r <= 0) goto out;
        if (c == '\n') break;
        if (n + 1 < cap) buf[n++] = c;
    }
    buf[n] = 0;
    rc = (int)n;
out:
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fputc('\n', stderr);
    return rc;
}

static int password_hash_mode(int argc, char **argv)
{
    int iter = 200000;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iter = atoi(argv[++i]);
            if (iter < 10000 || iter > 10000000) {
                fprintf(stderr, "ivo-keygen: iterations out of range\n");
                return 1;
            }
        } else {
            fprintf(stderr, "ivo-keygen: unknown --password-hash arg: %s\n",
                    argv[i]);
            return 1;
        }
    }

    char pass[256];
    fprintf(stderr, "Password: ");
    int n = read_password_line(pass, sizeof(pass));
    if (n <= 0) {
        fprintf(stderr, "ivo-keygen: empty or unreadable password\n");
        return 1;
    }

    uint8_t salt[16];
    {
        ssize_t r = getrandom(salt, sizeof(salt), 0);
        if (r != (ssize_t)sizeof(salt)) {
            fprintf(stderr, "ivo-keygen: entropy source failed\n");
            ivo_wipe(pass, sizeof(pass));
            return 1;
        }
    }

    uint8_t hash[32];
    if (pbkdf2_hmac_sha256((const uint8_t *)pass, (size_t)n,
                           salt, sizeof(salt), (uint32_t)iter,
                           hash, sizeof(hash)) != 0) {
        fprintf(stderr, "ivo-keygen: pbkdf2 failed\n");
        ivo_wipe(pass, sizeof(pass));
        return 1;
    }
    ivo_wipe(pass, sizeof(pass));

    printf("pbkdf2-sha256:%d:", iter);
    for (size_t i = 0; i < sizeof(salt); i++) printf("%02x", salt[i]);
    printf(":");
    for (size_t i = 0; i < sizeof(hash); i++) printf("%02x", hash[i]);
    printf("\n");

    ivo_wipe(salt, sizeof(salt));
    ivo_wipe(hash, sizeof(hash));
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--password-hash") == 0)
        return password_hash_mode(argc - 2, argv + 2);

    const char *prefix = NULL;
    int force = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--out-prefix") == 0 && i + 1 < argc) {
            prefix = argv[++i];
        } else if (strcmp(argv[i], "--force") == 0) {
            force = 1;
        } else {
            usage();
            return 1;
        }
    }
    if (!prefix || !prefix[0]) {
        usage();
        return 1;
    }

    char *path_pub = with_suffix(prefix, ".pub");
    char *path_sec = with_suffix(prefix, ".sec");
    char *path_h   = with_suffix(prefix, ".h");

    if (!force) {
        const char *paths[] = { path_sec, path_pub, path_h };
        for (int i = 0; i < 3; i++) {
            struct stat st;
            if (lstat(paths[i], &st) == 0) {
                fprintf(stderr, "ivo-keygen: %s exists; refusing to overwrite "
                        "(use --force to replace the key)\n", paths[i]);
                return 1;
            }
        }
    }

    uint8_t seed[ED25519_SEED_SIZE];
    uint8_t pub[ED25519_PUBLIC_KEY_SIZE];
    uint8_t expanded[ED25519_EXPANDED_KEY_SIZE];
    uint8_t sec[ED25519_SEED_SIZE + ED25519_PUBLIC_KEY_SIZE];

    if (ed25519_create_seed(seed) != 0) {
        fprintf(stderr, "ivo-keygen: seed generation failed\n");
        return 1;
    }
    ed25519_create_keypair(pub, expanded, seed);
    memcpy(sec, seed, ED25519_SEED_SIZE);
    memcpy(sec + ED25519_SEED_SIZE, pub, ED25519_PUBLIC_KEY_SIZE);

    {
        static const uint8_t msg[] = "ivo-keygen self-test";
        uint8_t sig[ED25519_SIGNATURE_SIZE];
        ed25519_sign(sig, msg, sizeof(msg), pub, expanded);
        int ok = ed25519_verify(sig, msg, sizeof(msg), pub);
        ivo_wipe(expanded, sizeof(expanded));
        ivo_wipe(seed, sizeof(seed));
        if (!ok) {
            ivo_wipe(sec, sizeof(sec));
            fprintf(stderr, "ivo-keygen: internal error: self-test failed\n");
            return 1;
        }
    }

    int flags = force ? 0 : IVO_WRITE_NOCLOBBER;

    int rc = ivo_write_file(path_sec, sec, sizeof(sec), 0600, flags);
    int err = errno;
    ivo_wipe(sec, sizeof(sec));
    if (rc != 0) {
        fprintf(stderr, "ivo-keygen: %s: %s\n", path_sec, strerror(err));
        return 1;
    }

    if (ivo_write_file(path_pub, pub, sizeof(pub), 0644, flags) != 0) {
        fprintf(stderr, "ivo-keygen: %s: %s\n", path_pub, strerror(errno));
        return 1;
    }

    ivo_buf_t h = {0};
    ivo_buf_puts(&h, "/* Generated by tools/ivo-keygen. Do not edit. */\n"
                     "#ifndef IVO_SECURE_BOOT_PUBKEY_H\n"
                     "#define IVO_SECURE_BOOT_PUBKEY_H\n\n"
                     "#include <stdint.h>\n\n"
                     "static const uint8_t ivo_pubkey[32] = {\n    ");
    for (int i = 0; i < 32; i++) {
        ivo_buf_printf(&h, "0x%02x", pub[i]);
        if (i < 31) ivo_buf_puts(&h, ", ");
        if ((i + 1) % 8 == 0 && i < 31) ivo_buf_puts(&h, "\n    ");
    }
    ivo_buf_puts(&h, "\n};\n\n#endif\n");
    if (h.failed || ivo_write_file(path_h, h.p, h.len, 0644, flags) != 0) {
        fprintf(stderr, "ivo-keygen: %s: %s\n", path_h,
                h.failed ? "out of memory" : strerror(errno));
        ivo_buf_free(&h);
        return 1;
    }
    ivo_buf_free(&h);

    printf("wrote %s\n", path_pub);
    printf("wrote %s  (KEEP SECRET)\n", path_sec);
    printf("wrote %s\n", path_h);
    free(path_pub);
    free(path_sec);
    free(path_h);
    return 0;
}
