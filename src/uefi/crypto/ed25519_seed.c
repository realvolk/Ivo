/* Ed25519 seed generation from the kernel CSPRNG.
 *
 * Linux-only. Uses getrandom(2), which blocks until the pool is
 * initialised, and falls back to /dev/urandom on kernels without it.
 * Host-only; not compiled into the bootloader. The empty translation
 * unit in the bootloader case is a deliberate no-op. */

#ifdef CONFIG_HOST

#include "ed25519.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>

int ed25519_create_seed(unsigned char seed[ED25519_SEED_SIZE])
{
    size_t got = 0;

    while (got < ED25519_SEED_SIZE) {
        ssize_t n = getrandom(seed + got, ED25519_SEED_SIZE - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        got += (size_t)n;
    }
    if (got == ED25519_SEED_SIZE) return 0;

    /* getrandom unavailable (ENOSYS): read /dev/urandom fully. */
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    got = 0;
    while (got < ED25519_SEED_SIZE) {
        ssize_t n = read(fd, seed + got, ED25519_SEED_SIZE - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    return (got == ED25519_SEED_SIZE) ? 0 : 1;
}

#endif
