#ifndef CORE_H
#define CORE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "hal/hal.h"
#include "fs/fs.h"

#define TPM_PCR_BOOTLOADER  4
#define TPM_PCR_KERNEL      8
#define TPM_PCR_INITRD      9
#define TPM_PCR_CMDLINE     9
#include "boot/config.h"

void  ivo_main(boot_context_t *ctx);
void  panic(const char *msg) __attribute__((noreturn));

void  mm_init(boot_context_t *ctx);
void *mm_alloc(size_t size);
void  mm_free(void *ptr);

int   tpm_init(void);
void  tpm_measure(uint32_t pcr, const uint8_t *data, size_t len);
void  tpm_measure_string(uint32_t pcr, const char *str);
int   tpm2_unseal(const uint8_t *blob, size_t blob_len,
                  const uint8_t *pin, size_t pin_len,
                  uint8_t *out, size_t *out_len);
int   tpm_seal_try_unlock(boot_context_t *ctx);
int   tpm_seal_request_pending(void);
int   tpm_seal_write_blob(const uint8_t *blob, size_t len);
int   tpm_seal_maybe_enroll(boot_context_t *ctx);
int   tpm2_seal_create(const uint8_t *secret, size_t secret_len,
                       const uint8_t *pin, size_t pin_len,
                       uint32_t pcr_mask,
                       uint8_t *blob_out, size_t *blob_out_len,
                       size_t blob_out_cap);

int   luks_enabled(boot_context_t *ctx);
int   luks_unlock(boot_context_t *ctx);
int   luks_unlock_with_passphrase(boot_context_t *ctx,
                                  const uint8_t *pass, size_t pass_len);
int   luks1_unlock_with_passphrase(boot_context_t *ctx,
                                   const uint8_t *pass, size_t pass_len);
int   luks2_unlock_with_passphrase(boot_context_t *ctx,
                                   const uint8_t *pass, size_t pass_len);

int   config_load(boot_context_t *ctx);

int   core_unlocked_without_passphrase(void);
void  core_passphrase_proven(void);
entry_t *config_get_entries(int *count);
entry_t *config_get_default(void);
int   config_get_timeout(void);

entry_t *menu_select(boot_context_t *ctx);

void  shell_enter(boot_context_t *ctx);

int   boot_entry(boot_context_t *ctx, entry_t *entry);

void  con_clear(void);
void  con_puts(const char *str);
void  con_putc(char c);
void  con_clear_row(void);
void  con_set_fg(uint32_t rgba);
int   con_read_secret(const char *label, char *out, size_t max_len, char echo);

void  halt(void) __attribute__((noreturn));

void  stack_chk_init(void);

#endif