# ==============================================================
#           DO NOT CHANGE THESE FLAGS
#      (Unless you like reading kernel bailouts)
#
#   It is easy to beat nettles with someone else's dick.
#                           - Ivo Andrić, novelist and poet
# ==============================================================

# Command-line overrides are refused for anything that defines how
# the code is compiled. config.mk picks from the supported menu; the
# command line does not.
ALLOWED_VARS := THEME GFX_FMT LUKS LVM TPM SECURE_BOOT LUKS_USE_ARGON2 \
                ESP CC_EFI ASM_EFI HOST_CC

CMD_LINE_VARS := $(foreach v,$(.VARIABLES),\
    $(if $(filter command line,$(origin $(v))),$(v),))

UNSUPPORTED := $(filter-out $(ALLOWED_VARS),$(CMD_LINE_VARS))

ifneq ($(UNSUPPORTED),)
$(error Unsupported command-line variable(s): $(UNSUPPORTED). Only $(ALLOWED_VARS) may be set on the command line.)
endif

include config.mk

ASM       = nasm
CC_EFI    = x86_64-w64-mingw32-gcc
ASM_EFI   = nasm
HOST_CC   = cc
TOOLS_DIR = tools
TESTS_DIR = tests
ESP       ?=

TOOLS_BIN = $(TOOLS_DIR)/mkinitivo $(TOOLS_DIR)/keymap_compiler \
            $(TOOLS_DIR)/ivo-sign $(TOOLS_DIR)/ivo-keygen \
            $(TOOLS_DIR)/ivo-convert $(TOOLS_DIR)/ivo-install \
            $(TOOLS_DIR)/ivo-config $(TOOLS_DIR)/ivo-doctor \
            $(TOOLS_DIR)/font_rasterize
TESTS_BIN = $(TESTS_DIR)/sha512-test $(TESTS_DIR)/ed25519-test \
            $(TESTS_DIR)/luks1-test $(TESTS_DIR)/luks2-test \
            $(TESTS_DIR)/btrfs-test

.DEFAULT_GOAL := all

ASMFLAGS_EFI = -f win64 -Isrc/uefi

CFLAGS_EFI = -Wall -Wextra -std=c11 -O2 -ffreestanding -fno-builtin \
             -fstack-protector-strong -mno-red-zone -fshort-wchar \
             -mno-sse -mno-mmx -mno-stack-arg-probe -DIVO_UEFI -MMD -MP \
             -Isrc -Isrc/uefi -Isrc/uefi/hal -Isrc/uefi/fs -Isrc/uefi/include \
             -DIVO_THEME_$(shell echo $(THEME) | tr a-z A-Z) \
             -DIVO_GFX_FMT_$(shell echo $(GFX_FMT) | tr a-z A-Z)

ifeq ($(LUKS),1)
    CFLAGS_EFI += -DLUKS
    ifeq ($(LUKS_USE_ARGON2),1)
        CFLAGS_EFI += -DLUKS_USE_ARGON2
    endif
endif

ifeq ($(LVM),1)
    CFLAGS_EFI += -DLVM
endif

ifeq ($(SECURE_BOOT),1)
    CFLAGS_EFI += -DSECURE_BOOT
endif

ifeq ($(TPM),1)
    CFLAGS_EFI += -DTPM
endif

STAGE2_C_SRC  = $(wildcard src/uefi/*.c) \
                $(wildcard src/uefi/boot/*.c) \
                $(wildcard src/uefi/ui/*.c) \
                $(wildcard src/uefi/hal/*.c) \
                $(wildcard src/uefi/fs/*.c) \
                $(wildcard src/uefi/storage/*.c) \
                $(wildcard src/uefi/crypto/*.c) \
                $(wildcard src/uefi/luks/*.c) \
                $(wildcard src/uefi/security/*.c) \
                $(wildcard src/uefi/security/tpm/*.c)

# ed25519_sign / keypair / seed are host-only.
STAGE2_C_SRC := $(filter-out \
    src/uefi/crypto/ed25519_sign.c \
    src/uefi/crypto/ed25519_keypair.c \
    src/uefi/crypto/ed25519_seed.c, $(STAGE2_C_SRC))
STAGE2_ASM_SRC = $(wildcard src/uefi/*.asm) \
                 $(wildcard src/uefi/ui/*.asm) \
                 $(wildcard src/uefi/hal/*.asm) \
                 $(wildcard src/uefi/crypto/*.asm)

STAGE2_OBJS = $(STAGE2_C_SRC:.c=.efi.o) $(STAGE2_ASM_SRC:.asm=.efi.o)

.PHONY: all tools tests install uninstall clean clean-all help

# Host tools. Every tool that reads or writes config.toml links the
# bootloader's own parser (src/uefi/boot/config.c, -DCONFIG_HOST), so the
# tools and the bootloader cannot disagree about what a config means.
TOOL_CFLAGS = -O2 -Wall -Wextra -DCONFIG_HOST \
              -I$(TOOLS_DIR) -Isrc/uefi -Isrc/uefi/boot -Isrc/uefi/crypto \
              -Isrc/uefi/fs -Isrc/uefi/security
TOOL_UTIL   = $(TOOLS_DIR)/ivo-util.c $(TOOLS_DIR)/ivo-util.h \
              src/uefi/crypto/sha512.c
TOOL_CONFIG = src/uefi/boot/config.c src/uefi/boot/config.h
TOOL_ED25519 = src/uefi/crypto/ed25519.h src/uefi/crypto/fe.c \
               src/uefi/crypto/ge.c src/uefi/crypto/sc.c

$(TOOLS_DIR)/mkinitivo: $(TOOLS_DIR)/mkinitivo.c $(TOOL_CONFIG) $(TOOL_UTIL)
	$(HOST_CC) $(TOOL_CFLAGS) -o $@ $(filter %.c,$^)

$(TOOLS_DIR)/keymap_compiler: $(TOOLS_DIR)/keymap_compiler.c
	$(HOST_CC) -O2 -Wall -Wextra -o $@ $<

$(TOOLS_DIR)/font_rasterize: $(TOOLS_DIR)/font_rasterize.c \
                             $(TOOLS_DIR)/third_party/stb_truetype.h
	$(HOST_CC) -O2 -Wall -Wextra -I$(TOOLS_DIR) -o $@ $(TOOLS_DIR)/font_rasterize.c -lm

src/uefi/ui/font_data.h: $(TOOLS_DIR)/font_rasterize assets/NotoSansMono-Regular.ttf
	$(TOOLS_DIR)/font_rasterize assets/NotoSansMono-Regular.ttf 24 19 $@

$(TOOLS_DIR)/ivo-sign: $(TOOLS_DIR)/ivo-sign.c \
                         $(TOOLS_DIR)/ivo-sign-host.c \
                         src/uefi/crypto/ed25519_sign.c \
                         src/uefi/crypto/ed25519_keypair.c \
                         src/uefi/crypto/ed25519_verify.c \
                         $(TOOL_ED25519) $(TOOL_CONFIG) $(TOOL_UTIL) \
                         src/uefi/fs/iso9660.c
	$(HOST_CC) $(TOOL_CFLAGS) -o $@ $(filter %.c,$^)

$(TOOLS_DIR)/ivo-keygen: $(TOOLS_DIR)/ivo-keygen.c \
                           src/uefi/crypto/ed25519_keypair.c \
                           src/uefi/crypto/ed25519_seed.c \
                           src/uefi/crypto/ed25519_sign.c \
                           src/uefi/crypto/ed25519_verify.c \
                           $(TOOL_ED25519) $(TOOL_UTIL)
	$(HOST_CC) $(TOOL_CFLAGS) -o $@ $(filter %.c,$^)

$(TOOLS_DIR)/ivo-convert: $(TOOLS_DIR)/ivo-convert.c $(TOOL_CONFIG) $(TOOL_UTIL)
	$(HOST_CC) $(TOOL_CFLAGS) -o $@ $(filter %.c,$^)

$(TOOLS_DIR)/ivo-install: $(TOOLS_DIR)/ivo-install.c $(TOOL_CONFIG) $(TOOL_UTIL)
	$(HOST_CC) $(TOOL_CFLAGS) -o $@ $(filter %.c,$^)

$(TOOLS_DIR)/ivo-config: $(TOOLS_DIR)/ivo-config.c $(TOOL_CONFIG) $(TOOL_UTIL)
	$(HOST_CC) $(TOOL_CFLAGS) -o $@ $(filter %.c,$^)

$(TOOLS_DIR)/ivo-doctor: $(TOOLS_DIR)/ivo-doctor.c \
                         src/uefi/crypto/ed25519_verify.c \
                         $(TOOL_ED25519) $(TOOL_CONFIG) $(TOOL_UTIL)
	$(HOST_CC) $(TOOL_CFLAGS) -o $@ $(filter %.c,$^)

tools: $(TOOLS_BIN)

$(TESTS_DIR)/sha512-test: $(TESTS_DIR)/sha512-test.c \
                          src/uefi/crypto/sha512.c
	$(HOST_CC) -O2 -Wall -Wextra -DCONFIG_HOST \
	    -Isrc/uefi/crypto \
	    -o $@ $^

$(TESTS_DIR)/ed25519-test: $(TESTS_DIR)/ed25519-test.c \
                           src/uefi/crypto/ed25519_verify.c \
                           src/uefi/crypto/fe.c \
                           src/uefi/crypto/ge.c \
                           src/uefi/crypto/sc.c \
                           src/uefi/crypto/sha512.c
	$(HOST_CC) -O2 -Wall -Wextra -DCONFIG_HOST \
	    -Isrc/uefi -Isrc/uefi/crypto \
	    -o $@ \
	    $(TESTS_DIR)/ed25519-test.c \
	    src/uefi/crypto/ed25519_verify.c \
	    src/uefi/crypto/fe.c \
	    src/uefi/crypto/ge.c \
	    src/uefi/crypto/sc.c \
	    src/uefi/crypto/sha512.c

$(TESTS_DIR)/luks1-test: $(TESTS_DIR)/luks1-test.c \
                         src/uefi/storage/luks1.c \
                         src/uefi/storage/luks_common.c \
                         src/uefi/crypto/aes.c \
                         src/uefi/crypto/sha1.c \
                         src/uefi/crypto/hmac.c \
                         src/uefi/crypto/hmac_sha1.c \
                         src/uefi/crypto/sha256.c \
                         src/uefi/crypto/pbkdf2.c \
                         src/uefi/crypto/xts.c
	$(HOST_CC) -O2 -Wall -Wextra -DCONFIG_HOST \
	    -I$(TESTS_DIR) -Isrc/uefi -Isrc/uefi/boot -Isrc/uefi/include \
	    -o $@ \
	    $(TESTS_DIR)/luks1-test.c \
	    src/uefi/storage/luks1.c \
	    src/uefi/storage/luks_common.c \
	    src/uefi/crypto/aes.c \
	    src/uefi/crypto/sha1.c \
	    src/uefi/crypto/hmac.c \
	    src/uefi/crypto/hmac_sha1.c \
	    src/uefi/crypto/sha256.c \
	    src/uefi/crypto/pbkdf2.c \
	    src/uefi/crypto/xts.c

$(TESTS_DIR)/luks2-test: $(TESTS_DIR)/luks2-test.c \
                         src/uefi/storage/luks2.c \
                         src/uefi/storage/luks_common.c \
                         src/uefi/luks/json.c \
                         src/uefi/luks/base64.c \
                         src/uefi/luks/mem.c \
                         src/uefi/crypto/aes.c \
                         src/uefi/crypto/xts.c \
                         src/uefi/crypto/sha1.c \
                         src/uefi/crypto/sha256.c \
                         src/uefi/crypto/hmac.c \
                         src/uefi/crypto/hmac_sha1.c \
                         src/uefi/crypto/pbkdf2.c \
                         src/uefi/crypto/blake2b.c \
                         src/uefi/crypto/argon2.c \
                         src/uefi/crypto/argon2_sse2.c \
                         src/uefi/crypto/argon2id.c
	$(HOST_CC) -O2 -Wall -Wextra -DCONFIG_HOST \
	    -I$(TESTS_DIR) -Isrc/uefi -Isrc/uefi/include \
	    -o $@ \
	    $(TESTS_DIR)/luks2-test.c \
	    src/uefi/storage/luks2.c \
	    src/uefi/storage/luks_common.c \
	    src/uefi/luks/json.c \
	    src/uefi/luks/base64.c \
	    src/uefi/luks/mem.c \
	    src/uefi/crypto/aes.c \
	    src/uefi/crypto/xts.c \
	    src/uefi/crypto/sha1.c \
	    src/uefi/crypto/sha256.c \
	    src/uefi/crypto/hmac.c \
	    src/uefi/crypto/hmac_sha1.c \
	    src/uefi/crypto/pbkdf2.c \
	    src/uefi/crypto/blake2b.c \
	    src/uefi/crypto/argon2.c \
	    src/uefi/crypto/argon2_sse2.c \
	    src/uefi/crypto/argon2id.c

$(TESTS_DIR)/btrfs-test: $(TESTS_DIR)/btrfs-test.c \
                         src/uefi/fs/btrfs.c
	$(HOST_CC) -O2 -Wall -Wextra -DCONFIG_HOST \
	    -I$(TESTS_DIR) -Isrc/uefi -Isrc/uefi/include -Isrc/uefi/hal \
	    -o $@ \
	    $(TESTS_DIR)/btrfs-test.c \
	    src/uefi/fs/btrfs.c

tests: $(TESTS_BIN)

all: ivo.efi

ivo.efi: $(STAGE2_OBJS)
	$(CC_EFI) -nostdlib -Wl,-subsystem,10 -Wl,-e,efi_main -Wl,-dll \
	          -Wl,--image-base,0 -Wl,-file-alignment,512 \
	          -o $@ $^

%.efi.o: %.c
	$(CC_EFI) $(CFLAGS_EFI) -c -o $@ $<

src/uefi/crypto/argon2_sse2.efi.o: src/uefi/crypto/argon2_sse2.c
	$(CC_EFI) $(CFLAGS_EFI) -msse2 -c -o $@ $<

src/uefi/security/stack_chk.efi.o: src/uefi/security/stack_chk.c
	$(CC_EFI) $(CFLAGS_EFI) -fno-stack-protector -c -o $@ $<

%.efi.o: %.asm
	$(ASM_EFI) $(ASMFLAGS_EFI) -o $@ $<

install: ivo.efi
	@test -n "$(ESP)" || { echo "usage: make install ESP=/boot/efi" >&2; exit 1; }
	@test -d "$(ESP)" || { echo "make install: $(ESP): not a directory" >&2; exit 1; }
	@install -d "$(ESP)/EFI/BOOT"
	@install -m 0644 ivo.efi "$(ESP)/EFI/BOOT/BOOTX64.EFI"
	@echo "installed $(ESP)/EFI/BOOT/BOOTX64.EFI"

uninstall:
	@test -n "$(ESP)" || { echo "usage: make uninstall ESP=/boot/efi" >&2; exit 1; }
	@rm -f "$(ESP)/EFI/BOOT/BOOTX64.EFI"
	@echo "removed $(ESP)/EFI/BOOT/BOOTX64.EFI"

clean:
	rm -f ivo.efi
	find src -name '*.efi.o' -delete
	find src -name '*.efi.d' -delete

clean-all: clean
	rm -f $(TOOLS_BIN) $(TESTS_BIN)

help:
	@echo "Ivo build targets:"
	@echo ""
	@echo "  make [FLAGS]            build ivo.efi"
	@echo "  make tools              build host tools"
	@echo "  make tests              build host tests"
	@echo "  make install ESP=DIR    copy ivo.efi to an ESP"
	@echo "  make uninstall ESP=DIR  remove it"
	@echo "  make clean              remove build artifacts"
	@echo "  make clean-all          also remove tools and tests"
	@echo ""
	@echo "Flags (override on the command line or set in config.mk):"
	@echo "  LUKS=1                  LUKS1 and LUKS2 unlock"
	@echo "  LVM=1                   LVM2 PV/label/metadata reader"
	@echo "  TPM=1                   TPM 2.0 measurement and sealed unlock"
	@echo "  SECURE_BOOT=1           Ed25519 config verification"
	@echo "  LUKS_USE_ARGON2=1       no-op, kept for compatibility"
	@echo "  THEME=name              default, nord, gruvbox, solarized, highcontrast"
	@echo "  GFX_FMT=name            bgrx (default) or rgbx"
	@echo ""
	@echo "Always run 'make clean' between flag changes."

-include $(STAGE2_C_SRC:.c=.efi.d)