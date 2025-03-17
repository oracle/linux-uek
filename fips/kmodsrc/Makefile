# SPDX-License-Identifier: GPL-2.0-only

#
# Global options
#

subdir-ccflags-y += -DFIPS_MODULE=1

# none of this code is going to be traced, instrumented, or patched
subdir-ccflags-y += $(call cc-option,-fpatchable-function-entry=0)
subdir-ccflags-remove-y += $(CC_FLAGS_FTRACE)
subdir-ccflags-remove-y += -ffunction-sections -fdata-sections
export KASAN_SANITIZE := n
export KCSAN_SANITIZE := n
export UBSAN_SANITIZE := n
export KMSAN_SANITIZE := n
export KCOV_INSTRUMENT := n
export GCOV_PROFILE := n

#
# Crypto algorithms
#

ifeq ($(FIPS140_BUILD_CRYPTO),1)
obj-y += crypto/
endif

#
# Crypto module
#

ifeq ($(FIPS140_BUILD_MODULE),1)
quiet_cmd_ld_bin = LD      $@
      cmd_ld_bin = (cd "$(dir $<)" && \
                    $(LD) -r -b binary -o $(abspath $@) $(notdir $<) && \
                    $(OBJCOPY) --rename-section .data=$(2) $(abspath $@))

$(obj)/fips140-archive.o: $(obj)/fips140-archive.a FORCE
	$(call if_changed,ld_bin,.rodata.fips140_archive)

CFLAGS_fips140-glue.o := -DFIPS140_INTEG_HMAC_KEY="\"$(FIPS140_INTEG_HMAC_KEY)\""

fips140-y := fips140-glue.o fips140-archive.o

fips140-y += crypto/algapi.o
fips140-y += crypto/api.o
fips140-y += crypto/ahash.o
fips140-y += crypto/cryptd.o
fips140-y += crypto/shash.o

obj-m += fips140.o
endif
