# SPDX-License-Identifier: GPL-2.0-only

#
# CONFIG overrides
#
# NOTE: the purpose of these overrides is to select modules independently
# from the target kernel, which may have different modules or built-in
# non-FIPS algorithms for non-FIPS operation.
#

CONFIG_CRYPTO_AES := m
CONFIG_CRYPTO_AES_NI_INTEL := m
CONFIG_CRYPTO_CBC := m
CONFIG_CRYPTO_CCM := m
CONFIG_CRYPTO_CMAC := m
CONFIG_CRYPTO_CRYPTD := m
CONFIG_CRYPTO_USER := m
CONFIG_CRYPTO_CTR := m
CONFIG_CRYPTO_DH := m
CONFIG_CRYPTO_DRBG := m
CONFIG_CRYPTO_ECB := m
CONFIG_CRYPTO_ECC := m
CONFIG_CRYPTO_ECDSA := m
CONFIG_CRYPTO_GCM := m
CONFIG_CRYPTO_HMAC := m
CONFIG_CRYPTO_JITTERENTROPY := m
CONFIG_CRYPTO_LIB_GF128MUL := m
CONFIG_CRYPTO_MANAGER2 := m
CONFIG_CRYPTO_RSA := m
CONFIG_CRYPTO_SHA1 := m
CONFIG_CRYPTO_SHA1_SSSE3 := m
CONFIG_CRYPTO_SHA256 := m
CONFIG_CRYPTO_SHA256_SSSE3 := m
CONFIG_CRYPTO_SHA3 := m
CONFIG_CRYPTO_SHA512 := m
CONFIG_CRYPTO_SHA512_SSSE3 := m
CONFIG_CRYPTO_SIMD := m
CONFIG_CRYPTO_TEST := m
CONFIG_CRYPTO_XTS := m

#
# aarch64-specific modules (copied from arch/arm64/crypto/Makefile)
#
ifdef CONFIG_ARM64
# TODO
endif

#
# x86_64-specific modules (copied from arch/x86/crypto/Makefile)
#
ifdef CONFIG_X86_64

# arch/x86/crypto/aesni-intel.ko
obj-$(CONFIG_CRYPTO_AES_NI_INTEL) += aesni-intel.o
aesni-intel-y := aesni-intel_asm.o aesni-intel_glue.o
aesni-intel-$(CONFIG_64BIT) += aes_ctrby8_avx-x86_64.o \
                               aes-gcm-aesni-x86_64.o \
                               aes-xts-avx-x86_64.o
ifeq ($(CONFIG_AS_VAES)$(CONFIG_AS_VPCLMULQDQ),yy)
aesni-intel-$(CONFIG_64BIT) += aes-gcm-avx10-x86_64.o
endif

# arch/x86/crypto/sha1-ssse3.ko
obj-$(CONFIG_CRYPTO_SHA1_SSSE3) += sha1-ssse3.o
sha1-ssse3-y := sha1_avx2_x86_64_asm.o sha1_ssse3_asm.o sha1_ssse3_glue.o
sha1-ssse3-$(CONFIG_AS_SHA1_NI) += sha1_ni_asm.o

# arch/x86/crypto/sha256-ssse3.ko
obj-$(CONFIG_CRYPTO_SHA256_SSSE3) += sha256-ssse3.o
sha256-ssse3-y := sha256-ssse3-asm.o sha256-avx-asm.o sha256-avx2-asm.o sha256_ssse3_glue.o
sha256-ssse3-$(CONFIG_AS_SHA256_NI) += sha256_ni_asm.o

# arch/x86/crypto/sha512-ssse3.ko
obj-$(CONFIG_CRYPTO_SHA512_SSSE3) += sha512-ssse3.o
sha512-ssse3-y := sha512-ssse3-asm.o sha512-avx-asm.o sha512-avx2-asm.o sha512_ssse3_glue.o

endif

#
# architecture-independent modules (copied from crypto/Makefile)
#

# crypto/aes_generic.ko
obj-$(CONFIG_CRYPTO_AES) += aes_generic.o
CFLAGS_aes_generic.o := $(call cc-option,-fno-code-hoisting) # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=83356
CFLAGS_aes_generic.o += $(call cc-option,-fpatchable-function-entry=0)

# crypto/algapi.ko
#obj-m += algapi.o

# crypto/cbc.ko
obj-$(CONFIG_CRYPTO_CBC) += cbc.o

# crypto/ccm.ko
obj-$(CONFIG_CRYPTO_CCM) += ccm.o

# crypto/cmac.ko
obj-$(CONFIG_CRYPTO_CMAC) += cmac.o

# crypto/cryptd.ko
#obj-$(CONFIG_CRYPTO_CRYPTD) += cryptd.o

# crypto/crypto_simd.ko
crypto_simd-y := simd.o
obj-$(CONFIG_CRYPTO_SIMD) += crypto_simd.o

# crypto/cryptomgr.ko
cryptomgr-y := algboss.o testmgr.o

obj-$(CONFIG_CRYPTO_MANAGER2) += cryptomgr.o

# crypto/crypto_user.ko
obj-$(CONFIG_CRYPTO_USER) += crypto_user.o

# crypto/ctr.ko
obj-$(CONFIG_CRYPTO_CTR) += ctr.o

# crypto/dh_generic.ko
dh_generic-y := dh.o
dh_generic-y += dh_helper.o
obj-$(CONFIG_CRYPTO_DH) += dh_generic.o

# crypto/drbg.ko
obj-$(CONFIG_CRYPTO_DRBG) += drbg.o

# crypto/ecb.ko
obj-$(CONFIG_CRYPTO_ECB) += ecb.o

# crypto/ecc.ko
obj-$(CONFIG_CRYPTO_ECC) += ecc.o

# crypto/ecdsa_generic.ko
$(obj)/ecdsasignature.asn1.o: $(obj)/ecdsasignature.asn1.c $(obj)/ecdsasignature.asn1.h
$(obj)/ecdsa.o: $(obj)/ecdsasignature.asn1.h
ecdsa_generic-y += ecdsa.o
ecdsa_generic-y += ecdsasignature.asn1.o
obj-$(CONFIG_CRYPTO_ECDSA) += ecdsa_generic.o

# crypto/gcm.ko
obj-$(CONFIG_CRYPTO_GCM) += gcm.o

# crypto/hmac.ko
obj-$(CONFIG_CRYPTO_HMAC) += hmac.o

# crypto/jitterentropy_rng.ko
obj-$(CONFIG_CRYPTO_JITTERENTROPY) += jitterentropy_rng.o
CFLAGS_jitterentropy.o = -O0
KASAN_SANITIZE_jitterentropy.o = n
UBSAN_SANITIZE_jitterentropy.o = n
jitterentropy_rng-y := jitterentropy.o jitterentropy-kcapi.o

# crypto/rsa_generic.ko
rsa_generic-y := rsapubkey.asn1.o
rsa_generic-y += rsaprivkey.asn1.o
rsa_generic-y += rsa.o
rsa_generic-y += rsa_helper.o
rsa_generic-y += rsa-pkcs1pad.o
obj-$(CONFIG_CRYPTO_RSA) += rsa_generic.o

# crypto/sha1_generic.ko
obj-$(CONFIG_CRYPTO_SHA1) += sha1_generic.o

# crypto/sha256_generic.ko
obj-$(CONFIG_CRYPTO_SHA256) += sha256_generic.o

# crypto/sha3_generic.ko
obj-$(CONFIG_CRYPTO_SHA3) += sha3_generic.o

# crypto/sha512_generic.ko
obj-$(CONFIG_CRYPTO_SHA512) += sha512_generic.o

# crypto/tcrypt.ko
obj-$(CONFIG_CRYPTO_TEST) += tcrypt.o

# crypto/xts.ko
obj-$(CONFIG_CRYPTO_XTS) += xts.o

#
# library modules (copied from lib/crypto/Makefile)
#

# lib/crypto/gf128mul.ko
obj-$(CONFIG_CRYPTO_LIB_GF128MUL)               += gf128mul.o
