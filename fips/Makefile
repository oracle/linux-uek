# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2014 Linaro Ltd <ard.biesheuvel@linaro.org>
# Copyright © 2025, Oracle and/or its affiliates.
#

include $(srctree)/fips/Makefile.fips140

fips140-y := fips140-glue.o

#
# crypto/Makefile
#

fips140-y += crypto/algapi.o
fips140-y += crypto/api.o
fips140-y += crypto/ahash.o
fips140-y += crypto/cryptd.o
fips140-y += crypto/shash.o
fips140-y += crypto/proc.o

# cryptomgr.ko
fips140-y += crypto/algboss.o crypto/testmgr.o

fips140-y += crypto/sha3_generic.o

# jitterentropy_rng.ko
CFLAGS_crypto/jitterentropy.o = -O0
KASAN_SANITIZE_crypto/jitterentropy.o = n
UBSAN_SANITIZE_crypto/jitterentropy.o = n
fips140-y += crypto/jitterentropy.o crypto/jitterentropy-kcapi.o

fips140-y += crypto/sha512_generic.o

fips140-y += crypto/pcrypt.o
fips140-y += crypto/ghash-generic.o

# crypto_simd.ko
fips140-y += crypto/simd.o

fips140-y += crypto/sha1_generic.o

fips140-y += crypto/hmac.o
fips140-y += crypto/authenc.o
fips140-y += crypto/authencesn.o

# rsa_generic.ko
fips140-y += $(addprefix crypto/, \
	rsapubkey.asn1.o \
	rsaprivkey.asn1.o \
	rsa.o \
	rsa_helper.o \
	rsa-pkcs1pad.o \
)

fips140-y += crypto/sha256_generic.o

fips140-y += crypto/crypto_user.o
fips140-y += crypto/cmac.o
fips140-y += crypto/aes_generic.o
fips140-y += crypto/cbc.o
fips140-y += crypto/ccm.o
fips140-y += crypto/ecb.o
fips140-y += crypto/ctr.o
fips140-y += crypto/ecc.o
fips140-y += crypto/essiv.o
fips140-y += crypto/drbg.o

fips140-y += $(addprefix crypto/, \
	ecdh.o \
	ecdh_helper.o \
)

# ecdsa_generic.ko
$(obj)/crypto/ecdsasignature.asn1.o: $(obj)/crypto/ecdsasignature.asn1.c $(obj)/crypto/ecdsasignature.asn1.h
$(obj)/crypto/ecdsa.o: $(obj)/crypto/ecdsasignature.asn1.h
fips140-y += $(addprefix crypto/, \
	ecdsa.o \
	ecdsasignature.asn1.o \
)

# dh_generic.ko
fips140-y += $(addprefix crypto/, \
	dh.o \
	dh_helper.o \
)

fips140-y += crypto/gcm.o
fips140-y += crypto/xts.o
fips140-y += crypto/echainiv.o
fips140-y += crypto/seqiv.o
fips140-y += crypto/tcrypt.o

fips140-y += crypto/aead.o
fips140-y += crypto/kpp.o
fips140-y += crypto/cipher.o
fips140-y += crypto/crypto_null.o
fips140-y += crypto/akcipher.o
fips140-y += crypto/skcipher.o
fips140-y += crypto/lskcipher.o
fips140-y += crypto/rng.o
fips140-y += crypto/sig.o
fips140-y += crypto/geniv.o
fips140-y += crypto/echainiv.o
fips140-y += crypto/seqiv.o

#
# crypto/asymmetric_keys/Makefile
#

$(obj)/crypto/asymmetric_keys/pkcs7_parser.o: $(obj)/crypto/asymmetric_keys/pkcs7.asn1.h
$(obj)/crypto/asymmetric_keys/pkcs7.asn1.o: $(addprefix $(obj)/crypto/asymmetric_keys/,pkcs7.asn1.c pkcs7.asn1.h)

$(obj)/crypto/asymmetric_keys/pkcs8_parser.o: $(obj)/crypto/asymmetric_keys/pkcs8.asn1.h
$(obj)/crypto/asymmetric_keys/pkcs8-asn1.o: $(addprefix $(obj)/crypto/asymmetric_keys/,pkcs8.asn1.c pkcs8.asn1.h)

$(obj)/crypto/asymmetric_keys/x509_cert_parser.o: $(addprefix $(obj)/crypto/asymmetric_keys/, \
	x509.asn1.h \
	x509_akid.asn1.h \
)

$(obj)/crypto/asymmetric_keys/x509.asn1.o: $(addprefix $(obj)/crypto/asymmetric_keys/,x509.asn1.c x509.asn1.h)
$(obj)/crypto/asymmetric_keys/x509_akid.asn1.o: $(addprefix $(obj)/crypto/asymmetric_keys/,x509_akid.asn1.c x509_akid.asn1.h)

fips140-y += crypto/asymmetric_keys/asymmetric_type.o
fips140-y += crypto/asymmetric_keys/pkcs7_parser.o
fips140-y += crypto/asymmetric_keys/pkcs7_trust.o
fips140-y += crypto/asymmetric_keys/pkcs7_verify.o
fips140-y += crypto/asymmetric_keys/pkcs7_key_type.o
fips140-y += crypto/asymmetric_keys/pkcs7.asn1.o
fips140-y += crypto/asymmetric_keys/pkcs8_parser.o
fips140-y += crypto/asymmetric_keys/pkcs8.asn1.o
fips140-y += crypto/asymmetric_keys/public_key.o
fips140-y += crypto/asymmetric_keys/restrict.o
fips140-y += crypto/asymmetric_keys/signature.o
fips140-y += crypto/asymmetric_keys/x509_cert_parser.o
fips140-y += crypto/asymmetric_keys/x509_loader.o
fips140-y += crypto/asymmetric_keys/x509_akid.asn1.o
fips140-y += crypto/asymmetric_keys/x509.asn1.o
fips140-y += crypto/asymmetric_keys/x509_public_key.o

#
# lib/crypto/Makefile
#

fips140-y += lib/crypto/gf128mul.o
fips140-y += lib/crypto/memneq.o
fips140-y += lib/crypto/utils.o

# collect arch-specific objects
arch-y :=

#
# arch/arm64/crypto/Makefile
#

ifeq ($(ARCH),arm64)
# sha1-ce.ko
arch-y += sha1-ce-glue.o sha1-ce-core.o

# sha2-ce.ko
arch-y += sha2-ce-glue.o sha2-ce-core.o

# sha512-ce.ko
arch-y += sha512-ce-glue.o sha512-ce-core.o

# sha3-ce.ko
arch-y += sha3-ce-glue.o sha3-ce-core.o

# aes-ce-cipher.ko
arch-y += aes-ce-core.o aes-ce-glue.o

# aes-ce-ccm.ko
arch-y += aes-ce-ccm-glue.o aes-ce-ccm-core.o

# aes-ce-blk.ko
arch-y += aes-glue-ce.o aes-ce.o

# aes-neon-blk.ko
arch-y += aes-glue-neon.o aes-neon.o

# sha256-arm64.ko
arch-y += sha256-glue.o sha256-core.o

# sha512-arm64.ko
arch-y += sha512-glue.o sha512-core.o

# aes-arm64.ko
arch-y += aes-cipher-core.o aes-cipher-glue.o

# aes-neon-bs.ko:
arch-y += aes-neonbs-core.o aes-neonbs-glue.o

quiet_cmd_perlasm = PERLASM $@
      cmd_perlasm = $(PERL) $(<) void $(@)

$(obj)/arch/arm64/crypto/%-core.S: $(src)/arch/arm64/crypto/%-armv8.pl
	$(call cmd,perlasm)

$(obj)/arch/arm64/crypto/sha256-core.S: $(src)/arch/arm64/crypto/sha512-armv8.pl
	$(call cmd,perlasm)

clean-files += $(addprefix arch/arm64/crypto/, sha256-core.S sha512-core.S)
endif

#
# arch/x86/crypto/Makefile
#

ifeq ($(ARCH),x86)
# sha512-ssse3.ko
arch-y += sha512-ssse3-asm.o sha512-avx-asm.o sha512-avx2-asm.o sha512_ssse3_glue.o

# sa256-ssse3.ko
arch-y += sha256-ssse3-asm.o sha256-avx-asm.o sha256-avx2-asm.o sha256_ssse3_glue.o sha256_ni_asm.o

# aesni-intel.ko
arch-y += aes_ctrby8_avx-x86_64.o aes-gcm-aesni-x86_64.o aes-xts-avx-x86_64.o aes-gcm-avx10-x86_64.o

# sha1-ssse3.ko
arch-y += sha1_avx2_x86_64_asm.o sha1_ssse3_asm.o sha1_ssse3_glue.o sha1_ni_asm.o
endif

fips140-y += $(addprefix arch/$(ARCH)/crypto/, $(arch-y))

# Use custom linker script to collect initcalls
LDFLAGS_fips140.o += -T $(src)/fips140.lds

obj-m += fips140.o
