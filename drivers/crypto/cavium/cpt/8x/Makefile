# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_CRYPTO_DEV_OCTEONTX_CPT) += cptpf8x.o cptvf8x.o

cptpf8x-objs := cpt8x_pf_main.o cpt8x_pf_mbox.o cpt8x_ucode.o cpt8x_pf_domain.o cpt8x_debug.o
cptvf8x-objs := cpt8x_vf_main.o cpt8x_vf_mbox.o cpt8x_reqmgr.o cpt8x_algs.o

ifeq ($(CONFIG_CRYPTO_DEV_OCTEONTX_CPT), m)
	cptvf8x-objs += cpt8x_debug.o
endif

ccflags-y := -I$(src)/../common/
ccflags-y += -I$(src)/../../../../net/ethernet/cavium/octeontx-83xx/
