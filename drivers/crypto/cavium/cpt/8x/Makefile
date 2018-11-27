# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_CRYPTO_DEV_OCTEONTX_CPT) += cptpf8x.o cptvf8x.o

common-objs := cpt8x_debug.o ../common/cpt_debug.o
cptpf8x-objs := cpt8x_pf_main.o cpt8x_pf_mbox.o cpt8x_ucode.o ../common/cpt_ucode.o ${common-objs}
cptvf8x-objs := cpt8x_vf_main.o cpt8x_vf_mbox.o cpt8x_reqmgr.o ../common/cpt_algs.o ../common/cpt_reqmgr.o

ifeq ($(CONFIG_CRYPTO_DEV_OCTEONTX_CPT), m)
	cptvf8x-objs += ${common-objs}
endif

ccflags-y := -I$(src)/../common/
ccflags-y += -I$(src)/../../../../net/ethernet/cavium/octeontx-83xx/
