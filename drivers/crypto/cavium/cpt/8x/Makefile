# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_CRYPTO_DEV_OCTEONTX_CPT) += octeontx-cpt.o octeontx-cptvf.o

octeontx-cpt-objs := cpt8x_pf_main.o cpt8x_pf_mbox.o cpt8x_ucode.o
octeontx-cptvf-objs := cpt8x_vf_main.o cpt8x_vf_mbox.o cpt8x_reqmgr.o \
		       cpt8x_algs.o

ccflags-y := -I$(src)/../common/
ccflags-y += -I$(src)/../../../../net/ethernet/cavium/octeontx-83xx/
