# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_CRYPTO_DEV_OCTEONTX2_CPT) += cptpf9x.o cptvf9x.o

common-objs := cpt9x_mbox_common.o cpt9x_debug.o
cptpf9x-objs := cpt9x_pf_main.o  cpt9x_pf_mbox.o cpt9x_ucode.o cpt9x_quota.o ${common-objs}
cptvf9x-objs := cpt9x_vf_main.o cpt9x_vf_mbox.o cpt9x_lf_main.o cpt9x_reqmgr.o cpt9x_algs.o cpt9x_passthrough.o

ifeq ($(CONFIG_CRYPTO_DEV_OCTEONTX2_CPT), m)
	cptvf9x-objs += ${common-objs}
endif

ccflags-y := -I$(src)/../common/
ccflags-y += -I$(src)/../../../../net/ethernet/marvell/octeontx2/af/
ccflags-y += -I$(src)/../../../../net/ethernet/marvell/octeontx2/nic/
