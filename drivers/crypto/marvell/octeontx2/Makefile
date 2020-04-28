# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_CRYPTO_DEV_OCTEONTX2_CPT) += octeontx2-cpt.o octeontx2-cptvf.o

common-objs := otx2_cpt_mbox_common.o
octeontx2-cpt-objs := otx2_cptpf_main.o otx2_cptpf_mbox.o otx2_cptpf_ucode.o \
		      ${common-objs}
octeontx2-cptvf-objs := otx2_cptvf_main.o otx2_cptvf_mbox.o otx2_cptlf_main.o \
			otx2_cptvf_reqmgr.o otx2_cptvf_algs.o

ifeq ($(CONFIG_CRYPTO_DEV_OCTEONTX2_CPT), m)
	octeontx2-cptvf-objs += ${common-objs}
endif

ccflags-y += -I$(src)/../../../net/ethernet/marvell/octeontx2/af/
