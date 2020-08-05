# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_CRYPTO_DEV_CN10K_CPT) += cn10k-cpt.o

cn10k-cpt-objs := cn10k_cptpf_main.o cn10k_cptpf_mbox.o cn10k_cptpf_ucode.o \
		  cn10k_cpt_mbox_common.o

ccflags-y += -I$(src)/../../../net/ethernet/marvell/octeontx2/af/
