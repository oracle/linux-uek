# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Marvell's RVU BPHY device drivers
#

obj-$(CONFIG_OCTEONTX2_BPHY_PF) += rvu_bphy_nicpf.o

rvu_bphy_nicpf-y := otx2_bphypf.o otx2_bphypf_ethtool.o

ccflags-y += -I$(srctree)/drivers/net/ethernet/marvell/octeontx2/af
ccflags-y += -I$(srctree)/drivers/net/ethernet/marvell/octeontx2/nic
ccflags-y += -I$(srctree)/drivers/soc/marvell/rvu_af_extn
