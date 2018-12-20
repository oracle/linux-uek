# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Marvell's OcteonTX2 SSO/TIM RVU device driver
#

obj-$(CONFIG_OCTEONTX2_RM) += octeontx2_rm.o

octeontx2_rm-y := otx2_rm.o quota.o
ccflags-y += -I$(srctree)/drivers/net/ethernet/marvell/octeontx2/af
