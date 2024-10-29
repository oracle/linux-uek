# SPDX-License-Identifier: GPL-2.0
#
## Makefile for Hardware device access driver
#

ccflags-y += -I$(src)
ccflags-y += -I$(srctree)/drivers/net/ethernet/marvell/octeontx2/af
obj-$(CONFIG_HW_CSR_ACCESS) := hw_access.o

hw_access-y := hw_rw_access.o
