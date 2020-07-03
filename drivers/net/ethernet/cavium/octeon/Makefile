# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the Cavium network device drivers.
#

obj-$(CONFIG_OCTEON_MGMT_ETHERNET)	+= octeon_mgmt.o
obj-$(CONFIG_OCTEON_POW_ONLY_ETHERNET)	+= octeon-pow-ethernet.o
obj-$(CONFIG_OCTEON_ETHERNET)		+= octeon-ethernet.o
obj-$(CONFIG_OCTEON_ETHERNET_MEM)	+= ethernet-mem.o
obj-$(CONFIG_OCTEON_ETHERNET_COMMON)	+= octeon_common.o

octeon-ethernet-objs := ethernet.o
octeon-ethernet-objs += ethernet-mdio.o
octeon-ethernet-objs += ethernet-rgmii.o
octeon-ethernet-objs += ethernet-rx.o
octeon-ethernet-objs += ethernet-sgmii.o
octeon-ethernet-objs += ethernet-spi.o
octeon-ethernet-objs += ethernet-tx.o
ifdef CONFIG_RAPIDIO
octeon-ethernet-objs += ethernet-srio.o
endif
