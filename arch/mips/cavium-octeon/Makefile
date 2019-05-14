#
# Makefile for the Cavium Octeon specific kernel interface routines
# under Linux.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 2005-2009 Cavium Networks
#

obj-y := cpu.o setup.o octeon-platform.o octeon-irq.o csrc-octeon.o \
	 octeon-hw-status.o octeon_info.o
obj-y += dma-octeon.o
obj-y += csrc-octeon-ptp.o
obj-y += octeon-pci-console.o
obj-y += octeon-memcpy.o
obj-y += executive/
obj-y += crypto/

obj-$(CONFIG_MTD)		      += flash_setup.o
obj-$(CONFIG_SMP)		      += smp.o
obj-$(CONFIG_OCTEON_ILM)	      += oct_ilm.o
obj-$(CONFIG_USB)		      += octeon-usb.o
obj-$(CONFIG_SYSFS)                   += octeon-power-throttle.o
