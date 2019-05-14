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

obj-y := setup.o serial.o octeon-platform.o octeon-irq.o csrc-octeon.o \
	 octeon-hw-status.o octeon_info.o cavium.o
obj-y += dma-octeon.o
obj-y += csrc-octeon-ptp.o
obj-y += octeon-pci-console.o
obj-y += perf_counters.o
obj-y += octeon-memcpy.o
obj-y += executive/
obj-y += crypto/

obj-$(CONFIG_MTD)		      += flash_setup.o
obj-$(CONFIG_SMP)		      += smp.o
obj-$(CONFIG_NUMA)			+= octeon-numa.o
obj-$(CONFIG_NUMA)			+= csrc-fpa-clk.o
obj-$(CONFIG_OCTEON_ILM)	      += oct_ilm.o
obj-$(CONFIG_USB)		      += octeon-usb.o
obj-$(CONFIG_SYSFS)                   += octeon-power-throttle.o
obj-$(CONFIG_OCTEON_ERROR_INJECTOR)	+= octeon-error-injector.o
obj-$(CONFIG_CAVIUM_OCTEON_RAPIDIO)	+= octeon-rapidio.o
obj-$(CONFIG_CAVIUM_OCTEON_ERROR_TREE)	+= octeon-error-tree.o octeon-78xx-errors.o \
	octeon-73xx-errors.o octeon-7xxx-errors.o octeon-75xx-errors.o
obj-$(CONFIG_SYSFS)                     += cacheinfo.o
obj-$(CONFIG_OCTEON_FPA3)		+= octeon-fpa3.o
obj-$(CONFIG_USB)		      += octeon-usb.o

ifdef CONFIG_SMP
ifdef CONFIG_SYSFS
ifdef CONFIG_HOTPLUG_CPU
obj-y += unplug-cpu.o unplug-cpu-ll.o
endif
endif
endif
