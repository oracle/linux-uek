# Makefile for the Sun Microsystems 10Gb ethernet driver
#

#EXTRA_CFLAGS += -DCONFIG_HXGE_NAPI 
EXTRA_CFLAGS += -DCONFIG_SKB_SHARED -DUSE_PIO 

ifeq ($(ERRINJECT),1)
EXTRA_CFLAGS += -DCONFIG_ERRINJECT
endif


obj-$(CONFIG_HXGE) += hxge.o
hxge-objs := hxge_other.o hxge_ethtool.o hxge_main.o hxge_stats.o hxge_vmac.o hxge_param.o hxge_pfc.o hxge_txdma.o hxge_rxdma.o hxge_intr.o 
ifeq ($(ERRINJECT),1)
hxge-objs += hxge_sysfs.o
endif
hxge-objs += hpi/hpi.o hpi/hpi_rxdma.o hpi/hpi_txdma.o hpi/hpi_pfc.o
hxge-objs += hpi/hpi_vir.o hpi/hpi_vmac.o
