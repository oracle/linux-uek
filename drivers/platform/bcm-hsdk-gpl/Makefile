# SPDX-License-Identifier: GPL-2.0
#
# Build Broadcom HSDK drivers from the local in-tree bcm-hsdk-gpl
# source tree.

bcm_hsdk_root := $(srctree)/drivers/platform/bcm-hsdk/bcm-hsdk-gpl
#bcm_hsdk_root := bcm-hsdk-gpl
bcm_hsdk_rel := bcm-hsdk-gpl/

bcm_hsdk_genhdrs := generated/include/bcmcnet/bcmcnet_dep.h \
	generated/include/bcmcnet/bcmcnet_buff.h
bcm_hsdk_genhdr_paths := $(addprefix $(obj)/,$(bcm_hsdk_genhdrs))

always-y += $(bcm_hsdk_genhdrs)
clean-files += $(bcm_hsdk_genhdrs)

$(obj)/generated/include/bcmcnet/bcmcnet_dep.h: $(bcm_hsdk_root)/linux/knet/ngknet_dep.h
	$(Q)mkdir -p $(dir $@)
	$(Q)cp $< $@

$(obj)/generated/include/bcmcnet/bcmcnet_buff.h: $(bcm_hsdk_root)/linux/knet/ngknet_buff.h
	$(Q)mkdir -p $(dir $@)
	$(Q)cp $< $@

ccflags-y += \
	-UNGKNET_NETIF_MAX -DNGKNET_NETIF_MAX=1056 \
	-UNGKNET_FILTER_MAX -DNGKNET_FILTER_MAX=1025 \
	-DSAL_LINUX -DKPMD \
	-I$(obj)/generated/include \
	-I$(bcm_hsdk_root)/shr/include \
	-I$(bcm_hsdk_root)/sal/include \
	-I$(bcm_hsdk_root)/bcmdrd/include \
	-I$(bcm_hsdk_root)/bcmltd/include \
	-I$(bcm_hsdk_root)/bcmlrd/include \
	-I$(bcm_hsdk_root)/bcmpkt/include \
	-I$(bcm_hsdk_root)/bcmcnet/include \
	-I$(bcm_hsdk_root)/linux/include \
	-I$(bcm_hsdk_root)/linux/include/lkm \
	-I$(bcm_hsdk_root)/linux/include/kernel \
	-I$(bcm_hsdk_root)/linux/bde \
	-I$(bcm_hsdk_root)/linux/knet \
	-I$(bcm_hsdk_root)/linux/knetcb \
	-I$(bcm_hsdk_root)/linux/bcmgenl

bcm_hsdk_knet_chip_srcs := $(sort $(wildcard $(bcm_hsdk_root)/bcmcnet/chip/bcm*/*_pdma_attach.c))
bcm_hsdk_knet_chip_objs := $(patsubst $(bcm_hsdk_root)/%.c,$(bcm_hsdk_rel)%.o,$(bcm_hsdk_knet_chip_srcs))

bcm_hsdk_pmd_common_srcs := \
	$(bcm_hsdk_root)/bcmpkt/lbpmd/bcmpkt_lbhdr.c \
	$(bcm_hsdk_root)/bcmpkt/rxpmd/bcmpkt_rxpmd.c \
	$(bcm_hsdk_root)/bcmpkt/rxpmd/bcmpkt_rxpmd_match_id.c \
	$(bcm_hsdk_root)/bcmpkt/txpmd/bcmpkt_txpmd.c \
	$(bcm_hsdk_root)/bcmpkt/flexhdr/bcmpkt_flexhdr.c \
	$(bcm_hsdk_root)/shr/bitop/shr_bitop_range_clear.c
bcm_hsdk_pmd_chip_srcs := $(sort \
	$(wildcard $(bcm_hsdk_root)/bcmpkt/chip/bcm*/*_pkt_lbhdr.c) \
	$(wildcard $(bcm_hsdk_root)/bcmpkt/chip/bcm*/*_pkt_rxpmd.c) \
	$(wildcard $(bcm_hsdk_root)/bcmpkt/chip/bcm*/*_pkt_rxpmd_field.c) \
	$(wildcard $(bcm_hsdk_root)/bcmpkt/chip/bcm*/*_pkt_txpmd.c))
bcm_hsdk_pmd_variant_srcs := $(sort \
	$(wildcard $(bcm_hsdk_root)/bcmpkt/xfcr/bcm*/*/*.c) \
	$(wildcard $(bcm_hsdk_root)/bcmpkt/ltt_stub/*/*/*/*.c))
bcm_hsdk_pmd_srcs := $(bcm_hsdk_pmd_common_srcs) \
	$(bcm_hsdk_pmd_chip_srcs) \
	$(bcm_hsdk_pmd_variant_srcs)
bcm_hsdk_pmd_objs := $(patsubst $(bcm_hsdk_root)/%.c,$(bcm_hsdk_rel)%.o,$(bcm_hsdk_pmd_srcs))

obj-$(CONFIG_BCM_HSDK_BDE) += linux_ngbde.o
linux_ngbde-y := \
	$(bcm_hsdk_rel)linux/bde/ngbde_main.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_kapi.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_ioctl.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_procfs.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_pio.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_iio.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_paxb.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_dma.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_intr.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_pgmem.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_pci_probe.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_iproc_probe.o \
	$(bcm_hsdk_rel)linux/bde/ngbde_swdev.o

obj-$(CONFIG_BCM_HSDK_KNET) += linux_ngknet.o
linux_ngknet-y := $(bcm_hsdk_knet_chip_objs) \
	$(bcm_hsdk_rel)bcmcnet/hmi/cmicd/bcmcnet_cmicd_pdma_hw.o \
	$(bcm_hsdk_rel)bcmcnet/hmi/cmicd/bcmcnet_cmicd_pdma_rxtx.o \
	$(bcm_hsdk_rel)bcmcnet/hmi/cmicx/bcmcnet_cmicx_pdma_hw.o \
	$(bcm_hsdk_rel)bcmcnet/hmi/cmicx/bcmcnet_cmicx_pdma_rxtx.o \
	$(bcm_hsdk_rel)bcmcnet/hmi/cmicr/bcmcnet_cmicr_pdma_hw.o \
	$(bcm_hsdk_rel)bcmcnet/hmi/cmicr/bcmcnet_cmicr_pdma_rxtx.o \
	$(bcm_hsdk_rel)bcmcnet/hmi/cmicr/bcmcnet_cmicr2_pdma_rxtx.o \
	$(bcm_hsdk_rel)bcmcnet/main/bcmcnet_core.o \
	$(bcm_hsdk_rel)bcmcnet/main/bcmcnet_dev.o \
	$(bcm_hsdk_rel)bcmcnet/main/bcmcnet_rxtx.o \
	$(bcm_hsdk_rel)linux/knet/ngknet_buff.o \
	$(bcm_hsdk_rel)linux/knet/ngknet_callback.o \
	$(bcm_hsdk_rel)linux/knet/ngknet_extra.o \
	$(bcm_hsdk_rel)linux/knet/ngknet_linux.o \
	$(bcm_hsdk_rel)linux/knet/ngknet_main.o \
	$(bcm_hsdk_rel)linux/knet/ngknet_procfs.o \
	$(bcm_hsdk_rel)linux/knet/ngknet_ptp.o

obj-$(CONFIG_BCM_HSDK_KNETCB) += linux_ngknetcb.o
linux_ngknetcb-y := $(bcm_hsdk_pmd_objs) \
	$(bcm_hsdk_rel)linux/knetcb/ngknetcb_main.o

obj-$(CONFIG_BCM_HSDK_GENL_PACKET) += genl-packet.o
genl-packet-y := \
	$(bcm_hsdk_rel)linux/genl-packet/genl-packet.o

obj-$(CONFIG_BCM_HSDK_BCMGENL) += linux_bcmgenl.o
linux_bcmgenl-y := $(bcm_hsdk_pmd_objs) \
	$(bcm_hsdk_rel)linux/bcmgenl/bcmgenl_packet.o \
	$(bcm_hsdk_rel)linux/bcmgenl/bcmgenl_psample.o \
	$(bcm_hsdk_rel)linux/bcmgenl/bcmgenl.o

obj-$(CONFIG_BCM_HSDK_EDK) += linux_ngedk.o
linux_ngedk-y := \
	$(bcm_hsdk_rel)linux/edk/ngedk_main.o

obj-$(CONFIG_BCM_HSDK_PTPCLOCK) += linux_ngptpclock.o
linux_ngptpclock-y := \
	$(bcm_hsdk_rel)linux/ptpclock/ngptpclock_main.o

obj-$(CONFIG_BCM_HSDK_ST) += linux_ngst.o
linux_ngst-y := \
	$(bcm_hsdk_rel)linux/st/ngst_main.o

bcm_hsdk_genhdr_deps := $(addprefix $(obj)/,$(linux_ngknet-y) $(linux_ngknetcb-y))
$(bcm_hsdk_genhdr_deps): $(bcm_hsdk_genhdr_paths)
