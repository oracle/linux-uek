#
# Pensando SoC drivers
#
obj-y += cap_soc.o

CFLAGS_cap_mem.o := -I$(src)
ccflags-$(CONFIG_PENSANDO_SOC_PCIE) += -DPEN_COMPAT_V2

obj-$(CONFIG_PENSANDO_SOC_CAPMEM) += cap_mem.o
obj-$(CONFIG_PENSANDO_SOC_REBOOT) += cap_reboot.o
obj-$(CONFIG_PENSANDO_SOC_PCIE) += cap_pcie.o
obj-$(CONFIG_PENSANDO_SOC_PCIE) += kpcimgr.o kpcimgr_sysfs.o
obj-$(CONFIG_PENSANDO_SOC_RSTCAUSE) += cap_rstcause.o
obj-$(CONFIG_PENSANDO_SOC_CRASH) += cap_crash.o
obj-$(CONFIG_PENSANDO_SOC_SAL_CRASH) += sal_crash.o
obj-$(CONFIG_PENSANDO_SOC_BSM) += cap_bsm.o
obj-$(CONFIG_PENSANDO_SOC_PENFW) += penfw_smc.o penfw_sysfs.o penfw_drv.o
obj-$(CONFIG_PENSANDO_SOC_SBUS) += sbus.o
obj-$(CONFIG_ARCH_PENSANDO_SALINA_SOC) += cmn_pmu_irq.o
obj-$(CONFIG_ARCH_PENSANDO_GIGLIO_SOC) += giglio_emmc_irq.o
