#
# Pensando SoC drivers
#
obj-y += cap_soc.o

CFLAGS_cap_mem.o := -I$(src)

obj-$(CONFIG_PENSANDO_SOC_CAPMEM) += cap_mem.o
obj-$(CONFIG_PENSANDO_SOC_PCIE) += cap_pcie.o cap_reboot.o
obj-$(CONFIG_PENSANDO_SOC_RSTCAUSE) += cap_rstcause.o
obj-$(CONFIG_PENSANDO_SOC_CRASH) += cap_crash.o
obj-$(CONFIG_PENSANDO_SOC_BSM) += cap_bsm.o
