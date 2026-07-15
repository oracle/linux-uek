# SPDX-License-Identifier: GPL-2.0
dtb-$(CONFIG_ARCH_PENSANDO_ELBA_SOC) += \
		elba-asic.dtb
dtb-$(CONFIG_ARCH_PENSANDO_ELBA_SOC) += giglio-asic.dtb giglio-asic-psci.dtb \
		giglio-asic-psci-flash128.dtb giglio-asic-flash128.dtb \
		giglio-secure.dtb giglio-deschutes-flash128.dtb

always-y	:= $(dtb-y)
subdir-y	:= $(dts-dirs)
clean-files	:= *.dtb
