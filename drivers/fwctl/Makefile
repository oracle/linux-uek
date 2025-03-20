# SPDX-License-Identifier: GPL-2.0

ccflags-y := -std=gnu11 -Wno-declaration-after-statement

obj-$(CONFIG_FWCTL) += fwctl.o
obj-$(CONFIG_FWCTL_MLX5) += mlx5/
obj-$(CONFIG_FWCTL_PDS) += pds/

fwctl-y += main.o
