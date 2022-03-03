#! /bin/bash

# This is the x86_64 override file for the core/drivers package split.  The
# module directories listed here and in the generic list in filter-modules.sh
# will be moved to the resulting kernel-modules package for this arch.
# Anything not listed in those files will be in the kernel-core package.
#
# Please review the default list in filter-modules.sh before making
# modifications to the overrides below.  If something should be removed across
# all arches, remove it in the default instead of per-arch.

overrides="cec rvu_mbox ib_core ib_cm iw_cm rdma_cm industrialio"

driverdirs="atm auxdisplay bcma bluetooth firewire fmc infiniband isdn leds media memstick message mmc mtd mwave nfc ntb pcmcia platform power ssb staging tty uwb w1"

ethdrvs="3com adaptec arc alteon atheros cadence calxeda chelsio cisco dec dlink emulex icplus marvell micrel myricom neterion nvidia oki-semi packetengines qlogic rdc renesas sfc silan sis smsc stmicro sun tehuti ti via wiznet xircom"

drmdrvs="amd arm bridge ast exynos hisilicon i2c imx mgag200 meson msm nouveau panel radeon rcar-du rockchip tegra sun4i tinydrm vc4"

singlemods="ntb_netdev iscsi_ibft megaraid pmcraid qedi qla1280 9pnet_rdma rpcrdma nvmet-rdma nvme-rdma hid-picolcd hid-prodikeys hwa-hc hwpoison-inject target_core_user sbp_target cxgbit iw_cxgb3 iw_cxgb4 cxgb3i cxgb3i cxgb3i_ddp cxgb4i chcr chtls cros_ec_sensors_core cros_ec_sensors cros_ec_baro cros_ec_light_prox cros_ec_keyb cros_ec_dev regmap-sdw regmap-sdw-mbq b44 tg3 ucb1400_core u132-hcd hid-asus typec_displayport nct6775"
