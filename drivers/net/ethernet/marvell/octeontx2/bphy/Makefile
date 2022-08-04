# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Marvell's OcteonTX2 BPHY RFOE netdev driver
#

obj-$(CONFIG_OCTEONTX2_BPHY_RFOE_NETDEV) += octeontx2_bphy_netdev.o

#EXTRA_CFLAGS += -DDEBUG

octeontx2_bphy_netdev-y := otx2_bphy_main.o otx2_rfoe.o otx2_rfoe_ethtool.o otx2_rfoe_ptp.o \
				otx2_cpri.o otx2_cpri_ethtool.o otx2_bphy_debugfs.o \
				cnf10k_rfoe.o cnf10k_rfoe_ethtool.o cnf10k_rfoe_ptp.o \
				cnf10k_cpri.o cnf10k_cpri_ethtool.o otx2_bcn_ptp.o cnf10k_bphy_debugfs.o
