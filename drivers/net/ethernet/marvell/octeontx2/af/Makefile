# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Marvell's RVU Admin Function driver
#

ccflags-y += -I$(src) -I$(src)/switch/
ccflags-y += -I$(srctree)/drivers/soc/marvell/rvu_af_extn
obj-$(CONFIG_OCTEONTX2_MBOX) += rvu_mbox.o
obj-$(CONFIG_OCTEONTX2_AF) += rvu_af.o
EB_DIR=../../../../../../drivers/soc/marvell/rvu_af_extn

rvu_mbox-y := mbox.o rvu_trace.o
rvu_af-y := cgx.o rvu.o rvu_cgx.o rvu_npa.o rvu_nix.o rvu_nix_spi.o \
		  rvu_reg.o rvu_npc.o rvu_debugfs.o ptp.o rvu_npc_fs.o \
		  rvu_cpt.o rvu_devlink.o rpm.o rvu_cn10k.o  \
		  rvu_sdp.o rvu_npc_hash.o mcs.o mcs_rvu_if.o mcs_cnf10kb.o \
		  rvu_rep.o cn20k/mbox_init.o cn20k/nix.o cn20k/debugfs.o \
		  cn20k/npa.o rvu_sso.o rvu_tim.o rvu_fixes.o mcs_fips.o \
		  cn20k/mcs.o mcs_devlink.o cn20k/npc.o cn20k/cpt.o cn20k/link.o \
		  cn20k/rvum.o cn20k/cplt.o rvu_switch.o switch/rvu_sw.o switch/rvu_sw_l2.o \
		  switch/rvu_sw_l3.o switch/rvu_sw_fl.o \
		  $(EB_DIR)/rvu_eblock.o \
		  $(EB_DIR)/rvu_eb_ree.o \
		  $(EB_DIR)/rvu_eb_sdp.o \
		  $(EB_DIR)/rvu_eb_dpi.o \
		  $(EB_DIR)/rvu_eb_cplt.o \
		  $(EB_DIR)/rvu_eb_ml.o \
		  $(EB_DIR)/rvu_eb_psw.o
