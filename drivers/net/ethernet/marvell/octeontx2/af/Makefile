# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Marvell's OcteonTX2 RVU Admin Function driver
#

obj-$(CONFIG_OCTEONTX2_MBOX) += octeontx2_mbox.o
obj-$(CONFIG_OCTEONTX2_AF) += octeontx2_af.o

octeontx2_mbox-y := mbox.o
octeontx2_af-y := cgx.o rvu.o ptp.o rvu_ptp.o rvu_cgx.o rvu_npa.o rvu_sso.o \
		  rvu_nix.o rvu_reg.o rvu_npc.o rvu_debugfs.o \
		  rvu_validation.o rvu_tim.o rvu_cpt.o rvu_fixes.o \
		  rvu_npc_fs.o rvu_sdp.o rvu_ree.o
