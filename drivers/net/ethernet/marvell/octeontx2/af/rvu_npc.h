/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#ifndef RVU_NPC_H
#define RVU_NPC_H

/* strtoull of "mkexprof" with base:36 */
#define MKEX_END_SIGN  0xdeadbeef

struct npc_kpu_profile_action;
struct npc_mcam;
struct rvu;

struct npc_lt_def {
	u8	ltype_mask;
	u8	ltype_match;
	u8	lid;
} __packed;

struct npc_lt_def_ipsec {
	u8	ltype_mask;
	u8	ltype_match;
	u8	lid;
	u8	spi_offset;
	u8	spi_nz;
} __packed;

struct npc_lt_def_apad {
	u8	ltype_mask;
	u8	ltype_match;
	u8	lid;
	u8	valid;
} __packed;

struct npc_lt_def_color {
	u8	ltype_mask;
	u8	ltype_match;
	u8	lid;
	u8	noffset;
	u8	offset;
} __packed;

struct npc_lt_def_et {
	u8	ltype_mask;
	u8	ltype_match;
	u8	lid;
	u8	valid;
	u8	offset;
} __packed;

struct npc_lt_def_cfg {
	struct npc_lt_def	rx_ol2;
	struct npc_lt_def	rx_oip4;
	struct npc_lt_def	rx_iip4;
	struct npc_lt_def	rx_oip6;
	struct npc_lt_def	rx_iip6;
	struct npc_lt_def	rx_otcp;
	struct npc_lt_def	rx_itcp;
	struct npc_lt_def	rx_oudp;
	struct npc_lt_def	rx_iudp;
	struct npc_lt_def	rx_osctp;
	struct npc_lt_def	rx_isctp;
	struct npc_lt_def_ipsec	rx_ipsec[2];
	struct npc_lt_def	pck_ol2;
	struct npc_lt_def	pck_oip4;
	struct npc_lt_def	pck_oip6;
	struct npc_lt_def	pck_iip4;
	struct npc_lt_def_apad	rx_apad0;
	struct npc_lt_def_apad	rx_apad1;
	struct npc_lt_def_color	ovlan;
	struct npc_lt_def_color	ivlan;
	struct npc_lt_def_color	rx_gen0_color;
	struct npc_lt_def_color	rx_gen1_color;
	struct npc_lt_def_et	rx_et[2];
} __packed;

u64 npc_enable_mask(int count);
void npc_load_kpu_profile(struct rvu *rvu);
void npc_config_kpuaction(struct rvu *rvu, int blkaddr,
			  const struct npc_kpu_profile_action *kpuaction,
			  int kpu, int entry, bool pkind);
int npc_fwdb_prfl_img_map(struct rvu *rvu, void __iomem **prfl_img_addr,
			  u64 *size);

void npc_mcam_clear_bit(struct npc_mcam *mcam, u16 index);
void npc_mcam_set_bit(struct npc_mcam *mcam, u16 index);

#endif /* RVU_NPC_H */
