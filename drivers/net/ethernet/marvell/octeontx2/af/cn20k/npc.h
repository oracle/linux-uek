/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#ifndef NPC_CN20K_H
#define NPC_CN20K_H

#define MAX_NUM_BANKS 2
#define MAX_NUM_SUB_BANKS 32
#define MAX_SUBBANK_DEPTH 256
#define NPC_CN20K_BYTESM GENMASK_ULL(18, 16)
#define NPC_CN20K_PARSE_NIBBLE GENMASK_ULL(22, 0)
#define NPC_CN20K_TOTAL_NIBBLE 23

#define CN20K_GET_KEX_CFG(intf)	\
	rvu_read64(rvu, BLKADDR_NPC, NPC_AF_INTFX_KEX_CFG(intf))

#define CN20K_GET_EXTR_LID(intf, extr)	\
	rvu_read64(rvu, BLKADDR_NPC,	\
		   NPC_AF_INTFX_EXTRACTORX_CFG(intf, extr))

#define CN20K_SET_EXTR_LT(intf, extr, ltype, cfg)	\
	rvu_write64(rvu, BLKADDR_NPC,	\
		    NPC_AF_INTFX_EXTRACTORX_LTX_CFG(intf, extr, ltype), cfg)

#define CN20K_GET_EXTR_LT(intf, extr, ltype)	\
	rvu_read64(rvu, BLKADDR_NPC,	\
		   NPC_AF_INTFX_EXTRACTORX_LTX_CFG(intf, extr, ltype))

enum npc_subbank_flag {
	NPC_SUBBANK_FLAG_UNINIT,	// npc_subbank is not initialized yet.
	NPC_SUBBANK_FLAG_FREE = BIT(0),	// No slot allocated
	NPC_SUBBANK_FLAG_USED = BIT(1), // At least one slot allocated
};

enum npc_dft_rule_id {
	NPC_DFT_RULE_START_ID = 1,
	NPC_DFT_RULE_PROMISC_ID = NPC_DFT_RULE_START_ID,
	NPC_DFT_RULE_MCAST_ID,
	NPC_DFT_RULE_BCAST_ID,
	NPC_DFT_RULE_UCAST_ID,
	NPC_DFT_RULE_MAX_ID,
};

struct npc_subbank {
	u16 b0t, b0b, b1t, b1b;		// mcam indexes of this subbank
	enum npc_subbank_flag flags;
	struct mutex lock;		// for flags & rsrc modification
	DECLARE_BITMAP(b0map, MAX_SUBBANK_DEPTH);	// for x4 and x2
	DECLARE_BITMAP(b1map, MAX_SUBBANK_DEPTH);	// for x2 only
	u16 idx;	// subbank index, 0 to npc_priv.subbank - 1
	u16 arr_idx;	// Index to the free array or used array
	u16 free_cnt;	// number of free slots;
	u8 key_type;	//NPC_MCAM_KEY_X4 or NPC_MCAM_KEY_X2
};

struct npc_defrag_show_node {
	u16 old_midx;
	u16 new_midx;
	u16 vidx;
	struct list_head list;
};

struct npc_priv_t {
	int bank_depth;
	const int num_banks;
	const int num_subbanks;
	int subbank_depth;
	u8 kw;				// Kex configure Keywidth.
	struct npc_subbank *sb;		// Array of subbanks
	struct xarray xa_sb_used;	// xarray of used subbanks
	struct xarray xa_sb_free;	// xarray of free subbanks
	struct xarray *xa_pf2idx_map;	// Each PF to map its mcam idxes
	struct xarray xa_idx2pf_map;	// Mcam idxes to pf map.
	struct xarray xa_pf_map;	// pcifunc to index map.
	struct xarray xa_pf2dfl_rmap;	// pcifunc to default rule index
	struct xarray xa_idx2vidx_map;	// mcam idx to virtual index map.
	struct xarray xa_vidx2idx_map;	// mcam vidx to index map.
	struct list_head defrag_lh;	// defrag list head for debugfs
	struct mutex lock;		// lock
	int pf_cnt;
	bool init_done;
};

struct npc_mcam_kex_extr {
	/* MKEX Profle Header */
	u64 mkex_sign; /* "mcam-kex-profile" (8 bytes/ASCII characters) */
	u8 name[MKEX_NAME_LEN];   /* MKEX Profile name */
	u64 cpu_model;   /* Format as profiled by CPU hardware */
	u64 kpu_version; /* KPU firmware/profile version */
	u64 reserved; /* Reserved for extension */

	/* MKEX Profle Data */
	u64 keyx_cfg[NPC_MAX_INTF]; /* NPC_AF_INTF(0..1)_KEX_CFG */
#define NPC_MAX_EXTRACTOR	24
	/* MKEX Extractor data */
	u64 intf_extr_lid[NPC_MAX_INTF][NPC_MAX_EXTRACTOR];
	/* KEX configuration per extractor */
	u64 intf_extr_lt[NPC_MAX_INTF][NPC_MAX_EXTRACTOR][NPC_MAX_LT];
} __packed;

struct npc_kpm_action0 {
#if defined(__BIG_ENDIAN_BITFIELD)
	u64 rsvd_63_57     : 7;
	u64 byp_count      : 3;
	u64 capture_ena    : 1;
	u64 parse_done     : 1;
	u64 next_state     : 8;
	u64 rsvd_43        : 1;
	u64 capture_lid    : 3;
	u64 capture_ltype  : 4;
	u64 rsvd_32_35     : 4;
	u64 capture_flags  : 4;
	u64 ptr_advance    : 8;
	u64 var_len_offset : 8;
	u64 var_len_mask   : 8;
	u64 var_len_right  : 1;
	u64 var_len_shift  : 3;
#else
	u64 var_len_shift  : 3;
	u64 var_len_right  : 1;
	u64 var_len_mask   : 8;
	u64 var_len_offset : 8;
	u64 ptr_advance    : 8;
	u64 capture_flags  : 4;
	u64 rsvd_32_35     : 4;
	u64 capture_ltype  : 4;
	u64 capture_lid    : 3;
	u64 rsvd_43        : 1;
	u64 next_state     : 8;
	u64 parse_done     : 1;
	u64 capture_ena    : 1;
	u64 byp_count      : 3;
	u64 rsvd_63_57     : 7;
#endif
};

struct rvu;
struct npc_priv_t *npc_priv_get(void);
int npc_cn20k_init(struct rvu *rvu);
int npc_cn20k_deinit(struct rvu *rvu);
void npc_cn20k_subbank_calc_free(struct rvu *rvu, int *x2_free, int *x4_free, int *sb_free);

int npc_cn20k_ref_idx_alloc(struct rvu *rvu, int pcifunc, int key_type,
			    int prio, u16 *mcam_idx, int ref, int limit,
			    bool contig, int count, bool virt);
int npc_cn20k_idx_free(struct rvu *rvu, u16 *mcam_idx, int count);

int npc_cn20k_dft_rules_alloc(struct rvu *rvu, u16 pcifunc);
void npc_cn20k_dft_rules_free(struct rvu *rvu, u16 pcifunc);

int npc_cn20k_dft_rules_idx_get(struct rvu *rvu, u16 pcifunc, u16 *bcast, u16 *mcast,
				u16 *promisc, u16 *ucast);
void npc_cn20k_parser_profile_init(struct rvu *rvu, int blkaddr);
struct npc_mcam_kex_extr *npc_mkex_extr_default_get(void);
void npc_cn20k_load_mkex_profile(struct rvu *rvu, int blkaddr, const char *mkex_profile);
void npc_cn20k_config_mcam_entry(struct rvu *rvu, int blkaddr, int index, u8 intf,
				 struct cn20k_mcam_entry *entry, bool enable, u8 hw_prio);
void npc_cn20k_enable_mcam_entry(struct rvu *rvu, int blkaddr, int index, bool enable);
void npc_cn20k_copy_mcam_entry(struct rvu *rvu, int blkaddr, u16 src, u16 dest);
void npc_cn20k_read_mcam_entry(struct rvu *rvu, int blkaddr, u16 index,
			       struct cn20k_mcam_entry *entry, u8 *intf, u8 *ena,
			       u8 *hw_prio);
u16 npc_cn20k_vidx2idx(u16 index);
u16 npc_cn20k_idx2vidx(u16 idx);
int npc_cn20k_defrag(struct rvu *rvu);

int npc_mcam_idx_2_key_type(struct rvu *rvu, u16 mcam_idx, u8 *key_type);

#endif /* NPC_CN20K_H */
