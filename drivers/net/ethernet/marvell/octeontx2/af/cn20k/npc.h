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

enum npc_subbank_flag {
	NPC_SUBBANK_FLAG_UNINIT,	// npc_subbank is not initialized yet.
	NPC_SUBBANK_FLAG_FREE = BIT(0),	// No slot allocated
	NPC_SUBBANK_FLAG_USED = BIT(1), // At least one slot allocated
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
	int pf_cnt;
	bool init_done;
};

struct rvu;

struct npc_priv_t *npc_priv_get(void);
int npc_cn20k_init(struct rvu *rvu);
int npc_cn20k_deinit(struct rvu *rvu);
void npc_cn20k_subbank_calc_free(struct rvu *rvu, int *x2_free, int *x4_free, int *sb_free);

int npc_cn20k_ref_idx_alloc(struct rvu *rvu, int pcifunc, int key_type,
			    int prio, u16 *mcam_idx, int ref, int limit,
			    bool contig, int count);
int npc_cn20k_idx_free(struct rvu *rvu, u16 *mcam_idx, int count);

int npc_mcam_idx_2_key_type(struct rvu *rvu, u16 mcam_idx, u8 *key_type);

#endif /* NPC_CN20K_H */
