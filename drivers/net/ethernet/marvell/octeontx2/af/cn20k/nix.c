// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/pci.h>

#include "struct.h"
#include "../rvu.h"
#include "nix.h"

int rvu_mbox_handler_nix_cn20k_aq_enq(struct rvu *rvu,
				      struct nix_cn20k_aq_enq_req *req,
				      struct nix_cn20k_aq_enq_rsp *rsp)
{
	return rvu_nix_aq_enq_inst(rvu, (struct nix_aq_enq_req *)req,
				  (struct nix_aq_enq_rsp *)rsp);
}

void rvu_nix_block_cn20k_init(struct rvu *rvu, struct nix_hw *nix_hw)
{
	int i;

	bitmap_zero(nix_hw->cn20k.rx_inl_profile_bmap, NIX_RX_INL_PROFILE_CNT);

	for (i = 0; i < NIX_RX_INL_PROFILE_CNT; i++)
		INIT_LIST_HEAD(&nix_hw->cn20k.inl_profiles[i].pfvf_list);

	mutex_init(&nix_hw->cn20k.rx_inl_lock);
}

static int nix_get_rx_inl_profile(struct nix_rx_inl_profile_cfg_req *req,
				  struct nix_cn20k_hw *nix_cn20k_hw,
				  u8 *profile_id)
{
	struct nix_rx_inl_profile *inl_profile;
	struct nix_rx_inl_profile_users *user;
	bool match = false;
	int pf_id, i;

	/* Check each configured profile */
	for_each_set_bit(pf_id, nix_cn20k_hw->rx_inl_profile_bmap,
			 NIX_RX_INL_PROFILE_CNT) {
		/* Match profile configuration */
		inl_profile = &nix_cn20k_hw->inl_profiles[pf_id];
		if (inl_profile->def_cfg != req->def_cfg ||
		    inl_profile->extract_cfg != req->extract_cfg ||
		    inl_profile->gen_cfg != req->gen_cfg)
			continue;

		match = true;
		for (i = 0; i < NIX_RX_INL_PROFILE_PROTO_CNT; i++) {
			if (inl_profile->prot_field_cfg[i] !=
			    req->prot_field_cfg[i]) {
				match = false;
				break;
			}
		}

		/* Return profile-id if match found */
		if (match) {
			*profile_id = pf_id;
			break;
		}
	}

	/* Return max profile if no match found */
	if (!match) {
		*profile_id = NIX_RX_INL_PROFILE_CNT;
		return 0;
	}

	/* Add requesting pcifunc to this profile user list */
	user = kzalloc(sizeof(*user), GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	user->pf_func = req->hdr.pcifunc;
	list_add_tail(&user->list, &inl_profile->pfvf_list);
	return 0;
}

static void nix_free_rx_inl_profiles(struct rvu *rvu, u16 pcifunc,
				     struct nix_cn20k_hw *nix_cn20k_hw,
				     int blkaddr)
{
	struct nix_rx_inl_profile_users *user, *next;
	struct nix_rx_inl_profile *inl_profile;
	int pf_id, i;

	for_each_set_bit(pf_id, nix_cn20k_hw->rx_inl_profile_bmap,
			 NIX_RX_INL_PROFILE_CNT) {
		inl_profile = &nix_cn20k_hw->inl_profiles[pf_id];
		list_for_each_entry_safe(user, next, &inl_profile->pfvf_list,
					 list) {
			if (user->pf_func == pcifunc) {
				list_del(&user->list);
				kfree(user);
			}
		}

		/* Do not free profile if there are users of this profile */
		if (!list_empty(&inl_profile->pfvf_list))
			continue;

		/* Free profile as no more reference */
		clear_bit(pf_id, nix_cn20k_hw->rx_inl_profile_bmap);

		rvu_write64(rvu, blkaddr, NIX_AF_RX_DEF_INLINEX(pf_id), 0);
		rvu_write64(rvu, blkaddr, NIX_AF_RX_EXTRACT_INLINEX(pf_id), 0);
		rvu_write64(rvu, blkaddr, NIX_AF_RX_INLINE_GEN_CFGX(pf_id), 0);

		/* Clear profile protocol configuration */
		for (i = 0; i < NIX_RX_INL_PROFILE_PROTO_CNT; i++)
			rvu_write64(rvu, blkaddr,
				    NIX_AF_RX_PROT_FIELDX_INLINEX(i, pf_id), 0);

		inl_profile->def_cfg = 0;
		inl_profile->extract_cfg = 0;
		inl_profile->gen_cfg = 0;
		memset(inl_profile->prot_field_cfg, 0,
		       sizeof(u64) * NIX_RX_INL_PROFILE_PROTO_CNT);
	}
}

static int nix_set_rx_inl_profile(struct rvu *rvu,
				  struct nix_rx_inl_profile_cfg_req *req,
				  struct nix_cn20k_hw *nix_cn20k_hw,
				  int blkaddr, u8 pf_id)
{
	struct nix_rx_inl_profile *inline_profile;
	struct nix_rx_inl_profile_users *user;
	int i;

	if (pf_id >= NIX_RX_INL_PROFILE_CNT)
		return -EINVAL;

	inline_profile = &nix_cn20k_hw->inl_profiles[pf_id];

	/* Save and update hardware register */
	inline_profile->def_cfg = req->def_cfg;
	inline_profile->extract_cfg = req->extract_cfg;
	inline_profile->gen_cfg = req->gen_cfg;

	rvu_write64(rvu, blkaddr, NIX_AF_RX_DEF_INLINEX(pf_id), req->def_cfg);
	rvu_write64(rvu, blkaddr, NIX_AF_RX_EXTRACT_INLINEX(pf_id),
		    req->extract_cfg);
	rvu_write64(rvu, blkaddr, NIX_AF_RX_INLINE_GEN_CFGX(pf_id),
		    req->gen_cfg);
	for (i = 0; i < NIX_RX_INL_PROFILE_PROTO_CNT; i++) {
		inline_profile->prot_field_cfg[i] = req->prot_field_cfg[i];
		rvu_write64(rvu, blkaddr,
			    NIX_AF_RX_PROT_FIELDX_INLINEX(i, pf_id),
			    req->prot_field_cfg[i]);
	}

	user = kzalloc(sizeof(*user), GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	user->pf_func = req->hdr.pcifunc;
	list_add_tail(&user->list, &inline_profile->pfvf_list);
	return 0;
}

int
rvu_mbox_handler_nix_rx_inl_profile_cfg(struct rvu *rvu,
					struct nix_rx_inl_profile_cfg_req *req,
					struct nix_rx_inl_profile_cfg_rsp *rsp)
{
	struct nix_cn20k_hw *nix_cn20k_hw;
	u8 pf_id = NIX_RX_INL_PROFILE_CNT;
	struct nix_hw *nix_hw;
	int blkaddr;
	int err;

	err = nix_get_struct_ptrs(rvu, req->hdr.pcifunc, &nix_hw, &blkaddr);
	if (err)
		return err;

	nix_cn20k_hw = &nix_hw->cn20k;
	mutex_lock(&nix_cn20k_hw->rx_inl_lock);

	err = nix_get_rx_inl_profile(req, nix_cn20k_hw, &pf_id);
	if (err)
		goto unlock;

	if (pf_id < NIX_RX_INL_PROFILE_CNT) {
		rsp->profile_id = pf_id;
		goto unlock;
	}

	pf_id = find_next_zero_bit(nix_cn20k_hw->rx_inl_profile_bmap,
				   NIX_RX_INL_PROFILE_CNT, 1);
	if (pf_id == NIX_RX_INL_PROFILE_CNT) {
		err = NIX_AF_ERR_RX_INL_PROFILE_NOT_FREE;
		goto unlock;
	}

	err = nix_set_rx_inl_profile(rvu, req, nix_cn20k_hw, blkaddr, pf_id);
	if (err)
		goto unlock;

	rsp->profile_id = pf_id;
	set_bit(pf_id, nix_cn20k_hw->rx_inl_profile_bmap);

unlock:
	mutex_unlock(&nix_cn20k_hw->rx_inl_lock);
	return err;
}

int rvu_nix_cn20k_free_resources(struct rvu *rvu, u16 pcifunc)
{
	struct nix_cn20k_hw *nix_cn20k_hw;
	struct nix_hw *nix_hw;
	int blkaddr;
	int err;

	err = nix_get_struct_ptrs(rvu, pcifunc, &nix_hw, &blkaddr);
	if (err)
		return err;

	nix_cn20k_hw = &nix_hw->cn20k;

	mutex_lock(&nix_cn20k_hw->rx_inl_lock);
	nix_free_rx_inl_profiles(rvu, pcifunc, nix_cn20k_hw, blkaddr);
	mutex_unlock(&nix_cn20k_hw->rx_inl_lock);

	return 0;
}
