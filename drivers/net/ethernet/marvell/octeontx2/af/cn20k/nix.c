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
				     int blkaddr, int nixlf)
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

		rvu_write64(rvu, blkaddr,
			    NIX_AF_LFX_RX_INLINE_SA_BASE(nixlf, pf_id), 0);
		rvu_write64(rvu, blkaddr,
			    NIX_AF_LFX_RX_INLINE_CFG0(nixlf, pf_id), 0);
		rvu_write64(rvu, blkaddr,
			    NIX_AF_LFX_RX_INLINE_CFG1(nixlf, pf_id), 0);

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

int rvu_mbox_handler_nix_rx_inl_lf_cfg(struct rvu *rvu,
				       struct nix_rx_inl_lf_cfg_req *req,
				       struct msg_rsp *rsp)
{
	struct nix_rx_inl_profile_users *user, *next;
	struct nix_rx_inl_profile *inl_profile;
	struct nix_cn20k_hw *nix_cn20k_hw;
	u16 pcifunc = req->hdr.pcifunc;
	u8 profile = req->profile_id;
	int err, nixlf, blkaddr;
	struct nix_hw *nix_hw;
	bool match = false;

	if (profile >= NIX_RX_INL_PROFILE_CNT)
		return NIX_AF_ERR_RX_INL_INVALID_PROFILE_ID;

	err = nix_get_nixlf(rvu, pcifunc, &nixlf, &blkaddr);
	if (err)
		return err;

	nix_hw = get_nix_hw(rvu->hw, blkaddr);
	if (!nix_hw)
		return NIX_AF_ERR_INVALID_NIXBLK;

	nix_cn20k_hw = &nix_hw->cn20k;

	mutex_lock(&nix_cn20k_hw->rx_inl_lock);
	if (!test_bit(profile, nix_cn20k_hw->rx_inl_profile_bmap)) {
		err = NIX_AF_ERR_RX_INL_INVALID_PROFILE_ID;
		goto unlock;
	}

	inl_profile = &nix_cn20k_hw->inl_profiles[profile];
	list_for_each_entry_safe(user, next, &inl_profile->pfvf_list, list) {
		if (user->pf_func == pcifunc) {
			match = true;
			break;
		}
	}

	if (!match) {
		err = NIX_AF_ERR_RX_INL_INVALID_PROFILE_ID;
		goto unlock;
	}

	if (!req->enable) {
		rvu_write64(rvu, blkaddr,
			    NIX_AF_LFX_RX_INLINE_SA_BASE(nixlf, profile), 0);
		rvu_write64(rvu, blkaddr,
			    NIX_AF_LFX_RX_INLINE_CFG0(nixlf, profile), 0);
		rvu_write64(rvu, blkaddr,
			    NIX_AF_LFX_RX_INLINE_CFG1(nixlf, profile), 0);
		goto unlock;
	}

	rvu_write64(rvu, blkaddr, NIX_AF_LFX_RX_INLINE_SA_BASE(nixlf, profile),
		    req->rx_inline_sa_base);
	rvu_write64(rvu, blkaddr, NIX_AF_LFX_RX_INLINE_CFG0(nixlf, profile),
		    req->rx_inline_cfg0);
	rvu_write64(rvu, blkaddr, NIX_AF_LFX_RX_INLINE_CFG1(nixlf, profile),
		    req->rx_inline_cfg1);

unlock:
	mutex_unlock(&nix_cn20k_hw->rx_inl_lock);
	return err;
}

int rvu_nix_cn20k_free_resources(struct rvu *rvu, u16 pcifunc)
{
	struct nix_cn20k_hw *nix_cn20k_hw;
	struct nix_hw *nix_hw;
	int err, nixlf;
	int blkaddr;

	err = nix_get_struct_ptrs(rvu, pcifunc, &nix_hw, &blkaddr);
	if (err)
		return err;

	err = nix_get_nixlf(rvu, pcifunc, &nixlf, &blkaddr);
	if (err)
		return err;

	nix_cn20k_hw = &nix_hw->cn20k;

	mutex_lock(&nix_cn20k_hw->rx_inl_lock);
	nix_free_rx_inl_profiles(rvu, pcifunc, nix_cn20k_hw, blkaddr, nixlf);
	nix_free_rx_inl_queues(rvu, pcifunc);
	mutex_unlock(&nix_cn20k_hw->rx_inl_lock);

	return 0;
}

void nix_free_rx_inl_queues(struct rvu *rvu, u16 pcifunc)
{
	struct rvu_cpt *cpt = &rvu->cpt;
	int queue_idx;
	u64 val;

	for_each_set_bit(queue_idx, cpt->cpt_rx_queue_bitmap,
			 CPT_AF_MAX_RXC_QUEUES) {
		/* Skip queues that don't match the given pcifunc, unless
		 * it's queue 0.
		 */
		if (cpt->cptpfvf_map[queue_idx] != pcifunc && queue_idx)
			continue;

		rvu_write64(rvu, BLKADDR_NIX0,
			    NIX_AF_CN20K_RX_CPTX_INST_QSEL(queue_idx),
			    0x0);
		val = rvu_read64(rvu, BLKADDR_NIX0,
				 NIX_AF_CN20K_RX_CPTX_CREDIT(queue_idx));
		if ((val & 0x3FFFFF) != 0x3FFFFF)
			rvu_write64(rvu, BLKADDR_NIX0,
				    NIX_AF_CN20K_RX_CPTX_CREDIT(queue_idx),
				    0x3FFFFF - val);
	}
}

static int nix_rx_inline_queue_cfg(struct rvu *rvu,
				   struct nix_rx_inline_qcfg_req *req,
				   int blkaddr)
{
	u64 val;
	u8 qsel;

	qsel = req->rx_queue_id;
	if (!req->enable) {
		rvu_write64(rvu, blkaddr, NIX_AF_CN20K_RX_CPTX_INST_QSEL(qsel),
			    0x0);
		val = rvu_read64(rvu, blkaddr,
				 NIX_AF_CN20K_RX_CPTX_CREDIT(qsel));
		if ((val & 0x3FFFFF) != 0x3FFFFF)
			rvu_write64(rvu, blkaddr,
				    NIX_AF_CN20K_RX_CPTX_CREDIT(qsel),
				    0x3FFFFF - val);
		return 0;
	}

	/* Set CPT queue for inline IPSec */
	val = FIELD_PREP(CPT_INST_QSEL_SLOT, req->cpt_slot);
	val |= FIELD_PREP(CPT_INST_QSEL_PF_FUNC, req->cpt_pf_func);
	val |= FIELD_PREP(CPT_INST_QSEL_BLOCK, BLKADDR_CPT0);
	rvu_write64(rvu, blkaddr, NIX_AF_CN20K_RX_CPTX_INST_QSEL(qsel), val);
	/* Set CPT credit */
	val = rvu_read64(rvu, blkaddr, NIX_AF_CN20K_RX_CPTX_CREDIT(qsel));
	if ((val & 0x3FFFFF) != 0x3FFFFF)
		rvu_write64(rvu, blkaddr,
			    NIX_AF_CN20K_RX_CPTX_CREDIT(qsel), 0x3FFFFF - val);

	val = FIELD_PREP(CPT_INST_CREDIT_CNT, req->cpt_credit);
	val |= FIELD_PREP(NIX_AF_CN20K_CPT_INST_CREDIT_BPID, req->bpid);
	val |= FIELD_PREP(NIX_AF_CN20K_CPT_INST_CREDIT_TH, req->credit_th);
	val |= FIELD_PREP(CPT_INST_CREDIT_HYST, req->hysteresis);
	rvu_write64(rvu, blkaddr, NIX_AF_CN20K_RX_CPTX_CREDIT(qsel), val);

	return 0;
}

int rvu_mbox_handler_nix_rx_inl_queue_cfg(struct rvu *rvu,
					  struct nix_rx_inline_qcfg_req *req,
					  struct msg_rsp *rsp)
{
	struct rvu_cpt *cpt = &rvu->cpt;

	if (!is_block_implemented(rvu->hw, BLKADDR_CPT0))
		return 0;

	if (req->rx_queue_id >= CPT_AF_MAX_RXC_QUEUES)
		return CPT_AF_ERR_RXC_QUEUE_INVALID;

	if (cpt->cptpfvf_map[req->rx_queue_id] != req->hdr.pcifunc)
		return CPT_AF_ERR_QUEUE_PCIFUNC_MAP_INVALID;

	return nix_rx_inline_queue_cfg(rvu, req, BLKADDR_NIX0);
}
