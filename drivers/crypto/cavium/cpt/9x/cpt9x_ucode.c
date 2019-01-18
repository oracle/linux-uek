// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "rvu_reg.h"
#include "cpt_ucode.h"
#include "cpt9x_mbox_common.h"

static struct bitmap get_cores_bmap(struct device *dev,
				    struct engine_group_info *eng_grp)
{
	struct bitmap bmap = { 0 };
	bool found = false;
	int i;

	if (eng_grp->g->engs_num > CPT_9X_MAX_ENGINES) {
		dev_err(dev, "9X plat unsupported number of engines %d",
			eng_grp->g->engs_num);
		return bmap;
	}

	for (i = 0; i  < MAX_ENGS_PER_GRP; i++)
		if (eng_grp->engs[i].type) {
			bitmap_or(bmap.bits, bmap.bits,
				  eng_grp->engs[i].bmap,
				  eng_grp->g->engs_num);
			bmap.size = eng_grp->g->engs_num;
			found = true;
		}

	if (!found)
		dev_err(dev, "No engines reserved for engine group %d",
			eng_grp->idx);
	return bmap;
}

static int cpt9x_detach_and_disable_cores(struct engine_group_info *eng_grp,
					  void *obj)
{
	struct cptpf_dev *cptpf = (struct cptpf_dev *) obj;
	struct bitmap bmap;
	int i, timeout = 10;
	int busy, ret = 0;
	u64 reg;

	bmap = get_cores_bmap(&cptpf->pdev->dev, eng_grp);
	if (!bmap.size)
		return -EINVAL;

	/* Detach the cores from group */
	for_each_set_bit(i, bmap.bits, bmap.size) {
		ret = cpt_read_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL2(i), &reg);
		if (ret)
			goto error;

		if (reg & (1ull << eng_grp->idx)) {
			eng_grp->g->eng_ref_cnt[i]--;
			reg &= ~(1ull << eng_grp->idx);

			ret = cpt_write_af_reg(cptpf->pdev,
					       CPT_AF_EXEX_CTL2(i), reg);
			if (ret)
				goto error;
		}
	}

	/* Wait for cores to become idle */
	do {
		busy = 0;
		usleep_range(10000, 20000);
		if (timeout-- < 0)
			return -EBUSY;

		for_each_set_bit(i, bmap.bits, bmap.size) {
			ret = cpt_read_af_reg(cptpf->pdev, CPT_AF_EXEX_STS(i),
					      &reg);
			if (ret)
				goto error;

			if (reg & 0x1) {
				busy = 1;
				break;
			}
		}
	} while (busy);

	/* Disable the cores only if they are not used anymore */
	for_each_set_bit(i, bmap.bits, bmap.size)
		if (!eng_grp->g->eng_ref_cnt[i]) {
			ret = cpt_write_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL(i),
					       0x0);
			if (ret)
				goto error;
		}
error:
	return ret;
}

static int cpt9x_set_ucode_base(struct engine_group_info *eng_grp, void *obj)
{
	struct cptpf_dev *cptpf = (struct cptpf_dev *) obj;
	struct engines_reserved *engs;
	dma_addr_t dma_addr;
	int i, bit, ret = 0;

	/* Set PF number for microcode fetches */
	ret = cpt_write_af_reg(cptpf->pdev, CPT_AF_PF_FUNC,
			       cptpf->pf_id << RVU_PFVF_PF_SHIFT);
	if (ret)
		goto error;

	for (i = 0; i < MAX_ENGS_PER_GRP; i++) {
		engs = &eng_grp->engs[i];
		if (!engs->type)
			continue;

		dma_addr = engs->ucode->align_dma;

		/* Set UCODE_BASE only for the cores which are not used,
		 * other cores should have already valid UCODE_BASE set
		 */
		for_each_set_bit(bit, engs->bmap, eng_grp->g->engs_num)
			if (!eng_grp->g->eng_ref_cnt[bit]) {
				ret = cpt_write_af_reg(cptpf->pdev,
						CPT_AF_EXEX_UCODE_BASE(bit),
						(u64) dma_addr);
				if (ret)
					goto error;
			}
	}
error:
	return ret;
}

static int cpt9x_attach_and_enable_cores(struct engine_group_info *eng_grp,
					 void *obj)
{
	struct cptpf_dev *cptpf = (struct cptpf_dev *) obj;
	struct bitmap bmap;
	u64 reg;
	int i, ret = 0;

	bmap = get_cores_bmap(&cptpf->pdev->dev, eng_grp);
	if (!bmap.size)
		return -EINVAL;

	/* Attach the cores to the group */
	for_each_set_bit(i, bmap.bits, bmap.size) {
		ret = cpt_read_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL2(i), &reg);
		if (ret)
			goto error;

		if (!(reg & (1ull << eng_grp->idx))) {
			eng_grp->g->eng_ref_cnt[i]++;
			reg |= 1ull << eng_grp->idx;

			ret = cpt_write_af_reg(cptpf->pdev,
					       CPT_AF_EXEX_CTL2(i), reg);
			if (ret)
				goto error;
		}
	}

	/* Enable the cores */
	for_each_set_bit(i, bmap.bits, bmap.size) {
		ret = cpt_add_write_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL(i),
					   0x1);
		if (ret)
			goto error;
	}
	ret = cpt_send_af_reg_requests(cptpf->pdev);
	if (ret)
		goto error;
error:
	return ret;
}

void cpt9x_print_engines_mask(struct engine_group_info *eng_grp, void *obj,
			      char *buf, int size)
{
	struct cptpf_dev *cptpf = (struct cptpf_dev *) obj;
	struct bitmap bmap;
	u32 mask[4];

	bmap = get_cores_bmap(&cptpf->pdev->dev, eng_grp);
	if (!bmap.size) {
		scnprintf(buf, size, "unknown");
		return;
	}

	bitmap_to_u32array(mask, 4, bmap.bits, bmap.size);
	scnprintf(buf, size, "%8.8x %8.8x %8.8x %8.8x", mask[3], mask[2],
		  mask[1], mask[0]);
}

static void cpt9x_notify_group_change(void *obj)
{
	struct cptpf_dev *cptpf = (struct cptpf_dev *) obj;
	struct engine_group_info *grp;
	int crypto_eng_grp = INVALID_CRYPTO_ENG_GRP;
	int i;

	for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
		grp = &cptpf->eng_grps.grp[i];
		if (!grp->is_enabled)
			continue;

		if (cpt_eng_grp_has_eng_type(grp, SE_TYPES) &&
		    !cpt_eng_grp_has_eng_type(grp, IE_TYPES) &&
		    !cpt_eng_grp_has_eng_type(grp, AE_TYPES)) {
			crypto_eng_grp = i;
			break;
		}
	}

	if (cptpf->crypto_eng_grp == crypto_eng_grp)
		return;
	cptpf_send_crypto_eng_grp_msg(cptpf, crypto_eng_grp);
}

int cpt9x_disable_all_cores(struct cptpf_dev *cptpf)
{
	int timeout = 10, ret = 0;
	int i, busy, total_cores;
	u64 reg;

	total_cores = cptpf->eng_grps.avail.max_se_cnt +
		      cptpf->eng_grps.avail.max_ie_cnt +
		      cptpf->eng_grps.avail.max_ae_cnt;

	/* Disengage the cores from groups */
	for (i = 0; i < total_cores; i++) {
		ret = cpt_add_write_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL2(i),
					   0x0);
		if (ret)
			goto error;

		cptpf->eng_grps.eng_ref_cnt[i] = 0;
	}
	ret = cpt_send_af_reg_requests(cptpf->pdev);
	if (ret)
		goto error;

	/* Wait for cores to become idle */
	do {
		busy = 0;
		usleep_range(10000, 20000);
		if (timeout-- < 0)
			return -EBUSY;

		for (i = 0; i < total_cores; i++) {
			ret = cpt_read_af_reg(cptpf->pdev, CPT_AF_EXEX_STS(i),
					      &reg);
			if (ret)
				goto error;

			if (reg & 0x1) {
				busy = 1;
				break;
			}
		}
	} while (busy);

	/* Disable the cores */
	for (i = 0; i < total_cores; i++) {
		ret = cpt_add_write_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL(i),
					   0x0);
		if (ret)
			goto error;
	}
	ret = cpt_send_af_reg_requests(cptpf->pdev);
	if (ret)
		goto error;
error:
	return ret;
}

struct ucode_ops cpt9x_get_ucode_ops(void)
{
	struct ucode_ops ops;

	ops.detach_and_disable_cores = cpt9x_detach_and_disable_cores;
	ops.attach_and_enable_cores = cpt9x_attach_and_enable_cores;
	ops.set_ucode_base = cpt9x_set_ucode_base;
	ops.print_engines_mask = cpt9x_print_engines_mask;
	ops.notify_group_change = cpt9x_notify_group_change;

	return ops;
}
