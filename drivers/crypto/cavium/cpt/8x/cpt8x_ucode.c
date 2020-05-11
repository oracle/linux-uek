// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt_ucode.h"
#include "cpt8x_pf.h"

static struct bitmap get_cores_bmap(struct device *dev,
				    struct engine_group_info *eng_grp)
{
	struct bitmap bmap = { 0 };
	bool found = false;
	int i;

	if (eng_grp->g->engs_num > CPT_8X_MAX_ENGINES) {
		dev_err(dev, "8X plat unsupported number of engines %d",
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

static int cpt8x_detach_and_disable_cores(struct engine_group_info *eng_grp,
					  void *obj)
{
	struct cpt_device *cpt = (struct cpt_device *) obj;
	struct bitmap bmap = { 0 };
	int timeout = 10;
	int i, busy;
	u64 reg;

	bmap = get_cores_bmap(&cpt->pdev->dev, eng_grp);
	if (!bmap.size)
		return -EINVAL;

	/* Detach the cores from group */
	reg = readq(cpt->reg_base + CPT_PF_GX_EN(eng_grp->idx));
	for_each_set_bit(i, bmap.bits, bmap.size) {
		if (reg & (1ull << i)) {
			eng_grp->g->eng_ref_cnt[i]--;
			reg &= ~(1ull << i);
		}
	}
	writeq(reg, cpt->reg_base + CPT_PF_GX_EN(eng_grp->idx));

	/* Wait for cores to become idle */
	do {
		busy = 0;
		usleep_range(10000, 20000);
		if (timeout-- < 0)
			return -EBUSY;

		reg = readq(cpt->reg_base + CPT_PF_EXEC_BUSY);
		for_each_set_bit(i, bmap.bits, bmap.size)
			if (reg & (1ull << i)) {
				busy = 1;
				break;
			}
	} while (busy);

	/* Disable the cores only if they are not used anymore */
	reg = readq(cpt->reg_base + CPT_PF_EXE_CTL);
	for_each_set_bit(i, bmap.bits, bmap.size)
		if (!eng_grp->g->eng_ref_cnt[i])
			reg &= ~(1ull << i);
	writeq(reg, cpt->reg_base + CPT_PF_EXE_CTL);

	return 0;
}

static int cpt8x_set_ucode_base(struct engine_group_info *eng_grp, void *obj)
{
	struct cpt_device *cpt = (struct cpt_device *) obj;
	dma_addr_t dma_addr;
	struct bitmap bmap;
	int i;

	bmap = get_cores_bmap(&cpt->pdev->dev, eng_grp);
	if (!bmap.size)
		return -EINVAL;

	if (eng_grp->mirror.is_ena)
		dma_addr =
		       eng_grp->g->grp[eng_grp->mirror.idx].ucode[0].align_dma;
	else
		dma_addr = eng_grp->ucode[0].align_dma;

	/* Set UCODE_BASE only for the cores which are not used,
	 * other cores should have already valid UCODE_BASE set
	 */
	for_each_set_bit(i, bmap.bits, bmap.size)
		if (!eng_grp->g->eng_ref_cnt[i])
			writeq((u64) dma_addr, cpt->reg_base +
				CPT_PF_ENGX_UCODE_BASE(i));
	return 0;
}

static int cpt8x_attach_and_enable_cores(struct engine_group_info *eng_grp,
					 void *obj)
{
	struct cpt_device *cpt = (struct cpt_device *) obj;
	struct bitmap bmap;
	u64 reg;
	int i;

	bmap = get_cores_bmap(&cpt->pdev->dev, eng_grp);
	if (!bmap.size)
		return -EINVAL;

	/* Attach the cores to the group */
	reg = readq(cpt->reg_base + CPT_PF_GX_EN(eng_grp->idx));
	for_each_set_bit(i, bmap.bits, bmap.size) {
		if (!(reg & (1ull << i))) {
			eng_grp->g->eng_ref_cnt[i]++;
			reg |= 1ull << i;
		}
	}
	writeq(reg, cpt->reg_base + CPT_PF_GX_EN(eng_grp->idx));

	/* Enable the cores */
	reg = readq(cpt->reg_base + CPT_PF_EXE_CTL);
	for_each_set_bit(i, bmap.bits, bmap.size)
		reg |= 1ull << i;
	writeq(reg, cpt->reg_base + CPT_PF_EXE_CTL);

	return 0;
}

static void cpt8x_print_engines_mask(struct engine_group_info *eng_grp,
				     void *obj, char *buf, int size)
{
	struct cpt_device *cpt = (struct cpt_device *) obj;
	struct bitmap bmap;
	u32 mask[2];

	bmap = get_cores_bmap(&cpt->pdev->dev, eng_grp);
	if (!bmap.size) {
		scnprintf(buf, size, "unknown");
		return;
	}

	bitmap_to_u32array(mask, 2, bmap.bits, bmap.size);
	scnprintf(buf, size, "%8.8x %8.8x", mask[1], mask[0]);
}

void cpt8x_disable_all_cores(struct cpt_device *cpt)
{
	u64 reg;
	int grp, timeout = 100;

	/* Disengage the cores from groups */
	for (grp = 0; grp < CPT_MAX_ENGINE_GROUPS; grp++) {
		writeq(0, cpt->reg_base + CPT_PF_GX_EN(grp));
		udelay(CSR_DELAY);
	}

	reg = readq(cpt->reg_base + CPT_PF_EXEC_BUSY);
	while (reg) {
		udelay(CSR_DELAY);
		reg = readq(cpt->reg_base + CPT_PF_EXEC_BUSY);
		if (timeout--) {
			dev_warn(&cpt->pdev->dev, "Cores still busy");
			break;
		}
	}

	/* Disable the cores */
	writeq(0, cpt->reg_base + CPT_PF_EXE_CTL);
}

struct ucode_ops cpt8x_get_ucode_ops(void)
{
	struct ucode_ops ops;

	ops.detach_and_disable_cores = cpt8x_detach_and_disable_cores;
	ops.attach_and_enable_cores = cpt8x_attach_and_enable_cores;
	ops.set_ucode_base = cpt8x_set_ucode_base;
	ops.print_engines_mask = cpt8x_print_engines_mask;

	return ops;
}
