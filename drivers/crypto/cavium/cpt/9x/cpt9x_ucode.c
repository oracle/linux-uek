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
#include "cpt9x_lf.h"
#include "cpt9x_reqmgr.h"

#define CPT_LOADFVC_RLEN	8
#define CPT_LOADFVC_MAJOR_OP	0x01
#define CPT_LOADFVC_MINOR_OP	0x08

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

static int cptx_detach_and_disable_cores(struct engine_group_info *eng_grp,
					 struct cptpf_dev *cptpf,
					 struct bitmap bmap)
{
	int i, busy, ret = 0;
	int timeout = 10;
	u64 reg;

	/* Detach the cores from group */
	for_each_set_bit(i, bmap.bits, bmap.size) {
		ret = cpt_read_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL2(i), &reg);
		if (ret)
			goto error;

		if (reg & (1ull << eng_grp->idx)) {
			eng_grp->g->eng_ref_cnt[i]--;
			reg &= ~(1ull << eng_grp->idx);

			ret = cpt_write_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL2(i),
					       reg);
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

static int cpt9x_detach_and_disable_cores(struct engine_group_info *eng_grp,
					  void *obj)
{
	struct cptpf_dev *cptpf = obj;
	struct bitmap bmap;
	int ret;

	bmap = get_cores_bmap(&cptpf->pdev->dev, eng_grp);
	if (!bmap.size)
		return -EINVAL;

	if (cptpf->cpt1_implemented) {
		cptpf->blkaddr = BLKADDR_CPT1;
		ret = cptx_detach_and_disable_cores(eng_grp, cptpf, bmap);
		if (ret)
			return ret;
	}
	cptpf->blkaddr = BLKADDR_CPT0;
	ret = cptx_detach_and_disable_cores(eng_grp, cptpf, bmap);

	return ret;
}

static int cptx_set_ucode_base(struct engine_group_info *eng_grp,
			       struct cptpf_dev *cptpf)
{
	struct engines_reserved *engs;
	dma_addr_t dma_addr;
	int i, bit, ret;

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

static int cpt9x_set_ucode_base(struct engine_group_info *eng_grp, void *obj)
{
	struct cptpf_dev *cptpf = obj;
	int ret;

	if (cptpf->cpt1_implemented) {
		cptpf->blkaddr = BLKADDR_CPT1;
		ret = cptx_set_ucode_base(eng_grp, cptpf);
		if (ret)
			return ret;
	}
	cptpf->blkaddr = BLKADDR_CPT0;
	ret = cptx_set_ucode_base(eng_grp, cptpf);

	return ret;
}

static int cptx_attach_and_enable_cores(struct engine_group_info *eng_grp,
					struct cptpf_dev *cptpf,
					struct bitmap bmap)
{
	u64 reg;
	int i, ret = 0;

	/* Attach the cores to the group */
	for_each_set_bit(i, bmap.bits, bmap.size) {
		ret = cpt_read_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL2(i), &reg);
		if (ret)
			goto error;

		if (!(reg & (1ull << eng_grp->idx))) {
			eng_grp->g->eng_ref_cnt[i]++;
			reg |= 1ull << eng_grp->idx;

			ret = cpt_write_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL2(i),
					       reg);
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

static int cpt9x_attach_and_enable_cores(struct engine_group_info *eng_grp,
					 void *obj)
{
	struct cptpf_dev *cptpf = obj;
	struct bitmap bmap;
	int ret;

	bmap = get_cores_bmap(&cptpf->pdev->dev, eng_grp);
	if (!bmap.size)
		return -EINVAL;

	if (cptpf->cpt1_implemented) {
		cptpf->blkaddr = BLKADDR_CPT1;
		ret = cptx_attach_and_enable_cores(eng_grp, cptpf, bmap);
		if (ret)
			return ret;
	}
	cptpf->blkaddr = BLKADDR_CPT0;
	ret = cptx_attach_and_enable_cores(eng_grp, cptpf, bmap);

	return ret;
}

static void cpt9x_print_engines_mask(struct engine_group_info *eng_grp,
				void *obj, char *buf, int size)
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

static int cptx_disable_all_cores(struct cptpf_dev *cptpf, int total_cores)
{
	int timeout = 10, ret;
	int i, busy;
	u64 reg;

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

int cpt9x_disable_all_cores(struct cptpf_dev *cptpf)
{
	int total_cores, ret;

	total_cores = cptpf->eng_grps.avail.max_se_cnt +
		      cptpf->eng_grps.avail.max_ie_cnt +
		      cptpf->eng_grps.avail.max_ae_cnt;

	if (cptpf->cpt1_implemented) {
		cptpf->blkaddr = BLKADDR_CPT1;
		ret = cptx_disable_all_cores(cptpf, total_cores);
		if (ret)
			return ret;
	}
	cptpf->blkaddr = BLKADDR_CPT0;
	ret = cptx_disable_all_cores(cptpf, total_cores);

	return ret;
}

/*
 * Get CPT HW capabilities using LOAD_FVC operation.
 */
int cpt9x_discover_eng_capabilities(void *obj)
{
	struct cptpf_dev *cptpf = obj;
	struct cpt_iq_command iq_cmd;
	struct cpt_info_buffer info;
	union opcode_info opcode;
	union cpt_res_s *result;
	union cpt_inst_s inst;
	dma_addr_t rptr_baddr;
	struct pci_dev *pdev;
	u32 len, compl_rlen;
	int ret, etype;
	void *rptr;

	/*
	 * We don't get capabilities if it was already done
	 * (when user enabled VFs for the first time)
	 */
	if (cptpf->is_eng_caps_discovered)
		return 0;

	pdev = cptpf->pdev;
	cptpf->blkaddr = BLKADDR_CPT0;

	ret = cpt_create_eng_caps_discovery_grps(pdev, &cptpf->eng_grps);
	if (ret)
		goto delete_grps;

	ret = cptpf_lf_init(cptpf, ALL_ENG_GRPS_MASK, QUEUE_HI_PRIO, 1);
	if (ret)
		goto delete_grps;

	compl_rlen = ALIGN(sizeof(union cpt_res_s), ARCH_DMA_MINALIGN);
	len = compl_rlen + CPT_LOADFVC_RLEN;

	result = kzalloc(len, GFP_KERNEL);
	if (!result) {
		ret = -ENOMEM;
		goto lf_cleanup;
	}
	rptr_baddr = dma_map_single(&pdev->dev, (void *)result, len,
				    DMA_BIDIRECTIONAL);
	if (dma_mapping_error(&pdev->dev, rptr_baddr)) {
		dev_err(&pdev->dev, "DMA mapping failed\n");
		ret = -EFAULT;
		goto free_result;
	}
	info.comp_baddr = rptr_baddr;
	rptr = (u8 *)result + compl_rlen;

	/* Fill in the command */
	opcode.s.major = CPT_LOADFVC_MAJOR_OP;
	opcode.s.minor = CPT_LOADFVC_MINOR_OP;

	iq_cmd.cmd.u64 = 0;
	iq_cmd.cmd.s.opcode = cpu_to_be16(opcode.flags);

	/* 64-bit swap for microcode data reads, not needed for addresses */
	cpu_to_be64s(&iq_cmd.cmd.u64);
	iq_cmd.dptr = 0;
	iq_cmd.rptr = rptr_baddr + compl_rlen;
	iq_cmd.cptr.u64 = 0;

	for (etype = 1; etype < CPT_MAX_ENG_TYPES; etype++) {
		result->s9x.compcode = COMPLETION_CODE_INIT;
		iq_cmd.cptr.s.grp = cpt_get_eng_caps_discovery_grp(
						&cptpf->eng_grps, etype);
		cpt9x_fill_inst(&inst, &info, &iq_cmd);
		cpt9x_send_cmd(&inst, 1, &cptpf->lfs.lf[0]);

		while (result->s9x.compcode == COMPLETION_CODE_INIT)
			cpu_relax();

		cptpf->eng_caps[etype].u = be64_to_cpup(rptr);
	}
	dma_unmap_single(&pdev->dev, rptr_baddr, len, DMA_BIDIRECTIONAL);
	cptpf->is_eng_caps_discovered = true;
free_result:
	kzfree(result);
lf_cleanup:
	cptpf_lf_cleanup(&cptpf->lfs);
delete_grps:
	cpt_delete_eng_caps_discovery_grps(pdev, &cptpf->eng_grps);

	return ret;
}

struct ucode_ops cpt9x_get_ucode_ops(void)
{
	struct ucode_ops ops;

	ops.detach_and_disable_cores = cpt9x_detach_and_disable_cores;
	ops.attach_and_enable_cores = cpt9x_attach_and_enable_cores;
	ops.set_ucode_base = cpt9x_set_ucode_base;
	ops.print_engines_mask = cpt9x_print_engines_mask;
	ops.discover_eng_capabilities = cpt9x_discover_eng_capabilities;

	return ops;
}
