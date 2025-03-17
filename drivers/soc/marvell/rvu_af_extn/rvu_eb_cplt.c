// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/bitfield.h>
#include <linux/pci.h>
#include "rvu.h"
#include "rvu_reg.h"
#include "rvu_eblock.h"
#include "rvu_cplt_mbox.h"

#define LMAC_BMAP_MASK 0xff

struct cplt_drvdata {
	int res_idx;
};

#define CPLT_OFFSET(x, y)	((((x) * (rvu->fwdata->num_rpm_in_chiplet)) \
					+ (y)) * (rvu->hw->lmac_per_cplt))

static void rvu_cplt_unregister_interrupts_block(struct rvu_block *block,
						 void *data)
{
	(void)block;
	(void)data;
}

static int rvu_cplt_register_interrupts_block(struct rvu_block *block,
					      void *data)
{
	(void)block;
	(void)data;

	return 0;
}

static u16 cpltlmac_id_map(u8 cplt_id, u8 rpm_id, u8 lmac_id)
{
	return (((cplt_id & 0xF) << 12) | ((rpm_id & 0xF) << 8) |
		(lmac_id & 0xFF));
}

static void __rvu_map_cplt_lmac_pf(struct rvu *rvu, int pf, int cplt,
				   int rpm, int lmac)
{
	rvu->cplt_rpm->pf2cpltlmac_map[pf] = cpltlmac_id_map(cplt, rpm, lmac);
	rvu->cplt_rpm->cpltlmac2pf_map[CPLT_OFFSET((cplt - 1), rpm) + lmac] =
		BIT_ULL(pf);

	rvu->cplt_rpm->cplt_mapped_pfs++;
	set_bit(pf, &rvu->cplt_rpm->cplt_pf_notify_bmap);
}

static int cplt_get_lmacid(struct rvu *rvu, int cplt, int iter)
{
	return iter;
}

unsigned long cplt_prepare_lmac_bmap(struct rvu *rvu, u8 max_lmac, int n_cplts)
{
	unsigned long lmac_bmap = 0;
	u16 lmac_exist;
	u8 node, rpm;
	u8 cnt = 0;

	/* Excluding compute chiplet */
	for (node = 1; node <= n_cplts; node++) {
		for (rpm = 0; rpm < rvu->fwdata->num_rpm_in_chiplet; rpm++) {
			lmac_exist = rvu->fwdata->csr_rpmx_cmr_num_lmacs
				[node][rpm] & LMAC_BMAP_MASK;
			if (lmac_exist) {
				lmac_bmap |= (((uint64_t)lmac_exist) <<
					      (cnt * max_lmac));
			}
			cnt++;
		}
	}

	return lmac_bmap;
}

static int rvu_map_cplt_rpm_lmac_pf(struct rvu *rvu)
{
	int cplt, lmac, iter, lmac_cnt;
	int pf = PF_CPLTMAP_BASE;
	unsigned long lmac_bmap;
	u32 num_rpm_in_chiplet;
	u8 lmac_in_n1_rpm0;
	u8 cplt_cnt_max;
	u64 rpmx_const;
	int size;

	cplt_cnt_max = rvu->cplt_rpm->cplt_cnt_max;
	num_rpm_in_chiplet = rvu->fwdata->num_rpm_in_chiplet;

	if (!num_rpm_in_chiplet)
		return -EINVAL;

	/* Assume all RPMs has same max number of LMACs */
	lmac_in_n1_rpm0 = FIELD_GET(GENMASK_ULL(31, 24),
				    rvu->fwdata->csr_rpmx_const[1][0]);

	rvu->hw->lmac_per_cplt = lmac_in_n1_rpm0;
	/* Alloc map table */
	size = (cplt_cnt_max * num_rpm_in_chiplet *
		rvu->hw->lmac_per_cplt) * sizeof(u16);
	rvu->cplt_rpm->pf2cpltlmac_map = devm_kmalloc(rvu->dev, size,
						      GFP_KERNEL);
	if (!rvu->cplt_rpm->pf2cpltlmac_map)
		return -ENOMEM;

	/* Initialize all entries with an invalid cplt and lmac id */
	memset(rvu->cplt_rpm->pf2cpltlmac_map, 0xFFFF, size);

	/* Reverse map table */
	rvu->cplt_rpm->cpltlmac2pf_map =
		devm_kzalloc(rvu->dev,
			     cplt_cnt_max * num_rpm_in_chiplet *
			     rvu->hw->lmac_per_cplt * sizeof(u64),
			     GFP_KERNEL);
	if (!rvu->cplt_rpm->cpltlmac2pf_map)
		return -ENOMEM;

	rvu->cplt_rpm->cplt_mapped_pfs = 0;
	lmac_bmap = cplt_prepare_lmac_bmap(rvu, lmac_in_n1_rpm0, cplt_cnt_max);
	rvu->cplt_rpm->lmac_bmap = lmac_bmap;
	for (cplt = 1; cplt <= cplt_cnt_max; cplt++) {
		for (int rpm = 0; rpm < num_rpm_in_chiplet; rpm++) {
			rpmx_const = rvu->fwdata->csr_rpmx_const[cplt][rpm];
			lmac_cnt = FIELD_GET(GENMASK_ULL(31, 24), rpmx_const);
			for_each_set_bit(iter, &lmac_bmap, lmac_cnt) {
				lmac = cplt_get_lmacid(rvu, cplt, iter);
				__rvu_map_cplt_lmac_pf(rvu, pf, cplt, rpm,
						       lmac);
				pf++;
			}
			lmac_bmap >>= lmac_in_n1_rpm0;
		}
	}
	return 0;
}

static int rvu_cplt_init(struct rvu *rvu)
{
	struct rvu_cplt_rpm *cplt_rpm_data;
	int err;

	if (!rvu->fwdata)
		return -EINVAL;

	cplt_rpm_data = kzalloc(sizeof(*cplt_rpm_data), GFP_KERNEL);
	if (!cplt_rpm_data)
		return -ENOMEM;

	rvu->cplt_rpm = cplt_rpm_data;
	if (!rvu->fwdata->csr_rpmx_cmr_num_lmacs[2][0])
		rvu->cplt_rpm->cplt_cnt_max = 1;
	else
		rvu->cplt_rpm->cplt_cnt_max = NODE_MAX - 1;

	cplt_rpm_data->rvu = rvu;

	/* Map CPLT LMAC interfaces to CPLT PFs */
	err = rvu_map_cplt_rpm_lmac_pf(rvu);
	if (err)
		return err;

	rvu->cplt_rpm->ready = 0;

	mutex_init(&rvu->cplt_rpm->cplt_cfg_lock);

	return 0;
}

static int cplt_exit(struct rvu *rvu)
{
	return 0;
}

static int rvu_cplt_init_block(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;

	if (!data)
		return -EINVAL;

	return rvu_cplt_init(rvu);
}

static void rvu_cplt_freemem_block(struct rvu_block *block, void *data)
{
	(void)block;
	(void)data;

	/* Free up resources related to CPLT etc.. */
}

static int rvu_setup_cplt_hw_resource(struct rvu_block *block, void *data)
{
	struct cplt_drvdata *drvdata = data;
	struct rvu *rvu = block->rvu;
	struct rvu_hwinfo *hw = rvu->hw;
	int blkid, blkaddr;

	blkid = drvdata->res_idx;
	blkaddr = blkid ? BLKADDR_RFOE1 : BLKADDR_RFOE0;
	block = &hw->block[blkaddr];

	if (!block->implemented)
		return 0;
	block->addr = blkaddr;
	block->type = BLKTYPE_RFOE;
	block->rvu = rvu;
	sprintf(block->name, "RFOE%d", blkid);
	block->multislot = true;

	return 0;
}

static int rvu_cplt_mbox_handler(struct otx2_mbox *mbox, int devid,
				 struct mbox_msghdr *req)
{
	(void)mbox;
	(void)devid;
	(void)req;

	return 0;
}

static void *rvu_cplt_probe(struct rvu *rvu, int blkaddr)
{
	struct cplt_drvdata *data;
	static int res_idx;

	switch (blkaddr) {
	case BLKADDR_RFOE0:
		data = devm_kzalloc(rvu->dev, sizeof(struct cplt_drvdata),
				    GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);
		data->res_idx = res_idx++;
		break;
	default:
		data = NULL;
	}

	return data;
}

static void rvu_cplt_remove(struct rvu_block *hwblock, void *data)
{
	cplt_exit(hwblock->rvu);
	devm_kfree(hwblock->rvu->dev, data);
}

struct mbox_op cplt_mbox_op = {
	.start = 0xD000,
	.end = 0xDFFF,
	.handler = rvu_cplt_mbox_handler,
};

static struct rvu_eblock_driver_ops cplt_ops = {
	.probe	= rvu_cplt_probe,
	.remove	= rvu_cplt_remove,
	.init	= rvu_cplt_init_block,
	.setup	= rvu_setup_cplt_hw_resource,
	.free	= rvu_cplt_freemem_block,
	.register_interrupt = rvu_cplt_register_interrupts_block,
	.unregister_interrupt = rvu_cplt_unregister_interrupts_block,
	.mbox_op = &cplt_mbox_op,
};

void cplt_eb_module_init(void)
{
	rvu_eblock_register_driver(&cplt_ops);
}

void cplt_eb_module_exit(void)
{
	rvu_eblock_unregister_driver(&cplt_ops);
}
