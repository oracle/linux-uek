/*
 * Copyright (C) 2018 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/interrupt.h>
#include <linux/module.h>

#include "bch_vf.h"
#include "bch_pf.h"

#define DRV_NAME	"thunder-bch_vf"
#define DRV_VERSION	"1.0"

/*
 * handles passed between client->VF->PF
 * bch_vf is held by cavium_nand, or a possible dmaengine client
 * bch_bp is ref to BF driver, whether VF sees it at this security level or not
 */
static void *bch_pf = (void *)(-EPROBE_DEFER);
#ifdef DEBUG
static int waits[3]; /*visible wait-loop count*/
module_param_array(waits, int, NULL, 0444);
#define WAIT_COUNT(n)	(void)(waits[n]++)
#else
static struct bch_vf *bch_vf = (void *)(-EPROBE_DEFER);
#define WAIT_COUNT(n)	(void)0
#endif

/**
 * Given a data block calculate the ecc data and fill in the response
 *
 * @param[in] block	8-byte aligned pointer to data block to calculate ECC
 * @param block_size	Size of block in bytes, must be a multiple of two.
 * @param bch_level	Number of errors that must be corrected.  The number of
 *			parity bytes is equal to ((15 * bch_level) + 7) / 8.
 *			Must be 4, 8, 16, 24, 32, 40, 48, 56, 60 or 64.
 * @param[out] ecc	8-byte aligned pointer to where ecc data should go
 * @param[in] resp	pointer to where responses will be written.
 *
 * @return Zero on success, negative on failure.
 */
int cavm_bch_encode(struct bch_vf *vf, dma_addr_t block, uint16_t block_size,
		    uint8_t bch_level, dma_addr_t ecc, dma_addr_t resp)
{
	union bch_cmd cmd;
	int rc;

	memset(&cmd, 0, sizeof(cmd));
	cmd.s.cword.ecc_gen = eg_gen;
	cmd.s.cword.ecc_level = bch_level;
	cmd.s.cword.size = block_size;

	cmd.s.oword.ptr = ecc;
	cmd.s.iword.ptr = block;
	cmd.s.rword.ptr = resp;
	rc = cavm_cmd_queue_write(QID_BCH, 1,
		sizeof(cmd) / sizeof(uint64_t), cmd.u);
	if (rc)
		return -1;

	cavm_bch_write_doorbell(1, vf);

	return 0;
}
EXPORT_SYMBOL(cavm_bch_encode);

/**
 * Given a data block and ecc data correct the data block
 *
 * @param[in] block_ecc_in	8-byte aligned pointer to data block with ECC
 *				data concatenated to the end to correct
 * @param block_size		Size of block in bytes, must be a multiple of
 *				two.
 * @param bch_level		Number of errors that must be corrected.  The
 *				number of parity bytes is equal to
 *				((15 * bch_level) + 7) / 8.
 *				Must be 4, 8, 16, 24, 32, 40, 48, 56, 60 or 64.
 * @param[out] block_out	8-byte aligned pointer to corrected data buffer.
 *				This should not be the same as block_ecc_in.
 * @param[in] resp		pointer to where responses will be written.
 *
 * @return Zero on success, negative on failure.
 */

int cavm_bch_decode(struct bch_vf *vf, dma_addr_t block_ecc_in,
		uint16_t block_size, uint8_t bch_level,
		dma_addr_t block_out, dma_addr_t resp)
{
	union bch_cmd cmd;
	int rc;

	memset(&cmd, 0, sizeof(cmd));
	cmd.s.cword.ecc_gen = eg_correct;
	cmd.s.cword.ecc_level = bch_level;
	cmd.s.cword.size = block_size;

	cmd.s.oword.ptr = block_out;
	cmd.s.iword.ptr = block_ecc_in;
	cmd.s.rword.ptr = resp;
	rc = cavm_cmd_queue_write(QID_BCH, 1,
		sizeof(cmd) / sizeof(uint64_t), cmd.u);
	if (rc)
		return -1;

	cavm_bch_write_doorbell(1, vf);
	return 0;
}
EXPORT_SYMBOL(cavm_bch_decode);

int cavm_bch_wait(struct bch_vf *vf, union bch_resp *resp, dma_addr_t handle)
{
	int max = 1000;

	rmb(); /* HW is updating *resp */
	WAIT_COUNT(0);
	while (!resp->s.done && max-- >= 0) {
		WAIT_COUNT(1);
		usleep_range(10, 20);
		rmb(); /* HW is updating *resp */
	}
	if (resp->s.done)
		return 0;
	WAIT_COUNT(2);
	return -ETIMEDOUT;
}
EXPORT_SYMBOL(cavm_bch_wait);

struct bch_q cavium_bch_q[QID_MAX];
EXPORT_SYMBOL(cavium_bch_q);

int cavm_cmd_queue_initialize(struct device *dev,
	int queue_id, int max_depth, int fpa_pool, int pool_size)
{
	/* some params are for later merge with CPT or cn83xx */
	struct bch_q *q = &cavium_bch_q[queue_id];
	union bch_cmd *qb;
	int chunk = max_depth + 1;
	int i, size;

	if ((unsigned int)queue_id >= QID_MAX)
		return -EINVAL;
	if (max_depth & chunk) /* must be 2^N - 1 */
		return -EINVAL;

	size = NQS * chunk * sizeof(u64);
	qb = dma_alloc_coherent(dev, size,
		&q->base_paddr,  GFP_KERNEL | GFP_DMA);

	if (!qb)
		return -ENOMEM;

	q->dev = dev;
	q->index = 0;
	q->max_depth = max_depth;
	q->pool_size_m1 = pool_size;
	q->base_vaddr = (u64 *)qb;

	for (i = 0; i < NQS; i++) {
		int inext = (i + 1) * chunk - 1;
		u64 *ixp = &qb->u[inext];
		int j = (i + 1) % NQS;
		int jnext = j * chunk;
		dma_addr_t jbase = q->base_paddr + jnext * sizeof(u64);
		*ixp = jbase;
	}

	return 0;
}
EXPORT_SYMBOL(cavm_cmd_queue_initialize);

int cavm_cmd_queue_shutdown(int queue_id)
{
	return 0;
}
EXPORT_SYMBOL(cavm_cmd_queue_shutdown);

static int bchvf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct bch_vf *vf;
	union bch_vqx_ctl ctl;
	union bch_vqx_cmd_buf cbuf;
	int err;

	vf = devm_kzalloc(dev, sizeof(*vf), GFP_KERNEL);
	if (!vf)
		return -ENOMEM;

	pci_set_drvdata(pdev, vf);
	vf->pdev = pdev;
	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto bchvf_err_disable_device;
	}
	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto release;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get 48-bit DMA for consistent allocations\n");
		goto release;
	}

	/* MAP PF's configuration registers */
	vf->reg_base = pcim_iomap(pdev, 0, 0);
	if (!vf->reg_base) {
		dev_err(dev, "Cannot map config register space, aborting\n");
		err = -ENOMEM;
		goto release;
	}

	err = cavm_cmd_queue_initialize(dev, QID_BCH, QDEPTH - 1, 0,
				sizeof(union bch_cmd) * QDEPTH);
	if (err) {
		dev_err(dev, "cavm_cmd_queue_initialize() failed");
		goto release;
	}

	ctl.u = readq(vf->reg_base + BCH_VQX_CTL(0));

	cbuf.u = 0;
	cbuf.s.ldwb = 1;
	cbuf.s.dfb = 1;
	cbuf.s.size = QDEPTH;
	writeq(cbuf.u, vf->reg_base + BCH_VQX_CMD_BUF(0));

	writeq(ctl.u, vf->reg_base + BCH_VQX_CTL(0));

	writeq(cavium_bch_q[QID_BCH].base_paddr,
		vf->reg_base + BCH_VQX_CMD_PTR(0));

	/* publish to _get/_put */
	bch_vf = vf;

	return 0;

release:
	pci_release_regions(pdev);
bchvf_err_disable_device:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	return err;
}

/* get/put async wrt probe, from VF */
void *cavm_bch_getv(void)
{
	if (!bch_vf)
		return NULL;
	bch_pf = cavm_bch_getp();
	if (IS_ERR_OR_NULL(bch_pf))
		return bch_pf;
	try_module_get(THIS_MODULE);
	return bch_vf;
}
EXPORT_SYMBOL(cavm_bch_getv);

void cavm_bch_putv(void *token)
{
	if (!IS_ERR_OR_NULL(token)) {
		module_put(THIS_MODULE);
		cavm_bch_putp(bch_pf);
	}
}
EXPORT_SYMBOL(cavm_bch_putv);

static void bchvf_remove(struct pci_dev *pdev)
{
	struct bch_vf *vf = pci_get_drvdata(pdev);

	if (!vf) {
		dev_err(&pdev->dev, "Invalid BCH-VF device\n");
		return;
	}

	pci_set_drvdata(pdev, NULL);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

/* Supported devices */
static const struct pci_device_id bchvf_id_table[] = {
	{PCI_VDEVICE(CAVIUM, BCH_PCI_VF_DEVICE_ID), 0},
	{ 0, }  /* end of table */
};

static struct pci_driver bchvf_pci_driver = {
	.name = DRV_NAME,
	.id_table = bchvf_id_table,
	.probe = bchvf_probe,
	.remove = bchvf_remove,
};

module_pci_driver(bchvf_pci_driver);

MODULE_AUTHOR("Cavium Inc");
MODULE_DESCRIPTION("Cavium Thunder BCH Virtual Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, bchvf_id_table);
