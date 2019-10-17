// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX and OcteonTX2 ZIP Virtual Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "zip_vf_deflate.h"
#include "zip_vf_debugfs.h"

static struct zip_vf_device *vf_devs[ZIP_MAX_VFS];
static struct class *vf_class;

static const struct pci_device_id zip_vf_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX_ZIPVF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_ZIPVF) },
	{ 0, }
};

static struct zip_vf_device *zip_vf_alloc_device(struct pci_dev *pdev)
{
	struct zip_vf_device *vf = NULL;
	int i;

	for (i = 0; i < ZIP_MAX_VFS; i++) {
		if (!vf_devs[i])
			break;
	}

	vf = devm_kzalloc(&pdev->dev, sizeof(*vf), GFP_KERNEL);
	if (!vf)
		return NULL;

	vf_devs[i] = vf;
	vf->index = i;

	return vf;
}

struct zip_vf_device *zip_vf_get_device_by_id(int id)
{
	if (id < ZIP_MAX_VFS)
		return vf_devs[id];
	return NULL;
}

s32 zip_vf_copy_from_user(struct zip_vf_state *s,
			  struct zip_operation *ops)
{
	if (copy_from_user((u8 *)s->input.dbuf, (u8 *)ops->history,
						ops->history_len))
		return ZIP_ERROR;

	if (copy_from_user((u8 *)s->input.dbuf + ops->history_len,
		(u8 *)ops->input, ops->input_len))
		return ZIP_ERROR;

	return 0;
}

s32 zip_vf_copy_to_user(struct zip_vf_state *s, struct zip_operation *ops)
{
	u64 bw; /* Bytes written */

	bw = s->result.rbuf->s.totalbyteswritten;
	if (copy_to_user((u8 *)ops->output, (u8 *)s->output.dbuf, bw))
		return ZIP_ERROR;

	return 0;
}

long zip_vf_unlocked_ioctl(struct file *file, u32 cmd, unsigned long arg)
{
	struct device *dev = NULL;
	struct zip_vf_device *vf = NULL;
	struct zip_vf_state s;
	struct zip_operation ops;
	u64 ret;

	vf = zip_vf_get_device_by_id(smp_processor_id() % 8);
	dev = &vf->pdev->dev;

	memset(&s, 0, sizeof(struct zip_vf_state));
	memset(&ops, 0, sizeof(struct zip_operation));

	ret = copy_from_user((u8 *)&ops, (u8 *)arg,
			     sizeof(struct zip_operation));
	if (ret) {
		dev_err(dev, "Failed to copy data from user");
		return ZIP_ERROR;
	}

	switch (cmd) {
	case CVM_ZIP_DRV_IOCTL_DEFLATE:
		ret = zip_vf_deflate_bufs_alloc(vf, &s, &ops);
		if (ret) {
			dev_err(dev, "Failed to create buffers\n");
			goto zip_error;
		}
		ret = zip_vf_copy_from_user(&s, &ops);
		if (ret) {
			dev_err(dev, "Failed to copy data from user\n");
			goto zip_error;
		}

		ret = zip_vf_deflate(vf, &s, &ops);
		if (ret) {
			dev_err(dev, "Failed to deflate data\n");
			goto zip_error;
		}

		ret = zip_vf_copy_to_user(&s, &ops);
		if (ret) {
			dev_err(dev, "Failed to copy data to user\n");
			goto zip_error;
		}

		zip_vf_deflate_bufs_free(vf, &s);
		break;
zip_error:
		zip_vf_deflate_bufs_free(vf, &s);
		return ret;

	/*
	 * To cleanup driver resources in case of errors in library or any
	 * signals from user (SIGTERM or SIGINT).
	 */
	case CVM_ZIP_DRV_IOCTL_CLEANUP:
		/* Free buffers if not NULL */
		zip_vf_deflate_bufs_free(vf, &s);
		return 0;

	default:
		dev_err(dev, "Wrong ioctl command %d\n", cmd);
		return ZIP_ERROR;
	}

	/* Send back the updated zip_operations to user-space */
	ret = copy_to_user((u8 *)arg, (u8 *)&ops,
			sizeof(struct zip_operation));
	if (ret) {
		dev_err(dev, "Failed to copy data to user\n");
		return ret;
	}

	return 0;
}

void zip_vf_load_instr(struct zip_vf_device *vf, union zip_inst_s *instr)
{
	union zip_vqx_doorbell dbell;
	u32 consumed;

	spin_lock(&vf->iq.lock);

	memcpy((u8 *)vf->iq.sw_head, (u8 *)instr, sizeof(*instr));

	/*
	 * Move sw_head forward OR wrap it back to start of virt_addr if
	 * CMD_QBUF is full. This will determine where the next instruction is
	 * written.
	 * Command buffer has 8 bytes at the end to store the address of the
	 * next command buffer.
	 */
	consumed = (vf->iq.sw_head - vf->sbuf.virt_addr);
	if ((consumed + (sizeof(*instr) / 8)) == ((ZIP_CMD_QBUF_SIZE / 8) - 1))
		vf->iq.sw_head = vf->sbuf.virt_addr;
	else
		vf->iq.sw_head += (sizeof(*instr) / 8);

	spin_unlock(&vf->iq.lock);

	dbell.u = 0ull;
	dbell.s.dbell_cnt = 1;

	zip_vf_reg_write(vf, ZIP_VF_VQX_DOORBELL, dbell.u);
}

static int zip_vf_init(struct zip_vf_device *vf)
{
	union zip_vqx_sbuf_addr sbuf_addr;
	union zip_vqx_ena que_ena;
	union zip_nptr_s ncp;
	u64 *ncb_ptr = NULL;

	memset(&vf->iq, 0, sizeof(struct zip_vf_iq));

	spin_lock_init(&vf->iq.lock);

	vf->sbuf.virt_addr = (u64 *)dmam_alloc_coherent(&vf->pdev->dev,
						    ZIP_CMD_QBUF_SIZE,
						    &vf->sbuf.dma_addr,
						    GFP_KERNEL | __GFP_ZERO);
	if (!vf->sbuf.virt_addr)
		return -ENOMEM;

	vf->iq.sw_head = vf->sbuf.virt_addr;

	sbuf_addr.u = 0ull;
	sbuf_addr.s.ptr = vf->sbuf.dma_addr >> 7;

	zip_vf_reg_write(vf, ZIP_VF_VQX_SBUF_ADDR, sbuf_addr.u);

	que_ena.u = 0ull;
	que_ena.s.ena = 1;
	zip_vf_reg_write(vf, ZIP_VF_VQX_ENA, que_ena.u);

	/* Update Next-Chunk Buffer Ptr */
	ncb_ptr = vf->iq.sw_head + (ZIP_CMD_QBUF_SIZE / 8) - 1;
	ncp.u = 0ull;
	ncp.s.addr = PTR_ALIGN(vf->sbuf.dma_addr, 128);
	*ncb_ptr = ncp.u;

	return 0;
}

static int zip_vf_probe(struct pci_dev *pdev,
			const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct zip_vf_device *vf = NULL;
	int err;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device: %d\n", err);
		return err;
	}

	err = pcim_iomap_regions_request_all(pdev, 0x1, DRV_NAME);
	if (err) {
		dev_err(dev, "Failed to reserve PCI resources: 0x%x\n", err);
		return err;
	}

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Failed to set DMA mask: %d\n", err);
		return err;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Failed to set consistent DMA mask: %d\n", err);
		return err;
	}

	vf = zip_vf_alloc_device(pdev);
	if (!vf) {
		dev_err(dev, "Failed to allocate memory\n");
		return err;
	}

	pci_set_drvdata(pdev, vf);
	vf->pdev = pdev;
	vf->reg_base = pcim_iomap_table(pdev)[0];
	if (!vf->reg_base) {
		dev_err(dev, "Failed to map PCI resource\n");
		err = -ENOMEM;
		goto remove_zip_vf_from_list;
	}

	err = zip_vf_init(vf);
	if (err) {
		dev_err(dev, "Failed to initialize ZIP VF\n");
		goto remove_zip_vf_from_list;
	}

	pci_set_dev_assigned(pdev);

	return 0;

remove_zip_vf_from_list:
	vf_devs[vf->index] = NULL;
	pci_set_drvdata(pdev, NULL);

	return err;
}

static void zip_vf_remove(struct pci_dev *pdev)
{
	struct zip_vf_device *vf = pci_get_drvdata(pdev);

	pci_set_drvdata(pdev, NULL);
	pci_clear_dev_assigned(pdev);

	vf_devs[vf->index] = NULL;
}

static const struct file_operations zip_vf_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = zip_vf_unlocked_ioctl,
};

static struct pci_driver zip_vf_driver = {
	.name        = DRV_NAME,
	.id_table    = zip_vf_id_table,
	.probe       = zip_vf_probe,
	.remove      = zip_vf_remove,
};

static int __init zip_vf_init_module(void)
{
	dev_t devt;

	vf_class = class_create(THIS_MODULE, "octeontx_devices");
	devt = MKDEV(DEVICE_MAJOR, 0);

	if (!device_create(vf_class, NULL, devt, NULL, DRV_NAME))
		goto destroy_device_class;

	if (register_chrdev(DEVICE_MAJOR, DRV_NAME, &zip_vf_fops) < 0)
		goto destroy_device_file;

	if (pci_register_driver(&zip_vf_driver) < 0)
		goto unregister_chrdev;

	if (zip_vf_debugfs_init() < 0)
		goto unregister_driver;

	return 0;

unregister_driver:
	pci_unregister_driver(&zip_vf_driver);
unregister_chrdev:
	unregister_chrdev(DEVICE_MAJOR, DRV_NAME);
destroy_device_file:
	device_destroy(vf_class, MKDEV(DEVICE_MAJOR, 0));
destroy_device_class:
	class_destroy(vf_class);

	return -1;
}

static void __exit zip_vf_cleanup_module(void)
{
	zip_vf_debugfs_exit();
	device_destroy(vf_class, MKDEV(DEVICE_MAJOR, 0));
	class_destroy(vf_class);
	unregister_chrdev(DEVICE_MAJOR, DRV_NAME);
	pci_unregister_driver(&zip_vf_driver);
}

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX ZIP Virtual Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, zip_vf_id_table);

module_init(zip_vf_init_module);
module_exit(zip_vf_cleanup_module);
