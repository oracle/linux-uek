/*
 * Copyright (c) 2013, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_elog.c: Log over PCIe support for firmware
 *   TBD: Remove
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include "sif_dev.h"
#include "sif_elog.h"
#include "sif_query.h"

static int sif_elog_wait(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	int ret;
	struct sif_eps *es = &sdev->es[eps_num];
	struct psif_epsc_csr_rsp resp;
	struct psif_epsc_csr_req req;

	init_completion(&es->logdev_more_log);

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_LOG_REQ_NOTIFY;
	ret = sif_eps_wr(sdev, eps_num, &req, &resp);
	if (ret || resp.status != EPSC_SUCCESS)
		return -EINVAL;

	/* data contains the last byte written by eps at the moment
	 * where the notify call was processed.
	 */

	if (resp.data > be64_to_cpu(es->data->log.consume_offset))
		return 0;

	ret = wait_for_completion_interruptible(&es->logdev_more_log);

	return ret;
}

void sif_elog_intr(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	complete(&sdev->es[eps_num].logdev_more_log);
}

static int sif_elog_open(struct inode *inode, struct file *f)
{
	struct sif_eps *es = container_of(f->f_op, struct sif_eps, logdev_ops);
	int ok = atomic_add_unless(&es->logdev_use, -1, 0);

	if (!ok)
		return -EBUSY;

	return 0;
}


static int sif_elog_release(struct inode *inode, struct file *f)
{
	struct sif_eps *es = container_of(f->f_op, struct sif_eps, logdev_ops);

	atomic_inc(&es->logdev_use);
	return 0;
}


static ssize_t sif_elog_read(struct file *f, char __user *user, size_t size, loff_t *offset)
{
	int stat;
	struct sif_eps *es = container_of(f->f_op, struct sif_eps, logdev_ops);
	struct sif_dev *sdev = es->sdev;
	struct psif_epsc_log_stat ls;
	u64 start_off, end_off, sz, len, start;
restart:
	if (eps_version_ge(es, 0, 31))
		copy_conv_to_sw(&ls, &es->data->log, sizeof(ls));
	else
		memcpy(&ls, &es->data->log, sizeof(ls));

	start_off = ls.consume_offset;
	end_off = ls.produce_offset;
	sz = ls.size;

	len = min((u64)size, end_off - start_off);
	start = start_off % sz;

	if (start + len > sz)
		len = sz - start;

	if (len == 0) {
		stat = sif_elog_wait(sdev, es->eps_num);
		if (stat < 0)
			return stat;
		goto restart;
	}

	sif_log(sdev, SIF_EPS, " requested sz %lx, off %llx. Queue: produce %llx, consume %llx - got %llx",
		size, *offset, ls.produce_offset, ls.consume_offset,
		len);

	if (copy_to_user(user, &es->data->log_data_area[start], len))
		return -EIO;

	ls.consume_offset += len;
	es->data->log.consume_offset = cpu_to_be64(ls.consume_offset);
	return len;
}



int sif_elog_init(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	struct sif_eps *es = &sdev->es[eps_num];
	struct miscdevice *logdev = &es->logdev;
	struct file_operations *logdev_ops = &es->logdev_ops;
	struct pci_dev *pdev = sdev->pdev;

	snprintf(es->logdevname, MAX_LOGDEVNAME, "infiniband/sif_eps%s/%02x:%02x.%x",
		eps_suffix(sdev, eps_num), pdev->bus->number,
		PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	logdev_ops->read = sif_elog_read;
	logdev_ops->open = sif_elog_open;
	logdev_ops->release = sif_elog_release;
	logdev_ops->owner = THIS_MODULE;
	logdev->name = es->logdevname;
	logdev->minor = MISC_DYNAMIC_MINOR;
	logdev->fops = &es->logdev_ops;
	atomic_set(&es->logdev_use, 1);
	return misc_register(logdev);
}

void sif_elog_deinit(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	misc_deregister(&sdev->es[eps_num].logdev);
}
