/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_debug.c: Use of debugfs for dumping internal data structure info
 */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include "sif_dev.h"
#include "sif_debug.h"
#include "sif_base.h"
#include "sif_query.h"
#include "sif_qp.h"
#include "sif_defs.h"
#include "sif_r3.h"

/* A 'reference' element to identify each table type
 */
struct sif_dfs_ref {
	struct sif_dev *sdev;
	bool is_eq;
	enum sif_tab_type type;
	sif_dfs_printer dfs_print;
};


/* Our private data within driver struct
 */
struct sif_dfs {
	struct dentry *root; /* The root of the debugfs tree, if set up (pci id name) */
	struct dentry *root_link; /* A symlink from ib device name to pci id name */
	struct dentry *raw_qp; /* Ref to directory with raw qp info, if set up */
	struct sif_dfs_ref sd[sif_tab_init_max];
	struct sif_dfs_ref sd_eq;
	struct sif_dfs_ref sd_irq_ch;
	struct sif_dfs_ref sd_ipoffload;
	struct sif_dfs_ref sd_wa_stats;
};

/* A simple iterator */

struct sif_dfs_iter {
	loff_t pos;   /* Current "virtual" offset */
	bool started; /* If header has been printed */
};


static void *sif_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct sif_dfs_iter *it = (struct sif_dfs_iter *) v;
	struct sif_dfs_ref *sd = (struct sif_dfs_ref *) s->private;
	struct sif_table *tp = &sd->sdev->ba[sd->type];

	++(*pos);
	*pos = sif_next_used(tp, *pos);
	sif_log(sd->sdev, SIF_DFS, "%lld -> %lld", it->pos, *pos);
	if (*pos < 0) {
		kfree(it);
		return NULL;
	}
	it->pos = *pos;
	return it;
}

static void *sif_seq_start(struct seq_file *s, loff_t *pos)
{
	struct sif_dfs_iter *it;
	struct sif_dfs_ref *sd = (struct sif_dfs_ref *) s->private;
	struct sif_table *tp = &sd->sdev->ba[sd->type];

	sif_log(sd->sdev, SIF_DFS, " at %lld", *pos);
	*pos = sif_next_used(tp, *pos);
	if (*pos < 0)
		return NULL;
	it = kmalloc(sizeof(struct sif_dfs_iter), GFP_KERNEL);
	if (!it)
		return NULL;
	it->pos = *pos;
	it->started = false;
	return it;
}

static void sif_seq_stop(struct seq_file *s, void *v)
{
	struct sif_dfs_ref *sd = (struct sif_dfs_ref *) s->private;

	if (v) {
		sif_log(sd->sdev, SIF_DFS, "sif_seq_stop at %p", v);
		kfree(v);
	}
	sif_log(sd->sdev, SIF_DFS, " [at end]");
}

static int sif_seq_show(struct seq_file *s, void *v)
{
	struct sif_dfs_iter *it = (struct sif_dfs_iter *) v;
	struct sif_dfs_ref *sd = (struct sif_dfs_ref *) s->private;

	sif_log(sd->sdev, SIF_DFS, "%lld", it->pos);
	if (!it->pos || !it->started) {
		if (!sd->is_eq)
			seq_printf(s, "# %s state (entries %d, extent %d):\n",
				sif_table_name(sd->type),
				sd->sdev->ba[sd->type].entry_cnt,
				sd->sdev->ba[sd->type].ext_sz);
		if (sd->dfs_print)
			sd->dfs_print(s, sd->sdev, -1);
		else
			seq_puts(s, "# Index\tValues\n");
		it->started = true;
	}
	if (sd->dfs_print)
		sd->dfs_print(s, sd->sdev, it->pos);
	else
		seq_printf(s, "%lld\n", it->pos);
	return 0;
}


static const struct seq_operations seq_ops = {
	.start = sif_seq_start,
	.next  = sif_seq_next,
	.stop  = sif_seq_stop,
	.show  = sif_seq_show
};


/* Specific support for eq reporting which has slightly different logic: */
static void *sif_eq_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct sif_dfs_iter *it = (struct sif_dfs_iter *) v;
	struct sif_dfs_ref *sd = (struct sif_dfs_ref *) s->private;
	struct sif_dev *sdev = sd->sdev;
	u32 cnt = sdev->es[sdev->mbox_epsc].eqs.cnt;

	if (*pos > cnt - 2)
		*pos = -1;
	else
		++(*pos);

	sif_log(sdev, SIF_DFS, "%lld -> %lld", it->pos, *pos);
	if (*pos < 0) {
		kfree(it);
		return NULL;
	}
	it->pos = *pos;
	return it;
}

static void *sif_eq_seq_start(struct seq_file *s, loff_t *pos)
{
	struct sif_dfs_iter *it;
	struct sif_dfs_ref *sd = (struct sif_dfs_ref *) s->private;
	struct sif_dev *sdev = sd->sdev;
	u32 cnt = sdev->es[sdev->mbox_epsc].eqs.cnt;

	sif_log(sdev, SIF_DFS, " at %lld", *pos);
	if (*pos > cnt - 2) {
		*pos = -1;
		return NULL;
	}
	it = kmalloc(sizeof(struct sif_dfs_iter), GFP_KERNEL);
	if (!it)
		return NULL;
	it->pos = *pos;
	it->started = false;
	return it;
}

static const struct seq_operations eq_seq_ops = {
	.start = sif_eq_seq_start,
	.next  = sif_eq_seq_next,
	.stop  = sif_seq_stop,
	.show  = sif_seq_show
};

static int sif_seq_open(struct inode *inode, struct file *file)
{
	int ret;
	struct sif_dfs_ref *sd = (struct sif_dfs_ref *)inode->i_private;
	struct seq_file *seq;

	if (!try_module_get(THIS_MODULE))
		return -EIO;

	if (unlikely(sd->is_eq))
		ret = seq_open(file, &eq_seq_ops);
	else
		ret = seq_open(file, &seq_ops);
	if (!ret) {
		seq = file->private_data;
		seq->private = inode->i_private;
	}
	return ret;
};

static int sif_seq_release(struct inode *inode, struct file *file)
{
	int stat = seq_release(inode, file);

	module_put(THIS_MODULE);
	return stat;
}


static const struct file_operations table_fops = {
	.owner   = THIS_MODULE,
	.open    = sif_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = sif_seq_release
};

static ssize_t irq_ch_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct seq_file *seq = file->private_data;
	struct sif_dfs_ref *sd = (struct sif_dfs_ref *) seq->private;
	struct sif_dev *sdev = sd->sdev;
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	u32 channels = es->eqs.cnt;

	struct sif_eq *eq = &es->eqs.eq[1];
	struct psif_epsc_csr_interrupt_channel *settings;
	struct psif_epsc_csr_req req; /* local epsc wr copy */
	struct psif_epsc_csr_rsp resp;

	char buffer[256] = ""; /* make a writable copy of const buf*/
	char *str, *token, *param[2];
	int ret;

	if (!eps_version_ge(es, 0, 36))
		goto opcode_not_available;

	if (count >= sizeof(buffer))
		return -ENOSPC;

	ret = simple_write_to_buffer(buffer, sizeof(buffer), ppos, buf, count);
	if (ret < 0) {
		sif_log(sd->sdev, SIF_INFO, "Not able to read input parameters from userspace");
		return ret;
	}
	buffer[ret] = '\0';
	str = buffer;

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_HOST_INT_CHANNEL_CTRL;
	req.uf = 0;
	settings = &req.u.int_channel;

	while ((token = strsep(&str, ";")) != NULL) {
		param[0] = strsep(&token, "=");
		if (param[0]) {
			param[1] = strsep(&token, "=");
			if (!param[1])
				continue;
		} else {
			continue;
		}

		if (strcmp(param[0], "channel") == 0) {
			u16 value;

			ret = kstrtou16(param[1], 10, &value);
			if (ret == 0 && value > 0 && value < channels) {
				settings->int_channel = value;
				eq = &es->eqs.eq[value];
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid irq channel: %hu",
					value);
				goto sif_invalid_channel;
			}
		} else if (strcmp(param[0], "adaptive") == 0) {
			u8 value;

			ret = kstrtou8(param[1], 10, &value);
			if (ret == 0 && value == 0) {
				settings->attributes.enable_adaptive = 1;
				settings->enable_adaptive = 0;
			} else if (ret == 0 && value > 0) {
				settings->attributes.enable_adaptive = 1;
				settings->enable_adaptive = 1;
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid channel_adaptive value: %hu",
					value);
			}
		} else if (strcmp(param[0], "rx_scale") == 0) {
			u16 value;

			ret = kstrtou16(param[1], 10, &value);
			if (!ret) {
				settings->attributes.channel_rx_scale = 1;
				settings->channel_rx_scale = value;
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid channel_rx_scale value: %hu",
					value);
			}
		} else if (strcmp(param[0], "rate_low") == 0) {
			u32 value;

			ret = kstrtou32(param[1], 10, &value);
			if (!ret) {
				settings->attributes.channel_rate_low = 1;
				settings->channel_rate_low = value;
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid channel_rate_low value: %u",
					value);
			}
		} else if (strcmp(param[0], "rate_high") == 0) {
			u32 value;

			ret = kstrtou32(param[1], 10, &value);
			if (!ret) {
				settings->attributes.channel_rate_high = 1;
				settings->channel_rate_high = value;
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid channel_rate_high value: %u",
					value);
			}
		} else if (strcmp(param[0], "ausec") == 0) {
			u16 value;

			ret = kstrtou16(param[1], 10, &value);
			if (!ret) {
				settings->attributes.channel_ausec = 1;
				settings->channel_ausec = value;
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid channel_ausec value: %hu",
					value);
			}
		} else if (strcmp(param[0], "ausec_low") == 0) {
			u16 value;

			ret = kstrtou16(param[1], 10, &value);
			if (!ret) {
				settings->attributes.channel_ausec_low = 1;
				settings->channel_ausec_low = value;
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid channel_ausec_low value: %hu",
					value);
			}
		} else if (strcmp(param[0], "ausec_high") == 0) {
			u16 value;

			ret = kstrtou16(param[1], 10, &value);
			if (!ret) {
				settings->attributes.channel_ausec_high = 1;
				settings->channel_ausec_high = value;
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid channel_ausec_high value: %hu",
					value);
			}
		} else if (strcmp(param[0], "pusec") == 0) {
			u16 value;

			ret = kstrtou16(param[1], 10, &value);
			if (!ret) {
				settings->attributes.channel_pusec = 1;
				settings->channel_pusec = value;
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid channel_pusec value: %hu",
					value);
			}
		} else if (strcmp(param[0], "pusec_low") == 0) {
			u16 value;

			ret = kstrtou16(param[1], 10, &value);
			if (!ret) {
				settings->attributes.channel_pusec_low = 1;
				settings->channel_pusec_low = value;
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid channel_pusec_low value: %hu",
					value);
			}
		} else if (strcmp(param[0], "pusec_high") == 0) {
			u16 value;

			ret = kstrtou16(param[1], 10, &value);
			if (!ret) {
				settings->attributes.channel_pusec_high = 1;
				settings->channel_pusec_high = value;
			} else {
				sif_log(sd->sdev, SIF_INTR, "Invalid channel_pusec_high value: %hu",
					value);
			}
		} else {
			sif_log(sd->sdev, SIF_INTR, "Omitting invalid irq coalesce parameter %s",
				param[0]);
		}
	}

	if (!settings->int_channel) {
		sif_log(sd->sdev, SIF_INTR, "Missing irq channel");
		goto sif_invalid_channel;
	}

	ret = sif_epsc_wr_poll(sd->sdev, &req, &resp);
	if (ret) {
		sif_log(sd->sdev, SIF_INFO, "Failed to configure the coalescing settings for irq channel %d",
			settings->int_channel);
		goto err_epsc_comm;
	}
	/* Update the driver device settings */
#define UPDATE_DRIVER_INT_CTRL_SETTING(attr) {			\
		if (settings->attributes.attr)			\
			eq->irq_ch.attr = settings->attr;	\
	}
	UPDATE_DRIVER_INT_CTRL_SETTING(enable_adaptive);
	UPDATE_DRIVER_INT_CTRL_SETTING(channel_rx_scale);
	UPDATE_DRIVER_INT_CTRL_SETTING(channel_rate_low);
	UPDATE_DRIVER_INT_CTRL_SETTING(channel_rate_high);
	UPDATE_DRIVER_INT_CTRL_SETTING(channel_ausec);
	UPDATE_DRIVER_INT_CTRL_SETTING(channel_ausec_low);
	UPDATE_DRIVER_INT_CTRL_SETTING(channel_ausec_high);
	UPDATE_DRIVER_INT_CTRL_SETTING(channel_pusec);
	UPDATE_DRIVER_INT_CTRL_SETTING(channel_pusec_low);
	UPDATE_DRIVER_INT_CTRL_SETTING(channel_pusec_high);
	/* Update the irq_ch debug file*/
	sd->dfs_print(seq, sd->sdev, *ppos);

	return count;

opcode_not_available:
sif_invalid_channel:
	return -EINVAL;
err_epsc_comm:
	return ret;
}

static const struct file_operations table_fops_rw = {
	.owner   = THIS_MODULE,
	.open    = sif_seq_open,
	.read    = seq_read,
	.write	 = irq_ch_write,
	.llseek  = seq_lseek,
	.release = sif_seq_release
};

/**** support for workaround statistics */

static int r_open(struct inode *inode, struct file *file)
{
	if (!try_module_get(THIS_MODULE))
		return -EIO;

	file->private_data = inode->i_private;
	return 0;
};

static int r_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t rwa_read(struct file *file, char __user *buf, size_t sz, loff_t *off)
{
	struct sif_dev *sdev = ((struct sif_dfs_ref *)file->private_data)->sdev;
	size_t len = 0;
	struct xchar xc;
	size_t dump_size = 12000; /* enough space for allocating the workaround statistics dump */
	char *dump;

	if (*off > 0)
		return 0;

	dump = kmalloc(dump_size, GFP_KERNEL);
	if (!dump) {
		sif_log0(SIF_INFO, "Error allocating temp.storage for wa statistics");
		return -ENOMEM;
	}

	memset(dump, 0, dump_size*sizeof(char));
	xc.buf = dump;

	sif_dfs_print_wa_stats(sdev, xc.buf);

	len = simple_read_from_buffer(buf, sz, off, dump, strlen(dump));
	kfree(dump);

	return len;
}

static const struct file_operations wa_fops = {
	.owner   = THIS_MODULE,
	.open    = r_open,
	.read    = rwa_read,
	.release = r_release,
};

/* Setup/teardown */

/* Called before sif_hw_init in main since needed by pqp setup */
int sif_dfs_register(struct sif_dev *sdev)
{
	struct dentry *df;
	struct sif_dfs_ref *sdr;
	int i;
	char name[100];

	sprintf(name, "%s", dev_name(&sdev->pdev->dev));
	sdev->dfs = kzalloc(sizeof(struct sif_dfs), GFP_KERNEL);
	if (sdev->dfs)
		sdev->dfs->root = debugfs_create_dir(name, NULL);
	if (!sdev->dfs || !sdev->dfs->root) {
		sif_log(sdev, SIF_INFO,
			"Unable to set up debugfs file system for %s", name);
		goto sif_dfs_reg_failed;
	}

	for (i = 0; i < sif_tab_init_max; i++) {
		sdr = &sdev->dfs->sd[i];
		sdr->sdev = sdev;
		sdr->is_eq = false;
		sdr->type = i;
		sdr->dfs_print = sif_table_dfs_printer(i);
		df = debugfs_create_file(sif_table_name(i), S_IRUGO, sdev->dfs->root,
					(void *)sdr, &table_fops);
		if (!df) {
			sif_log(sdev, SIF_INFO, "Unable to set up debugfs file %s",
				sif_table_name(i));
			goto sif_dfs_reg_failed;
		}
	}

	/* Single file for the event queues */
	sdr = &sdev->dfs->sd_eq;
	sdr->sdev = sdev;
	sdr->is_eq = true;
	sdr->dfs_print = sif_dfs_print_eq;
	df = debugfs_create_file("eq", S_IRUGO, sdev->dfs->root,
				(void *)sdr, &table_fops);
	if (!df) {
		sif_log(sdev, SIF_INFO, "Unable to set up debugfs file for event queues");
		return -ENOMEM;
	}
	/* Single file for the ipoffload qp-statistics */
	sdr = &sdev->dfs->sd_ipoffload;
	sdr->sdev = sdev;
	sdr->dfs_print = sif_dfs_print_ipoffload;
	sdr->type = qp;
	df = debugfs_create_file("ipoffload", S_IRUGO, sdev->dfs->root,
				(void *)sdr, &table_fops);
	if (!df) {
		sif_log(sdev, SIF_INFO, "Unable to set up debugfs file for ipoffload qp stat");
		return -ENOMEM;
	}
	/* Single file for the wa statistics */
	sdr = &sdev->dfs->sd_wa_stats;
	sdr->sdev = sdev;
	df = debugfs_create_file("wa_stats", S_IRUGO, sdev->dfs->root,
				(void *)sdr, &wa_fops);
	if (!df) {
		sif_log(sdev, SIF_INFO, "Unable to set up debugfs file for wa stat");
		return -ENOMEM;
	}
	/* Single file for the int channel coalescing settings */
	sdr = &sdev->dfs->sd_irq_ch;
	sdr->sdev = sdev;
	sdr->is_eq = true;
	sdr->dfs_print = sif_dfs_print_irq_ch;
	df = debugfs_create_file("irq_ch", S_IWUSR | S_IRUGO, sdev->dfs->root,
				(void *)sdr, &table_fops_rw);
	if (!df) {
		sif_log(sdev, SIF_INFO,
			"Unable to set up debugfs file for interrupt channels coalescing settings");
		return -ENOMEM;
	}

	/* Create a directory for raw qp dump info */
	sdev->dfs->raw_qp = debugfs_create_dir("raw_qp", sdev->dfs->root);
	if (!sdev->dfs->raw_qp) {
		sif_log(sdev, SIF_INFO, "Unable to set up debugfs directory for raw QP information");
		goto sif_dfs_reg_failed;
	}
	return 0;

sif_dfs_reg_failed:
	sif_dfs_unregister(sdev);
	return -ENOMEM;
}


/* Symlink ib device name to debugfs root node - named by PCI id */
void sif_dfs_link_to_ibdev(struct sif_dev *sdev)
{
	sdev->dfs->root_link =
		debugfs_create_symlink(sdev->ib_dev.name, NULL, sdev->dfs->root->d_iname);
	if (!sdev->dfs->root_link)
		sif_log(sdev, SIF_INFO, "Failed to create link %s -> %s",
			sdev->dfs->root->d_iname, sdev->ib_dev.name);
}


void sif_dfs_unregister(struct sif_dev *sdev)
{
	if (!sdev->dfs)
		return;
	debugfs_remove(sdev->dfs->root_link);
	debugfs_remove_recursive(sdev->dfs->root);
	kfree(sdev->dfs);
	sdev->dfs = NULL;
}


/**** support for raw QP state dump */

static ssize_t rqp_read(struct file *file, char __user *buf, size_t sz, loff_t *off)
{
	struct sif_qp *qp = (struct sif_qp *)file->private_data;
	struct psif_query_qp lqqp;
	int ret;
	size_t len = 0;
	struct xchar xc;
	size_t dump_size = 12000; /* enough space for allocating the qp dump*/
	char *dump;

	sif_log0(SIF_QP, "rqp_read idx %d, sz %ld offset 0x%llx", qp->qp_idx, sz, *off);
	if (*off > 0)
		return 0;

	dump = kmalloc(dump_size, GFP_KERNEL);
	if (!dump) {
		sif_log0(SIF_INFO, "Error allocating temp.storage for raw qp read");
		return -ENOMEM;
	}

	memset(dump, 0, dump_size*sizeof(char));
	xc.buf = dump;

	ret = epsc_query_qp(qp, &lqqp);
	if (ret) {
		len = snprintf(xc.buf, sz,
			"[query_qp failed with status %d - returning last cached state]\n",
			ret);
		xc.buf += len;
		sz -= len;
	}
	/* TBD: Could cause buffer overflow in theory: see #2738 */
	write_struct_psif_query_qp(&xc, 0, &lqqp);
	sprintf(xc.buf, "\n");
	len = simple_read_from_buffer(buf, sz, off, dump, strlen(dump));
	kfree(dump);

	return len;
}

static const struct file_operations qp_fops = {
	.owner   = THIS_MODULE,
	.open    = r_open,
	.read    = rqp_read,
	.release = r_release,
};

/* TBD: Ref.cnt or other protection probably needed to protect agains "take down" while
 * a query is in progress
 */
int sif_dfs_add_qp(struct sif_dev *sdev, struct sif_qp *qp)
{
	char tmp[20];

	sprintf(tmp, "%d", qp->qp_idx);
	qp->dfs_qp = debugfs_create_file(tmp, S_IRUGO, sdev->dfs->raw_qp,
				(void *)qp, &qp_fops);
	if (!qp->dfs_qp)
		return -ENOMEM;
	return 0;
}


void sif_dfs_remove_qp(struct sif_qp *qp)
{
	debugfs_remove(qp->dfs_qp);
	qp->dfs_qp = NULL;
}
