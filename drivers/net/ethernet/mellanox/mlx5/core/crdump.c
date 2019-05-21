/*
 * Copyright (c) 2017, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/proc_fs.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/compat/config.h>
#include "mlx5_core.h"

#define MLX5_PROTECTED_CR_SPCAE_DOMAIN 0x6
#define MLX5_PROTECTED_CR_SCAN_CRSPACE 0x7

/* iter func */
struct mlx5_crdump_iter {
	struct mlx5_fw_crdump *dump;
	u32 cur_index;
	u32 cur_data;
};

int mlx5_crdump_iter_next(struct mlx5_crdump_iter *iter)
{
	int ret = -1;

	/* check if we are at the end */
	mutex_lock(&iter->dump->crspace_mutex);
	if (iter->cur_index >= iter->dump->crspace_size)
		goto unlock;

	/* if not, read the next data */
	iter->cur_data = swab32(readl(&iter->dump->crspace[iter->cur_index]));
	iter->cur_index += 4;
	ret = 0;

unlock:
	mutex_unlock(&iter->dump->crspace_mutex);
	return ret;
}

struct mlx5_crdump_iter *mlx5_crdump_iter_init(struct mlx5_fw_crdump *dump)
{
	struct mlx5_crdump_iter *iter;

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return NULL;

	iter->dump = dump;
	iter->cur_index = 0;

	if (mlx5_crdump_iter_next(iter)) {
		kfree(iter);
		return NULL;
	}

	return iter;
}

void mlx5_crdump_iter_read(struct mlx5_crdump_iter *iter,
			   u32 *data, u32 *offset)
{
	*data = iter->cur_data;
	*offset = iter->cur_index - 4;
}

/* seq func */
static void *mlx5_crdump_seq_start(struct seq_file *file, loff_t *pos)
{
	struct mlx5_crdump_iter *iter;
	loff_t n = *pos;

	iter = mlx5_crdump_iter_init(file->private);
	if (!iter)
		return NULL;

	while (n--) {
		if (mlx5_crdump_iter_next(iter)) {
			kfree(iter);
			return NULL;
		}
	}

	return iter;
}

static void *mlx5_crdump_seq_next(struct seq_file *file, void *iter_ptr,
				  loff_t *pos)
{
	struct mlx5_crdump_iter *iter = iter_ptr;

	(*pos)++;

	if (mlx5_crdump_iter_next(iter)) {
		kfree(iter);
		return NULL;
	}

	return iter;
}

static void mlx5_crdump_seq_stop(struct seq_file *file, void *iter_ptr)
{
	/* nothing for now */
}

static int mlx5_crdump_seq_show(struct seq_file *file, void *iter_ptr)
{
	struct mlx5_crdump_iter *iter = iter_ptr;
	u32 data;
	u32 offset;

	if (!iter)
		return 0;

	mlx5_crdump_iter_read(iter, &data, &offset);

	seq_printf(file, "0x%08x 0x%08x\n", offset, cpu_to_be32(data));

	return 0;
}

static const struct seq_operations mlx5_crdump_seq_ops = {
	.start = mlx5_crdump_seq_start,
	.next  = mlx5_crdump_seq_next,
	.stop  = mlx5_crdump_seq_stop,
	.show  = mlx5_crdump_seq_show,
};

static int mlx5_crdump_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int ret;
#ifndef HAVE_PDE_DATA
	struct proc_dir_entry *pde;
#endif
	ret = seq_open(file, &mlx5_crdump_seq_ops);
	if (ret)
		return ret;

	seq = file->private_data;
#ifdef HAVE_PDE_DATA
	seq->private = PDE_DATA(inode);
#else
	pde = PDE(inode);
	seq->private = pde->data;
#endif
	return 0;
}

static const struct file_operations mlx5_crdump_fops = {
	.owner   = THIS_MODULE,
	.open    = mlx5_crdump_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

int mlx5_cr_protected_capture(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;
	void *cr_data = NULL;
	u32 total_len = 0;
	int ret = 0;

	if (!priv->health.crdump->vsec_addr)
		return -ENODEV;

	ret = mlx5_pciconf_cap9_sem(dev, LOCK);
	if (ret)
		return ret;

	ret = mlx5_pciconf_set_protected_addr_space(dev, &total_len);
	if (ret)
		goto unlock;

	cr_data = kcalloc(total_len, sizeof(u8), GFP_KERNEL);
	if (!cr_data) {
		ret = -ENOMEM;
		goto unlock;
	}
	if (priv->health.crdump->space == MLX5_PROTECTED_CR_SCAN_CRSPACE)
		ret = mlx5_block_op_pciconf_fast(dev, (u32 *)cr_data, total_len);
	else
		ret = mlx5_block_op_pciconf(dev, 0, (u32 *)cr_data, total_len);
	if (ret < 0)
		goto free_mem;

	if (total_len != ret) {
		pr_warn("crdump failed to read full dump, read %d out of %u\n",
			ret, total_len);
		ret = -EINVAL;
		goto free_mem;
	}

	priv->health.crdump->crspace = cr_data;
	priv->health.crdump->crspace_size = total_len;
	ret = 0;

free_mem:
	if (ret)
		kfree(cr_data);
unlock:
	mlx5_pciconf_cap9_sem(dev, UNLOCK);
	return ret;
}

int mlx5_fill_cr_dump(struct mlx5_core_dev *dev)
{
	int ret = 0;

	if (!mlx5_core_is_pf(dev))
		return 0;

	mutex_lock(&dev->priv.health.crdump->crspace_mutex);
	if (dev->priv.health.crdump->crspace_size) {
		/* reading only at the first time */
		pr_debug("crdump was already taken, returning\n");
		goto unlock;
	}

	dev->priv.health.crdump->vsec_addr = pci_find_capability(dev->pdev, CAP_ID);
	if (!dev->priv.health.crdump->vsec_addr) {
		pr_warn("failed reading	vsec_addr\n");
		ret = -EIO;
		goto unlock;
	}

	kfree(dev->priv.health.crdump->crspace);
	dev->priv.health.crdump->crspace_size = 0;

	ret = mlx5_cr_protected_capture(dev);
	if (ret) {
		dev_err(&dev->pdev->dev, "failed capture crdump (err: %d)\n", ret);
		goto unlock;
	}

	pr_info("crdump: Crash snapshot collected to /proc/%s/%s/%s\n",
		MLX5_CORE_PROC, MLX5_CORE_PROC_CRDUMP,
		pci_name(dev->pdev));

unlock:
	mutex_unlock(&dev->priv.health.crdump->crspace_mutex);
	return ret;
}

int mlx5_crdump_init(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_fw_crdump *crdump;
	int ret = -1;

	if (!mlx5_core_is_pf(dev))
		return 0;

	priv->health.crdump = kzalloc(sizeof(*crdump), GFP_KERNEL);
	if (!priv->health.crdump)
		return -ENOMEM;

	crdump = priv->health.crdump;

	mutex_init(&crdump->crspace_mutex);

	if (mlx5_crdump_dir)
		if (!proc_create_data(pci_name(dev->pdev), S_IRUGO,
				      mlx5_crdump_dir, &mlx5_crdump_fops,
				      crdump)) {
			pr_warn("failed creating proc file\n");
			goto clean_mem;
		}

	return 0;

clean_mem:
	kfree(crdump);
	return ret;
}

void mlx5_crdump_cleanup(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_fw_crdump *crdump = priv->health.crdump;

	if (!mlx5_core_is_pf(dev))
		return;

	if (mlx5_crdump_dir)
		remove_proc_entry(pci_name(dev->pdev), mlx5_crdump_dir);

	if (crdump) {
		kfree(crdump->crspace);
		kfree(crdump);
	}
}
