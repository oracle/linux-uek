/*
 * Copyright (c) 2012, Mellanox Technologies inc.  All rights reserved.
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


#include <linux/kref.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/debugfs.h>
#include <linux/export.h>
#include <rdma/ib_umem.h>
#include "mlx5_ib.h"

MLX5_IB_MOD_DBG_MASK(MLX5_IB_MOD_MR);


enum {
	DEF_CACHE_SIZE	= 10,
};

static int file_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;

	return 0;
}

static int order2idx(struct mlx5_ib_dev *dev, int order)
{
	struct mlx5_mr_cache *cache = &dev->cache;

	if (order < cache->ent[0].order)
		return 0;
	else
		return order - cache->ent[0].order;
}

static int add_keys(struct mlx5_ib_dev *dev, int c, int num)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_ib_mr *mr;
	int err = 0;
	int i;
	struct mlx5_create_mkey_mbox_in *in;
	struct mlx5_cache_ent *ent = &cache->ent[c];
	int npages = 1 << ent->order;
	struct device *ddev = dev->ib_dev.dma_device;
	int size = ALIGN(sizeof(u64) * npages, 0x40);

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in) {
		mlx5_ib_warn(dev, "allocation failed\n");
		return -ENOMEM;
	}

	for (i = 0; i < num; ++i) {
		mr = kzalloc(sizeof(*mr), GFP_KERNEL);
		if (!mr) {
			mlx5_ib_warn(dev, "allocation failed\n");
			err = -ENOMEM;
			goto out;
		}
		mr->order = ent->order;
		mr->umred = 1;
		mr->pas = kmalloc(size, GFP_KERNEL);
		if (!mr->pas) {
			kfree(mr);
			err = -ENOMEM;
			goto out;
		}
		mr->dma = dma_map_single(ddev, mr->pas, size, DMA_TO_DEVICE);
		if (dma_mapping_error(ddev, mr->dma)) {
			kfree(mr->pas);
			kfree(mr);
			err = -ENOMEM;
			goto out;
		}

		in->seg.status = 1 << 6;
		in->seg.xlt_oct_size = cpu_to_be32((npages + 1) / 2);
		in->seg.qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
		in->seg.flags = MLX5_ACCESS_MODE_MTT | 0x80;
		in->seg.log2_page_size = 12;

		err = mlx5_core_create_mkey(&dev->mdev, &mr->mmr, in,
					    sizeof(*in));
		if (err) {
			mlx5_ib_warn(dev, "create mkey failed %d\n", err);
			dma_unmap_single(ddev, mr->dma, size, DMA_TO_DEVICE);
			kfree(mr->pas);
			kfree(mr);
			goto out;
		}

		spin_lock(&ent->lock);
		list_add_tail(&mr->list, &ent->head);
		ent->cur++;
		ent->size++;
		spin_unlock(&ent->lock);
	}

out:
	kfree(in);
	return err;
}

static void remove_keys(struct mlx5_ib_dev *dev, int c, int num)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_ib_mr *mr;
	int err;
	struct mlx5_cache_ent *ent = &cache->ent[c];
	struct device *ddev = dev->ib_dev.dma_device;
	int size;
	int i;

	for (i = 0; i < num; ++i) {
		spin_lock(&ent->lock);
		if (list_empty(&ent->head)) {
			spin_unlock(&ent->lock);
			return;
		}
		mr = list_first_entry(&ent->head, struct mlx5_ib_mr, list);
		list_del(&mr->list);
		ent->cur--;
		ent->size--;
		spin_unlock(&ent->lock);
		err = mlx5_core_destroy_mkey(&dev->mdev, &mr->mmr);
		if (err) {
			mlx5_ib_warn(dev, "failed destroy mkey\n");
		} else {
			size = ALIGN(sizeof(u64) * (1 << mr->order), 0x40);
			dma_unmap_single(ddev, mr->dma, size, DMA_TO_DEVICE);
			kfree(mr->pas);
			kfree(mr);
		}
	};
}

static ssize_t size_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *pos)
{
	struct mlx5_cache_ent *ent = filp->private_data;
	struct mlx5_ib_dev *dev = ent->dev;
	char lbuf[20];
	u32 var;
	int err;
	int c;

	if (copy_from_user(lbuf, buf, sizeof(lbuf)))
		return -EPERM;

	c = order2idx(dev, ent->order);
	lbuf[sizeof(lbuf) - 1] = 0;

	if (sscanf(lbuf, "%u", &var) != 1)
		return -EINVAL;

	if (var < ent->limit)
		return -EINVAL;

	if (var > ent->size) {
		err = add_keys(dev, c, var - ent->size);
		if (err)
			return err;
	} else if (var < ent->size) {
		remove_keys(dev, c, ent->size - var);
	}

	return count;
}

static ssize_t size_read(struct file *filp, char __user *buf, size_t count,
			 loff_t *pos)
{
	struct mlx5_cache_ent *ent = filp->private_data;
	char lbuf[20];
	int err;

	if (*pos)
		return 0;

	err = snprintf(lbuf, sizeof(lbuf), "%d\n", ent->size);
	if (err < 0)
		return err;

	if (copy_to_user(buf, lbuf, err))
		return -EPERM;

	*pos += err;

	return err;
}

static const struct file_operations size_fops = {
	.owner	= THIS_MODULE,
	.open	= file_open,
	.write	= size_write,
	.read	= size_read,
};


static ssize_t limit_write(struct file *filp, const char __user *buf,
			   size_t count, loff_t *pos)
{
	struct mlx5_cache_ent *ent = filp->private_data;
	struct mlx5_ib_dev *dev = ent->dev;
	char lbuf[20];
	u32 var;
	int err;
	int c;

	if (copy_from_user(lbuf, buf, sizeof(lbuf)))
		return -EPERM;

	c = order2idx(dev, ent->order);
	lbuf[sizeof(lbuf) - 1] = 0;

	if (sscanf(lbuf, "%u", &var) != 1)
		return -EINVAL;

	if (var > ent->size)
		return -EINVAL;

	ent->limit = var;

	if (ent->cur < ent->limit) {
		err = add_keys(dev, c, 2 * ent->limit - ent->cur);
		if (err)
			return err;
	}

	return count;
}

static ssize_t limit_read(struct file *filp, char __user *buf, size_t count,
			  loff_t *pos)
{
	struct mlx5_cache_ent *ent = filp->private_data;
	char lbuf[20];
	int err;

	if (*pos)
		return 0;

	err = snprintf(lbuf, sizeof(lbuf), "%d\n", ent->limit);
	if (err < 0)
		return err;

	if (copy_to_user(buf, lbuf, err))
		return -EPERM;

	*pos += err;

	return err;
}

static const struct file_operations limit_fops = {
	.owner	= THIS_MODULE,
	.open	= file_open,
	.write	= limit_write,
	.read	= limit_read,
};

static struct mlx5_ib_mr *alloc_cached_mr(struct mlx5_ib_dev *dev, int order)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	struct mlx5_ib_mr *mr;
	int c;
	int requeue = 0;

	c = order2idx(dev, order);
	if (c < 0 || c > 17) {
		mlx5_ib_warn(dev, "order %d, cache index %d\n", order, c);
		return NULL;
	}

	ent = &cache->ent[c];

	mlx5_ib_dbg(dev, "order %d, cache index %d\n", order, c);

	spin_lock(&ent->lock);
	if (!list_empty(&ent->head)) {
		mr = list_first_entry(&ent->head, struct mlx5_ib_mr, list);
		list_del(&mr->list);
		ent->cur--;
	} else {
		ent->miss++;
		mr = NULL;
	}

	if (ent->cur < ent->limit)
		requeue = 1;

	spin_unlock(&ent->lock);

	if (requeue)
		queue_work(cache->wq, &cache->work.work);

	return mr;
}

static void free_cached_mr(struct mlx5_ib_dev *dev, struct mlx5_ib_mr *mr)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	int c;

	c = order2idx(dev, mr->order);
	if (c < 0 || c > 17) {
		mlx5_ib_warn(dev, "order %d, cache index %d\n", mr->order, c);
		return;
	}
	ent = &cache->ent[c];

	spin_lock(&ent->lock);
	list_add_tail(&mr->list, &ent->head);
	ent->cur++;
	spin_unlock(&ent->lock);
}

static void clean_keys(struct mlx5_ib_dev *dev, int c)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_ib_mr *mr;
	int err;
	struct mlx5_cache_ent *ent = &cache->ent[c];
	struct device *ddev = dev->ib_dev.dma_device;
	int size;

	while (1) {
		spin_lock(&ent->lock);
		if (list_empty(&ent->head)) {
			spin_unlock(&ent->lock);
			return;
		}
		mr = list_first_entry(&ent->head, struct mlx5_ib_mr, list);
		list_del(&mr->list);
		ent->cur--;
		ent->size--;
		spin_unlock(&ent->lock);
		err = mlx5_core_destroy_mkey(&dev->mdev, &mr->mmr);
		if (err) {
			mlx5_ib_warn(dev, "failed destroy mkey\n");
		} else {
			size = ALIGN(sizeof(u64) * (1 << mr->order), 0x40);
			dma_unmap_single(ddev, mr->dma, size, DMA_TO_DEVICE);
			kfree(mr->pas);
			kfree(mr);
		}
	};
}

static void cache_work_func(struct work_struct *work)
{
	struct mlx5_mkey_work *mkw = container_of(work, struct mlx5_mkey_work,
						  work);
	struct mlx5_ib_dev *dev = mkw->dev;
	struct mlx5_cache_ent *ent;
	int i;

	if (dev->cache.stopped)
		return;

	for (i = 0; i < MAX_MR_CACHE_ENTRIES; ++i) {
		ent = &dev->cache.ent[i];
		if (ent->cur < ent->limit)
			add_keys(dev, i, 2 * ent->limit - ent->cur);
	}
}

static int mlx5_mr_cache_debugfs_init(struct mlx5_ib_dev *dev)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	struct mlx5_cache_ent *ent;
	int i;

	if (!mlx5_debugfs_root)
		return 0;

	cache->root = debugfs_create_dir("mr_cache", dev->mdev.priv.dbg_root);
	if (!cache->root)
		return -ENOMEM;

	for (i = 0; i < MAX_MR_CACHE_ENTRIES; ++i) {
		ent = &cache->ent[i];
		sprintf(ent->name, "%d", ent->order);
		ent->dir = debugfs_create_dir(ent->name,  cache->root);
		if (!ent->dir)
			return -ENOMEM;

		ent->fsize = debugfs_create_file("size", 0600, ent->dir, ent,
						 &size_fops);
		if (!ent->fsize)
			return -ENOMEM;

		ent->flimit = debugfs_create_file("limit", 0600, ent->dir, ent,
						  &limit_fops);
		if (!ent->flimit)
			return -ENOMEM;

		ent->fcur = debugfs_create_u32("cur", 0400, ent->dir,
					       &ent->cur);
		if (!ent->fcur)
			return -ENOMEM;

		ent->fmiss = debugfs_create_u32("miss", 0600, ent->dir,
						&ent->miss);
		if (!ent->fmiss)
			return -ENOMEM;
	}

	return 0;
}

static void mlx5_mr_cache_debugfs_cleanup(struct mlx5_ib_dev *dev)
{
	if (!mlx5_debugfs_root)
		return;

	debugfs_remove_recursive(dev->cache.root);
}

int mlx5_mr_cache_init(struct mlx5_ib_dev *dev)
{
	struct mlx5_mr_cache *cache = &dev->cache;
	int err;
	int i;
	struct mlx5_cache_ent *ent;
	int size;
	int limit;

	cache->wq = create_singlethread_workqueue("mkey_cache");
	if (!cache->wq) {
		mlx5_ib_warn(dev, "failed to create work queue\n");
		return -ENOMEM;
	}

	for (i = 0; i < MAX_MR_CACHE_ENTRIES; ++i) {
		INIT_LIST_HEAD(&cache->ent[i].head);
		spin_lock_init(&cache->ent[i].lock);

		ent = &cache->ent[i];
		INIT_LIST_HEAD(&ent->head);
		spin_lock_init(&ent->lock);
		ent->order = i + 2;
		ent->dev = dev;

		if (dev->mdev.profile->mask & MLX5_PROF_MASK_MR_CACHE) {
			size = dev->mdev.profile->mr_cache[i].size;
			limit = dev->mdev.profile->mr_cache[i].limit;
		} else {
			size = DEF_CACHE_SIZE;
			limit = 0;
		}
		err = add_keys(dev, i, size);
		if (err) {
			mlx5_ib_warn(dev, "add keys failed %d\n", err);
			goto error;
		}
		ent->limit = limit;
	}
	INIT_WORK(&cache->work.work, cache_work_func);

	err = mlx5_mr_cache_debugfs_init(dev);
	if (err)
		mlx5_ib_warn(dev, "cache debugfs failure\n");


	cache->work.dev = dev;

	return 0;

error:
	for (--i; i >= 0; --i)
		clean_keys(dev, i);

	destroy_workqueue(cache->wq);
	return err;
}

int mlx5_mr_cache_cleanup(struct mlx5_ib_dev *dev)
{
	int i;

	dev->cache.stopped = 1;
	destroy_workqueue(dev->cache.wq);

	mlx5_mr_cache_debugfs_cleanup(dev);

	for (i = 0; i < MAX_MR_CACHE_ENTRIES; ++i)
		clean_keys(dev, i);

	return 0;
}

struct ib_mr *mlx5_ib_get_dma_mr(struct ib_pd *pd, int acc)
{
	struct mlx5_ib_mr *mr;
	int err;
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_core_dev *mdev = &dev->mdev;
	struct mlx5_mkey_seg *seg;
	struct mlx5_create_mkey_mbox_in *in;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	seg = &in->seg;
	seg->flags = convert_access(acc) | MLX5_ACCESS_MODE_PA;
	seg->flags_pd = cpu_to_be32(to_mpd(pd)->pdn | MLX5_MKEY_LEN64);
	seg->qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
	seg->start_addr = 0;

	err = mlx5_core_create_mkey(mdev, &mr->mmr, in, sizeof(*in));
	if (err)
		goto err_in;

	kfree(in);
	mr->ibmr.lkey = mr->mmr.key;
	mr->ibmr.rkey = mr->mmr.key;
	mr->umem = NULL;

	return &mr->ibmr;

err_in:
	kfree(in);

err_free:
	kfree(mr);

	return ERR_PTR(err);
}

static int get_octo_len(u64 addr, u64 len, int page_size)
{
	u64 offset;
	int npages;

	offset = addr & (page_size - 1);
	npages = ALIGN(len + offset, page_size) >> ilog2(page_size);
	return (npages + 1) / 2;
}

static int use_umr(int order)
{
	return order <= 17;
}

static void prep_umr_reg_wqe(struct ib_pd *pd, struct ib_send_wr *wr,
			     struct ib_sge *sg, u64 dma, int n, u32 key,
			     int page_shift, u64 virt_addr, u64 len,
			     int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct ib_mr *mr = dev->umrc.mr;

	sg->addr = dma;
	sg->length = ALIGN(sizeof(u64) * n, 64);
	sg->lkey = mr->lkey;

	wr->next = NULL;
	wr->send_flags = 0;
	wr->sg_list = sg;
	if (n)
		wr->num_sge = 1;
	else
		wr->num_sge = 0;

	wr->opcode = IB_WR_UMR;
	wr->wr.umr.npages = n;
	wr->wr.umr.page_shift = page_shift;
	wr->wr.umr.mkey = key;
	wr->wr.umr.virt_addr = virt_addr;
	wr->wr.umr.length = len;
	wr->wr.umr.access_flags = access_flags;
	wr->wr.umr.pd = pd;
}

static void prep_umr_unreg_wqe(struct mlx5_ib_dev *dev,
			       struct ib_send_wr *wr, u32 key)
{
	wr->send_flags = IB_SEND_UMR_UNREG;
	wr->opcode = IB_WR_UMR;
	wr->wr.umr.mkey = key;
}

static int poll_timeout(struct mlx5_ib_dev *dev, u64 wrid)
{
	struct umr_common *umrc = &dev->umrc;
	unsigned long end;
	struct ib_wc wc;
	int err;
	unsigned long start, delta;

	start = jiffies;
poll_again:
	end = jiffies + HZ;
	do {
		err = ib_poll_cq(umrc->cq, 1, &wc);
		if (err < 0) {
			mlx5_ib_warn(dev, "poll err %d\n", err);
			while (1)
				msleep(10000);

			return err;
		} else if (err > 1) {
			err = -EIO;
			mlx5_ib_warn(dev, "expected 1 completion but got %d\n",
				     err);
			while (1)
				msleep(10000);

			return err;
		}
	} while (err == 0 && time_before(jiffies, end));

	if (err == 0) {
		mlx5_ib_warn(dev, "waited too long with no completion: wrid: 0x%llx\n", wrid);
		while (1) {
			msleep(10000);
			goto poll_again;
		}
		return -ENOENT;
	}

	delta = jiffies - start;
	if (wc.wr_id != wrid || wc.status != IB_WC_SUCCESS) {
		mlx5_ib_warn(dev, "expected wrid 0x%llx, got 0x%llx, status %d, total time %lu\n",
			     wrid, wc.wr_id, wc.status, delta);
		return -EINVAL;
	}

	if (delta > HZ) {
		mlx5_ib_warn(dev, "UMR completed in %lu jiffies - freezing\n", delta);
		while (1)
			msleep(10000);
	}

	return 0;
}

static struct mlx5_ib_mr *reg_umr(struct ib_pd *pd, struct ib_umem *umem,
				  u64 virt_addr, u64 len, int npages,
				  int page_shift, int order, int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct umr_common *umrc = &dev->umrc;
	struct mlx5_ib_mr *mr;
	struct ib_send_wr wr, *bad;
	struct ib_sge sg;
	int err;

	mr = alloc_cached_mr(dev, order);
	if (!mr)
		return ERR_PTR(-EAGAIN);

	mlx5_ib_populate_pas(dev, umem, page_shift, mr->pas, 1);

	memset(&wr, 0, sizeof(wr));
	get_random_bytes(&wr.wr_id, sizeof(wr.wr_id));
	prep_umr_reg_wqe(pd, &wr, &sg, mr->dma, npages, mr->mmr.key, page_shift, virt_addr, len, access_flags);

	/*
	 * we serialize polls so one process does not kidnap another's
	 * completion. This is not a problem since wr is completed in
	 * around 1 usec
	 */
	mutex_lock(&umrc->lock);
	err = ib_post_send(umrc->qp, &wr, &bad);
	if (err) {
		mlx5_ib_warn(dev, "post send failed, err %d\n", err);
		goto error;
	}
	err = poll_timeout(dev, wr.wr_id);
	if (err)
		goto error;

	mutex_unlock(&umrc->lock);

	return mr;

error:
	mutex_unlock(&umrc->lock);
	free_cached_mr(dev, mr);
	return ERR_PTR(err);
}

static struct mlx5_ib_mr *reg_create(struct ib_pd *pd, u64 virt_addr,
				     u64 length, struct ib_umem *umem,
				     int npages, int page_shift,
				     int access_flags)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_mr *mr;
	struct mlx5_create_mkey_mbox_in *in;
	int err;
	int inlen;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		mlx5_ib_warn(dev, "allocation failed\n");
		mr = ERR_PTR(-ENOMEM);
	}

	inlen = sizeof(*in) + sizeof(*in->pas) * ((npages + 1) / 2) * 2;
	in = vzalloc(inlen);
	if (!in) {
		mlx5_ib_warn(dev, "alloc failed\n");
		err = -ENOMEM;
		goto err_1;
	}
	mlx5_ib_populate_pas(dev, umem, page_shift, in->pas, 0);

	in->seg.flags = convert_access(access_flags) |
		MLX5_ACCESS_MODE_MTT;
	in->seg.flags_pd = cpu_to_be32(to_mpd(pd)->pdn);
	in->seg.start_addr = cpu_to_be64(virt_addr);
	in->seg.len = cpu_to_be64(length);
	in->seg.bsfs_octo_size = 0;
	in->seg.xlt_oct_size = cpu_to_be32(get_octo_len(virt_addr, length, 1 << page_shift));
	in->seg.log2_page_size = page_shift;
	in->seg.qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
	in->xlat_oct_act_size = cpu_to_be32(get_octo_len(virt_addr, length, 1 << page_shift));
	err = mlx5_core_create_mkey(&dev->mdev, &mr->mmr, in, inlen);
	if (err) {
		mlx5_ib_warn(dev, "create mkey failed\n");
		goto err_2;
	}
	mr->umem = umem;
	vfree(in);

	mlx5_ib_dbg(dev, "mkey = 0x%x\n", mr->mmr.key);

	return mr;

err_2:
	vfree(in);

err_1:
	kfree(mr);

	return ERR_PTR(err);
}

struct ib_mr *mlx5_ib_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				  u64 virt_addr, int access_flags,
				  struct ib_udata *udata, int mr_id)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_mr *mr = NULL;
	int npages;
	int ncont;
	int page_shift;
	struct ib_umem *umem;
	int order;
	int err;

	mlx5_ib_dbg(dev, "start 0x%llx, virt_addr 0x%llx, length 0x%llx\n",
		    start, virt_addr, length);
	umem = ib_umem_get(pd->uobject->context, start, length, access_flags,
			   0);
	if (IS_ERR(umem)) {
		mlx5_ib_dbg(dev, "umem get failed\n");
		return (void *)umem;
	}

	mlx5_ib_cont_pages(umem, start, &npages, &page_shift, &ncont, &order);
	if (!npages) {
		mlx5_ib_warn(dev, "avoid zero region\n");
		err = -EINVAL;
		goto error;
	}

	mlx5_ib_dbg(dev, "npages %d, ncont %d, order %d, page_shift %d\n",
		    npages, ncont, order, page_shift);

	if (use_umr(order)) {
		mr = reg_umr(pd, umem, virt_addr, length, ncont, page_shift,
			     order, access_flags);
		if (PTR_ERR(mr) == -EAGAIN) {
			mlx5_ib_dbg(dev, "cache empty for order %d", order);
			mr = NULL;
		}
	}

	if (!mr)
		mr = reg_create(pd, virt_addr, length, umem, ncont, page_shift,
				access_flags);

	if (IS_ERR(mr)) {
		err = PTR_ERR(mr);
		goto error;
	}

	mlx5_ib_dbg(dev, "mkey 0x%x\n", mr->mmr.key);

	mr->umem = umem;
	mr->npages = npages;
	spin_lock(&dev->mr_lock);
	dev->mdev.priv.reg_pages += npages;
	spin_unlock(&dev->mr_lock);
	mr->ibmr.lkey = mr->mmr.key;
	mr->ibmr.rkey = mr->mmr.key;

	return &mr->ibmr;

error:
	ib_umem_release(umem);
	return ERR_PTR(err);
}

static int unreg_umr(struct mlx5_ib_dev *dev, u32 key)
{
	struct umr_common *umrc = &dev->umrc;
	struct ib_send_wr wr, *bad;
	int err;

	memset(&wr, 0, sizeof(wr));
	get_random_bytes(&wr.wr_id, sizeof(wr.wr_id));
	prep_umr_unreg_wqe(dev, &wr, key);

	mutex_lock(&umrc->lock);
	err = ib_post_send(umrc->qp, &wr, &bad);
	if (err) {
		mlx5_ib_dbg(dev, "err %d\n", err);
		goto error;
	}

	err = poll_timeout(dev, wr.wr_id);

error:
	mutex_unlock(&umrc->lock);
	return err;
}

int mlx5_ib_dereg_mr(struct ib_mr *ibmr)
{
	struct mlx5_ib_dev *dev = to_mdev(ibmr->device);
	struct mlx5_ib_mr *mr = to_mmr(ibmr);
	int err;
	int npages = mr->npages;
	struct ib_umem *umem = mr->umem;
	int umred = mr->umred;

	if (!umred) {
		err = mlx5_core_destroy_mkey(&dev->mdev, &mr->mmr);
		if (err) {
			mlx5_ib_warn(dev, "failed to destroy mkey 0x%x (%d)\n",
				     mr->mmr.key, err);
			return err;
		}
	} else {
		err = unreg_umr(dev, mr->mmr.key);
		if (err) {
			mlx5_ib_warn(dev, "failed unregister\n");
			return err;
		}
		free_cached_mr(dev, mr);
	}

	if (umem) {
		ib_umem_release(umem);
		spin_lock(&dev->mr_lock);
		dev->mdev.priv.reg_pages -= npages;
		spin_unlock(&dev->mr_lock);
	}

	if (!umred)
		kfree(mr);

	return 0;
}

struct ib_mr *mlx5_ib_alloc_fast_reg_mr(struct ib_pd *pd,
					int max_page_list_len)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_mr *mr;
	int err;
	struct mlx5_create_mkey_mbox_in *in;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_free;
	}

	in->seg.status = 1 << 6; /* free */
	in->seg.flags = MLX5_PERM_UMR_EN | MLX5_ACCESS_MODE_MTT;
	in->seg.flags_pd = cpu_to_be32(to_mpd(pd)->pdn | MLX5_MKEY_REMOTE_INVAL);
	in->seg.xlt_oct_size = cpu_to_be32(max_page_list_len);

	err = mlx5_core_create_mkey(&dev->mdev, &mr->mmr, in, sizeof(*in));
	kfree(in);
	if (err)
		goto err_free;

	mr->ibmr.lkey = mr->mmr.key;
	mr->ibmr.rkey = mr->mmr.key;
	mr->umem = NULL;

	return &mr->ibmr;

err_free:
	kfree(mr);
	return ERR_PTR(err);
}

struct ib_fast_reg_page_list *mlx5_ib_alloc_fast_reg_page_list(struct ib_device *ibdev,
							       int page_list_len)
{
	struct mlx5_ib_fast_reg_page_list *mfrpl;
	int size = page_list_len * sizeof(u64);

	mfrpl = kmalloc(sizeof(*mfrpl), GFP_KERNEL);
	if (!mfrpl)
		return ERR_PTR(-ENOMEM);

	mfrpl->ibfrpl.page_list = kmalloc(size, GFP_KERNEL);
	if (!mfrpl->ibfrpl.page_list)
		goto err_free;

	mfrpl->mapped_page_list = dma_alloc_coherent(ibdev->dma_device,
						     size, &mfrpl->map,
						     GFP_KERNEL);
	if (!mfrpl->mapped_page_list)
		goto err_free;

	WARN_ON(mfrpl->map & 0x3f);

	return &mfrpl->ibfrpl;

err_free:
	kfree(mfrpl->ibfrpl.page_list);
	kfree(mfrpl);
	return ERR_PTR(-ENOMEM);
}

void mlx5_ib_free_fast_reg_page_list(struct ib_fast_reg_page_list *page_list)
{
	struct mlx5_ib_dev *dev = to_mdev(page_list->device);
	struct mlx5_ib_fast_reg_page_list *mfrpl = to_mfrpl(page_list);
	int size = page_list->max_page_list_len * sizeof(u64);

	dma_free_coherent(&dev->mdev.pdev->dev, size, mfrpl->mapped_page_list,
			  mfrpl->map);
	kfree(mfrpl->ibfrpl.page_list);
	kfree(mfrpl);
}
