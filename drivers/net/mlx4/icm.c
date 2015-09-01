/*
 * Copyright (c) 2005, 2006, 2007, 2008 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems, Inc.  All rights reserved.
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

#include <linux/init.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>

#include <linux/mlx4/cmd.h>

#include "mlx4.h"
#include "icm.h"
#include "fw.h"
#include "fmr_api.h"
#include "fmr_slave.h"
#include "fmr_master.h"

static void mlx4_free_icm_pages(struct mlx4_dev *dev, struct mlx4_icm_chunk *chunk)
{
	int i;

	if (chunk->nsg > 0)
		pci_unmap_sg(dev->pdev, chunk->mem, chunk->npages,
			     PCI_DMA_BIDIRECTIONAL);

	for (i = 0; i < chunk->npages; ++i)
		__free_pages(sg_page(&chunk->mem[i]),
			     get_order(chunk->mem[i].length));
}

static void mlx4_free_icm_coherent(struct mlx4_dev *dev, struct mlx4_icm_chunk *chunk)
{
	int i;

	for (i = 0; i < chunk->npages; ++i)
		dma_free_coherent(&dev->pdev->dev, chunk->mem[i].length,
				  lowmem_page_address(sg_page(&chunk->mem[i])),
				  sg_dma_address(&chunk->mem[i]));
}

void mlx4_free_icm(struct mlx4_dev *dev, struct mlx4_icm *icm, int coherent,
		   enum mlx4_mr_flags flags)
{
	struct mlx4_icm_chunk *chunk, *tmp;
	int fmr_flow, i;

	if (!icm)
		return;

	fmr_flow = mlx4_fmr_flow(dev, flags);

	list_for_each_entry_safe(chunk, tmp, &icm->chunk_list, list) {
		if (fmr_flow)
			for (i = 0; i < chunk->npages; ++i) {
				__free_page(chunk->fmr_pages[i]);
				chunk->fmr_pages[i] = NULL;
			} else if (coherent)
			mlx4_free_icm_coherent(dev, chunk);
		else
			mlx4_free_icm_pages(dev, chunk);

		kfree(chunk);
	}

	kfree(icm);
}

static int mlx4_alloc_icm_pages(struct scatterlist *mem, int order, gfp_t gfp_mask)
{
	struct page *page;

	page = alloc_pages(gfp_mask, order);
	if (!page)
		return -ENOMEM;

	sg_set_page(mem, page, PAGE_SIZE << order, 0);
	return 0;
}

static int mlx4_alloc_icm_coherent(struct device *dev, struct scatterlist *mem,
				    int order, gfp_t gfp_mask)
{
	void *buf = dma_alloc_coherent(dev, PAGE_SIZE << order,
				       &sg_dma_address(mem), gfp_mask);
	if (!buf)
		return -ENOMEM;

	sg_set_buf(mem, buf, PAGE_SIZE << order);
	BUG_ON(mem->offset);
	sg_dma_len(mem) = PAGE_SIZE << order;
	return 0;
}

struct mlx4_icm *mlx4_alloc_icm(struct mlx4_dev *dev, int npages,
				gfp_t gfp_mask, int coherent)
{
	struct mlx4_icm *icm;
	struct mlx4_icm_chunk *chunk = NULL;
	int cur_order;
	int ret;

	/* We use sg_set_buf for coherent allocs, which assumes low memory */
	BUG_ON(coherent && (gfp_mask & __GFP_HIGHMEM));

	icm = kzalloc(sizeof *icm, gfp_mask & ~(__GFP_HIGHMEM | __GFP_NOWARN));
	if (!icm)
		return NULL;

	icm->refcount = 0;
	INIT_LIST_HEAD(&icm->chunk_list);

	cur_order = get_order(MLX4_ICM_ALLOC_SIZE);

	while (npages > 0) {
		if (!chunk) {
			chunk = kzalloc(sizeof *chunk,
					gfp_mask & ~(__GFP_HIGHMEM | __GFP_NOWARN));
			if (!chunk)
				goto fail;

			sg_init_table(chunk->mem, MLX4_ICM_CHUNK_LEN);
			chunk->npages = 0;
			chunk->nsg    = 0;
			list_add_tail(&chunk->list, &icm->chunk_list);
		}

		while (1 << cur_order > npages)
			--cur_order;

		if (coherent)
			ret = mlx4_alloc_icm_coherent(&dev->pdev->dev,
						      &chunk->mem[chunk->npages],
						      cur_order, gfp_mask);
		else
			ret = mlx4_alloc_icm_pages(&chunk->mem[chunk->npages],
						   cur_order, gfp_mask);

		if (!ret) {
			++chunk->npages;

			if (coherent)
				++chunk->nsg;
			else if (chunk->npages == MLX4_ICM_CHUNK_LEN) {
				chunk->nsg = pci_map_sg(dev->pdev, chunk->mem,
							chunk->npages,
							PCI_DMA_BIDIRECTIONAL);

				if (chunk->nsg <= 0)
					goto fail;
			}

			if (chunk->npages == MLX4_ICM_CHUNK_LEN)
				chunk = NULL;

			npages -= 1 << cur_order;
		} else {
			--cur_order;
			if (cur_order < 0)
				goto fail;
		}
	}

	if (!coherent && chunk) {
		chunk->nsg = pci_map_sg(dev->pdev, chunk->mem,
					chunk->npages,
					PCI_DMA_BIDIRECTIONAL);

		if (chunk->nsg <= 0)
			goto fail;
	}

	return icm;

fail:
	mlx4_free_icm(dev, icm, coherent, MLX4_MR_FLAG_NONE);
	return NULL;
}

static int mlx4_UNMAP_FMR(struct mlx4_dev *dev, u64 virt, u32 page_count,
			  struct mlx4_icm *icm)
{
	struct mlx4_icm_chunk   *chunk;
	int			err, i;

	err = mlx4_cmd(dev, virt, page_count, 1, MLX4_CMD_UNMAP_ICM,
		       MLX4_CMD_TIME_CLASS_B, 0);
	if (err) {
		mlx4_dbg(dev, "UNMAP FMR failed for virt 0x%llx\n",
			 (unsigned long long) virt);
		return err;
	}

	/* fmr flow maps all pages into first chunk */
	chunk = list_empty(&icm->chunk_list) ? NULL :
		list_entry(icm->chunk_list.next, struct mlx4_icm_chunk, list);
	if (!chunk) {
		mlx4_dbg(dev, "UNMAP FMR got null chunk\n");
		return -EINVAL;
	}

	for (i = 0; i < page_count; ++i) {
		mlx4_fmr_slave_unshare(chunk->fmr_vpm_ctx[i]);
		chunk->fmr_vpm_ctx[i] = NULL;
	}

	return 0;
}

static int mlx4_MAP_FMR(struct mlx4_dev *dev, struct mlx4_icm *icm, u64 virt)
{
	struct mlx4_cmd_mailbox *mailbox;
	struct mlx4_icm_chunk   *chunk;
	struct vpm		*vpm;
	void			*vpm_raw;
	int                     fmr_vpm_size, i, nent;
	int			err;



	err = mlx4_fmr_slave_context_init(dev);
	if (err) {
		mlx4_warn(dev, "FMR init failed. FMR disabled.\n");
		return err;
	}

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	/* fmr flow maps all pages into first chunk */
	chunk = list_empty(&icm->chunk_list) ? NULL :
		list_entry(icm->chunk_list.next, struct mlx4_icm_chunk, list);
	if (!chunk) {
		mlx4_dbg(dev, "MAP FMR got null chunk\n");
		err = -EINVAL;
		goto out_free_mailbox;
	}

	vpm_raw = mailbox->buf;

	/* vpm includes two u64 fields and private data in 2 byte words */
	fmr_vpm_size = sizeof(struct vpm) + mlx4_fmr_slave_vpm_info_size();

	for (i = 0, nent = 0; i < chunk->npages; ++i, virt += PAGE_SIZE,
	     vpm_raw += fmr_vpm_size) {
		vpm = (struct vpm *)vpm_raw;
		memset(vpm_raw, 0, fmr_vpm_size);
		err = mlx4_fmr_slave_share(dev,
				lowmem_page_address(chunk->fmr_pages[i]),
				vpm, &chunk->fmr_vpm_ctx[i]);

		if (err) {
			mlx4_dbg(dev, "MAP FMR failed to share page, err %d\n",
				 err);
			goto out;
		}

		vpm->va = cpu_to_be64(virt);

		if ((++nent + 1) * fmr_vpm_size > MLX4_MAILBOX_SIZE) {
			err = mlx4_cmd(dev, mailbox->dma | dev->caps.function,
				       nent, 1, MLX4_CMD_MAP_ICM,
				       MLX4_CMD_TIME_CLASS_B, 0);
			if (err) {
				mlx4_dbg(dev, "MAP FMR cmd failed, err %d\n",
					 err);
				goto out_unshare;
			}
			vpm_raw = mailbox->buf;
			nent = 0;
		}
	}

	if (nent) {
		err = mlx4_cmd(dev, mailbox->dma | dev->caps.function, nent, 1,
			       MLX4_CMD_MAP_ICM,
			       MLX4_CMD_TIME_CLASS_B, 0);
		if (err) {
			mlx4_dbg(dev, "MAP FMR cmd failed, err %d\n", err);
			goto out;
		}
	}

	mlx4_dbg(dev, "MAP FMR %d pages at %llx for ICM.\n",
		 chunk->npages, (unsigned long long) (virt - i * PAGE_SIZE));

	mlx4_free_cmd_mailbox(dev, mailbox);
	return 0;

out_unshare:
	mlx4_fmr_slave_unshare(chunk->fmr_vpm_ctx[i]);

out:
	mlx4_UNMAP_FMR(dev, virt -= i * PAGE_SIZE, i, icm);

out_free_mailbox:
	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;
}

int mlx4_MAP_ICM_wrapper(struct mlx4_dev *dev, int slave,
			 struct mlx4_vhcr *vhcr,
			 struct mlx4_cmd_mailbox *inbox,
			 struct mlx4_cmd_mailbox *outbox,
			 struct mlx4_cmd_info *cmd)
{
	int err, nent, i;
	u64 va;
	struct vpm *vpm;
	void *vpm_raw;
	int vpm_info_size;
	dma_addr_t addr;

	nent = vhcr->in_modifier;

	if (!vhcr->op_modifier)
		return mlx4_cmd(dev, inbox->dma, nent, 0, MLX4_CMD_MAP_ICM,
				MLX4_CMD_TIME_CLASS_B, 1);


	vpm_info_size = sizeof(struct vpm) + mlx4_fmr_master_vpm_info_size();
	vpm_raw = inbox->buf;

	for (i = 0; i < nent; ++i, vpm_raw += vpm_info_size) {
		vpm  = (struct vpm *)vpm_raw;
		va   = be64_to_cpu(vpm->va);
		addr = mlx4_fmr_master_dma_map(dev, slave, vpm);
		if (!addr) {
			mlx4_dbg(dev, "MAP ICM wrapper failed to get fmr dma"
				 " addr for va 0x%llx\n",
				 (unsigned long long)va);
			err = -EINVAL;
			goto out_addr;
		}

		err = mlx4_MAP_ICM_page(dev, (u64)addr, va);
		if (err) {
			mlx4_dbg(dev, "MAP ICM wrapper failed to map icm"
				 " addr for va 0x%llx\n",
				 (unsigned long long)va);
			err = -EINVAL;
			goto out_dma_free;
		}
	}

	return 0;

out_dma_free:
	mlx4_fmr_master_dma_unmap(dev, slave, be64_to_cpu(vpm->va));

out_addr:
	for (--i, vpm_raw -= vpm_info_size; i >= 0; --i, vpm_raw -= vpm_info_size) {
		vpm  = (struct vpm *)vpm_raw;
		va  = be64_to_cpu(vpm->va);
		if (mlx4_UNMAP_ICM(dev, va, 1))
			mlx4_warn(dev, "MAP ICM wrapper failed to unmap icm"
				  " addr for va 0x%llx with err %d\n",
				  (unsigned long long)va, err);
		mlx4_fmr_master_dma_unmap(dev, slave, va);
	}

	return err;
}

static int mlx4_MAP_ICM(struct mlx4_dev *dev, struct mlx4_icm *icm, u64 virt)
{
	return mlx4_map_cmd(dev, MLX4_CMD_MAP_ICM, icm, virt);
}

int mlx4_UNMAP_ICM_wrapper(struct mlx4_dev *dev, int slave,
			   struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox,
			   struct mlx4_cmd_mailbox *outbox,
			   struct mlx4_cmd_info *cmd)
{
	u32 page_count = vhcr->in_modifier;
	u64 virt = vhcr->in_param;
	int err, i;

	err = mlx4_cmd(dev, virt, page_count, 0, MLX4_CMD_UNMAP_ICM,
		       MLX4_CMD_TIME_CLASS_B, 1);

	if (err) {
		mlx4_dbg(dev, "UNMAP ICM wrapper failed for addr 0x%llx,"
			 " page count %d with err %d\n",
			 (unsigned long long)virt, page_count, err);
		return err;
	}
	if (!vhcr->op_modifier)
	   return err;

	for (i = 0; i < page_count; ++i, virt += PAGE_SIZE)
		mlx4_fmr_master_dma_unmap(dev, slave, virt);

	return 0;
}

int mlx4_UNMAP_ICM(struct mlx4_dev *dev, u64 virt, u32 page_count)
{
	return mlx4_cmd(dev, virt, page_count, 0, MLX4_CMD_UNMAP_ICM,
			MLX4_CMD_TIME_CLASS_B, 1);
}

int mlx4_MAP_ICM_page(struct mlx4_dev *dev, u64 dma_addr, u64 virt)
{
	struct mlx4_cmd_mailbox *mailbox;
	__be64 *inbox;
	int err;

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);
	inbox = mailbox->buf;

	inbox[0] = cpu_to_be64(virt);
	inbox[1] = cpu_to_be64(dma_addr);

	err = mlx4_cmd(dev, mailbox->dma, 1, 0, MLX4_CMD_MAP_ICM,
		       MLX4_CMD_TIME_CLASS_B, 1);

	mlx4_free_cmd_mailbox(dev, mailbox);

	if (!err)
		mlx4_dbg(dev, "Mapped page at %llx to %llx for ICM.\n",
			  (unsigned long long) dma_addr, (unsigned long long) virt);

	return err;
}

int mlx4_MAP_ICM_AUX(struct mlx4_dev *dev, struct mlx4_icm *icm)
{
	return mlx4_map_cmd(dev, MLX4_CMD_MAP_ICM_AUX, icm, -1);
}

int mlx4_UNMAP_ICM_AUX(struct mlx4_dev *dev)
{
	return mlx4_cmd(dev, 0, 0, 0, MLX4_CMD_UNMAP_ICM_AUX, MLX4_CMD_TIME_CLASS_B, 1);
}

static struct mlx4_icm *mlx4_alloc_fmr(struct mlx4_dev *dev, int npages,
				    gfp_t gfp_mask)
{
	struct mlx4_icm *icm;
	struct mlx4_icm_chunk *chunk;
	int i;

	icm = kzalloc(sizeof *icm, gfp_mask & ~(__GFP_HIGHMEM | __GFP_NOWARN));
	if (!icm) {
		mlx4_dbg(dev, "alloc fmr failed to alloc icm mem\n");
		return NULL;
	}

	icm->refcount = 0;
	INIT_LIST_HEAD(&icm->chunk_list);

	/* Fmr flow maps all pages into first chunk */
	chunk = kzalloc(sizeof *chunk,
			gfp_mask & ~(__GFP_HIGHMEM | __GFP_NOWARN));
	if (!chunk) {
		mlx4_dbg(dev, "alloc fmr failed to alloc chunk mem\n");
		goto out_free_icm;
	}

	/* The memory is allocated but not dma mapped */
	for (i = 0; i < npages; ++i) {
		chunk->fmr_pages[i] = alloc_page(gfp_mask);
		if (!chunk->fmr_pages[i]) {
			mlx4_dbg(dev, "alloc fmr failed to alloc chunk mem\n");
			goto out_free_chunk;
		}
	}

	chunk->npages = npages;
	list_add_tail(&chunk->list, &icm->chunk_list);
	return icm;

out_free_chunk:
	for (; i > 0; --i)
		__free_page(chunk->fmr_pages[i]);
	kfree(chunk);

out_free_icm:
	kfree(icm);

	return NULL;
}

int mlx4_table_get(struct mlx4_dev *dev, struct mlx4_icm_table *table, u32 obj,
		   enum mlx4_mr_flags flags)
{
	u32 i = (obj & (table->num_obj - 1)) /
			(MLX4_TABLE_CHUNK_SIZE / table->obj_size);
	int ret = 0;
	int fmr_flow;
	gfp_t gfp_mask;

	mutex_lock(&table->mutex);

	if (table->icm[i]) {
		++table->icm[i]->refcount;
		goto out;
	}

	fmr_flow = mlx4_fmr_flow(dev, flags);
	gfp_mask = (table->lowmem ? GFP_KERNEL : GFP_HIGHUSER) | __GFP_NOWARN;

	table->icm[i] = fmr_flow ?
			mlx4_alloc_fmr(dev, MLX4_TABLE_CHUNK_PAGES, gfp_mask) :
			mlx4_alloc_icm(dev, MLX4_TABLE_CHUNK_PAGES, gfp_mask,
				       table->coherent);
	if (!table->icm[i]) {
		ret = -ENOMEM;
		goto out;
	}

	ret = fmr_flow ?
		mlx4_MAP_FMR(dev, table->icm[i], table->virt +
			     (u64) i * MLX4_TABLE_CHUNK_SIZE) :
		mlx4_MAP_ICM(dev, table->icm[i], table->virt +
			     (u64) i * MLX4_TABLE_CHUNK_SIZE);

	if (ret) {
		mlx4_free_icm(dev, table->icm[i], table->coherent, flags);
		table->icm[i] = NULL;
		ret = -ENOMEM;
		goto out;
	}

	++table->icm[i]->refcount;
	table->icm[i]->chunk_size = MLX4_TABLE_CHUNK_SIZE;

out:
	mutex_unlock(&table->mutex);
	return ret;
}

void mlx4_table_put(struct mlx4_dev *dev, struct mlx4_icm_table *table, u32 obj,
		    enum mlx4_mr_flags flags)
{
	u32 i;
	u64 offset;

	int fmr_flow;

	i = (obj & (table->num_obj - 1)) / (MLX4_TABLE_CHUNK_SIZE / table->obj_size);

	mutex_lock(&table->mutex);

	if (--table->icm[i]->refcount > 0)
		goto out;

	fmr_flow = mlx4_fmr_flow(dev, flags);
	offset = i * MLX4_TABLE_CHUNK_SIZE;
	if (fmr_flow)
		mlx4_UNMAP_FMR(dev, table->virt + offset,
			       table->icm[i]->chunk_size / MLX4_ICM_PAGE_SIZE,
			       table->icm[i]);
	else
		mlx4_UNMAP_ICM(dev, table->virt + offset,
			       table->icm[i]->chunk_size / MLX4_ICM_PAGE_SIZE);

	mlx4_free_icm(dev, table->icm[i], table->coherent, flags);
	table->icm[i] = NULL;

out:
	mutex_unlock(&table->mutex);
}

void *mlx4_table_find(struct mlx4_dev *dev, struct mlx4_icm_table *table,
		      u32 obj, dma_addr_t *dma_handle,
		      enum mlx4_mr_flags flags)
{
	int offset, dma_offset, i;
	u64 idx;
	struct mlx4_icm_chunk *chunk;
	struct mlx4_icm *icm;
	struct page *page = NULL;

	if (!table->lowmem)
		return NULL;

	mutex_lock(&table->mutex);

	idx = (u64) (obj & (table->num_obj - 1)) * table->obj_size;
	icm = table->icm[idx / MLX4_TABLE_CHUNK_SIZE];
	dma_offset = offset = idx % MLX4_TABLE_CHUNK_SIZE;

	if (!icm)
		goto out;

	if (mlx4_fmr_flow(dev, flags)) {
		/* fmr flow maps all pages into first chunk */
		chunk = list_empty(&icm->chunk_list) ? NULL :
			list_entry(icm->chunk_list.next, struct mlx4_icm_chunk,
				   list);
		if (!chunk)
			return NULL;

		page = chunk->fmr_pages[offset / PAGE_SIZE];
		offset %= PAGE_SIZE;
		goto out;
	}
	list_for_each_entry(chunk, &icm->chunk_list, list) {
		for (i = 0; i < chunk->npages; ++i) {
			if (dma_handle && dma_offset >= 0) {
				if (sg_dma_len(&chunk->mem[i]) > dma_offset)
					*dma_handle = sg_dma_address(&chunk->mem[i]) +
						dma_offset;
				dma_offset -= sg_dma_len(&chunk->mem[i]);
			}
			/*
			 * DMA mapping can merge pages but not split them,
			 * so if we found the page, dma_handle has already
			 * been assigned to.
			 */
			if (chunk->mem[i].length > offset) {
				page = sg_page(&chunk->mem[i]);
				goto out;
			}
			offset -= chunk->mem[i].length;
		}
	}

out:
	mutex_unlock(&table->mutex);
	return page ? lowmem_page_address(page) + offset : NULL;
}

int mlx4_table_get_range(struct mlx4_dev *dev, struct mlx4_icm_table *table,
			 u32 start, u32 end, enum mlx4_mr_flags flags)
{
	int inc = MLX4_TABLE_CHUNK_SIZE / table->obj_size;
	int err;
	u32 i;

	for (i = start; i <= end; i += inc) {
		err = mlx4_table_get(dev, table, i, flags);
		if (err)
			goto fail;
	}

	return 0;

fail:
	while (i > start) {
		i -= inc;
		mlx4_table_put(dev, table, i, flags);
	}

	return err;
}

void mlx4_table_put_range(struct mlx4_dev *dev, struct mlx4_icm_table *table,
			  u32 start, u32 end, enum mlx4_mr_flags flags)
{
	u32 i;

	for (i = start; i <= end; i += MLX4_TABLE_CHUNK_SIZE / table->obj_size)
		mlx4_table_put(dev, table, i, flags);
}

int mlx4_init_icm_table(struct mlx4_dev *dev, struct mlx4_icm_table *table,
			u64 virt, int obj_size, u32 nobj, int reserved,
			int use_lowmem, int use_coherent)
{
	int obj_per_chunk;
	int num_icm;
	unsigned chunk_size;
	int i;
	u64 size;

	obj_per_chunk = MLX4_TABLE_CHUNK_SIZE / obj_size;
	num_icm = (nobj + obj_per_chunk - 1) / obj_per_chunk;

	table->icm      = kcalloc(num_icm, sizeof *table->icm, GFP_KERNEL);
	if (!table->icm)
		return -ENOMEM;

	for (i = 0; i < num_icm; ++i)
		table->icm[i] = NULL;

	table->virt     = virt;
	table->num_icm  = num_icm;
	table->num_obj  = nobj;
	table->obj_size = obj_size;
	table->lowmem   = use_lowmem;
	table->coherent = use_coherent;
	mutex_init(&table->mutex);

	size = (u64) nobj * obj_size;
	for (i = 0; i * MLX4_TABLE_CHUNK_SIZE < reserved * obj_size; ++i) {
		chunk_size = MLX4_TABLE_CHUNK_SIZE;
		if ((i + 1) * MLX4_TABLE_CHUNK_SIZE > size)
			chunk_size = PAGE_ALIGN(size -
				i * MLX4_TABLE_CHUNK_SIZE);

		table->icm[i] = mlx4_alloc_icm(dev, chunk_size >> PAGE_SHIFT,
					       (use_lowmem ? GFP_KERNEL : GFP_HIGHUSER) |
					       __GFP_NOWARN, use_coherent);
		if (!table->icm[i])
			goto err;
		if (mlx4_MAP_ICM(dev, table->icm[i], virt +
				 i * MLX4_TABLE_CHUNK_SIZE)) {
			mlx4_free_icm(dev, table->icm[i], use_coherent,
				      MLX4_MR_FLAG_NONE);
			table->icm[i] = NULL;
			goto err;
		}

		/*
		 * Add a reference to this ICM chunk so that it never
		 * gets freed (since it contains reserved firmware objects).
		 */
		++table->icm[i]->refcount;
		table->icm[i]->chunk_size = chunk_size;
	}

	return 0;

err:
	for (i = 0; i < num_icm; ++i)
		if (table->icm[i]) {
			mlx4_UNMAP_ICM(dev, virt + i * MLX4_TABLE_CHUNK_SIZE,
				       table->icm[i]->chunk_size /
				       MLX4_ICM_PAGE_SIZE);
			mlx4_free_icm(dev, table->icm[i], use_coherent,
				      MLX4_MR_FLAG_NONE);
		}

	return -ENOMEM;
}

void mlx4_cleanup_icm_table(struct mlx4_dev *dev, struct mlx4_icm_table *table,
			    enum mlx4_mr_flags flags)
{
	int i;

	for (i = 0; i < table->num_icm; ++i) {
		if (!table->icm[i])
			continue;

		if (mlx4_fmr_flow(dev, flags))
			mlx4_UNMAP_FMR(dev, table->virt + i * MLX4_TABLE_CHUNK_SIZE,
				       table->icm[i]->chunk_size / MLX4_ICM_PAGE_SIZE,
				       table->icm[i]);
		else
			mlx4_UNMAP_ICM(dev, table->virt + i * MLX4_TABLE_CHUNK_SIZE,
				       table->icm[i]->chunk_size /
				       MLX4_ICM_PAGE_SIZE);

		mlx4_free_icm(dev, table->icm[i], table->coherent, flags);
	}

	kfree(table->icm);
	table->icm = NULL;
}
