// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifdef CONFIG_DEBUG_FS

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "rvu_struct.h"
#include "rvu_reg.h"
#include "rvu.h"
#include "cgx.h"

enum {
	CGX_STAT0,
	CGX_STAT1,
	CGX_STAT2,
	CGX_STAT3,
	CGX_STAT4,
	CGX_STAT5,
	CGX_STAT6,
	CGX_STAT7,
	CGX_STAT8,
	CGX_STAT9,
	CGX_STAT10,
	CGX_STAT11,
	CGX_STAT12,
	CGX_STAT13,
	CGX_STAT14,
	CGX_STAT15,
	CGX_STAT16,
	CGX_STAT17,
	CGX_STAT18,
};

static char *cgx_rx_stats_fields[] = {
	[CGX_STAT0]	= "Received packets",
	[CGX_STAT1]	= "Octets of received packets",
	[CGX_STAT2]	= "Received PAUSE packets",
	[CGX_STAT3]	= "Received PAUSE and control packets",
	[CGX_STAT4]	= "Filtered DMAC0 (NIX-bound) packets",
	[CGX_STAT5]	= "Filtered DMAC0 (NIX-bound) octets",
	[CGX_STAT6]	= "Packets dropped due to RX FIFO full",
	[CGX_STAT7]	= "Octets dropped due to RX FIFO full",
	[CGX_STAT8]	= "Error packets",
	[CGX_STAT9]	= "Filtered DMAC1 (NCSI-bound) packets",
	[CGX_STAT10]	= "Filtered DMAC1 (NCSI-bound) octets",
	[CGX_STAT11]	= "NCSI-bound packets dropped",
	[CGX_STAT12]	= "NCSI-bound octets dropped",
};

static char *cgx_tx_stats_fields[] = {
	[CGX_STAT0]	= "Packets dropped due to excessive collisions",
	[CGX_STAT1]	= "Packets dropped due to excessive deferral",
	[CGX_STAT2]	= "Multiple collisions before successful transmission",
	[CGX_STAT3]	= "Single collisions before successful transmission",
	[CGX_STAT4]	= "Total octets sent on the interface",
	[CGX_STAT5]	= "Total frames sent on the interface",
	[CGX_STAT6]	= "Packets sent with an octet count < 64",
	[CGX_STAT7]	= "Packets sent with an octet count == 64",
	[CGX_STAT8]	= "Packets sent with an octet count of 65–127",
	[CGX_STAT9]	= "Packets sent with an octet count of 128-255",
	[CGX_STAT10]	= "Packets sent with an octet count of 256-511",
	[CGX_STAT11]	= "Packets sent with an octet count of 512-1023",
	[CGX_STAT12]	= "Packets sent with an octet count of 1024-1518",
	[CGX_STAT13]	= "Packets sent with an octet count of > 1518",
	[CGX_STAT14]	= "Packets sent to a broadcast DMAC",
	[CGX_STAT15]	= "Packets sent to the multicast DMAC",
	[CGX_STAT16]	= "Transmit underflow and were truncated",
	[CGX_STAT17]    = "Control/PAUSE packets sent",
};

#define rvu_dbg_NULL NULL
#define RVU_DEBUG_FOPS(name, read_op, write_op) \
static const struct file_operations rvu_dbg_##name##_fops = { \
	.owner = THIS_MODULE, \
	.open = simple_open, \
	.read = rvu_dbg_##read_op, \
	.write = rvu_dbg_##write_op \
}

/* Dumps current provisioning status of all RVU block LFs */
static ssize_t rvu_dbg_rsrc_attach_status(struct file *filp,
					  char __user *buffer,
					  size_t count, loff_t *ppos)
{
	int index, off = 0, flag = 0, go_back = 0, off_prev;
	struct rvu *rvu = filp->private_data;
	int lf, pf, vf, pcifunc;
	struct rvu_block block;
	int bytes_not_copied;
	int buf_size = 1024;
	char *buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;
	if (count < buf_size)
		return -ENOSPC;

	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOSPC;
	off +=	scnprintf(&buf[off], PAGE_SIZE - off, "\npcifunc\t\t");
	for (index = 0; index < BLK_COUNT; index++)
		if (strlen(rvu->hw->block[index].name))
			off +=	scnprintf(&buf[off], PAGE_SIZE - off, "%*s\t",
					  (index - 1) * 2,
					  rvu->hw->block[index].name);
	off += scnprintf(&buf[off], PAGE_SIZE - off, "\n");
	for (pf = 0; pf < rvu->hw->total_pfs; pf++) {
		for (vf = 0; vf <= rvu->hw->total_vfs; vf++) {
			pcifunc = pf << 10 | vf;
			go_back = scnprintf(&buf[off], PAGE_SIZE - off,
					    "0x%3x\t\t", pcifunc);

			off += go_back;
			for (index = 0; index < BLKTYPE_MAX; index++) {
				block = rvu->hw->block[index];
				if (!strlen(block.name))
					continue;
				off_prev = off;
				for (lf = 0; lf < block.lf.max; lf++) {
					if (block.fn_map[lf] != pcifunc)
						continue;
					flag = 1;
					off += scnprintf(&buf[off], PAGE_SIZE -
							off, "%3d,", lf);
				}
				if (flag && off_prev != off)
					off--;
				else
					go_back++;
				off += scnprintf(&buf[off], PAGE_SIZE - off,
						"\t");
			}
			if (!flag)
				off -= go_back;
			else
				flag = 0;
			off--;
			off +=	scnprintf(&buf[off], PAGE_SIZE - off, "\n");
		}
	}

	bytes_not_copied = copy_to_user(buffer, buf, off);
	kfree(buf);

	if (bytes_not_copied)
		return -EFAULT;

	*ppos = off;
	return off;
}
RVU_DEBUG_FOPS(rsrc_status, rsrc_attach_status, NULL);

/* The 'qsize' entry dumps current Aura/Pool context Qsize
 * and each context's current enable/disable status in a bitmap.
 */
static ssize_t rvu_dbg_npa_qsize_display(struct file *filp,
					 const char __user *buffer,
					 size_t count, loff_t *ppos)
{
	char *cmd_buf, *cmd_buf_tmp, *buf, *subtoken;
	struct rvu *rvu = filp->private_data;
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	struct rvu_pfvf *pfvf;
	int bytes_not_copied;
	u64 pcifunc;
	int npalf;
	int ret;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;

	cmd_buf = kzalloc(count + 1, GFP_KERNEL);
	if (!cmd_buf)
		return count;
	bytes_not_copied = copy_from_user(cmd_buf, buffer, count);
	if (bytes_not_copied) {
		kfree(cmd_buf);
		return -EFAULT;
	}
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = cmd_buf_tmp - cmd_buf + 1;
	}
	subtoken = strsep(&cmd_buf, " ");
	ret = subtoken ? kstrtoint(subtoken, 10, &npalf) : -EINVAL;
	if (cmd_buf)
		ret = -EINVAL;

	if (!strncmp(subtoken, "help", 4) || (ret < 0)) {
		pr_info("Use echo <npalf > qsize\n");
		goto npa_qsize_display_done;
	}

	block = &hw->block[BLKTYPE_NPA];
	if (npalf < 0 || npalf >= block->lf.max) {
		pr_info("Invalid NPALF, valid range is 0-%d\n",
			block->lf.max - 1);
		goto npa_qsize_display_done;
	}

	pcifunc = block->fn_map[npalf];
	if (!pcifunc) {
		pr_info("This NPALF is not attached to any RVU PFFUNC\n");
		goto npa_qsize_display_done;
	}

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		pr_info("failed to allocate memory\n");
		goto npa_qsize_display_done;
	}

	if (!pfvf->aura_ctx) {
		pr_info("Aura context is not initialized\n");
	} else {
		bitmap_print_to_pagebuf(false, buf, pfvf->aura_bmap,
					pfvf->aura_ctx->qsize);
		pr_info("Aura count  : %d\n", pfvf->aura_ctx->qsize);
		pr_info("Aura context ena/dis bitmap : %s\n", buf);
	}

	if (!pfvf->pool_ctx) {
		pr_info("Pool context is not initialized\n");
	} else {
		bitmap_print_to_pagebuf(false, buf, pfvf->pool_bmap,
					pfvf->pool_ctx->qsize);
		pr_info("Pool count  : %d\n", pfvf->pool_ctx->qsize);
		pr_info("Pool context ena/dis bitmap : %s\n", buf);
	}
	kfree(buf);
npa_qsize_display_done:
	kfree(cmd_buf);
	return count;
}

/* Dumps given NPA Aura's context */
static void print_npa_aura_ctx(struct npa_aq_enq_rsp *rsp)
{
	struct npa_aura_s *aura = &rsp->aura;

	pr_info("W0: Pool addr\t\t%llx\n", aura->pool_addr);

	pr_info("W1: ena\t\t\t%d\nW1: pool caching\t\t%d\n",
		aura->ena, aura->pool_caching);
	pr_info("W1: pool way mask\t%d\nW1: avg con\t\t%d\n",
		aura->pool_way_mask, aura->avg_con);
	pr_info("W1: pool drop ena\t%d\nW1: aura drop ena\t%d\n",
		aura->pool_drop_ena, aura->aura_drop_ena);
	pr_info("W1: bp_ena\t\t%d\nW1: aura drop\t\t%d\n",
		aura->aura_drop, aura->shift);
	pr_info("W1: aura shift\t\t%d\nW1: avg_level\t\t%d\n",
		aura->bp_ena, aura->avg_level);

	pr_info("W2: count\t\t%llu\nW2: nix0_bpid\t\t%d\nW2: nix1_bpid\t\t%d\n",
		(u64)aura->count, aura->nix0_bpid, aura->nix1_bpid);

	pr_info("W3: limit\t\t%llu\nW3: bp\t\t\t%d\nW3: fc_ena\t\t%d\n",
		(u64)aura->limit, aura->bp, aura->fc_ena);
	pr_info("W3: fc_up_crossing\t%d\nW3: fc_stype\t\t%d\n",
		aura->fc_up_crossing, aura->fc_stype);
	pr_info("W3: fc_hyst_bits\t\t%d\n", aura->fc_hyst_bits);

	pr_info("W4: fc_addr\t\t%llx\n", aura->fc_addr);

	pr_info("W5: pool_drop\t\t%d\nW5: update_time\t\t%d\n",
		aura->pool_drop, aura->update_time);
	pr_info("W5: err_int \t\t%d\nW5: err_int_ena\t\t%d\n",
		aura->err_int, aura->err_int_ena);
	pr_info("W5: thresh_int\t\t%d\nW5: thresh_int_ena \t%d\n",
		aura->thresh_int, aura->thresh_int_ena);
	pr_info("W5: thresh_up\t\t%d\nW5: thresh_qint_idx\t%d\n",
		aura->thresh_qint_idx, aura->err_qint_idx);
	pr_info("W5: err_qint_idx \t\t%d\n", aura->thresh_up);

	pr_info("W6: thresh\t\t%llu\n", (u64)aura->thresh);
}

/* Dumps given NPA Pool's context */
static void print_npa_pool_ctx(struct npa_aq_enq_rsp *rsp)
{
	struct npa_pool_s *pool = &rsp->pool;

	pr_info("W0: Stack base\t\t%llx\n", pool->stack_base);

	pr_info("W1: ena \t\t\t%d\nW1: nat_align \t\t%d\n",
		pool->ena, pool->nat_align);
	pr_info("W1: stack_caching\t%d\nW1: stack_way_mask\t%d\n",
		pool->stack_caching, pool->stack_way_mask);
	pr_info("W1: buf_offset\t\t%d\nW1: buf_size\t\t%d\n",
		pool->buf_offset, pool->buf_size);

	pr_info("W2: stack_max_pages \t%d\nW2: stack_pages\t\t%d\n",
		pool->stack_max_pages, pool->stack_pages);

	pr_info("W3: op_pc \t\t%llu\n", (u64)pool->op_pc);

	pr_info("W4: stack_offset\t\t%d\nW4: shift\t\t%d\nW4: avg_level\t\t%d\n",
		pool->stack_offset, pool->shift, pool->avg_level);
	pr_info("W4: avg_con \t\t%d\nW4: fc_ena\t\t%d\nW4: fc_stype\t\t%d\n",
		pool->avg_con, pool->fc_ena, pool->fc_stype);
	pr_info("W4: fc_hyst_bits\t\t%d\nW4: fc_up_crossing\t%d\n",
		pool->fc_hyst_bits, pool->fc_up_crossing);
	pr_info("W4: update_time\t\t%d\n", pool->update_time);

	pr_info("W5: fc_addr\t\t%llx\n", pool->fc_addr);

	pr_info("W6: ptr_start\t\t%llx\n", pool->ptr_start);

	pr_info("W7: ptr_end\t\t%llx\n", pool->ptr_end);

	pr_info("W8: err_int\t\t%d\nW8: err_int_ena\t\t%d\n",
		pool->err_int, pool->err_int_ena);
	pr_info("W8: thresh_int\t\t%d\n", pool->thresh_int);
	pr_info("W8: thresh_int_ena\t%d\nW8: thresh_up\t\t%d\n",
		pool->thresh_int_ena, pool->thresh_up);
	pr_info("W8: thresh_qint_idx\t%d\nW8: err_qint_idx\t\t%d\n",
		pool->thresh_qint_idx, pool->err_qint_idx);
}

/* Reads aura/pool's ctx from admin queue */
static void read_npa_ctx(struct rvu *rvu, bool all,
			 int npalf, int id, int ctype)
{
	void (*print_npa_ctx)(struct npa_aq_enq_rsp *rsp);
	struct rvu_hwinfo *hw = rvu->hw;
	struct npa_aq_enq_req aq_req;
	struct npa_aq_enq_rsp rsp;
	struct rvu_block *block;
	struct rvu_pfvf *pfvf;
	int aura, rc, max_id;
	u64 pcifunc;
	int blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NPA, 0);
	if (blkaddr < 0)
		return;

	block = &hw->block[blkaddr];
	if (npalf < 0 || npalf >= block->lf.max) {
		pr_info("Invalid NPALF, valid range is 0-%d\n",
			block->lf.max - 1);
		return;
	}

	pcifunc = block->fn_map[npalf];
	if (!pcifunc) {
		pr_info("This NPALF is not attached to any RVU PFFUNC\n");
		return;
	}

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	if (ctype == NPA_AQ_CTYPE_AURA && !pfvf->aura_ctx) {
		pr_info("Aura context is not initialized\n");
		return;
	} else if (ctype == NPA_AQ_CTYPE_POOL && !pfvf->pool_ctx) {
		pr_info("Pool context is not initialized\n");
		return;
	}

	memset(&aq_req, 0, sizeof(struct npa_aq_enq_req));
	aq_req.hdr.pcifunc = pcifunc;
	aq_req.ctype = ctype;
	aq_req.op = NPA_AQ_INSTOP_READ;
	if (ctype == NPA_AQ_CTYPE_AURA) {
		max_id =  pfvf->aura_ctx->qsize;
		print_npa_ctx = print_npa_aura_ctx;
	} else {
		max_id =  pfvf->pool_ctx->qsize;
		print_npa_ctx = print_npa_pool_ctx;
	}

	if (id < 0 || id >= max_id) {
		pr_info("Invalid %s, valid range is 0-%d\n",
			(ctype == NPA_AQ_CTYPE_AURA) ? "aura" : "pool",
			max_id - 1);
		return;
	}

	if (all)
		id = 0;
	else
		max_id = id + 1;

	for (aura = id; aura < max_id; aura++) {
		aq_req.aura_id = aura;
		pr_info("======%s : %d=======\n",
			(ctype == NPA_AQ_CTYPE_AURA) ? "AURA" : "POOL",
			aq_req.aura_id);
		rc = rvu_npa_aq_enq_inst(rvu, &aq_req, &rsp);
		if (rc) {
			pr_info("Failed to read context\n");
			return;
		}
		print_npa_ctx(&rsp);
	}
}

static int parse_cmd_buffer_ctx(char *cmd_buf, size_t *count,
				const char __user *buffer, int *npalf,
				int *id, bool *all)
{
	int bytes_not_copied;
	char *cmd_buf_tmp;
	char *subtoken;
	int ret;

	bytes_not_copied = copy_from_user(cmd_buf, buffer, *count);
	if (bytes_not_copied)
		return -EFAULT;

	cmd_buf[*count] = '\0';
	cmd_buf_tmp = strchr(cmd_buf, '\n');

	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		*count = cmd_buf_tmp - cmd_buf + 1;
	}

	subtoken = strsep(&cmd_buf, " ");
	ret = subtoken ? kstrtoint(subtoken, 10, npalf) : -EINVAL;
	if (ret < 0)
		return ret;
	subtoken = strsep(&cmd_buf, " ");
	if (subtoken && strcmp(subtoken, "all") == 0) {
		*all = true;
	} else{
		ret = subtoken ? kstrtoint(subtoken, 10, id) : -EINVAL;
		if (ret < 0)
			return ret;
	}
	if (cmd_buf)
		return -EINVAL;
	return ret;
}

static ssize_t rvu_dbg_npa_ctx_display(struct file *filp,
				       const char __user *buffer,
				       size_t count, loff_t *ppos, int ctype)
{
	char *cmd_buf, *ctype_string = (ctype ==  NPA_AQ_CTYPE_AURA) ?
					"aura" : "pool";
	struct rvu *rvu = filp->private_data;
	int npalf, id = 0;
	bool all = false;

	if ((*ppos != 0) || !count)
		return 0;

	cmd_buf = kzalloc(count + 1, GFP_KERNEL);

	if (!cmd_buf)
		return count;
	if (parse_cmd_buffer_ctx(cmd_buf, &count, buffer,
				 &npalf, &id, &all) < 0) {
		pr_info("Usage: echo <npalf> [%s number/all] > %s_ctx\n",
			ctype_string, ctype_string);
	} else {
		read_npa_ctx(rvu, all, npalf, id, ctype);
	}

	kfree(cmd_buf);
	return count;
}
RVU_DEBUG_FOPS(npa_qsize, NULL, npa_qsize_display);

static ssize_t rvu_dbg_npa_aura_ctx_display(struct file *filp,
					    const char __user *buffer,
					    size_t count, loff_t *ppos)
{
	return  rvu_dbg_npa_ctx_display(filp, buffer, count, ppos,
					NPA_AQ_CTYPE_AURA);
}
RVU_DEBUG_FOPS(npa_aura_ctx,  NULL, npa_aura_ctx_display);

static ssize_t rvu_dbg_npa_pool_ctx_display(struct file *filp,
					    const char __user *buffer,
					    size_t count, loff_t *ppos)
{
	return  rvu_dbg_npa_ctx_display(filp, buffer, count, ppos,
					NPA_AQ_CTYPE_POOL);
}
RVU_DEBUG_FOPS(npa_pool_ctx, NULL, npa_pool_ctx_display);

static void rvu_dbg_npa_init(struct rvu *rvu)
{
	const struct device *dev = &rvu->pdev->dev;
	struct dentry *pfile;

	rvu->rvu_dbg.npa = debugfs_create_dir("npa", rvu->rvu_dbg.root);
	if (!rvu->rvu_dbg.npa)
		return;

	pfile = debugfs_create_file("qsize", 0600, rvu->rvu_dbg.npa, rvu,
				    &rvu_dbg_npa_qsize_fops);
	if (!pfile)
		goto create_failed;

	pfile = debugfs_create_file("aura_ctx", 0600, rvu->rvu_dbg.npa, rvu,
				    &rvu_dbg_npa_aura_ctx_fops);
	if (!pfile)
		goto create_failed;

	pfile = debugfs_create_file("pool_ctx", 0600, rvu->rvu_dbg.npa, rvu,
				    &rvu_dbg_npa_pool_ctx_fops);
	if (!pfile)
		goto create_failed;

	return;
create_failed:
	dev_err(dev, "Failed to create debugfs dir/file for NPA\n");
	debugfs_remove_recursive(rvu->rvu_dbg.npa);
}

static int cgx_print_stats(void *cgxd, int lmac_id)
{
	int stat = 0, err = 0;
	u64 tx_stat, rx_stat;

	/* Rx stats */
	pr_info("\n=======RX_STATS======\n\n");
	while (stat < CGX_RX_STATS_COUNT) {
		err = cgx_get_rx_stats(cgxd, lmac_id, stat, &rx_stat);
		if (err)
			return err;
		pr_info("%s: %llu\n", cgx_rx_stats_fields[stat], rx_stat);
		stat++;
	}

	/* Tx stats */
	stat = 0;
	pr_info("\n=======TX_STATS======\n\n");
	while (stat < CGX_TX_STATS_COUNT) {
		err = cgx_get_tx_stats(cgxd, lmac_id, stat, &tx_stat);
		if (err)
			return err;
		pr_info("%s: %llu\n", cgx_tx_stats_fields[stat], tx_stat);
		stat++;
	}
	return err;
}

static ssize_t rvu_dbg_cgx_stat_display(struct file *filp,
					char __user *buffer,
					size_t count, loff_t *ppos)
{
	void *data = filp->private_data;
	struct dentry *current_dir;
	int err = 0, lmac_id = 0;
	char *subtoken, *buf;

	current_dir = filp->f_path.dentry->d_parent;
	buf = kzalloc(strlen(current_dir->d_name.name), GFP_KERNEL);
	if (!buf)
		return count;

	memcpy(buf, current_dir->d_name.name,
	       strlen(current_dir->d_name.name));

	subtoken = strsep(&buf, "c");
	if (kstrtoint(buf, 10, &lmac_id) >= 0) {
		err = cgx_print_stats(data, lmac_id);
		if (err)
			goto stat_display_done;
	}

stat_display_done:
	kfree(buf);
	return err;
}
RVU_DEBUG_FOPS(cgx_stat, cgx_stat_display, NULL);

static void rvu_dbg_cgx_init(struct rvu *rvu)
{
	const struct device *dev = &rvu->pdev->dev;
	struct dentry *pfile;
	int i, lmac_id;
	char dname[20];
	void *cgx;

	rvu->rvu_dbg.cgx_root = debugfs_create_dir("cgx", rvu->rvu_dbg.root);

	for (i = 0; i < cgx_get_cgx_cnt(); i++) {
		cgx = cgx_get_pdata(i);
		/* cgx debugfs dir */
		sprintf(dname, "cgx%d", i);
		rvu->rvu_dbg.cgx = debugfs_create_dir(dname,
					rvu->rvu_dbg.cgx_root);
		for (lmac_id = 0; lmac_id < cgx_get_lmac_cnt(cgx); lmac_id++) {
			/* lmac debugfs dir */
			sprintf(dname, "lmac%d", lmac_id);
			rvu->rvu_dbg.lmac =
				debugfs_create_dir(dname, rvu->rvu_dbg.cgx);

			pfile =	debugfs_create_file("stats", 0600,
						    rvu->rvu_dbg.lmac, cgx,
						    &rvu_dbg_cgx_stat_fops);
			if (!pfile)
				goto create_failed;
		}
	}
	return;

create_failed:
	dev_err(dev, "Failed to create debugfs dir/file for CGX\n");
	debugfs_remove_recursive(rvu->rvu_dbg.cgx_root);
}

/* Dumps given nix_sq's context */
static void print_nix_sq_ctx(struct nix_aq_enq_rsp *rsp)
{
	struct  nix_sq_ctx_s *sq_ctx = &rsp->sq;

	pr_info("W0: sqe_way_mask \t\t%d\nW0: cq \t\t\t\t%d\n",
		sq_ctx->sqe_way_mask, sq_ctx->cq);
	pr_info("W0: sdp_mcast \t\t\t%d\nW0: substream \t\t\t0x%03x\n",
		sq_ctx->sdp_mcast, sq_ctx->substream);
	pr_info("W0: qint_idx \t\t\t%d\nW0: ena \t\t\t\t%d\n\n",
		sq_ctx->qint_idx, sq_ctx->ena);

	pr_info("W1: sqb_count \t\t\t%d\nW1: default_chan \t\t%d\n",
		sq_ctx->sqb_count, sq_ctx->default_chan);
	pr_info("W1: smq_rr_quantum \t\t%d\nW1: sso_ena \t\t\t%d\n",
		sq_ctx->smq_rr_quantum, sq_ctx->sso_ena);
	pr_info("W1: xoff \t\t\t%d\nW1: cq_ena \t\t\t%d\nW1: smq\t\t\t\t%d\n\n",
		sq_ctx->xoff, sq_ctx->cq_ena, sq_ctx->smq);

	pr_info("W2: sqe_stype \t\t\t%d\nW2: sq_int_ena \t\t\t%d\n",
		sq_ctx->sqe_stype, sq_ctx->sq_int_ena);
	pr_info("W2: sq_int  \t\t\t%d\nW2: sqb_aura \t\t\t%d\n",
		sq_ctx->sq_int, sq_ctx->sqb_aura);
	pr_info("W2: smq_rr_count \t\t%d\n\n",  sq_ctx->smq_rr_count);

	pr_info("W3: smq_next_sq_vld\t\t%d\nW3: smq_pend\t\t\t%d\n",
		sq_ctx->smq_next_sq_vld, sq_ctx->smq_pend);
	pr_info("W3: smenq_next_sqb_vld  \t\t%d\nW3: head_offset\t\t\t%d\n",
		sq_ctx->smenq_next_sqb_vld, sq_ctx->head_offset);
	pr_info("W3: smenq_offset\t\t\t%d\nW3: tail_offset \t\t\t%d\n",
		sq_ctx->smenq_offset, sq_ctx->tail_offset);
	pr_info("W3: smq_lso_segnum \t\t%d\nW3: smq_next_sq \t\t\t%d\n",
		sq_ctx->smq_lso_segnum, sq_ctx->smq_next_sq);
	pr_info("W3: mnq_dis \t\t\t%d\nW3: lmt_dis \t\t\t%d\n",
		sq_ctx->mnq_dis, sq_ctx->lmt_dis);
	pr_info("W3: cq_limit\t\t\t%d\nW3: max_sqe_size\t\t\t%d\n\n",
		sq_ctx->cq_limit, sq_ctx->max_sqe_size);

	pr_info("W4: next_sqb \t\t\t%llx\n\n", sq_ctx->next_sqb);
	pr_info("W5: tail_sqb \t\t\t%llx\n\n", sq_ctx->tail_sqb);
	pr_info("W6: smenq_sqb \t\t\t%llx\n\n", sq_ctx->smenq_sqb);
	pr_info("W7: smenq_next_sqb \t\t%llx\n\n", sq_ctx->smenq_next_sqb);
	pr_info("W8: head_sqb \t\t\t%llx\n\n", sq_ctx->head_sqb);

	pr_info("W9: vfi_lso_vld \t\t\t%d\nW9: vfi_lso_vlan1_ins_ena\t%d\n",
		sq_ctx->vfi_lso_vld, sq_ctx->vfi_lso_vlan1_ins_ena);
	pr_info("W9: vfi_lso_vlan0_ins_ena\t%d\nW9: vfi_lso_mps\t\t\t%d\n",
		sq_ctx->vfi_lso_vlan0_ins_ena, sq_ctx->vfi_lso_mps);
	pr_info("W9: vfi_lso_sb\t\t\t%d\nW9: vfi_lso_sizem1\t\t%d\n",
		sq_ctx->vfi_lso_sb, sq_ctx->vfi_lso_sizem1);
	pr_info("W9: vfi_lso_total\t\t%d\n\n",  sq_ctx->vfi_lso_total);

	pr_info("W10: scm_lso_rem  \t\t%llu\n\n", (u64)sq_ctx->scm_lso_rem);
	pr_info("W11: octs \t\t\t%llu\n\n", (u64)sq_ctx->octs);
	pr_info("W12: pkts \t\t\t%llu\n\n", (u64)sq_ctx->pkts);
	pr_info("W14: dropped_octs \t\t%llu\n\n", (u64)sq_ctx->dropped_octs);
	pr_info("W15: dropped_pkts \t\t%llu\n\n", (u64)sq_ctx->dropped_pkts);
}

/* Dumps given nix_rq's context */
static void print_nix_rq_ctx(struct nix_aq_enq_rsp *rsp)
{
	struct  nix_rq_ctx_s *rq_ctx = &rsp->rq;

	pr_info("W0: wqe_aura \t\t\t%d\nW0: substream \t\t\t0x%03x\n",
		rq_ctx->wqe_aura, rq_ctx->substream);
	pr_info("W0: cq \t\t\t\t%d\nW0: ena_wqwd \t\t\t%d\n",
		rq_ctx->cq, rq_ctx->ena_wqwd);
	pr_info("W0: ipsech_ena \t\t\t%d\nW0: sso_ena \t\t\t%d\n",
		rq_ctx->ipsech_ena, rq_ctx->sso_ena);
	pr_info("W0: ena \t\t\t\t%d\n\n", rq_ctx->ena);

	pr_info("W1: lpb_drop_ena \t\t%d\nW1: spb_drop_ena \t\t%d\n",
		rq_ctx->lpb_drop_ena, rq_ctx->spb_drop_ena);
	pr_info("W1: xqe_drop_ena \t\t%d\nW1: wqe_caching \t\t\t%d\n",
		rq_ctx->xqe_drop_ena, rq_ctx->wqe_caching);
	pr_info("W1: pb_caching \t\t\t%d\nW1: sso_tt \t\t\t%d\n",
		rq_ctx->pb_caching, rq_ctx->sso_tt);
	pr_info("W1: sso_grp \t\t\t%d\nW1: lpb_aura \t\t\t%d\n",
		rq_ctx->sso_grp, rq_ctx->lpb_aura);
	pr_info("W1: spb_aura \t\t\t%d\n\n", rq_ctx->spb_aura);

	pr_info("W2: xqe_hdr_split \t\t%d\nW2: xqe_imm_copy \t\t%d\n",
		rq_ctx->xqe_hdr_split, rq_ctx->xqe_imm_copy);
	pr_info("W2: xqe_imm_size \t\t%d\nW2: later_skip \t\t\t%d\n",
		rq_ctx->xqe_imm_size, rq_ctx->later_skip);
	pr_info("W2: first_skip \t\t\t%d\nW2: lpb_sizem1 \t\t\t%d\n",
		rq_ctx->first_skip, rq_ctx->lpb_sizem1);
	pr_info("W2: spb_ena \t\t\t%d\nW2: wqe_skip \t\t\t%d\n",
		rq_ctx->spb_ena, rq_ctx->wqe_skip);
	pr_info("W2: spb_sizem1 \t\t\t%d\n\n", rq_ctx->spb_sizem1);

	pr_info("W3: spb_pool_pass \t\t%d\nW3: spb_pool_drop \t\t%d\n",
		rq_ctx->spb_pool_pass, rq_ctx->spb_pool_drop);
	pr_info("W3: spb_aura_pass \t\t%d\nW3: spb_aura_drop \t\t%d\n",
		rq_ctx->spb_aura_pass, rq_ctx->spb_aura_drop);
	pr_info("W3: wqe_pool_pass \t\t%d\nW3: wqe_pool_drop \t\t%d\n",
		rq_ctx->wqe_pool_pass, rq_ctx->wqe_pool_drop);
	pr_info("W3: xqe_pass \t\t\t%d\nW3: xqe_drop \t\t\t%d\n\n",
		rq_ctx->xqe_pass, rq_ctx->xqe_drop);

	pr_info("W4: qint_idx \t\t\t%d\nW4: rq_int_ena \t\t\t%d\n",
		rq_ctx->qint_idx, rq_ctx->rq_int_ena);
	pr_info("W4: rq_int \t\t\t%d\nW4: lpb_pool_pass \t\t%d\n",
		rq_ctx->rq_int, rq_ctx->lpb_pool_pass);
	pr_info("W4: lpb_pool_drop \t\t%d\nW4: lpb_aura_pass \t\t%d\n",
		rq_ctx->lpb_pool_drop, rq_ctx->lpb_aura_pass);
	pr_info("W4: lpb_aura_drop \t\t%d\n\n", rq_ctx->lpb_aura_drop);

	pr_info("W5: flow_tagw \t\t\t%d\nW5: bad_utag \t\t\t%d\n",
		rq_ctx->flow_tagw, rq_ctx->bad_utag);
	pr_info("W5: good_utag \t\t\t%d\nW5: ltag \t\t\t%d\n\n",
		rq_ctx->good_utag, rq_ctx->ltag);

	pr_info("W6: octs \t\t\t%llu\n\n", (u64)rq_ctx->octs);
	pr_info("W7: pkts \t\t\t%llu\n\n", (u64)rq_ctx->pkts);
	pr_info("W8: drop_octs \t\t\t%llu\n\n", (u64)rq_ctx->drop_octs);
	pr_info("W9: drop_pkts \t\t\t%llu\n\n", (u64)rq_ctx->drop_pkts);
	pr_info("W10: re_pkts \t\t\t%llu\n", (u64)rq_ctx->re_pkts);
}

/* Dumps given nix_cq's context */
static void print_nix_cq_ctx(struct nix_aq_enq_rsp *rsp)
{
	struct  nix_cq_ctx_s *cq_ctx = &rsp->cq;

	pr_info("W0: base \t\t\t%llx\n\n", cq_ctx->base);

	pr_info("W1: wrptr \t\t\t%llx\n", (u64)cq_ctx->wrptr);
	pr_info("W1: avg_con \t\t\t%d\nW1: cint_idx \t\t\t%d\n",
		cq_ctx->avg_con, cq_ctx->cint_idx);
	pr_info("W1: cq_err \t\t\t%d\nW1: qint_idx \t\t\t%d\n",
		cq_ctx->cq_err, cq_ctx->qint_idx);
	pr_info("W1: bpid  \t\t\t%d\nW1: bp_ena \t\t\t%d\n\n",
		cq_ctx->bpid, cq_ctx->bp_ena);

	pr_info("W2: update_time \t\t\t%d\nW2:avg_level \t\t\t%d\n",
		cq_ctx->update_time, cq_ctx->avg_level);
	pr_info("W2: head \t\t\t%d\nW2:tail \t\t\t\t%d\n\n",
		cq_ctx->head, cq_ctx->tail);

	pr_info("W3: cq_err_int_ena \t\t%d\nW3:cq_err_int \t\t\t%d\n",
		cq_ctx->cq_err_int_ena, cq_ctx->cq_err_int);
	pr_info("W3: qsize \t\t\t%d\nW3:caching \t\t\t%d\n",
		cq_ctx->qsize, cq_ctx->caching);
	pr_info("W3: substream \t\t\t0x%03x\nW3: ena \t\t\t\t%d\n",
		cq_ctx->substream, cq_ctx->ena);
	pr_info("W3: drop_ena \t\t\t%d\nW3: drop \t\t\t%d\n",
		cq_ctx->drop_ena, cq_ctx->drop);
	pr_info("W3: dp \t\t\t\t%d\n\n", cq_ctx->dp);
}

static void read_nix_ctx(struct rvu *rvu, bool all, int nixlf,
			 int id, int ctype, char *ctype_string)
{
	void (*print_nix_ctx)(struct nix_aq_enq_rsp *rsp) = NULL;
	int blkaddr, qidx, rc, max_id = 0;
	struct rvu_hwinfo *hw = rvu->hw;
	struct nix_aq_enq_req aq_req;
	struct nix_aq_enq_rsp rsp;
	struct rvu_block *block;
	struct rvu_pfvf *pfvf;
	u64 pcifunc;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, 0);
	if (blkaddr < 0)
		return;

	block = &hw->block[blkaddr];
	if (nixlf < 0 || nixlf >= block->lf.max) {
		pr_info("Invalid NIX LF, Valid range 0-%d\n",
			block->lf.max - 1);
		return;
	}

	pcifunc = block->fn_map[nixlf];
	if (!pcifunc) {
		pr_info("This NIX LF is not attached to any RVU PFFUNC\n");
		return;
	}

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	if ((ctype == NIX_AQ_CTYPE_SQ) && (!pfvf->sq_ctx)) {
		pr_info("SQ context is not initialized\n");
		return;
	} else if ((ctype == NIX_AQ_CTYPE_RQ) && (!pfvf->rq_ctx)) {
		pr_info("RQ context is not initialized\n");
		return;
	} else if ((ctype == NIX_AQ_CTYPE_CQ) && (!pfvf->cq_ctx)) {
		pr_info("CQ context is not initialized\n");
		return;
	}

	if (ctype == NIX_AQ_CTYPE_SQ) {
		max_id =  pfvf->sq_ctx->qsize;
		print_nix_ctx = print_nix_sq_ctx;
	} else if (ctype == NIX_AQ_CTYPE_RQ) {
		max_id =  pfvf->rq_ctx->qsize;
		print_nix_ctx = print_nix_rq_ctx;
	} else if (ctype == NIX_AQ_CTYPE_CQ) {
		max_id =  pfvf->cq_ctx->qsize;
		print_nix_ctx = print_nix_cq_ctx;
	}

	if (id < 0 || id >= max_id) {
		pr_info("Invalid %s_ctx valid range 0-%d\n",
			ctype_string, max_id - 1);
		return;
	}

	memset(&aq_req, 0, sizeof(struct nix_aq_enq_req));
	aq_req.hdr.pcifunc = pcifunc;
	aq_req.ctype = ctype;
	aq_req.op = NIX_AQ_INSTOP_READ;
	if (all)
		id = 0;
	else
		max_id = id + 1;
	for (qidx = id; qidx < max_id; qidx++) {
		aq_req.qidx = qidx;
		pr_info("=====%s_ctx for nixlf:%d and qidx:%d is=====\n",
			ctype_string, nixlf, aq_req.qidx);
		rc = rvu_mbox_handler_NIX_AQ_ENQ(rvu, &aq_req, &rsp);
		if (rc) {
			pr_info("Failed to read the context\n");
			return;
		}
		print_nix_ctx(&rsp);
	}
}

static ssize_t rvu_dbg_nix_ctx_display(struct file *filp,
				       const char __user *buffer,
				       size_t count, loff_t *ppos, int ctype)
{
	struct rvu *rvu = filp->private_data;
	char *cmd_buf, *ctype_string;
	int nixlf, id = 0;
	bool all = false;

	if ((*ppos != 0) || !count)
		return 0;
	switch (ctype) {
	case NIX_AQ_CTYPE_SQ:
		ctype_string = "sq";
		break;
	case NIX_AQ_CTYPE_RQ:
		ctype_string = "rq";
		break;
	case NIX_AQ_CTYPE_CQ:
	default:
		ctype_string = "cq";
		break;
	}

	cmd_buf = kzalloc(count + 1, GFP_KERNEL);

	if (!cmd_buf)
		return count;
	if (parse_cmd_buffer_ctx(cmd_buf, &count, buffer,
				 &nixlf, &id, &all) < 0) {
		pr_info("Usage: echo <nixlf> [%s number/all] > %s_ctx\n",
			ctype_string, ctype_string);
	} else {
		read_nix_ctx(rvu, all, nixlf, id, ctype, ctype_string);
	}

	kfree(cmd_buf);
	return count;
}

static ssize_t rvu_dbg_nix_sq_ctx_display(struct file *filp,
					  const char __user *buffer,
					  size_t count, loff_t *ppos)
{
	return  rvu_dbg_nix_ctx_display(filp, buffer,
					count, ppos, NIX_AQ_CTYPE_SQ);
}
RVU_DEBUG_FOPS(nix_sq_ctx, NULL, nix_sq_ctx_display);

static ssize_t rvu_dbg_nix_rq_ctx_display(struct file *filp,
					  const char __user *buffer,
					  size_t count, loff_t *ppos)
{
	return  rvu_dbg_nix_ctx_display(filp, buffer,
					count, ppos, NIX_AQ_CTYPE_RQ);
}
RVU_DEBUG_FOPS(nix_rq_ctx, NULL, nix_rq_ctx_display);

static ssize_t rvu_dbg_nix_cq_ctx_display(struct file *filp,
					   const char __user *buffer,
					    size_t count, loff_t *ppos)
{
	return  rvu_dbg_nix_ctx_display(filp, buffer,
					count, ppos, NIX_AQ_CTYPE_CQ);
}
RVU_DEBUG_FOPS(nix_cq_ctx, NULL, nix_cq_ctx_display);

static void rvu_dbg_nix_init(struct rvu *rvu)
{
	const struct device *dev = &rvu->pdev->dev;
	struct dentry *pfile;

	rvu->rvu_dbg.nix = debugfs_create_dir("nix", rvu->rvu_dbg.root);
	if (!rvu->rvu_dbg.nix) {
		pr_info("create debugfs dir failed for nix\n");
		return;
	}

	pfile = debugfs_create_file("sq_ctx", 0600, rvu->rvu_dbg.nix, rvu,
				    &rvu_dbg_nix_sq_ctx_fops);
	if (!pfile)
		goto create_failed;

	pfile = debugfs_create_file("rq_ctx", 0600, rvu->rvu_dbg.nix, rvu,
				    &rvu_dbg_nix_rq_ctx_fops);
	if (!pfile)
		goto create_failed;

	pfile = debugfs_create_file("cq_ctx", 0600, rvu->rvu_dbg.nix, rvu,
				    &rvu_dbg_nix_cq_ctx_fops);
	if (!pfile)
		goto create_failed;

	return;
create_failed:
	dev_err(dev, "Failed to create debugfs dir/file for NIX\n");
	debugfs_remove_recursive(rvu->rvu_dbg.nix);
}

void rvu_dbg_init(struct rvu *rvu)
{
	struct device *dev = &rvu->pdev->dev;
	struct dentry *pfile;

	rvu->rvu_dbg.root = debugfs_create_dir("octeontx2", NULL);
	if (!rvu->rvu_dbg.root) {
		pr_info("%s failed\n", __func__);
		return;
	}
	pfile = debugfs_create_file("rsrc_alloc", 0444, rvu->rvu_dbg.root, rvu,
				    &rvu_dbg_rsrc_status_fops);
	if (!pfile)
		goto create_failed;

	rvu_dbg_npa_init(rvu);

	rvu_dbg_cgx_init(rvu);

	rvu_dbg_nix_init(rvu);

	return;

create_failed:
	dev_err(dev, "Failed to create debugfs dir\n");
	debugfs_remove_recursive(rvu->rvu_dbg.root);
}

void rvu_dbg_exit(struct rvu *rvu)
{
	debugfs_remove_recursive(rvu->rvu_dbg.root);
}
#endif /* CONFIG_DEBUG_FS */
