// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#ifdef CONFIG_DEBUG_FS

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/pci.h>
#include "struct.h"
#include "debugfs.h"
#include "mcs_reg.h"
#include "cn20k/npc.h"

#define MAX_MCS_PORTS	20

#define rvu_dbg_NULL NULL
#define rvu_dbg_open_NULL NULL

static void npc_subbank_srch_order_dbgfs_usage(void)
{
	pr_err("Usage: echo \"[0]=[8],[1]=7,[2]=30,...[31]=0\" > <debugfs>/subbank_srch_order\n");
}

static int
npc_subbank_srch_order_parse_n_fill(struct rvu *rvu, char *options, int num_subbanks)
{
	unsigned long w1 = 0, w2 = 0;
	char *p, *last, *t1, *t2;
	int (*arr)[2];
	int idx, val;
	int cnt, ret;

	cnt = 0;

	options[strcspn(options, "\r\n")] = 0;
	last = strrchr(options, ' ');

	arr = kcalloc(num_subbanks, sizeof(*arr), GFP_KERNEL);
	if (!arr)
		return -ENOMEM;

	while ((p = strsep(&options, " ,")) != NULL) {
		if (!*p)
			continue;

		t1 = strsep(&p, "=");
		t2 = strsep(&p, "");

		if (strlen(t1) < 3) {
			pr_err("%s:%d Bad Token %s=%s\n",
			       __func__, __LINE__, t1, t2);
			goto err;
		}

		if (t1[0] != '[' || t1[strlen(t1) - 1] != ']') {
			pr_err("%s:%d Bad Token %s=%s\n",
			       __func__, __LINE__, t1, t2);
			goto err;
		}

		t1[0] = ' ';
		t1[strlen(t1) - 1] = ' ';
		t1 = strim(t1);

		ret = kstrtoint(t1, 10, &idx);
		if (ret) {
			pr_err("%s:%d Bad Token %s=%s\n",
			       __func__, __LINE__, t1, t2);
			goto err;
		}

		ret = kstrtoint(t2, 10, &val);
		if (ret) {
			pr_err("%s:%d Bad Token %s=%s\n",
			       __func__, __LINE__, t1, t2);
			goto err;
		}

		(*(arr + cnt))[0] = idx;
		(*(arr + cnt))[1] = val;

		cnt++;
	}

	if (cnt != num_subbanks) {
		pr_err("Could find %u tokens, but exact %u tokens needed\n",
		       cnt, num_subbanks);
		goto err;
	}

	for (int i = 0; i < cnt; i++) {
		w1 |= BIT_ULL((*(arr + i))[0]);
		w2 |= BIT_ULL((*(arr + i))[1]);
	}

	if (bitmap_weight(&w1, cnt) != cnt) {
		pr_err("Missed to fill for [%lu]=\n",
		       find_first_zero_bit(&w1, cnt));
		goto err;
	}

	if (bitmap_weight(&w2, cnt) != cnt) {
		pr_err("Missed to fill value %lu\n",
		       find_first_zero_bit(&w2, cnt));
		goto err;
	}

	npc_cn20k_search_order_set(rvu, arr, cnt);

	kfree(arr);
	return 0;
err:
	kfree(arr);
	return -EINVAL;
}

static ssize_t
npc_subbank_srch_order_write(struct file *file, const char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	struct npc_priv_t *npc_priv;
	struct rvu *rvu;
	char buf[1024];
	int len;

	npc_priv = npc_priv_get();

	rvu = file->private_data;

	len = simple_write_to_buffer(buf, sizeof(buf), ppos, user_buf, count);
	if (npc_subbank_srch_order_parse_n_fill(rvu, buf, npc_priv->num_subbanks)) {
		npc_subbank_srch_order_dbgfs_usage();
		return -EFAULT;
	}

	return len;
}

static ssize_t
npc_subbank_srch_order_read(struct file *file, char __user *user_buf,
			    size_t count, loff_t *ppos)
{
	struct npc_priv_t *npc_priv;
	bool restricted_order;
	const int *srch_order;
	struct rvu *rvu;
	char buf[1024];
	int len = 0;

	npc_priv = npc_priv_get();
	rvu = file->private_data;

	len += snprintf(buf + len, sizeof(buf) - len, "%s",
			"Usage: echo \"[0]=0,[1]=1,[2]=2,..[31]=31\" > <debugfs>/subbank_srch_order\n");

	len += snprintf(buf + len, sizeof(buf) - len, "%s",
			"Search order\n");

	srch_order = npc_cn20k_search_order_get(&restricted_order);

	for (int i = 0;  i < npc_priv->num_subbanks; i++)
		len += snprintf(buf + len, sizeof(buf) - len, "[%d]=%d,",
				i, srch_order[i]);

	len += snprintf(buf + len - 1, sizeof(buf) - len, "%s", "\n");

	if (restricted_order)
		len += snprintf(buf + len, sizeof(buf) - len,
				"Restricted allocation for subbanks %u, %u\n",
				npc_priv->num_subbanks - 1, 0);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations npc_subbank_srch_order_ops = {
	.open           = simple_open,
	.write		= npc_subbank_srch_order_write,
	.read		= npc_subbank_srch_order_read,
};

#define RVU_DEBUG_SEQ_FOPS(name, read_op, write_op)	\
static int rvu_dbg_open_##name(struct inode *inode, struct file *file) \
{ \
	return single_open(file, rvu_dbg_##read_op, inode->i_private); \
} \
static const struct file_operations rvu_dbg_##name##_fops = { \
	.owner		= THIS_MODULE, \
	.open		= rvu_dbg_open_##name, \
	.read		= seq_read, \
	.write		= rvu_dbg_##write_op, \
	.llseek		= seq_lseek, \
	.release	= single_release, \
}

static int npc_mcam_layout_show(struct seq_file *s, void *unused)
{
	struct npc_priv_t *npc_priv;
	struct npc_subbank *sb;
	unsigned int bw0, bw1;
	int i, j, sbd;
	int pf1, pf2;
	bool e0, e1;
	void *map;

	npc_priv = s->private;

	sbd = npc_priv->subbank_depth;

	for (i = npc_priv->num_subbanks - 1; i >= 0; i--) {
		sb = &npc_priv->sb[i];
		mutex_lock(&sb->lock);

		if (sb->flags & NPC_SUBBANK_FLAG_FREE)
			goto next;

		bw0 = bitmap_weight(sb->b0map, npc_priv->subbank_depth);
		if (sb->key_type == NPC_MCAM_KEY_X4) {
			seq_printf(s, "\n\nsubbank:%u, x4, free=%u, used=%u\n",
				   sb->idx, sb->free_cnt, bw0);

			for (j = sbd - 1; j >= 0; j--) {
				if (!test_bit(j, sb->b0map))
					continue;

				map = xa_load(&npc_priv->xa_idx2pf_map, sb->b0b + j);
				pf1 = xa_to_value(map);

				seq_printf(s, "\t%u(%#x)\n", sb->b0b + j, pf1);
			}
			goto next;
		}

		bw1 = bitmap_weight(sb->b1map, npc_priv->subbank_depth);
		seq_printf(s, "\n\nsubbank:%u, x2, free=%u, used=%u\n",
			   sb->idx, sb->free_cnt, bw0 + bw1);
		seq_printf(s, "bank1(%u)\t\tbank0(%u)\n", bw1, bw0);

		for (j = sbd - 1; j >= 0; j--) {
			e0 = test_bit(j, sb->b0map);
			e1 = test_bit(j, sb->b1map);

			if (!e1 && !e0)
				continue;

			if (e1 && e0) {
				map = xa_load(&npc_priv->xa_idx2pf_map, sb->b0b + j);
				pf1 = xa_to_value(map);

				map = xa_load(&npc_priv->xa_idx2pf_map, sb->b1b + j);
				pf2 = xa_to_value(map);

				seq_printf(s, "%u(%#x)\t\t%u(%#x)\n",
					   sb->b1b + j, pf2,
					   sb->b0b + j, pf1);

				continue;
			}

			if (e0) {
				map = xa_load(&npc_priv->xa_idx2pf_map, sb->b0b + j);
				pf1 = xa_to_value(map);
				seq_printf(s, "\t\t\t%u(%#x)\n", sb->b0b + j, pf1);
				continue;
			}

			map = xa_load(&npc_priv->xa_idx2pf_map, sb->b1b + j);
			pf1 = xa_to_value(map);
			seq_printf(s, "%u(%#x)\n", sb->b1b + j, pf1);
		}
next:
		mutex_unlock(&sb->lock);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(npc_mcam_layout);

static int npc_mcam_default_show(struct seq_file *s, void *unused)
{
	struct npc_priv_t *npc_priv;
	unsigned long index;
	u16 ptr[4], pcifunc;
	struct rvu *rvu;
	int rc, i;
	void *map;

	npc_priv = npc_priv_get();
	rvu = s->private;

	seq_puts(s, "\npcifunc\tBcast\tmcast\tpromisc\tucast\n");

	xa_for_each(&npc_priv->xa_pf_map, index, map) {
		pcifunc = index;

		for (i = 0; i < ARRAY_SIZE(ptr); i++)
			ptr[i] = USHRT_MAX;

		rc = npc_cn20k_dft_rules_idx_get(rvu, pcifunc, &ptr[0],
						 &ptr[1], &ptr[2], &ptr[3]);
		if (rc)
			continue;

		seq_printf(s, "%#x\t", pcifunc);
		for (i = 0; i < ARRAY_SIZE(ptr); i++) {
			if (ptr[i] != USHRT_MAX)
				seq_printf(s, "%u\t", ptr[i]);
			else
				seq_puts(s, "\t");
		}
		seq_puts(s, "\n");
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(npc_mcam_default);

int npc_cn20k_debugfs_init(struct rvu *rvu)
{
	struct npc_priv_t *npc_priv = npc_priv_get();
	struct dentry *npc_dentry;

	npc_dentry = debugfs_create_file("mcam_layout", 0444, rvu->rvu_dbg.npc,
					 npc_priv, &npc_mcam_layout_fops);

	if (!npc_dentry)
		return -EFAULT;

	npc_dentry = debugfs_create_file("subbank_srch_order", 0644,
					 rvu->rvu_dbg.npc,
					 rvu, &npc_subbank_srch_order_ops);

	if (!npc_dentry)
		return -EFAULT;

	npc_dentry = debugfs_create_file("mcam_default", 0444, rvu->rvu_dbg.npc,
					 rvu, &npc_mcam_default_fops);

	if (!npc_dentry)
		return -EFAULT;

	return 0;
}

void npc_cn20k_debugfs_deinit(struct rvu *rvu)
{
	debugfs_remove_recursive(rvu->rvu_dbg.npc);
}

void print_nix_cn20k_sq_ctx(struct seq_file *m,
			    struct nix_cn20k_sq_ctx_s *sq_ctx)
{
	seq_printf(m, "W0: ena \t\t\t%d\nW0: qint_idx \t\t\t%d\n",
		   sq_ctx->ena, sq_ctx->qint_idx);
	seq_printf(m, "W0: substream \t\t\t0x%03x\nW0: sdp_mcast \t\t\t%d\n",
		   sq_ctx->substream, sq_ctx->sdp_mcast);
	seq_printf(m, "W0: cq \t\t\t\t%d\nW0: sqe_way_mask \t\t%d\n\n",
		   sq_ctx->cq, sq_ctx->sqe_way_mask);

	seq_printf(m, "W1: smq \t\t\t%d\nW1: cq_ena \t\t\t%d\nW1: xoff\t\t\t%d\n",
		   sq_ctx->smq, sq_ctx->cq_ena, sq_ctx->xoff);
	seq_printf(m, "W1: sso_ena \t\t\t%d\nW1: smq_rr_weight\t\t%d\n",
		   sq_ctx->sso_ena, sq_ctx->smq_rr_weight);
	seq_printf(m, "W1: default_chan\t\t%d\nW1: sqb_count\t\t\t%d\n\n",
		   sq_ctx->default_chan, sq_ctx->sqb_count);

	seq_printf(m, "W1: smq_rr_count_lb \t\t%d\n", sq_ctx->smq_rr_count_lb);
	seq_printf(m, "W2: smq_rr_count_ub \t\t%d\n", sq_ctx->smq_rr_count_ub);
	seq_printf(m, "W2: sqb_aura \t\t\t%d\nW2: sq_int \t\t\t%d\n",
		   sq_ctx->sqb_aura, sq_ctx->sq_int);
	seq_printf(m, "W2: sq_int_ena \t\t\t%d\nW2: sqe_stype \t\t\t%d\n",
		   sq_ctx->sq_int_ena, sq_ctx->sqe_stype);

	seq_printf(m, "W3: max_sqe_size\t\t%d\nW3: cq_limit\t\t\t%d\n",
		   sq_ctx->max_sqe_size, sq_ctx->cq_limit);
	seq_printf(m, "W3: lmt_dis \t\t\t%d\nW3: mnq_dis \t\t\t%d\n",
		   sq_ctx->lmt_dis, sq_ctx->mnq_dis);
	seq_printf(m, "W3: smq_next_sq\t\t\t%d\nW3: smq_lso_segnum\t\t%d\n",
		   sq_ctx->smq_next_sq, sq_ctx->smq_lso_segnum);
	seq_printf(m, "W3: tail_offset \t\t%d\nW3: smenq_offset\t\t%d\n",
		   sq_ctx->tail_offset, sq_ctx->smenq_offset);
	seq_printf(m, "W3: head_offset\t\t\t%d\nW3: smenq_next_sqb_vld\t\t%d\n\n",
		   sq_ctx->head_offset, sq_ctx->smenq_next_sqb_vld);

	seq_printf(m, "W3: smq_next_sq_vld\t\t%d\nW3: smq_pend\t\t\t%d\n",
		   sq_ctx->smq_next_sq_vld, sq_ctx->smq_pend);
	seq_printf(m, "W4: next_sqb \t\t\t%llx\n\n", sq_ctx->next_sqb);
	seq_printf(m, "W5: tail_sqb \t\t\t%llx\n\n", sq_ctx->tail_sqb);
	seq_printf(m, "W6: smenq_sqb \t\t\t%llx\n\n", sq_ctx->smenq_sqb);
	seq_printf(m, "W7: smenq_next_sqb \t\t%llx\n\n",
		   sq_ctx->smenq_next_sqb);

	seq_printf(m, "W8: head_sqb\t\t\t%llx\n\n", sq_ctx->head_sqb);

	seq_printf(m, "W9: vfi_lso_total\t\t%d\n", sq_ctx->vfi_lso_total);
	seq_printf(m, "W9: vfi_lso_sizem1\t\t%d\nW9: vfi_lso_sb\t\t\t%d\n",
		   sq_ctx->vfi_lso_sizem1, sq_ctx->vfi_lso_sb);
	seq_printf(m, "W9: vfi_lso_mps\t\t\t%d\nW9: vfi_lso_vlan0_ins_ena\t%d\n",
		   sq_ctx->vfi_lso_mps, sq_ctx->vfi_lso_vlan0_ins_ena);
	seq_printf(m, "W9: vfi_lso_vlan1_ins_ena\t%d\nW9: vfi_lso_vld \t\t%d\n\n",
		   sq_ctx->vfi_lso_vld, sq_ctx->vfi_lso_vlan1_ins_ena);

	seq_printf(m, "W10: scm_lso_rem \t\t%llu\n\n",
		   (u64)sq_ctx->scm_lso_rem);
	seq_printf(m, "W11: octs \t\t\t%llu\n\n", (u64)sq_ctx->octs);
	seq_printf(m, "W12: pkts \t\t\t%llu\n\n", (u64)sq_ctx->pkts);
	seq_printf(m, "W13: aged_drop_octs \t\t\t%llu\n\n",
		   (u64)sq_ctx->aged_drop_octs);
	seq_printf(m, "W13: aged_drop_pkts \t\t\t%llu\n\n",
		   (u64)sq_ctx->aged_drop_pkts);
	seq_printf(m, "W14: dropped_octs \t\t%llu\n\n",
		   (u64)sq_ctx->dropped_octs);
	seq_printf(m, "W15: dropped_pkts \t\t%llu\n\n",
		   (u64)sq_ctx->dropped_pkts);
}

void print_nix_cn20k_cq_ctx(struct seq_file *m,
			    struct nix_cn20k_aq_enq_rsp *rsp)
{
	struct nix_cn20k_cq_ctx_s *cq_ctx = &rsp->cq;

	seq_printf(m, "W0: base \t\t\t%llx\n\n", cq_ctx->base);

	seq_printf(m, "W1: wrptr \t\t\t%llx\n", (u64)cq_ctx->wrptr);
	seq_printf(m, "W1: avg_con \t\t\t%d\nW1: cint_idx \t\t\t%d\n",
		   cq_ctx->avg_con, cq_ctx->cint_idx);
	seq_printf(m, "W1: cq_err \t\t\t%d\nW1: qint_idx \t\t\t%d\n",
		   cq_ctx->cq_err, cq_ctx->qint_idx);
	seq_printf(m, "W1: bpid \t\t\t%d\nW1: bp_ena \t\t\t%d\n\n",
		   cq_ctx->bpid, cq_ctx->bp_ena);

	seq_printf(m, "W1: lbpid_high \t\t\t0x%03x\n", cq_ctx->lbpid_high);
	seq_printf(m, "W1: lbpid_med \t\t\t0x%03x\n", cq_ctx->lbpid_med);
	seq_printf(m, "W1: lbpid_low \t\t\t0x%03x\n", cq_ctx->lbpid_low);
	seq_printf(m, "(W1: lbpid) \t\t\t0x%03x\n",
		   cq_ctx->lbpid_high << 6 | cq_ctx->lbpid_med << 3 |
		   cq_ctx->lbpid_low);
	seq_printf(m, "W1: lbp_ena \t\t\t\t%d\n\n", cq_ctx->lbp_ena);

	seq_printf(m, "W2: update_time \t\t%d\nW2:avg_level \t\t\t%d\n",
		   cq_ctx->update_time, cq_ctx->avg_level);
	seq_printf(m, "W2: head \t\t\t%d\nW2:tail \t\t\t%d\n\n",
		   cq_ctx->head, cq_ctx->tail);

	seq_printf(m, "W3: cq_err_int_ena \t\t%d\nW3:cq_err_int \t\t\t%d\n",
		   cq_ctx->cq_err_int_ena, cq_ctx->cq_err_int);
	seq_printf(m, "W3: qsize \t\t\t%d\nW3:stashing \t\t\t%d\n",
		   cq_ctx->qsize, cq_ctx->stashing);

	seq_printf(m, "W3: caching \t\t\t%d\n", cq_ctx->caching);
	seq_printf(m, "W3: lbp_frac \t\t\t%d\n", cq_ctx->lbp_frac);
	seq_printf(m, "W3: stash_thresh \t\t\t%d\n",
		   cq_ctx->stash_thresh);

	seq_printf(m, "W3: msh_valid \t\t\t%d\nW3:msh_dst \t\t\t%d\n",
		   cq_ctx->msh_valid, cq_ctx->msh_dst);

	seq_printf(m, "W3: cpt_drop_err_en \t\t\t%d\n",
		   cq_ctx->cpt_drop_err_en);
	seq_printf(m, "W3: ena \t\t\t%d\n",
		   cq_ctx->ena);
	seq_printf(m, "W3: drop_ena \t\t\t%d\nW3: drop \t\t\t%d\n",
		   cq_ctx->drop_ena, cq_ctx->drop);
	seq_printf(m, "W3: bp \t\t\t\t%d\n\n", cq_ctx->bp);

	seq_printf(m, "W4: lbpid_ext \t\t\t\t%d\n\n", cq_ctx->lbpid_ext);
	seq_printf(m, "W4: bpid_ext \t\t\t\t%d\n\n", cq_ctx->bpid_ext);
}

void print_npa_cn20k_aura_ctx(struct seq_file *m,
			      struct npa_cn20k_aq_enq_rsp *rsp)
{
	struct npa_cn20k_aura_s *aura = &rsp->aura;

	seq_printf(m, "W0: Pool addr\t\t%llx\n", aura->pool_addr);

	seq_printf(m, "W1: ena\t\t\t%d\nW1: pool caching\t%d\n",
		   aura->ena, aura->pool_caching);
	seq_printf(m, "W1: avg con\t\t%d\n", aura->avg_con);
	seq_printf(m, "W1: pool drop ena\t%d\nW1: aura drop ena\t%d\n",
		   aura->pool_drop_ena, aura->aura_drop_ena);
	seq_printf(m, "W1: bp_ena\t\t%d\nW1: aura drop\t\t%d\n",
		   aura->bp_ena, aura->aura_drop);
	seq_printf(m, "W1: aura shift\t\t%d\nW1: avg_level\t\t%d\n",
		   aura->shift, aura->avg_level);

	seq_printf(m, "W2: count\t\t%llu\nW2: nix_bpid\t\t%d\n",
		   (u64)aura->count, aura->bpid);

	seq_printf(m, "W3: limit\t\t%llu\nW3: bp\t\t\t%d\nW3: fc_ena\t\t%d\n",
		   (u64)aura->limit, aura->bp, aura->fc_ena);

	seq_printf(m, "W3: fc_up_crossing\t%d\nW3: fc_stype\t\t%d\n",
		   aura->fc_up_crossing, aura->fc_stype);
	seq_printf(m, "W3: fc_hyst_bits\t%d\n", aura->fc_hyst_bits);

	seq_printf(m, "W4: fc_addr\t\t%llx\n", aura->fc_addr);

	seq_printf(m, "W5: pool_drop\t\t%d\nW5: update_time\t\t%d\n",
		   aura->pool_drop, aura->update_time);
	seq_printf(m, "W5: err_int \t\t%d\nW5: err_int_ena\t\t%d\n",
		   aura->err_int, aura->err_int_ena);
	seq_printf(m, "W5: thresh_int\t\t%d\nW5: thresh_int_ena \t%d\n",
		   aura->thresh_int, aura->thresh_int_ena);
	seq_printf(m, "W5: thresh_up\t\t%d\nW5: thresh_qint_idx\t%d\n",
		   aura->thresh_up, aura->thresh_qint_idx);
	seq_printf(m, "W5: err_qint_idx \t%d\n", aura->err_qint_idx);

	seq_printf(m, "W6: thresh\t\t%llu\n", (u64)aura->thresh);
	seq_printf(m, "W6: fc_msh_dst\t\t%d\n", aura->fc_msh_dst);
}

void print_npa_cn20k_pool_ctx(struct seq_file *m,
			      struct npa_cn20k_aq_enq_rsp *rsp)
{
	struct npa_cn20k_pool_s *pool = &rsp->pool;

	seq_printf(m, "W0: Stack base\t\t%llx\n", pool->stack_base);

	seq_printf(m, "W1: ena \t\t%d\nW1: nat_align \t\t%d\n",
		   pool->ena, pool->nat_align);
	seq_printf(m, "W1: stack_caching\t%d\n",
		   pool->stack_caching);
	seq_printf(m, "W1: buf_offset\t\t%d\nW1: buf_size\t\t%d\n",
		   pool->buf_offset, pool->buf_size);

	seq_printf(m, "W2: stack_max_pages \t%d\nW2: stack_pages\t\t%d\n",
		   pool->stack_max_pages, pool->stack_pages);

	seq_printf(m, "W4: stack_offset\t%d\nW4: shift\t\t%d\nW4: avg_level\t\t%d\n",
		   pool->stack_offset, pool->shift, pool->avg_level);
	seq_printf(m, "W4: avg_con \t\t%d\nW4: fc_ena\t\t%d\nW4: fc_stype\t\t%d\n",
		   pool->avg_con, pool->fc_ena, pool->fc_stype);
	seq_printf(m, "W4: fc_hyst_bits\t%d\nW4: fc_up_crossing\t%d\n",
		   pool->fc_hyst_bits, pool->fc_up_crossing);
	seq_printf(m, "W4: update_time\t\t%d\n", pool->update_time);

	seq_printf(m, "W5: fc_addr\t\t%llx\n", pool->fc_addr);

	seq_printf(m, "W6: ptr_start\t\t%llx\n", pool->ptr_start);

	seq_printf(m, "W7: ptr_end\t\t%llx\n", pool->ptr_end);

	seq_printf(m, "W8: err_int\t\t%d\nW8: err_int_ena\t\t%d\n",
		   pool->err_int, pool->err_int_ena);
	seq_printf(m, "W8: thresh_int\t\t%d\n", pool->thresh_int);
	seq_printf(m, "W8: thresh_int_ena\t%d\nW8: thresh_up\t\t%d\n",
		   pool->thresh_int_ena, pool->thresh_up);
	seq_printf(m, "W8: thresh_qint_idx\t%d\nW8: err_qint_idx\t%d\n",
		   pool->thresh_qint_idx, pool->err_qint_idx);
	seq_printf(m, "W8: fc_msh_dst\t\t%d\n", pool->fc_msh_dst);
}

static int rvu_dbg_mcs_rx_port_mapped_display(struct seq_file *filp, void *unused)
{
	struct mcs *mcs = filp->private;

	for (int port = 0; port < MAX_MCS_PORTS; port++) {
		seq_printf(filp, "\n=======Port%d======\n", port);

		seq_puts(filp, "\n=======Secy stats======\n");
		seq_printf(filp, "Ctrl bcast pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_IFCTLBCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Ctrl Mcast pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_IFCTLMCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Ctrl ucast pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_IFCTLUCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Ctrl octets: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_IFCTLOCTETS_PORTMAPPED_X(port)));
		seq_printf(filp, "Unctrl bcast cnt: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_IFUNCTLBCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Unctrl mcast pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_IFUNCTLMCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Unctrl ucast pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_IFUNCTLUCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Unctrl octets: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_IFUNCTLOCTETS_PORTMAPPED_X(port)));
		seq_printf(filp, "Octet decrypted: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_OCTETSSECYDECRYPTED_PORTMAPPED_X(port)));
		seq_printf(filp, "octet validated: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_OCTETSSECYVALIDATE_PORTMAPPED_X(port)));
		seq_printf(filp, "Pkts on disable port: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSCTRLPORTDISABLED_PORTMAPPED_X(port)));
		seq_printf(filp, "Pkts with badtag: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSECYBADTAG_PORTMAPPED_X(port)));
		seq_printf(filp, "Pkts with no SA(sectag.tci.c=0): %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSECYNOSA_PORTMAPPED_X(port)));
		seq_printf(filp, "Pkts with nosaerror: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSECYNOSAERROR_PORTMAPPED_X(port)));
		seq_printf(filp, "Tagged ctrl pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSECYTAGGEDCTL_PORTMAPPED_X(port)));
		seq_printf(filp, "Untagged pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSECYUNTAGGED_PORTMAPPED_X(port)));
		seq_printf(filp, "Ctrl pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSECYCTL_PORTMAPPED_X(port)));

		seq_puts(filp, "\n=======SC stats======\n");
		seq_printf(filp, "CAM hits: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSCCAMHIT_PORTMAPPED_X(port)));
		seq_printf(filp, "Invalid packets: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSCINVALID_PORTMAPPED_X(port)));
		seq_printf(filp, "Late or Delayed packets: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSCLATEORDELAYED_PORTMAPPED_X(port)));
		seq_printf(filp, "Not valid packets: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSCNOTVALID_PORTMAPPED_X(port)));
		seq_printf(filp, "Unchecked packets: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSCUNCHECKEDOROK_PORTMAPPED_X(port)));

		seq_puts(filp, "\n=======SA stats======\n");
		seq_printf(filp, "Not using SA errors: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSANOTUSINGSAERROR_PORTMAPPED(port)));
		seq_printf(filp, "SA Ok: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSAOK_PORTMAPPED_X(port)));
		seq_printf(filp, "SA unused packets: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSAUNUSEDSA_PORTMAPPED_X(port)));
	}

	return 0;
}

RVU_DEBUG_SEQ_FOPS(mcs_rx_port_mapped, mcs_rx_port_mapped_display, NULL);

static int rvu_dbg_mcs_tx_port_mapped_display(struct seq_file *filp, void *unused)
{
	struct mcs *mcs = filp->private;

	for (int port = 0; port < MAX_MCS_PORTS; port++) {
		seq_printf(filp, "\n=======Port%d======\n", port);

		seq_puts(filp, "\n=======Secy stats======\n");
		seq_printf(filp, "Ctrl bcast pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_IFCTLBCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Ctrl Mcast pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_IFCTLMCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Ctrl ucast pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_IFCTLUCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Ctrl octets: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_IFCTLOCTETS_PORTMAPPED_X(port)));
		seq_printf(filp, "Unctrl bcast cnt: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_IFUNCTLBCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Unctrl mcast pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_IFUNCTLMCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Unctrl ucast pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_IFUNCTLUCPKTS_PORTMAPPED_X(port)));
		seq_printf(filp, "Unctrl octets: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_IFUNCTLOCTETS_PORTMAPPED_X(port)));
		seq_printf(filp, "Octets encrypted: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_OCTETSSECYENCRYPTED_PORTMAPPED_X(port)));
		seq_printf(filp, "octets protected: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_OCTETSSECYPROTECTED_PORTMAPPED_X(port)));
		seq_printf(filp, "No active SA pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_PKTSSECYNOACTIVESA_PORTMAPPED_X(port)));
		seq_printf(filp, "Packets sent on disabled port: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_PKTSCTRLPORTDISABLED_PORTMAPPED_X(port)));
		seq_printf(filp, "Packets too long: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_PKTSSECYTOOLONG_PORTMAPPED_X(port)));
		seq_printf(filp, "Packets untagged: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_TX_PKTSSECYUNTAGGED_PORTMAPPED_X(port)));

		seq_puts(filp, "\n=======SC stats======\n");
		seq_printf(filp, "Encrypted pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSCENCRYPTED_PORTMAPPED_X(port)));
		seq_printf(filp, "Protected pkts: %lld\n",
			   mcs_reg_read(mcs, MCSX_CSE_RX_PKTSSCPROTECTED_PORTMAPPED_X(port)));
	}

	return 0;
}

RVU_DEBUG_SEQ_FOPS(mcs_tx_port_mapped, mcs_tx_port_mapped_display, NULL);

void rvu_cn20ka_handle_port_mapped_stats(struct rvu *rvu, struct mcs *mcs, int dir)
{
	struct dentry *parent;

	parent = dir == MCS_RX ? rvu->rvu_dbg.mcs_rx : rvu->rvu_dbg.mcs_tx;

	if (dir == MCS_RX)
		debugfs_create_file("port_mapped", 0600, parent,
				    mcs, &rvu_dbg_mcs_rx_port_mapped_fops);
	else if (dir == MCS_TX)
		debugfs_create_file("port_mapped", 0600, parent,
				    mcs, &rvu_dbg_mcs_tx_port_mapped_fops);
}

#endif /* CONFIG_DEBUG_FS */
