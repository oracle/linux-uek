// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/debugfs.h>

#include "rvu.h"
#include "rvu_struct.h"
#include "rvu_eblock.h"
#include "rvu_eblock_reg.h"
#include "rvu_psw_mbox.h"

#define rvu_dbg_NULL NULL
#define rvu_dbg_open_NULL NULL

#define RVU_PSW_DEBUG_SEQ_FOPS(name, read_op, write_op)	\
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

static int parse_psw_cmd_buffer(char *cmd_buf, size_t *count, const char __user *buffer,
				u16 *qid, bool *inb)
{
	int ret, bytes_not_copied;
	char *cmd_buf_tmp;
	char *subtoken;

	bytes_not_copied = copy_from_user(cmd_buf, buffer, *count);
	if (bytes_not_copied) {
		kfree(cmd_buf);
		return -EFAULT;
	}

	cmd_buf[*count] = '\0';
	cmd_buf_tmp = strchr(cmd_buf, '\n');

	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		*count = cmd_buf_tmp - cmd_buf + 1;
	}

	subtoken = strsep(&cmd_buf, " ");
	ret = subtoken ? kstrtou16(subtoken, 10, qid) : -EINVAL;
	if (ret < 0)
		return ret;

	subtoken = strsep(&cmd_buf, " ");
	if (subtoken && strcmp(subtoken, "inb") == 0)
		*inb = true;

	if (cmd_buf)
		return -EINVAL;

	return 0;
}

static ssize_t rvu_dbg_psw_cmd_parser(struct file *filp,
				      const char __user *buffer, size_t count,
				      loff_t *ppos)
{
	struct seq_file *seqfile = filp->private_data;
	struct psw_dbg_ctx *ctx = seqfile->private;
	bool inb = false;
	char *cmd_buf;
	u16 qid = 0;
	int ret;

	if (*ppos != 0)
		return 0;

	cmd_buf = kzalloc(count + 1, GFP_KERNEL);

	if (!cmd_buf || !count)
		return count;
	ret = parse_psw_cmd_buffer(cmd_buf, &count, buffer, &qid, &inb);
	if (ret < 0) {
		dev_info(ctx->rvu->dev,
			 "Usage: echo <qid> [inb/outb]  > queue_conf\n");
		goto done;
	} else {
		ctx->qid = qid;
		ctx->inb = inb;
	}

done:
	kfree(cmd_buf);
	return ret ? ret : count;
}

static int rvu_dbg_psw_gid_entries_read(struct seq_file *filp, void *unused)
{
	struct psw_dbg_ctx *ctx = filp->private;
	u8 oqvalid, iqvalid, mvalid;
	int blkaddr = ctx->blkaddr;
	struct rvu *rvu = ctx->rvu;
	u16 num_gid_entries;
	u16 entry;
	u64 reg;

	reg = rvu_read64(rvu, blkaddr, PSW_AF_CONST1);
	num_gid_entries = FIELD_GET(GENMASK_ULL(63, 48), reg);

	seq_puts(filp, "==================================================\n");
	for (entry = 0; entry < num_gid_entries; entry++) {
		reg = rvu_read64(rvu, blkaddr, PSW_AF_GID_ENTRY0(entry));
		iqvalid = reg & BIT_ULL(0);
		oqvalid = reg & BIT_ULL(1);
		mvalid = reg & BIT_ULL(2);
		if (iqvalid || oqvalid || mvalid) {
			seq_printf(filp, "GID Entry %4u\n", entry);
			seq_printf(filp, "iqvalid: %u oqvalid: %u mvalid: %u\n", !!iqvalid,
				   !!oqvalid, !!mvalid);
			seq_printf(filp, "link: %4llu mid: %4llu qid: %4llu\n",
				   FIELD_GET(GENMASK_ULL(61, 48), reg),
				   FIELD_GET(GENMASK_ULL(45, 32), reg),
				   FIELD_GET(GENMASK_ULL(29, 16), reg));
			reg = rvu_read64(rvu, blkaddr, PSW_AF_GID_ENTRY1(entry));
			seq_printf(filp, "rid: %4llu epf_func: 0x%llx\n",
				   FIELD_GET(GENMASK_ULL(24, 16), reg),
				   FIELD_GET(GENMASK_ULL(15, 0), reg));
			seq_puts(filp, "==================================================\n");
		}
	}

	return 0;
}

static int rvu_dbg_psw_fid_entries_read(struct seq_file *filp, void *unused)
{
	struct psw_dbg_ctx *ctx = filp->private;
	struct rvu *rvu = ctx->rvu;
	int blkaddr = ctx->blkaddr;
	u16 num_fid_entries;
	int entry;
	u64 reg;

	reg = rvu_read64(rvu, blkaddr, PSW_AF_CONST1);
	num_fid_entries = FIELD_GET(GENMASK_ULL(31, 16), reg);

	seq_puts(filp, "==================================================\n");
	for (entry = 0; entry < num_fid_entries; entry++) {
		reg = rvu_read64(rvu, blkaddr, PSW_AF_FID_ATTR(entry));
		if (reg & BIT_ULL(0)) {
			seq_printf(filp, "FID Entry %4u\n", entry);
			seq_printf(filp, "epf_num: %llu epf_mask: 0x%llx\n",
				   FIELD_GET(GENMASK_ULL(43, 40), reg),
				   FIELD_GET(GENMASK_ULL(35, 32), reg));
			seq_printf(filp, "evfm1_num: %llu evfm1_mask: 0x%llx\n",
				   FIELD_GET(GENMASK_ULL(30, 24), reg),
				   FIELD_GET(GENMASK_ULL(22, 16), reg));
			seq_printf(filp, "is_epf: %llu ebar: %llu read: %llu read_mask: 0x%llx\n",
				   FIELD_GET(GENMASK_ULL(6, 6), reg),
				   FIELD_GET(GENMASK_ULL(5, 4), reg),
				   FIELD_GET(GENMASK_ULL(3, 3), reg),
				   FIELD_GET(GENMASK_ULL(2, 2), reg));
			reg = rvu_read64(rvu, blkaddr, PSW_AF_FID_BASE(entry));
			seq_printf(filp, "base_mask: 0x%llx base_addr: 0x%llx\n",
				   FIELD_GET(GENMASK_ULL(63, 35), reg),
				   FIELD_GET(GENMASK_ULL(31, 3), reg));
			reg = rvu_read64(rvu, blkaddr, PSW_AF_FID_IND(entry));
			seq_printf(filp, "log2stride: %llu log2size: %llu offset: %llu psw_type: %llu\n",
				   FIELD_GET(GENMASK_ULL(44, 40), reg),
				   FIELD_GET(GENMASK_ULL(36, 32), reg),
				   FIELD_GET(GENMASK_ULL(31, 4), reg),
				   FIELD_GET(GENMASK_ULL(3, 0), reg));
			seq_puts(filp, "==================================================\n");
		}
	}

	return 0;
}

static ssize_t rvu_dbg_psw_qconf_write(struct file *filp, const char __user *buffer,
				       size_t count, loff_t *ppos)
{
	return rvu_dbg_psw_cmd_parser(filp, buffer, count, ppos);
}

static void psw_inbq_ctx_display(struct seq_file *filp)
{
	struct psw_dbg_ctx *ctx = filp->private;
	struct rvu *rvu = ctx->rvu;
	int blkaddr = ctx->blkaddr;
	u16 qid = ctx->qid;
	u64 reg;

	seq_printf(filp, "====Host inb_qidx:%d ctx is=====\n", qid);

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HIX_QCX(qid, 0));
	seq_printf(filp, "W0: ena \t\t\t%lld\nW0: log2ds \t\t\t%lld\nW0: log2qs \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(0, 0), reg), FIELD_GET(GENMASK_ULL(6, 4), reg),
		   FIELD_GET(GENMASK_ULL(11, 8), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HIX_QCX(qid, 1));
	seq_printf(filp, "W1: base_addr \t\t\t0x%llx\n", FIELD_GET(GENMASK_ULL(63, 6), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HIX_QCX(qid, 2));
	seq_printf(filp, "W2: pi \t\t\t\t%lld\nW2: pround \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(15, 0), reg), FIELD_GET(GENMASK_ULL(63, 16), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HIX_QCX(qid, 3));
	seq_printf(filp, "W3: ci \t\t\t\t%lld\n", FIELD_GET(GENMASK_ULL(15, 0), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HIX_QCX(qid, 4));
	seq_printf(filp, "W4: pcie_attr \t\t\t0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HIX_QCX(qid, 5));
	seq_printf(filp, "W5: msix_vec_num \t\t%lld\nW5: msg_type \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(24, 16), reg), FIELD_GET(GENMASK_ULL(9, 8), reg));
	seq_printf(filp, "W5: inplace \t\t\t%lld\nW5: log2bs \t\t\t%lld\nW5: cimode \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(6, 6), reg), FIELD_GET(GENMASK_ULL(5, 4), reg),
		   FIELD_GET(GENMASK_ULL(0, 0), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HIX_QCX(qid, 6));
	seq_printf(filp, "W6: pi_addr \t\t\t0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HIX_QCX(qid, 7));
	seq_printf(filp, "W7: ii \t\t\t\t%lld\nW7: idle \t\t\t%lld\nW7: qerror \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(31, 16), reg), FIELD_GET(GENMASK_ULL(3, 3), reg),
		   FIELD_GET(GENMASK_ULL(0, 0), reg));

	seq_printf(filp, "====Shadow inb_qidx:%d ctx is=====\n", qid);

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHIX_QCX(qid, 0));
	seq_printf(filp, "W0: ena \t\t\t%lld\nW0: log2ds \t\t\t%lld\nW0: log2qs \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(0, 0), reg), FIELD_GET(GENMASK_ULL(6, 4), reg),
		   FIELD_GET(GENMASK_ULL(11, 8), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHIX_QCX(qid, 1));
	seq_printf(filp, "W1: base_addr \t\t\t0x%llx\n", FIELD_GET(GENMASK_ULL(63, 6), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHIX_QCX(qid, 2));
	seq_printf(filp, "W2: pi \t\t\t\t%lld\nW2: pround \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(15, 0), reg), FIELD_GET(GENMASK_ULL(63, 16), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHIX_QCX(qid, 3));
	seq_printf(filp, "W3: ci \t\t\t\t%lld\n", FIELD_GET(GENMASK_ULL(15, 0), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHIX_QCX(qid, 7));
	seq_printf(filp, "W7: ii \t\t\t\t%lld\nW7: idle \t\t\t%lld\nW7: qerror \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(31, 16), reg), FIELD_GET(GENMASK_ULL(3, 3), reg),
		   FIELD_GET(GENMASK_ULL(0, 0), reg));
}

static void psw_outbq_ctx_display(struct seq_file *filp)
{
	struct psw_dbg_ctx *ctx = filp->private;
	struct rvu *rvu = ctx->rvu;
	int blkaddr = ctx->blkaddr;
	u16 qid = ctx->qid;
	u64 reg;

	seq_printf(filp, "====Host outb_qidx:%d ctx is=====\n", qid);

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HOX_QCX(qid, 0));
	seq_printf(filp, "W0: ena \t\t\t%lld\nW0: log2ds \t\t\t%lld\nW0: log2qs \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(0, 0), reg), FIELD_GET(GENMASK_ULL(6, 4), reg),
		   FIELD_GET(GENMASK_ULL(11, 8), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HOX_QCX(qid, 1));
	seq_printf(filp, "W1: base_addr \t\t\t0x%llx\n", FIELD_GET(GENMASK_ULL(63, 6), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HOX_QCX(qid, 2));
	seq_printf(filp, "W2: pi \t\t\t\t%lld\nW2: pround \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(15, 0), reg), FIELD_GET(GENMASK_ULL(63, 16), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HOX_QCX(qid, 3));
	seq_printf(filp, "W3: ci \t\t\t\t%lld\n", FIELD_GET(GENMASK_ULL(15, 0), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HOX_QCX(qid, 4));
	seq_printf(filp, "W4: pcie_attr \t\t\t0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HOX_QCX(qid, 5));
	seq_printf(filp, "W5: incr_pi \t\t\t%lld\nW5: anp_qos \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(24, 24), reg), FIELD_GET(GENMASK_ULL(9, 8), reg));
	seq_printf(filp, "W5: inplace \t\t\t%lld\nW5: log2bs\t\t\t%lld\nW5: notif_qnum \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(6, 6), reg), FIELD_GET(GENMASK_ULL(5, 4), reg),
		   FIELD_GET(GENMASK_ULL(2, 0), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_HOX_QCX(qid, 7));
	seq_printf(filp, "W7: epffunc \t\t\t0x%llx\nW7: qid \t\t\t%lld\nW7: lf \t\t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(63, 48), reg), FIELD_GET(GENMASK_ULL(47, 40), reg),
		   FIELD_GET(GENMASK_ULL(39, 32), reg));
	seq_printf(filp, "W7: ii \t\t\t\t%lld\nW7: idle \t\t\t%lld\nW7: qerror \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(31, 16), reg), FIELD_GET(GENMASK_ULL(3, 3), reg),
		   FIELD_GET(GENMASK_ULL(0, 0), reg));
	seq_printf(filp, "W7: twin \t\t\t%lld\n", FIELD_GET(GENMASK_ULL(7, 4), reg));

	seq_printf(filp, "====Shadow outb_qidx:%d ctx is=====\n", qid);

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHOX_QCX(qid, 0));
	seq_printf(filp, "W0: ena \t\t\t%lld\nW0: log2ds \t\t\t%lld\nW0: log2qs \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(0, 0), reg), FIELD_GET(GENMASK_ULL(6, 4), reg),
		   FIELD_GET(GENMASK_ULL(11, 8), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHOX_QCX(qid, 1));
	seq_printf(filp, "W1: base_addr \t\t\t0x%llx\n", FIELD_GET(GENMASK_ULL(63, 6), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHOX_QCX(qid, 2));
	seq_printf(filp, "W2: pi \t\t\t\t%lld\nW2: pround \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(15, 0), reg), FIELD_GET(GENMASK_ULL(63, 16), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHOX_QCX(qid, 3));
	seq_printf(filp, "W3: ci \t\t\t\t%lld\n", FIELD_GET(GENMASK_ULL(15, 0), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHOX_QCX(qid, 4));
	seq_printf(filp, "W5: ci_addr \t\t\t0x%llx\nW5: ci_msg_en \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(63, 2), reg), FIELD_GET(GENMASK_ULL(0, 0), reg));

	reg = rvu_read64(rvu, blkaddr, PSW_AF_SHOX_QCX(qid, 7));
	seq_printf(filp, "W7: ii \t\t\t\t%lld\nW7: idle \t\t\t%lld\nW7: qerror \t\t\t%lld\n",
		   FIELD_GET(GENMASK_ULL(31, 16), reg), FIELD_GET(GENMASK_ULL(3, 3), reg),
		   FIELD_GET(GENMASK_ULL(0, 0), reg));
}

static int rvu_dbg_psw_qconf_read(struct seq_file *filp, void *unused)
{
	struct psw_dbg_ctx *ctx = filp->private;

	if (ctx->inb)
		psw_inbq_ctx_display(filp);
	else
		psw_outbq_ctx_display(filp);

	return 0;
}

RVU_PSW_DEBUG_SEQ_FOPS(gid_entries, psw_gid_entries_read, NULL);
RVU_PSW_DEBUG_SEQ_FOPS(fid_entries, psw_fid_entries_read, NULL);
RVU_PSW_DEBUG_SEQ_FOPS(queue_conf, psw_qconf_read, psw_qconf_write);

void rvu_psw_dbg_init(struct rvu *rvu, struct psw_dbg_ctx *dbg_ctx, int blkaddr)
{
	if (!rvu->rvu_dbg.root)
		return;
	dbg_ctx->psw = debugfs_create_dir("psw", rvu->rvu_dbg.root);
	if (!dbg_ctx->psw)
		return;

	dbg_ctx->rvu = rvu;
	dbg_ctx->blkaddr = blkaddr;

	debugfs_create_file("gid_entries", 0600, dbg_ctx->psw, dbg_ctx, &rvu_dbg_gid_entries_fops);
	debugfs_create_file("fid_entries", 0600, dbg_ctx->psw, dbg_ctx, &rvu_dbg_fid_entries_fops);
	debugfs_create_file("queue_conf", 0600, dbg_ctx->psw, dbg_ctx, &rvu_dbg_queue_conf_fops);
}
