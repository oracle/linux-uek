/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006, 2007, 2008 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2005, 2006, 2007 Cisco Systems, Inc.  All rights reserved.
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

#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <rdma/ib_smi.h>
#include <linux/semaphore.h>

#include <asm/io.h>

#include "mlx4.h"
#include "fw.h"
#include "icm.h"
#include "fmr_master.h"

#define CMD_POLL_TOKEN 0xffff
#define INBOX_MASK	0xffffffffffffff00ULL

#define CMD_CHAN_VER 1
#define CMD_CHAN_IF_REV 1

enum {
	/* command completed successfully: */
	CMD_STAT_OK		= 0x00,
	/* Internal error (such as a bus error) occurred while processing command: */
	CMD_STAT_INTERNAL_ERR	= 0x01,
	/* Operation/command not supported or opcode modifier not supported: */
	CMD_STAT_BAD_OP		= 0x02,
	/* Parameter not supported or parameter out of range: */
	CMD_STAT_BAD_PARAM	= 0x03,
	/* System not enabled or bad system state: */
	CMD_STAT_BAD_SYS_STATE	= 0x04,
	/* Attempt to access reserved or unallocaterd resource: */
	CMD_STAT_BAD_RESOURCE	= 0x05,
	/* Requested resource is currently executing a command, or is otherwise busy: */
	CMD_STAT_RESOURCE_BUSY	= 0x06,
	/* Required capability exceeds device limits: */
	CMD_STAT_EXCEED_LIM	= 0x08,
	/* Resource is not in the appropriate state or ownership: */
	CMD_STAT_BAD_RES_STATE	= 0x09,
	/* Index out of range: */
	CMD_STAT_BAD_INDEX	= 0x0a,
	/* FW image corrupted: */
	CMD_STAT_BAD_NVMEM	= 0x0b,
	/* Error in ICM mapping (e.g. not enough auxiliary ICM pages to execute command): */
	CMD_STAT_ICM_ERROR	= 0x0c,
	/* Attempt to modify a QP/EE which is not in the presumed state: */
	CMD_STAT_BAD_QP_STATE   = 0x10,
	/* Bad segment parameters (Address/Size): */
	CMD_STAT_BAD_SEG_PARAM	= 0x20,
	/* Memory Region has Memory Windows bound to: */
	CMD_STAT_REG_BOUND	= 0x21,
	/* HCA local attached memory not present: */
	CMD_STAT_LAM_NOT_PRE	= 0x22,
	/* Bad management packet (silently discarded): */
	CMD_STAT_BAD_PKT	= 0x30,
	/* More outstanding CQEs in CQ than new CQ size: */
	CMD_STAT_BAD_SIZE	= 0x40,
	/* Multi Function device support required: */
	CMD_STAT_MULTI_FUNC_REQ	= 0x50,
};

enum {
	HCR_IN_PARAM_OFFSET	= 0x00,
	HCR_IN_MODIFIER_OFFSET	= 0x08,
	HCR_OUT_PARAM_OFFSET	= 0x0c,
	HCR_TOKEN_OFFSET	= 0x14,
	HCR_STATUS_OFFSET	= 0x18,

	HCR_OPMOD_SHIFT		= 12,
	HCR_T_BIT		= 21,
	HCR_E_BIT		= 22,
	HCR_GO_BIT		= 23
};

enum {
	GO_BIT_TIMEOUT_MSECS	= 10000
};

struct mlx4_cmd_context {
	struct completion	done;
	int			result;
	int			next;
	u64			out_param;
	u16			token;
	u8			fw_status;
};

static int mlx4_master_process_vhcr(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *in_vhcr);

static int mlx4_status_to_errno(u8 status)
{
	static const int trans_table[] = {
		[CMD_STAT_INTERNAL_ERR]	  = -EIO,
		[CMD_STAT_BAD_OP]	  = -EPERM,
		[CMD_STAT_BAD_PARAM]	  = -EINVAL,
		[CMD_STAT_BAD_SYS_STATE]  = -ENXIO,
		[CMD_STAT_BAD_RESOURCE]	  = -EBADF,
		[CMD_STAT_RESOURCE_BUSY]  = -EBUSY,
		[CMD_STAT_EXCEED_LIM]	  = -ENOMEM,
		[CMD_STAT_BAD_RES_STATE]  = -EBADF,
		[CMD_STAT_BAD_INDEX]	  = -EBADF,
		[CMD_STAT_BAD_NVMEM]	  = -EFAULT,
		[CMD_STAT_ICM_ERROR]	  = -ENFILE,
		[CMD_STAT_BAD_QP_STATE]   = -EINVAL,
		[CMD_STAT_BAD_SEG_PARAM]  = -EFAULT,
		[CMD_STAT_REG_BOUND]	  = -EBUSY,
		[CMD_STAT_LAM_NOT_PRE]	  = -EAGAIN,
		[CMD_STAT_BAD_PKT]	  = -EINVAL,
		[CMD_STAT_BAD_SIZE]	  = -ENOMEM,
		[CMD_STAT_MULTI_FUNC_REQ] = -EACCES,
	};

	if (status >= ARRAY_SIZE(trans_table) ||
	    (status != CMD_STAT_OK && trans_table[status] == 0))
		return -EIO;

	return trans_table[status];
}

static int comm_pending(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	u32 status = readl(&priv->mfunc.comm->slave_read);

	return (swab32(status) >> 31) != priv->cmd.comm_toggle;
}

static void mlx4_comm_cmd_post(struct mlx4_dev *dev, u8 cmd, u16 param)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	u32 val;

	priv->cmd.comm_toggle ^= 1;
	val = param | (cmd << 16) | (priv->cmd.comm_toggle << 31);
	__raw_writel((__force u32) cpu_to_be32(val), &priv->mfunc.comm->slave_write);
	mmiowb();
}

int mlx4_comm_cmd_poll(struct mlx4_dev *dev, u8 cmd, u16 param, unsigned long timeout)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	unsigned long end;
	int err = 0;
	int ret_from_pending = 0;

	/* First, verify that the master reports correct status */
	if (comm_pending(dev)) {
		mlx4_warn(dev, "Communication channel is not idle. my toggle is %d (cmd:0x%x)\n",
			  priv->cmd.comm_toggle, cmd);
		return -EAGAIN;
	}

	/* Write command */
	down(&priv->cmd.poll_sem);
	mlx4_comm_cmd_post(dev, cmd, param);

	end = msecs_to_jiffies(timeout) + jiffies;
	while (comm_pending(dev) && time_before(jiffies, end))
		cond_resched();
	ret_from_pending = comm_pending(dev);
	if (ret_from_pending) {
		/*check if the slave is trying to boot in the middle of FLR process.
		 The only result in the RESET command that is not 0 is the MLX4_DELAY_RESET_SLAVE*/
		if ((MLX4_COMM_CMD_RESET == cmd)) {
			mlx4_warn(dev, "Got slave FLRed from Communication channel (ret:0x%x)\n", ret_from_pending);
			err = MLX4_DELAY_RESET_SLAVE;
		} else {
			mlx4_warn(dev, "Communication channel timed out\n");
			err = -ETIMEDOUT;
		}
	}

	up(&priv->cmd.poll_sem);
	return err;
}

static int mlx4_comm_cmd_wait(struct mlx4_dev *dev, u8 op,
			      u16 param, unsigned long timeout)
{
	struct mlx4_cmd *cmd = &mlx4_priv(dev)->cmd;
	struct mlx4_cmd_context *context;
	int err = 0;

	down(&cmd->event_sem);

	spin_lock(&cmd->context_lock);
	BUG_ON(cmd->free_head < 0);
	context = &cmd->context[cmd->free_head];
	context->token += cmd->token_mask + 1;
	cmd->free_head = context->next;
	spin_unlock(&cmd->context_lock);

	init_completion(&context->done);

	mlx4_comm_cmd_post(dev, op, param);

	if (!wait_for_completion_timeout(&context->done, msecs_to_jiffies(timeout))) {
		err = -EBUSY;
		goto out;
	}

	err = context->result;
	if (err && context->fw_status != CMD_STAT_MULTI_FUNC_REQ) {
		mlx4_err(dev, "command 0x%x failed: fw status = 0x%x\n",
			 op, context->fw_status);
		goto out;
	}

out:
	spin_lock(&cmd->context_lock);
	context->next = cmd->free_head;
	cmd->free_head = context - cmd->context;
	spin_unlock(&cmd->context_lock);

	up(&cmd->event_sem);
	return err;
}

int mlx4_comm_cmd(struct mlx4_dev *dev, u8 cmd, u16 param, unsigned long timeout)
{
	if (mlx4_priv(dev)->cmd.use_events)
		return mlx4_comm_cmd_wait(dev, cmd, param, timeout);
	return mlx4_comm_cmd_poll(dev, cmd, param, timeout);
}

static int cmd_pending(struct mlx4_dev *dev)
{
	u32 status = readl(mlx4_priv(dev)->cmd.hcr + HCR_STATUS_OFFSET);

	return (status & swab32(1 << HCR_GO_BIT)) ||
		(mlx4_priv(dev)->cmd.toggle ==
		 !!(status & swab32(1 << HCR_T_BIT)));
}

static int mlx4_cmd_post(struct mlx4_dev *dev, u64 in_param, u64 out_param,
			 u32 in_modifier, u8 op_modifier, u16 op, u16 token,
			 int event)
{
	struct mlx4_cmd *cmd = &mlx4_priv(dev)->cmd;
	u32 __iomem *hcr = cmd->hcr;
	int ret = -EAGAIN;
	unsigned long end;

	mutex_lock(&cmd->hcr_mutex);

	end = jiffies;
	if (event)
		end += msecs_to_jiffies(GO_BIT_TIMEOUT_MSECS);

	while (cmd_pending(dev)) {
		if (time_after_eq(jiffies, end)) {
			mlx4_err(dev, "%s:cmd_pending failed\n", __func__);
			goto out;
		}
		cond_resched();
	}

	/*
	 * We use writel (instead of something like memcpy_toio)
	 * because writes of less than 32 bits to the HCR don't work
	 * (and some architectures such as ia64 implement memcpy_toio
	 * in terms of writeb).
	 */
	__raw_writel((__force u32) cpu_to_be32(in_param >> 32),		  hcr + 0);
	__raw_writel((__force u32) cpu_to_be32(in_param & 0xfffffffful),  hcr + 1);
	__raw_writel((__force u32) cpu_to_be32(in_modifier),		  hcr + 2);
	__raw_writel((__force u32) cpu_to_be32(out_param >> 32),	  hcr + 3);
	__raw_writel((__force u32) cpu_to_be32(out_param & 0xfffffffful), hcr + 4);
	__raw_writel((__force u32) cpu_to_be32(token << 16),		  hcr + 5);

	/* __raw_writel may not order writes. */
	wmb();

	__raw_writel((__force u32) cpu_to_be32((1 << HCR_GO_BIT)		|
					       (cmd->toggle << HCR_T_BIT)	|
					       (event ? (1 << HCR_E_BIT) : 0)	|
					       (op_modifier << HCR_OPMOD_SHIFT) |
					       op),			  hcr + 6);

	/*
	 * Make sure that our HCR writes don't get mixed in with
	 * writes from another CPU starting a FW command.
	 */
	mmiowb();

	cmd->toggle = cmd->toggle ^ 1;

	ret = 0;

out:
	mutex_unlock(&cmd->hcr_mutex);
	return ret;
}

static int mlx4_slave_cmd(struct mlx4_dev *dev, u64 in_param, u64 *out_param,
			  int out_is_imm, u32 in_modifier, u8 op_modifier,
			  u16 op, unsigned long timeout)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_vhcr *vhcr = priv->mfunc.vhcr;
	int ret;

	down(&priv->cmd.slave_sem);
	vhcr->in_param = in_param;
	vhcr->out_param = out_param ? *out_param : 0;
	vhcr->in_modifier = in_modifier;
	vhcr->timeout = timeout;
	vhcr->op = op;
	vhcr->token = CMD_POLL_TOKEN;
	vhcr->op_modifier = op_modifier;
	vhcr->errno = 0;
	vhcr->cookie++;
	if (mlx4_is_master(dev)) {
		ret = mlx4_master_process_vhcr(dev, dev->caps.function, vhcr);
		if (!ret) {
			if (out_is_imm) {
				if (out_param)
					*out_param = vhcr->out_param;
				else {
					mlx4_err(dev, "response expected while output mailbox is "
						      "NULL for command 0x%x\n", op);
					vhcr->errno = -EINVAL;
				}
			}
			ret = vhcr->errno;
		}
	} else {
		ret = mlx4_comm_cmd(dev, MLX4_COMM_CMD_VHCR_POST, 0,
				    MLX4_COMM_TIME + timeout);
		if (!ret) {
			if (out_is_imm) {
				if (out_param)
					*out_param = vhcr->out_param;
				else {
					mlx4_err(dev, "response expected while output mailbox is "
						      "NULL for command 0x%x\n", op);
					vhcr->errno = -EINVAL;
				}
			}
			ret = vhcr->errno;
		} else
			mlx4_err(dev, "failed execution of VHCR_POST command opcode 0x%x, cookie %d\n", op, vhcr->cookie);
	}
	up(&priv->cmd.slave_sem);
	return ret;
}

static int mlx4_cmd_poll(struct mlx4_dev *dev, u64 in_param, u64 *out_param,
			 int out_is_imm, u32 in_modifier, u8 op_modifier,
			 u16 op, unsigned long timeout)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	void __iomem *hcr = priv->cmd.hcr;
	int err = 0;
	unsigned long end;
	u32 stat;

	down(&priv->cmd.poll_sem);

	err = mlx4_cmd_post(dev, in_param, out_param ? *out_param : 0,
			    in_modifier, op_modifier, op, CMD_POLL_TOKEN, 0);
	if (err) {
		mlx4_err(dev, "%s:command 0x%x, mlx4_cmd_post failed\n", __func__, op);
		goto out;
	}

	end = msecs_to_jiffies(timeout) + jiffies;
	while (cmd_pending(dev) && time_before(jiffies, end))
		cond_resched();

	if (cmd_pending(dev)) {
		mlx4_err(dev, "%s:command 0x%x, cmd_pending failed\n", __func__, op);
		err = -ETIMEDOUT;
		goto out;
	}

	if (out_is_imm)
		*out_param =
			(u64) be32_to_cpu((__force __be32)
					  __raw_readl(hcr + HCR_OUT_PARAM_OFFSET)) << 32 |
			(u64) be32_to_cpu((__force __be32)
					  __raw_readl(hcr + HCR_OUT_PARAM_OFFSET + 4));
	stat = be32_to_cpu((__force __be32) __raw_readl(hcr + HCR_STATUS_OFFSET)) >> 24;
	err = mlx4_status_to_errno(stat);
	if (err && stat != CMD_STAT_MULTI_FUNC_REQ)
		mlx4_err(dev, "command 0x%x failed: fw status = 0x%x\n", op, stat);

out:
	up(&priv->cmd.poll_sem);
	return err;
}

void mlx4_cmd_event(struct mlx4_dev *dev, u16 token, u8 status, u64 out_param)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_cmd_context *context =
		&priv->cmd.context[token & priv->cmd.token_mask];

	/* previously timed out command completing at long last */
	if (token != context->token)
		return;

	context->fw_status = status;
	context->result    = mlx4_status_to_errno(status);
	context->out_param = out_param;

	complete(&context->done);
}

static int mlx4_cmd_wait(struct mlx4_dev *dev, u64 in_param, u64 *out_param,
			 int out_is_imm, u32 in_modifier, u8 op_modifier,
			 u16 op, unsigned long timeout)
{
	struct mlx4_cmd *cmd = &mlx4_priv(dev)->cmd;
	struct mlx4_cmd_context *context;
	int err = 0;

	down(&cmd->event_sem);

	spin_lock(&cmd->context_lock);
	BUG_ON(cmd->free_head < 0);
	context = &cmd->context[cmd->free_head];
	context->token += cmd->token_mask + 1;
	cmd->free_head = context->next;
	spin_unlock(&cmd->context_lock);

	init_completion(&context->done);

	mlx4_cmd_post(dev, in_param, out_param ? *out_param : 0,
		      in_modifier, op_modifier, op, context->token, 1);

	if (!wait_for_completion_timeout(&context->done, msecs_to_jiffies(timeout))) {
		err = -EBUSY;
		mlx4_err(dev, "%s:command 0x%x, wait_for_completion_timeout failed\n", __func__, op);
		goto out;
	}

	err = context->result;
	if (err && context->fw_status != CMD_STAT_MULTI_FUNC_REQ) {
		mlx4_err(dev, "command 0x%x failed: fw status = 0x%x\n",
			 op, context->fw_status);
		goto out;
	}

	if (out_is_imm) {
		if (out_param)
			*out_param = context->out_param;
		else {
			mlx4_err(dev, "response expected while output mailbox is NULL for command 0x%x\n", op);
			err = -EINVAL;
		}
	}

out:
	spin_lock(&cmd->context_lock);
	context->next = cmd->free_head;
	cmd->free_head = context - cmd->context;
	spin_unlock(&cmd->context_lock);

	up(&cmd->event_sem);
	return err;
}

int __mlx4_cmd(struct mlx4_dev *dev, u64 in_param, u64 *out_param,
	       int out_is_imm, u32 in_modifier, u8 op_modifier,
	       u16 op, unsigned long timeout, int native)
{
	if (!mlx4_is_mfunc(dev) || (native && mlx4_is_master(dev))) {
		if (mlx4_priv(dev)->cmd.use_events)
			return mlx4_cmd_wait(dev, in_param, out_param, out_is_imm,
					     in_modifier, op_modifier, op, timeout);
		else
			return mlx4_cmd_poll(dev, in_param, out_param, out_is_imm,
					     in_modifier, op_modifier, op, timeout);
	}
	return mlx4_slave_cmd(dev, in_param, out_param, out_is_imm,
			      in_modifier, op_modifier, op, timeout);
}
EXPORT_SYMBOL_GPL(__mlx4_cmd);


static int mlx4_ARM_COMM_CHANNEL(struct mlx4_dev *dev)
{
	return mlx4_cmd(dev, 0, 0, 0, MLX4_CMD_ARM_COMM_CHANNEL, MLX4_CMD_TIME_CLASS_B, 1);
}

static int mlx4_ACCESS_MEM(struct mlx4_dev *dev, u64 master_addr,
			   int slave, u64 slave_addr,
			   int size, int is_read)
{
	u64 in_param;
	u64 out_param;

	if ((slave_addr & 0xfff) | (master_addr & 0xfff) |
	    (slave & ~0x7f) | (size & 0xff)) {
		mlx4_err(dev, "Bad access mem params - slave_addr:0x%llx "
			      "master_addr:0x%llx slave_id:%d size:%d\n",
			      slave_addr, master_addr, slave, size);
		return -EINVAL;
	}

	if (is_read) {
		in_param = (u64) slave | slave_addr;
		out_param = (u64) dev->caps.function | master_addr;
	} else {
		in_param = (u64) dev->caps.function | master_addr;
		out_param = (u64) slave | slave_addr;
	}

	return mlx4_cmd_imm(dev, in_param, &out_param, size, 0,
					   MLX4_CMD_ACCESS_MEM,
					   MLX4_CMD_TIME_CLASS_A, 1);
}

static int MAD_IFC(struct mlx4_dev *dev, int ignore_mkey, int ignore_bkey,
		   int port, struct ib_wc *in_wc, struct ib_grh *in_grh,
		   void *in_mad, void *response_mad)
{
	struct mlx4_cmd_mailbox *inmailbox, *outmailbox;
	void *inbox;
	int err;
	u32 in_modifier = port;
	u8 op_modifier = 0;

	inmailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(inmailbox))
		return PTR_ERR(inmailbox);
	inbox = inmailbox->buf;

	outmailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(outmailbox)) {
		mlx4_free_cmd_mailbox(dev, inmailbox);
		return PTR_ERR(outmailbox);
	}

	memcpy(inbox, in_mad, 256);

	/*
	 * Key check traps can't be generated unless we have in_wc to
	 * tell us where to send the trap.
	 */
	if (ignore_mkey || !in_wc)
		op_modifier |= 0x1;
	if (ignore_bkey || !in_wc)
		op_modifier |= 0x2;

	if (in_wc) {
		struct {
			__be32		my_qpn;
			u32		reserved1;
			__be32		rqpn;
			u8		sl;
			u8		g_path;
			u16		reserved2[2];
			__be16		pkey;
			u32		reserved3[11];
			u8		grh[40];
		} *ext_info;

		memset(inbox + 256, 0, 256);
		ext_info = inbox + 256;

		ext_info->my_qpn = cpu_to_be32(in_wc->qp->qp_num);
		ext_info->rqpn   = cpu_to_be32(in_wc->src_qp);
		ext_info->sl     = in_wc->sl << 4;
		ext_info->g_path = in_wc->dlid_path_bits |
			(in_wc->wc_flags & IB_WC_GRH ? 0x80 : 0);
		ext_info->pkey   = cpu_to_be16(in_wc->pkey_index);

		if (in_grh)
			memcpy(ext_info->grh, in_grh, 40);

		op_modifier |= 0x4;

		in_modifier |= in_wc->slid << 16;
	}

	err = mlx4_cmd_box(dev, inmailbox->dma, outmailbox->dma,
			   in_modifier, op_modifier,
			   MLX4_CMD_MAD_IFC, MLX4_CMD_TIME_CLASS_C, 1);

	if (!err)
		memcpy(response_mad, outmailbox->buf, 256);

	mlx4_free_cmd_mailbox(dev, inmailbox);
	mlx4_free_cmd_mailbox(dev, outmailbox);

	return err;
}

static int query_pkey_block(struct mlx4_dev *dev, u8 port, u16 index, u16 *pkey, struct ib_smp *in_mad, struct ib_smp *out_mad)
{
	int err = -ENOMEM;
	int i;

	if (index & 0x1f)
		return -EINVAL;

	in_mad->attr_mod = cpu_to_be32(index / 32);

	err = MAD_IFC(dev, 1, 1, port, NULL, NULL, in_mad, out_mad);
	if (err)
		return err;

	for (i = 0; i < 32; ++i)
		pkey[i] = be16_to_cpu(((__be16 *) out_mad->data)[i]);

	return err;
}

static int get_full_pkey_table(struct mlx4_dev *dev, u8 port, u16 *table, struct ib_smp * in_mad, struct ib_smp *outsmp)
{
	int i;
	int err;

	for (i = 0; i < dev->caps.pkey_table_len[port]; i += 32) {
		err = query_pkey_block(dev, port, i, table + i, in_mad, outsmp);
		if (err)
			return err;
	}

	return 0;
}
#define PORT_CAPABILITY_LOCATION_IN_SMP 20
#define PORT_STATE_OFFSET 32

static enum ib_port_state vf_port_state(struct mlx4_dev *dev, int port, int vf)
{
	if (mlx4_get_slave_port_state(dev, vf, port) == SLAVE_PORT_UP)
		return IB_PORT_ACTIVE;
	else
		return IB_PORT_DOWN;
}

static int mlx4_MAD_IFC_wrapper(struct mlx4_dev *dev, int slave,
				struct mlx4_vhcr *vhcr,
				struct mlx4_cmd_mailbox *inbox,
				struct mlx4_cmd_mailbox *outbox,
				struct mlx4_cmd_info *cmd)
{
	struct ib_smp *smp = inbox->buf;
	u32 index;
	u8 port;
	u16 *table;
	int err;
	int vidx, pidx;
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct ib_smp *outsmp = outbox->buf;
	__be16 *outtab = (__be16 *)(outsmp->data);
	__be32 slave_cap_mask;
	port = vhcr->in_modifier;

	/*mlx4_dbg(dev, "%s, slave %d, bv %d, mc %d, cv %d, mtd %d atrr %d\n",
		 __func__, slave, smp->base_version, smp->mgmt_class, smp->class_version, smp->method, be16_to_cpu(smp->attr_id));
	*/
	if (smp->base_version == 1 &&
	    smp->mgmt_class == IB_MGMT_CLASS_SUBN_LID_ROUTED &&
	    smp->class_version == 1) {
		if (smp->method	== IB_MGMT_METHOD_GET) {
			if (smp->attr_id == IB_SMP_ATTR_PKEY_TABLE) {
				index = be32_to_cpu(smp->attr_mod);
				/*mlx4_dbg(dev, "query pkey for slave %d, port %d, index %d\n", slave, port, index);*/
				if (port < 1 || port > dev->caps.num_ports)
					return -EINVAL;
				table = kzalloc(dev->caps.pkey_table_len[port] * sizeof *table, GFP_KERNEL);
				if (!table)
					return -ENOMEM;
				err = get_full_pkey_table(dev, port, table, smp, outsmp);
				if (!err) {
					for (vidx = index * 32; vidx < (index + 1) * 32; ++vidx) {
						pidx = priv->virt2phys_pkey[slave][port - 1][vidx];
						outtab[vidx % 32] = cpu_to_be16(table[pidx]);
						/*mlx4_dbg(dev, "vidx = %d, pidx = %d, pkey = 0x%04x\n", vidx, pidx, table[pidx]);*/
					}
				}
				kfree(table);
				return err;
			}
			if (smp->attr_id == IB_SMP_ATTR_PORT_INFO) {
				/*get the slave specific caps:*/
				/*do the command */
				err = mlx4_cmd_box(dev, inbox->dma, outbox->dma,
					    vhcr->in_modifier, vhcr->op_modifier,
					    vhcr->op, vhcr->timeout, 1);
				/*mlx4_dbg(dev, "query port_info for slave %d, port %d, slave_cap: 0x%x\n", slave, port, slave_cap_mask);*/
				/* modify the response for slaves */
				if (!err) {
					u8 *state = outsmp->data + PORT_STATE_OFFSET;

					*state = (*state & 0xf0) | vf_port_state(dev, port, slave);
					if (slave != dev->caps.function) {
						slave_cap_mask = priv->mfunc.master.slave_state[slave].ib_cap_mask[port];
						memcpy(outsmp->data + PORT_CAPABILITY_LOCATION_IN_SMP, &slave_cap_mask, 4);
					}
				}
				return err;
			} else if (smp->attr_id == IB_SMP_ATTR_GUID_INFO && mlx4_is_mfunc(dev)) {
				__be64 *gids_block = (__be64 *)outsmp->data;
				u8 block_idx;
				int i;

				/* for every record, we need to go index by index and see if it's valid for this slave */
				err = mlx4_cmd_box(dev, inbox->dma, outbox->dma,
						   vhcr->in_modifier, vhcr->op_modifier,
						   vhcr->op, vhcr->timeout, 1);
				if (!err) {
					/* Verify that the slave only access GIDs that are
					mapped to it */
					block_idx = be32_to_cpu(smp->attr_mod) * 8;
					for (i = 0; i < 8; i++, block_idx++) {
						if (slave != mlx4_gid_idx_to_slave(dev, block_idx))
							gids_block[i] = 0x0;
					}
				}
				return err;
			}
		}
		if (smp->method	== IB_MGMT_METHOD_SET && slave != dev->caps.function) {
			mlx4_err(dev, "slave %d is trying to execute a IB_MGMT_METHOD_SET operation (%d). aborting\n", slave,smp->attr_id);
			return -EPERM;
		}
	}
	/*default:*/
	return mlx4_cmd_box(dev, inbox->dma, outbox->dma,
				    vhcr->in_modifier, vhcr->op_modifier,
				    vhcr->op, vhcr->timeout, 1);
}

int mlx4_DMA_wrapper(struct mlx4_dev *dev, int slave,
		     struct mlx4_vhcr *vhcr,
		     struct mlx4_cmd_mailbox *inbox,
		     struct mlx4_cmd_mailbox *outbox,
		     struct mlx4_cmd_info *cmd)
{
	u64 in_param;
	u64 out_param;
	int err;

	in_param = cmd->has_inbox ? (u64) inbox->dma : vhcr->in_param;
	out_param = cmd->has_outbox ? (u64) outbox->dma : vhcr->out_param;
	if (cmd->encode_slave_id) {
		in_param &= 0xffffffffffffff00ll;
		in_param |= slave;
	}

	err = __mlx4_cmd(dev, in_param, &out_param, cmd->out_is_imm,
			 vhcr->in_modifier, vhcr->op_modifier, vhcr->op,
			 vhcr->timeout, 1);

	if (cmd->out_is_imm)
		vhcr->out_param = out_param;

	return err;
}

static struct mlx4_cmd_info cmd_info[] = {
	{
		.opcode = MLX4_CMD_QUERY_FW,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = NULL
	},
	{
		.opcode = MLX4_CMD_QUERY_SLAVE_CAP,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_QUERY_SLAVE_CAP_wrapper
	},
	{
		.opcode = MLX4_CMD_ENABLE_FMR,
		.has_outbox = true,
		.wrapper = mlx4_ENABLE_FMR_wrapper
	},
	{
		.opcode = MLX4_CMD_QUERY_ADAPTER,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = NULL
	},
	{
		.opcode = MLX4_CMD_COMM_INT,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_COMM_INT_wrapper
	},
	{
		.opcode = MLX4_CMD_INIT_PORT,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_INIT_PORT_wrapper
	},
	{
		.opcode = MLX4_CMD_CLOSE_PORT,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm  = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_CLOSE_PORT_wrapper
	},
	{
		.opcode = MLX4_CMD_SENSE_PORT,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = true,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = NULL
	},
	{
		.opcode = MLX4_CMD_QUERY_PORT,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_QUERY_PORT_wrapper
	},
	{
		.opcode = MLX4_CMD_SET_PORT,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_SET_PORT_wrapper
	},
	{
		.opcode = MLX4_CMD_SET_NODE,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = NULL
	},
	{
		.opcode = MLX4_CMD_MAP_EQ,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_MAP_EQ_wrapper
	},
	{
		.opcode = MLX4_CMD_SW2HW_EQ,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = true,
		.verify = NULL,
		.wrapper = mlx4_SW2HW_EQ_wrapper
	},
	{
		.opcode = MLX4_CMD_HW_HEALTH_CHECK,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = NULL
	},
	{
		.opcode = MLX4_CMD_NOP,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = NULL
	},
	{
		.opcode = MLX4_CMD_ALLOC_RES,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = true,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_ALLOC_RES_wrapper
	},
	{
		.opcode = MLX4_CMD_FREE_RES,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_FREE_RES_wrapper
	},
	{
		.opcode = MLX4_CMD_GET_EVENT,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = true,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_GET_EVENT_wrapper
	},

	{
		.opcode = MLX4_CMD_REPLACE_RES,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = true,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = NULL
	},
	{
		.opcode = MLX4_CMD_SW2HW_MPT,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = true,
		.verify = NULL,
		.wrapper = mlx4_SW2HW_MPT_wrapper
	},
	{
		.opcode = MLX4_CMD_QUERY_MPT,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_QUERY_MPT_wrapper
	},
	{
		.opcode = MLX4_CMD_HW2SW_MPT,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_HW2SW_MPT_wrapper
	},
	{
		.opcode = MLX4_CMD_READ_MTT,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = NULL
	},
	{
		.opcode = MLX4_CMD_WRITE_MTT,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_WRITE_MTT_wrapper
	},
	{
		.opcode = MLX4_CMD_SYNC_TPT,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = NULL
	},

	{
		.opcode = MLX4_CMD_HW2SW_EQ,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = true,
		.verify = NULL,
		.wrapper = mlx4_HW2SW_EQ_wrapper
	},
	{
		.opcode = MLX4_CMD_QUERY_EQ,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = true,
		.verify = NULL,
		.wrapper = mlx4_QUERY_EQ_wrapper
	},
	{
		.opcode = MLX4_CMD_SW2HW_CQ,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = true,
		.verify = NULL,
		.wrapper = mlx4_SW2HW_CQ_wrapper
	},
	{
		.opcode = MLX4_CMD_HW2SW_CQ,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_HW2SW_CQ_wrapper
	},
	{
		.opcode = MLX4_CMD_QUERY_CQ,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_QUERY_CQ_wrapper
	},
	{
		.opcode = MLX4_CMD_MODIFY_CQ,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = true,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_MODIFY_CQ_wrapper
	},
	{
		.opcode = MLX4_CMD_SW2HW_SRQ,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = true,
		.verify = NULL,
		.wrapper = mlx4_SW2HW_SRQ_wrapper
	},
	{
		.opcode = MLX4_CMD_HW2SW_SRQ,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_HW2SW_SRQ_wrapper
	},
	{
		.opcode = MLX4_CMD_QUERY_SRQ,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_QUERY_SRQ_wrapper
	},
	{
		.opcode = MLX4_CMD_ARM_SRQ,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_ARM_SRQ_wrapper
	},
	{
		.opcode = MLX4_CMD_RST2INIT_QP,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = true,
		.verify = NULL,
		.wrapper = mlx4_RST2INIT_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_INIT2INIT_QP,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_INIT2INIT_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_INIT2RTR_QP,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_INIT2RTR_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_RTR2RTS_QP,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_RTR2RTS_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_RTS2RTS_QP,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_RTS2RTS_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_SQERR2RTS_QP,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_SQERR2RTS_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_2ERR_QP,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_2ERR_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_RTS2SQD_QP,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_RTS2SQD_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_SQD2SQD_QP,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_SQD2SQD_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_SQD2RTS_QP,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_SQD2RTS_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_2RST_QP,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_2RST_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_QUERY_QP,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_QUERY_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_INIT2INIT_QP,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_INIT2INIT_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_SUSPEND_QP,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_SUSPEND_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_UNSUSPEND_QP,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_UNSUSPEND_QP_wrapper
	},
	{
		.opcode = MLX4_CMD_CONF_SPECIAL_QP,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL, /* XXX verify: only demux can do this */
		.wrapper = NULL
	},
	{
		.opcode = MLX4_CMD_MAD_IFC,
		.has_inbox = true,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_MAD_IFC_wrapper
	},
	{
		.opcode = MLX4_CMD_QUERY_IF_STAT,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_QUERY_IF_STAT_wrapper
	},
	{
		.opcode = MLX4_CMD_MAP_ICM,
		.has_inbox = true,
		.wrapper = mlx4_MAP_ICM_wrapper
	},
	{
		.opcode = MLX4_CMD_UNMAP_ICM,
		.wrapper = mlx4_UNMAP_ICM_wrapper
	},
	{
		.opcode = MLX4_CMD_GET_GID_MAP,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_GET_GID_MAP_wrapper
	},
	/* Native multicast commands are not available for guests */
	{
		.opcode = MLX4_CMD_MCAST_ATTACH,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_MCAST_wrapper
	},
	{
		.opcode = MLX4_CMD_PROMISC,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_PROMISC_wrapper
	},
	{
		.opcode = MLX4_CMD_DIAG_RPRT,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL, /* need verifier */
		.wrapper = NULL
	},
	{
		.opcode = MLX4_CMD_GET_PKEY_TABLE,
		.has_outbox = true,
		.wrapper = mlx4_PKEY_TABLE_wrapper,
	},

	/* Ethernet specific commands */
	{
		.opcode = MLX4_CMD_SET_VLAN_FLTR,
		.has_inbox = true,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_SET_VLAN_FLTR_wrapper
	},
	{
		.opcode = MLX4_CMD_SET_MCAST_FLTR,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_SET_MCAST_FLTR_wrapper
	},
	{
		.opcode = MLX4_CMD_DUMP_ETH_STATS,
		.has_inbox = false,
		.has_outbox = true,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = mlx4_DUMP_ETH_STATS_wrapper
	},
	{
		.opcode = MLX4_CMD_INFORM_FLR_DONE,
		.has_inbox = false,
		.has_outbox = false,
		.out_is_imm = false,
		.encode_slave_id = false,
		.verify = NULL,
		.wrapper = NULL
	},
};

static int mlx4_master_process_vhcr(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *in_vhcr)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_cmd_info *cmd = NULL;
	struct mlx4_vhcr *vhcr = in_vhcr ? in_vhcr : priv->mfunc.vhcr;
	struct mlx4_cmd_mailbox *inbox = NULL;
	struct mlx4_cmd_mailbox *outbox = NULL;
	u64 in_param;
	u64 out_param;
	int ret = 0;
	int i;

	/* DMA in the vHCR */
	if (!in_vhcr) {
		ret = mlx4_ACCESS_MEM(dev, priv->mfunc.vhcr_dma, slave,
				      priv->mfunc.master.slave_state[slave].vhcr_dma,
				      ALIGN(sizeof(struct mlx4_vhcr),
					    MLX4_ACCESS_MEM_ALIGN), 1);
		if (ret) {
			mlx4_err(dev, "%s:Failed reading vhcr ret: 0x%x\n", __func__, ret);
			return ret;
		}
		if (vhcr->cookie != ++priv->mfunc.master.slave_state[slave].cookie)
			mlx4_err(dev, "**** VHCR INCONSISTENCY vhcr cookie %d, expected state cookie %d\n",
				 vhcr->cookie, priv->mfunc.master.slave_state[slave].cookie);
	}

	/* Lookup command */
	for (i = 0; i < ARRAY_SIZE(cmd_info); ++i) {
		if (vhcr->op == cmd_info[i].opcode) {
			cmd = &cmd_info[i];
			break;
		}
	}
	if (!cmd) {
		mlx4_err(dev, "Unknown command:0x%x accepted from slave:%d\n",
							      vhcr->op, slave);
		vhcr->errno = -EINVAL;
		goto out_status;
	}

	/* Read inbox */
	if (cmd->has_inbox) {
		vhcr->in_param &= INBOX_MASK;
		inbox = mlx4_alloc_cmd_mailbox(dev);
		if (IS_ERR(inbox)) {
			ret = PTR_ERR(inbox);
			inbox = NULL;
			goto out;
		}

		/* FIXME: add mailbox size per-command */
		ret = mlx4_ACCESS_MEM(dev, inbox->dma, slave,
				      vhcr->in_param,
				      MLX4_MAILBOX_SIZE, 1);
		if (ret) {
			mlx4_err(dev, "%s: Failed reading inbox (cmd:0x%x)\n", __func__, cmd->opcode);
			goto out;
		}
	}

	/* Apply permission and bound checks if applicable */
	if (cmd->verify && cmd->verify(dev, slave, vhcr, inbox)) {
		mlx4_warn(dev, "Command:0x%x from slave: %d failed protection checks for resource_id:%d\n", vhcr->op, slave, vhcr->in_modifier);
		vhcr->errno = -EPERM;
		goto out_status;
	}

	/* Allocate outbox */
	if (cmd->has_outbox) {
		outbox = mlx4_alloc_cmd_mailbox(dev);
		if (IS_ERR(outbox)) {
			ret = PTR_ERR(outbox);
			outbox = NULL;
			goto out;
		}
	}

	/* Execute the command! */
	if (cmd->wrapper)
		vhcr->errno = cmd->wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	else {
		in_param = cmd->has_inbox ? (u64) inbox->dma : vhcr->in_param;
		out_param = cmd->has_outbox ? (u64) outbox->dma : vhcr->out_param;
		vhcr->errno = __mlx4_cmd(dev, in_param, &out_param,
							cmd->out_is_imm,
							vhcr->in_modifier,
							vhcr->op_modifier,
							vhcr->op,
							vhcr->timeout, 1);
		if (cmd->out_is_imm)
			vhcr->out_param = out_param;
	}

	/* Write outbox if command completed successfully */
	if (cmd->has_outbox && !vhcr->errno) {
		ret = mlx4_ACCESS_MEM(dev, outbox->dma, slave,
				      vhcr->out_param,
				      MLX4_MAILBOX_SIZE, 0);
		if (ret) {
			mlx4_err(dev, "%s:Failed writing outbox\n", __func__);
			goto out;
		}
	}

out_status:
	/* DMA back vhcr result */
	if (!in_vhcr) {
		ret = mlx4_ACCESS_MEM(dev, priv->mfunc.vhcr_dma, slave,
				      priv->mfunc.master.slave_state[slave].vhcr_dma,
				      ALIGN(sizeof(struct mlx4_vhcr),
					    MLX4_ACCESS_MEM_ALIGN), 0);
		if (ret)
			mlx4_err(dev, "%s:Failed writing vhcr result\n", __func__);
	}

	if (vhcr->errno)
		mlx4_swarn("vhcr command:0x%x slave:%d failed with error:%d\n",
							vhcr->op, slave, vhcr->errno);
	/* Fall through... */

out:
	mlx4_free_cmd_mailbox(dev, inbox);
	mlx4_free_cmd_mailbox(dev, outbox);
	return ret;
}

static void mlx4_master_do_cmd(struct mlx4_dev *dev, int slave, u8 cmd, u16 param, u8 toggle)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_slave_state *slave_state = priv->mfunc.master.slave_state;
	u32 reply;
	u32 slave_status = 0;
	u8 is_going_down = 0;

	slave_state[slave].comm_toggle ^= 1;
	reply = (u32) slave_state[slave].comm_toggle << 31;
	if (toggle != slave_state[slave].comm_toggle) {
		mlx4_warn(dev, "Incorrect toggle %d from slave %d. *** MASTER STATE COMPROMISIED ***\n",
			  toggle, slave);
		goto reset_slave;
	}
	if (cmd == MLX4_COMM_CMD_RESET) {
		mlx4_warn(dev, "Received reset from slave:%d\n", slave);
		slave_state[slave].active = false;
		/*check if we are in the middle of FLR process,
		if so return "retry" status to the slave*/
		if (MLX4_COMM_CMD_FLR == slave_state[slave].last_cmd) {
			slave_status = MLX4_DELAY_RESET_SLAVE;
			goto inform_slave_state;
		}
		mlx4_dispatch_event(dev, MLX4_DEV_EVENT_SLAVE_SHUTDOWN,
				    (unsigned long)slave);

		/* write the version in the event field */
		reply |= mlx4_comm_get_version();

		goto reset_slave;
	}
	/*command from slave in the middle of FLR*/
	if (cmd != MLX4_COMM_CMD_RESET && MLX4_COMM_CMD_FLR == slave_state[slave].last_cmd) {
		mlx4_warn(dev, "slave:%d is Trying to run cmd(0x%x) in the middle of FLR\n", slave, cmd);
		return;
	}

	switch (cmd) {
	case MLX4_COMM_CMD_VHCR0:
		if (slave_state[slave].last_cmd != MLX4_COMM_CMD_RESET)
			goto reset_slave;
		slave_state[slave].vhcr_dma = ((u64) param) << 48;
		priv->mfunc.master.slave_state[slave].cookie = 0;
		mutex_init(&priv->mfunc.master.gen_eqe_mutex[slave]);
		break;
	case MLX4_COMM_CMD_VHCR1:
		if (slave_state[slave].last_cmd != MLX4_COMM_CMD_VHCR0)
			goto reset_slave;
		slave_state[slave].vhcr_dma |= ((u64) param) << 32;
		break;
	case MLX4_COMM_CMD_VHCR2:
		if (slave_state[slave].last_cmd != MLX4_COMM_CMD_VHCR1)
			goto reset_slave;
		slave_state[slave].vhcr_dma |= ((u64) param) << 16;
		break;
	case MLX4_COMM_CMD_VHCR_EN:
		if (slave_state[slave].last_cmd != MLX4_COMM_CMD_VHCR2)
			goto reset_slave;
		slave_state[slave].vhcr_dma |= param;
		if (mlx4_QUERY_FUNC(dev, slave, &slave_state[slave].pf_num)) {
			mlx4_err(dev, "Failed to determine physical function "
				      "number for slave %d\n", slave);
			goto reset_slave;
		}
		slave_state[slave].vep_num = slave_state[slave].pf_num >> 1;
		slave_state[slave].active = true;
		mlx4_dispatch_event(dev, MLX4_DEV_EVENT_SLAVE_INIT, slave);
		break;
	case MLX4_COMM_CMD_VHCR_POST:
		if ((slave_state[slave].last_cmd != MLX4_COMM_CMD_VHCR_EN) &&
		    (slave_state[slave].last_cmd != MLX4_COMM_CMD_VHCR_POST))
			goto reset_slave;
		down(&priv->cmd.slave_sem);
		if (mlx4_master_process_vhcr(dev, slave, NULL)) {
			mlx4_err(dev, "Failed processing vhcr for slave:%d, reseting slave.\n", slave);
			up(&priv->cmd.slave_sem);
			goto reset_slave;
		}
		up(&priv->cmd.slave_sem);
		break;
	default:
		mlx4_warn(dev, "Bad comm cmd:%d from slave:%d\n", cmd, slave);
		goto reset_slave;
	}
	spin_lock(&priv->mfunc.master.slave_state_lock);
	if (!slave_state[slave].is_slave_going_down) {
		slave_state[slave].last_cmd = cmd;
	} else {
		is_going_down = 1;
	}
	spin_unlock(&priv->mfunc.master.slave_state_lock);
	if (is_going_down) {
		mlx4_warn(dev, "Slave is going down aborting command(%d) executing from slave:%d\n",
			  cmd, slave);
		return;
	}
	__raw_writel((__force u32) cpu_to_be32(reply),
		     &priv->mfunc.comm[slave].slave_read);
	mmiowb();
	if (mlx4_GEN_EQE(dev, slave, &priv->mfunc.master.cmd_eqe))
		mlx4_warn(dev, "Failed to generate command completion eqe "
			       "for slave %d\n", slave);

	return;

reset_slave:
	/* cleanup any slave resources */
	mlx4_delete_all_resources_for_slave(dev, slave);
	spin_lock(&priv->mfunc.master.slave_state_lock);
	if (!slave_state[slave].is_slave_going_down) {
		slave_state[slave].last_cmd = MLX4_COMM_CMD_RESET;
	}
	spin_unlock(&priv->mfunc.master.slave_state_lock);
	/*with slave in the middle of flr, no need to clean resources again.*/
inform_slave_state:
	memset(&slave_state[slave].event_eq, 0,
	       sizeof(struct mlx4_slave_event_eq_info));
	__raw_writel((__force u32) cpu_to_be32(reply),
		     &priv->mfunc.comm[slave].slave_read);
	wmb();
}

/* master command processing */
void mlx4_master_comm_channel(struct work_struct *work)
{
	struct mlx4_mfunc_master_ctx *master = container_of(work,
							   struct mlx4_mfunc_master_ctx,
							   comm_work);
	struct mlx4_mfunc *mfunc = container_of(master, struct mlx4_mfunc, master);
	struct mlx4_priv *priv = container_of(mfunc, struct mlx4_priv, mfunc);
	struct mlx4_dev *dev = &priv->dev;
	u32 *bit_vec;
	u32 comm_cmd;
	u32 vec;
	int i, j, slave;
	int toggle;
	int served = 0;
	int reported = 0;
	u32 slt;

	bit_vec = master->comm_arm_bit_vector;
	for (i = 0; i < COMM_CHANNEL_BIT_ARRAY_SIZE; i++) {
		vec = be32_to_cpu(bit_vec[i]);
		for (j = 0; j < 32; j++) {
			if (!(vec & (1 << j)))
				continue;
			++reported;
			slave = (i * 32) + j;
			comm_cmd = swab32(readl(&mfunc->comm[slave].slave_write));
			slt = swab32(readl(&mfunc->comm[slave].slave_read)) >> 31;
			toggle = comm_cmd >> 31;
			if (toggle != slt) {
				if (master->slave_state[slave].comm_toggle != slt) {
					printk("slave %d out of sync. read toggle %d, state toggle %d. Resynching.\n",
					       slave, slt, master->slave_state[slave].comm_toggle);
					master->slave_state[slave].comm_toggle = slt;
				}
				mlx4_master_do_cmd(dev, slave, comm_cmd >> 16 & 0xff,
						   comm_cmd & 0xffff, toggle);
				++served;
			}
		}
	}

	if (reported && reported != served)
		mlx4_warn(dev, "Got command event with bitmask from %d slaves but %d were served\n",
			  reported, served);

	if (mlx4_ARM_COMM_CHANNEL(dev))
		mlx4_warn(dev, "Failed to arm comm channel events\n");
}

static int sync_toggles(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int wr_toggle;
	int rd_toggle;
	unsigned long end;
	
	wr_toggle = swab32(readl(&priv->mfunc.comm->slave_write)) >> 31;
	end = jiffies + msecs_to_jiffies(5000);
	
	while (time_before(jiffies, end)) {
		rd_toggle = swab32(readl(&priv->mfunc.comm->slave_read)) >> 31;
		if (rd_toggle == wr_toggle) {
			priv->cmd.comm_toggle = rd_toggle;
			return 0;
		}
	
		cond_resched();
	}

	/*
	 * we coud reach here if for example the previous VM using this function
	 * misbehaved and left the channel with unsynced state. We should fix
	 * this here and give this VM a chance to use a properly synced channel
	 */
	mlx4_warn(dev, "recovering from previously mis-behaved VM\n");
	__raw_writel((__force u32) 0, &priv->mfunc.comm->slave_read);
	__raw_writel((__force u32) 0, &priv->mfunc.comm->slave_write);
	priv->cmd.comm_toggle = 0;

	return 0;
}

int mlx4_multi_func_init(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_slave_state *s_state;
	int i, err, port;

	priv->mfunc.vhcr = dma_alloc_coherent(&(dev->pdev->dev), PAGE_SIZE,
					    &priv->mfunc.vhcr_dma,
					    GFP_KERNEL);
	if (!priv->mfunc.vhcr) {
		mlx4_err(dev, "Couldn't allocate vhcr.\n");
		return -ENOMEM;
	}
	priv->mfunc.vhcr->cookie = 0;

	if (mlx4_is_master(dev))
		priv->mfunc.comm = ioremap(pci_resource_start(dev->pdev,
							    priv->fw.comm_bar) +
								priv->fw.comm_base,
							    MLX4_COMM_PAGESIZE);
	else
		priv->mfunc.comm = ioremap(pci_resource_start(dev->pdev, 2) +
							    MLX4_SLAVE_COMM_BASE,
							    MLX4_COMM_PAGESIZE);
	if (!priv->mfunc.comm) {
		mlx4_err(dev, "Couldn't map communication vector.\n");
		goto err_vhcr;
	}

	if (mlx4_is_master(dev)) {
		priv->mfunc.master.slave_state = kzalloc(dev->num_slaves *
					   sizeof(struct mlx4_slave_state),
					   GFP_KERNEL);
		if (!priv->mfunc.master.slave_state)
			goto err_comm;

		for (i = 0; i < dev->num_slaves; ++i) {
			s_state = &priv->mfunc.master.slave_state[i];
			s_state->last_cmd = MLX4_COMM_CMD_RESET;
			__raw_writel((__force u32) 0, &priv->mfunc.comm[i].slave_write);
			__raw_writel((__force u32) 0, &priv->mfunc.comm[i].slave_read);
			mmiowb();
			for (port = 1; port <= MLX4_MAX_PORTS; port++) {
				s_state->vlan_filter[port] =
					kzalloc(sizeof(struct mlx4_vlan_fltr),
						GFP_KERNEL);
				if (!s_state->vlan_filter[port]) {
					if (--port)
						kfree(s_state->vlan_filter[port]);
					goto err_slaves;
				}
				INIT_LIST_HEAD(&s_state->mcast_filters[port]);
			}
			spin_lock_init(&s_state->lock);
		}

		memset(&priv->mfunc.master.cmd_eqe, 0, sizeof(struct mlx4_eqe));
		priv->mfunc.master.cmd_eqe.type = MLX4_EVENT_TYPE_CMD;
		INIT_WORK(&priv->mfunc.master.comm_work, mlx4_master_comm_channel);
		INIT_WORK(&priv->mfunc.master.slave_event_work, mlx4_gen_slave_eqe);
		INIT_WORK(&priv->mfunc.master.vep_config_work, mlx4_update_vep_config);
		INIT_WORK(&priv->mfunc.master.slave_flr_event_work, mlx4_master_handle_slave_flr);
		spin_lock_init(&priv->mfunc.master.vep_config_lock);
		spin_lock_init(&priv->mfunc.master.slave_state_lock);
		spin_lock_init(&priv->mfunc.master.slave_eq.event_lock);
		priv->mfunc.master.comm_wq = create_singlethread_workqueue("mlx4_comm");
		if (!priv->mfunc.master.comm_wq)
			goto err_slaves;

		if (mlx4_init_resource_tracker(dev))
			goto err_thread;

		mlx4_QUERY_VEP_CFG(dev, dev->caps.function,
				   &priv->mfunc.master.slave_state[dev->caps.function].vep_cfg);
		priv->mfunc.master.slave_state[dev->caps.function].pf_num = dev->caps.function;
		priv->mfunc.master.slave_state[dev->caps.function].vep_num = dev->caps.function >> 1;

		sema_init(&priv->cmd.slave_sem, 1);
		err = mlx4_ARM_COMM_CHANNEL(dev);
		if (err) {
			mlx4_err(dev, " Failed to arm comm channel eq: %x\n", err);
			goto err_resource;
		}

	} else {
		err = sync_toggles(dev);
		if (err) {
			mlx4_err(dev, "Couldn't sync toggles\n");
			goto err_comm;
		}

		sema_init(&priv->cmd.slave_sem, 1);
	}
	return 0;

err_resource:
	mlx4_free_resource_tracker(dev);
err_thread:
	flush_workqueue(priv->mfunc.master.comm_wq);
	destroy_workqueue(priv->mfunc.master.comm_wq);
err_slaves:
	while (--i) {
		for (port = 1; port <= MLX4_MAX_PORTS; port++)
			kfree(priv->mfunc.master.slave_state[i].vlan_filter[port]);
	}
	kfree(priv->mfunc.master.slave_state);
err_comm:
	iounmap(priv->mfunc.comm);
err_vhcr:
	dma_free_coherent(&(dev->pdev->dev), PAGE_SIZE,
					     priv->mfunc.vhcr,
					     priv->mfunc.vhcr_dma);
	priv->mfunc.vhcr = NULL;
	return -ENOMEM;
}

int mlx4_cmd_init(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	mutex_init(&priv->cmd.hcr_mutex);
	sema_init(&priv->cmd.poll_sem, 1);
	priv->cmd.use_events = 0;
	priv->cmd.toggle     = 1;

	priv->cmd.hcr = NULL;
	priv->mfunc.vhcr = NULL;

	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev)) {
		priv->cmd.hcr = ioremap(pci_resource_start(dev->pdev, 0) +
					MLX4_HCR_BASE, MLX4_HCR_SIZE);
		if (!priv->cmd.hcr) {
			mlx4_err(dev, "Couldn't map command register.\n");
			return -ENOMEM;
		}
	}

	priv->cmd.pool = pci_pool_create("mlx4_cmd", dev->pdev,
					 MLX4_MAILBOX_SIZE,
					 MLX4_MAILBOX_SIZE, 0);
	if (!priv->cmd.pool)
		goto err_hcr;

	return 0;

err_hcr:
	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev))
		iounmap(priv->cmd.hcr);
	return -ENOMEM;
}

void mlx4_multi_func_cleanup(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int i, port;

	if (mlx4_is_master(dev)) {
		flush_workqueue(priv->mfunc.master.comm_wq);
		destroy_workqueue(priv->mfunc.master.comm_wq);
		for (i = 0; i < dev->num_slaves; i++) {
			for (port = 1; port <= MLX4_MAX_PORTS; port++)
				kfree(priv->mfunc.master.slave_state[i].vlan_filter[port]);
		}
		kfree(priv->mfunc.master.slave_state);
	}
	iounmap(priv->mfunc.comm);
	dma_free_coherent(&(dev->pdev->dev), PAGE_SIZE,
			  priv->mfunc.vhcr, priv->mfunc.vhcr_dma);
	priv->mfunc.vhcr = NULL;
}

void mlx4_cmd_cleanup(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	pci_pool_destroy(priv->cmd.pool);

	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev))
		iounmap(priv->cmd.hcr);
}

/*
 * Switch to using events to issue FW commands (can only be called
 * after event queue for command events has been initialized).
 */
int mlx4_cmd_use_events(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int i;
	int err = 0;

	priv->cmd.context = kmalloc(priv->cmd.max_cmds *
				   sizeof (struct mlx4_cmd_context),
				   GFP_KERNEL);
	if (!priv->cmd.context)
		return -ENOMEM;

	for (i = 0; i < priv->cmd.max_cmds; ++i) {
		priv->cmd.context[i].token = i;
		priv->cmd.context[i].next  = i + 1;
	}

	priv->cmd.context[priv->cmd.max_cmds - 1].next = -1;
	priv->cmd.free_head = 0;

	sema_init(&priv->cmd.event_sem, priv->cmd.max_cmds);
	spin_lock_init(&priv->cmd.context_lock);

	for (priv->cmd.token_mask = 1;
	     priv->cmd.token_mask < priv->cmd.max_cmds;
	     priv->cmd.token_mask <<= 1)
		; /* nothing */
	--priv->cmd.token_mask;

	down(&priv->cmd.poll_sem);
	priv->cmd.use_events = 1;

	if (mlx4_is_mfunc(dev) && !mlx4_is_master(dev)) {
		err = mlx4_cmd(dev, 0, 1, 0, MLX4_CMD_COMM_INT, MLX4_CMD_TIME_CLASS_A, 0);
		if (err) {
			mlx4_err(dev, "Failed to move to events for the slave\n");
			priv->cmd.use_events = 0;
			for (i = 0; i < priv->cmd.max_cmds; ++i)
				down(&priv->cmd.event_sem);

			up(&priv->cmd.poll_sem);
		}
	}


	return err;
}

/*
 * Switch back to polling (used when shutting down the device)
 */
void mlx4_cmd_use_polling(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int i;

	priv->cmd.use_events = 0;

	for (i = 0; i < priv->cmd.max_cmds; ++i)
		down(&priv->cmd.event_sem);

	kfree(priv->cmd.context);

	up(&priv->cmd.poll_sem);

	if (mlx4_is_mfunc(dev) && !mlx4_is_master(dev))
		mlx4_cmd(dev, 0, 0, 0, MLX4_CMD_COMM_INT, MLX4_CMD_TIME_CLASS_A, 0);
}

struct mlx4_cmd_mailbox *mlx4_alloc_cmd_mailbox(struct mlx4_dev *dev)
{
	struct mlx4_cmd_mailbox *mailbox;

	mailbox = kmalloc(sizeof *mailbox, GFP_KERNEL);
	if (!mailbox)
		return ERR_PTR(-ENOMEM);

	mailbox->buf = pci_pool_alloc(mlx4_priv(dev)->cmd.pool, GFP_KERNEL,
				      &mailbox->dma);
	if (!mailbox->buf) {
		kfree(mailbox);
		return ERR_PTR(-ENOMEM);
	}

	return mailbox;
}
EXPORT_SYMBOL_GPL(mlx4_alloc_cmd_mailbox);

void mlx4_free_cmd_mailbox(struct mlx4_dev *dev, struct mlx4_cmd_mailbox *mailbox)
{
	if (!mailbox)
		return;

	pci_pool_free(mlx4_priv(dev)->cmd.pool, mailbox->buf, mailbox->dma);
	kfree(mailbox);
}
EXPORT_SYMBOL_GPL(mlx4_free_cmd_mailbox);

int mlx4_COMM_INT_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
			  struct mlx4_cmd_mailbox *outbox,
			  struct mlx4_cmd_info *cmd)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_slave_event_eq_info *event_eq =
		&priv->mfunc.master.slave_state[slave].event_eq;

	if (vhcr->in_modifier)
		event_eq->use_int = true;
	else
		event_eq->use_int = false;

	return 0;
}

u32 mlx4_comm_get_version(void)
{
	 return (((u32)CMD_CHAN_IF_REV << 8) | (u32)CMD_CHAN_VER);
}
