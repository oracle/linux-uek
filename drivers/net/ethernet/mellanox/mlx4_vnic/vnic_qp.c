/*
 * Copyright (c) 2007 Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
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

#include <linux/log2.h>
#include <linux/netdevice.h>

#include <rdma/ib_cache.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_addr.h>

#include <linux/mlx4/qp.h>
#include <linux/io.h>

#include "vnic.h"

/* compare with drivers/infiniband/hw/mlx4/qp.c */
#define mlx4_ib_dbg(format, arg...) vnic_dbg(NULL, format, ## arg)

enum {
	MLX4_IB_ACK_REQ_FREQ	= 8,
};

enum {
	MLX4_IB_DEFAULT_SCHED_QUEUE	= 0x83,
	MLX4_IB_DEFAULT_QP0_SCHED_QUEUE	= 0x3f,
	MLX4_IB_LINK_TYPE_IB		= 0,
	MLX4_IB_LINK_TYPE_ETH		= 1,
};

enum {
	/*
	 * Largest possible UD header: send with GRH and immediate data.
	 * 4 bytes added to accommodate for eth header instead of lrh
	 */
	MLX4_IB_UD_HEADER_SIZE		= 76,
	MLX4_IB_MAX_RAW_ETY_HDR_SIZE	= 12
};

enum {
	MLX4_IBOE_ETHERTYPE = 0x8915
};

struct mlx4_ib_sqp {
	struct mlx4_ib_qp	qp;
	int			pkey_index;
	u32			qkey;
	u32			send_psn;
	struct ib_ud_header	ud_header;
	u8			header_buf[MLX4_IB_UD_HEADER_SIZE];
};

enum {
	MLX4_IB_MIN_SQ_STRIDE = 6
};

static const __be32 mlx4_ib_opcode[] = {
	[IB_WR_SEND]			= cpu_to_be32(MLX4_OPCODE_SEND),
	[IB_WR_LSO]			= cpu_to_be32(MLX4_OPCODE_LSO),
	[IB_WR_SEND_WITH_IMM]		= cpu_to_be32(MLX4_OPCODE_SEND_IMM),
	[IB_WR_RDMA_WRITE]		= cpu_to_be32(MLX4_OPCODE_RDMA_WRITE),
	[IB_WR_RDMA_WRITE_WITH_IMM]	= cpu_to_be32(MLX4_OPCODE_RDMA_WRITE_IMM),
	[IB_WR_RDMA_READ]		= cpu_to_be32(MLX4_OPCODE_RDMA_READ),
	[IB_WR_ATOMIC_CMP_AND_SWP]	= cpu_to_be32(MLX4_OPCODE_ATOMIC_CS),
	[IB_WR_ATOMIC_FETCH_AND_ADD]	= cpu_to_be32(MLX4_OPCODE_ATOMIC_FA),
	[IB_WR_SEND_WITH_INV]		= cpu_to_be32(MLX4_OPCODE_SEND_INVAL),
	[IB_WR_LOCAL_INV]		= cpu_to_be32(MLX4_OPCODE_LOCAL_INVAL),
	[IB_WR_FAST_REG_MR]		= cpu_to_be32(MLX4_OPCODE_FMR),
	[IB_WR_MASKED_ATOMIC_CMP_AND_SWP]	= cpu_to_be32(MLX4_OPCODE_MASKED_ATOMIC_CS),
	[IB_WR_MASKED_ATOMIC_FETCH_AND_ADD]	= cpu_to_be32(MLX4_OPCODE_MASKED_ATOMIC_FA),
};

#ifndef wc_wmb
	#if defined(__i386__)
		#define wc_wmb() asm volatile("lock; addl $0,0(%%esp) " ::: "memory")
	#elif defined(__x86_64__)
		#define wc_wmb() asm volatile("sfence" ::: "memory")
	#elif defined(__ia64__)
		#define wc_wmb() asm volatile("fwb" ::: "memory")
	#else
		#define wc_wmb() wmb()
	#endif
#endif

#if 0
static struct mlx4_ib_sqp *to_msqp(struct mlx4_ib_qp *mqp)
{
	return container_of(mqp, struct mlx4_ib_sqp, qp);
}
#endif

static void *get_wqe(struct mlx4_ib_qp *qp, int offset)
{
	return mlx4_buf_offset(&qp->buf, offset);
}

static void *get_recv_wqe(struct mlx4_ib_qp *qp, int n)
{
	return get_wqe(qp, qp->rq.offset + (n << qp->rq.wqe_shift));
}

static void *get_send_wqe(struct mlx4_ib_qp *qp, int n)
{
	return get_wqe(qp, qp->sq.offset + (n << qp->sq.wqe_shift));
}

/*
 * Stamp a SQ WQE so that it is invalid if prefetched by marking the
 * first four bytes of every 64 byte chunk with
 *     0x7FFFFFF | (invalid_ownership_value << 31).
 *
 * When the max work request size is less than or equal to the WQE
 * basic block size, as an optimization, we can stamp all WQEs with
 * 0xffffffff, and skip the very first chunk of each WQE.
 */
static void stamp_send_wqe(struct mlx4_ib_qp *qp, int n, int size)
{
	__be32 *wqe;
	int i;
	int s;
	int ind;
	void *buf;
	__be32 stamp;
	struct mlx4_wqe_ctrl_seg *ctrl;

	if (qp->sq_max_wqes_per_wr > 1) {
		s = roundup(size, 1U << qp->sq.wqe_shift);
		for (i = 0; i < s; i += 64) {
			ind = (i >> qp->sq.wqe_shift) + n;
			stamp = ind & qp->sq.wqe_cnt ? cpu_to_be32(0x7fffffff) :
						       cpu_to_be32(0xffffffff);
			buf = get_send_wqe(qp, ind & (qp->sq.wqe_cnt - 1));
			wqe = buf + (i & ((1 << qp->sq.wqe_shift) - 1));
			*wqe = stamp;
		}
	} else {
		ctrl = buf = get_send_wqe(qp, n & (qp->sq.wqe_cnt - 1));
		s = (ctrl->fence_size & 0x3f) << 4;
		for (i = 64; i < s; i += 64) {
			wqe = buf + i;
			*wqe = cpu_to_be32(0xffffffff);
		}
	}
}

static void post_nop_wqe(struct mlx4_ib_qp *qp, int n, int size)
{
	struct mlx4_wqe_ctrl_seg *ctrl;
	struct mlx4_wqe_inline_seg *inl;
	void *wqe;
	int s;

	ctrl = wqe = get_send_wqe(qp, n & (qp->sq.wqe_cnt - 1));
	s = sizeof(struct mlx4_wqe_ctrl_seg);

	if (qp->ibqp.qp_type == IB_QPT_UD) {
		struct mlx4_wqe_datagram_seg *dgram = wqe + sizeof *ctrl;
		struct mlx4_av *av = (struct mlx4_av *)dgram->av;
		memset(dgram, 0, sizeof *dgram);
		av->port_pd = cpu_to_be32((qp->port << 24) | to_mpd(qp->ibqp.pd)->pdn);
		s += sizeof(struct mlx4_wqe_datagram_seg);
	}

	/* Pad the remainder of the WQE with an inline data segment. */
	if (size > s) {
		inl = wqe + s;
		inl->byte_count = cpu_to_be32(1 << 31 | (size - s - sizeof *inl));
	}
	ctrl->srcrb_flags = 0;
	ctrl->fence_size = size / 16;
	/*
	 * Make sure descriptor is fully written before setting ownership bit
	 * (because HW can start executing as soon as we do).
	 */
	wmb();

	ctrl->owner_opcode = cpu_to_be32(MLX4_OPCODE_NOP | MLX4_WQE_CTRL_NEC) |
		(n & qp->sq.wqe_cnt ? cpu_to_be32(1 << 31) : 0);

	stamp_send_wqe(qp, n + qp->sq_spare_wqes, size);
}

/* Post NOP WQE to prevent wrap-around in the middle of WR */
static inline unsigned pad_wraparound(struct mlx4_ib_qp *qp, int ind)
{
	unsigned s = qp->sq.wqe_cnt - (ind & (qp->sq.wqe_cnt - 1));
	if (unlikely(s < qp->sq_max_wqes_per_wr)) {
		post_nop_wqe(qp, ind, s << qp->sq.wqe_shift);
		ind += s;
	}
	return ind;
}

static void mlx4_ib_qp_event(struct mlx4_qp *qp, enum mlx4_event type)
{
	struct ib_event event;
	struct mlx4_ib_qp *mqp = to_mibqp(qp);
	struct ib_qp *ibqp = &mqp->ibqp;

	if (type == MLX4_EVENT_TYPE_PATH_MIG)
		to_mibqp(qp)->port = to_mibqp(qp)->alt_port;

	if (ibqp->event_handler) {
		event.device     = ibqp->device;
		switch (type) {
		case MLX4_EVENT_TYPE_PATH_MIG:
			event.event = IB_EVENT_PATH_MIG;
			break;
		case MLX4_EVENT_TYPE_COMM_EST:
			event.event = IB_EVENT_COMM_EST;
			break;
		case MLX4_EVENT_TYPE_SQ_DRAINED:
			event.event = IB_EVENT_SQ_DRAINED;
			break;
		case MLX4_EVENT_TYPE_SRQ_QP_LAST_WQE:
			event.event = IB_EVENT_QP_LAST_WQE_REACHED;
			break;
		case MLX4_EVENT_TYPE_WQ_CATAS_ERROR:
			event.event = IB_EVENT_QP_FATAL;
			break;
		case MLX4_EVENT_TYPE_PATH_MIG_FAILED:
			event.event = IB_EVENT_PATH_MIG_ERR;
			break;
		case MLX4_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
			event.event = IB_EVENT_QP_REQ_ERR;
			break;
		case MLX4_EVENT_TYPE_WQ_ACCESS_ERROR:
			event.event = IB_EVENT_QP_ACCESS_ERR;
			break;
		default:
			printk(KERN_WARNING "mlx4_ib: Unexpected event type %d "
			       "on QP %06x\n", type, qp->qpn);
			return;
		}

		event.element.qp = ibqp;
		ibqp->event_handler(&event, ibqp->qp_context);
	}
}

static int send_wqe_overhead(enum ib_qp_type type, u32 flags)
{
	/*
	 * UD WQEs must have a datagram segment.
	 * RC and UC WQEs might have a remote address segment.
	 * MLX WQEs need two extra inline data segments (for the UD
	 * header and space for the ICRC).
	 */
	switch (type) {
	case IB_QPT_UD:
		return sizeof (struct mlx4_wqe_ctrl_seg) +
			sizeof (struct mlx4_wqe_datagram_seg) +
			((flags & MLX4_IB_QP_LSO) ? 128 : 0);
	case IB_QPT_UC:
		return sizeof (struct mlx4_wqe_ctrl_seg) +
			sizeof (struct mlx4_wqe_raddr_seg);
	case IB_QPT_XRC_TGT:
	case IB_QPT_RC:
		return sizeof (struct mlx4_wqe_ctrl_seg) +
			sizeof (struct mlx4_wqe_atomic_seg) +
			sizeof (struct mlx4_wqe_raddr_seg);
	case IB_QPT_SMI:
	case IB_QPT_GSI:
		return sizeof (struct mlx4_wqe_ctrl_seg) +
			ALIGN(MLX4_IB_UD_HEADER_SIZE +
			      DIV_ROUND_UP(MLX4_IB_UD_HEADER_SIZE,
					   MLX4_INLINE_ALIGN) *
			      sizeof (struct mlx4_wqe_inline_seg),
			      sizeof (struct mlx4_wqe_data_seg)) +
			ALIGN(4 +
			      sizeof (struct mlx4_wqe_inline_seg),
			      sizeof (struct mlx4_wqe_data_seg));
	case IB_QPT_RAW_ETHERTYPE:
		return sizeof(struct mlx4_wqe_ctrl_seg) +
			ALIGN(MLX4_IB_MAX_RAW_ETY_HDR_SIZE +
			      sizeof(struct mlx4_wqe_inline_seg),
			      sizeof(struct mlx4_wqe_data_seg));

	default:
		return sizeof (struct mlx4_wqe_ctrl_seg);
	}
}

static int set_rq_size(struct mlx4_ib_dev *dev, struct ib_qp_cap *cap,
		       int is_user, int has_rq, struct mlx4_ib_qp *qp)
{
	/* Sanity check RQ size before proceeding */
	if (cap->max_recv_wr > dev->dev->caps.max_wqes - MLX4_IB_SQ_MAX_SPARE ||
		cap->max_recv_sge > min(dev->dev->caps.max_sq_sg, dev->dev->caps.max_rq_sg))
		return -EINVAL;

	if (!has_rq) {
		if (cap->max_recv_wr)
			return -EINVAL;

		qp->rq.wqe_cnt = qp->rq.max_gs = 0;
	} else {
		/* HW requires >= 1 RQ entry with >= 1 gather entry */
		if (is_user && (!cap->max_recv_wr || !cap->max_recv_sge))
			return -EINVAL;

		qp->rq.wqe_cnt	 = roundup_pow_of_two(max(1U, cap->max_recv_wr));
		qp->rq.max_gs	 = roundup_pow_of_two(max(1U, cap->max_recv_sge));
		qp->rq.wqe_shift = ilog2(qp->rq.max_gs * sizeof (struct mlx4_wqe_data_seg));
	}

	/* leave userspace return values as they were, so as not to break ABI */
	if (is_user) {
		cap->max_recv_wr  = qp->rq.max_post = qp->rq.wqe_cnt;
		cap->max_recv_sge = qp->rq.max_gs;
	} else {
		cap->max_recv_wr  = qp->rq.max_post =
			min(dev->dev->caps.max_wqes - MLX4_IB_SQ_MAX_SPARE, qp->rq.wqe_cnt);
		cap->max_recv_sge = min(qp->rq.max_gs,
					min(dev->dev->caps.max_sq_sg,
					    dev->dev->caps.max_rq_sg));
	}

	return 0;
}

static int set_kernel_sq_size(struct mlx4_ib_dev *dev, struct ib_qp_cap *cap,
			      enum mlx4_ib_qp_type type, struct mlx4_ib_qp *qp)
{
	int s;

	/* Sanity check SQ size before proceeding */
	if (cap->max_send_wr  > (dev->dev->caps.max_wqes - MLX4_IB_SQ_MAX_SPARE) ||
	    cap->max_send_sge > min(dev->dev->caps.max_sq_sg, dev->dev->caps.max_rq_sg) ||
	    cap->max_inline_data + send_wqe_overhead(type, qp->flags) +
	    sizeof (struct mlx4_wqe_inline_seg) > dev->dev->caps.max_sq_desc_sz)
		return -EINVAL;

	/*
	 * For MLX transport we need 2 extra S/G entries:
	 * one for the header and one for the checksum at the end
	 */
	if ((type == MLX4_IB_QPT_SMI || type == MLX4_IB_QPT_GSI ||
	     type & (MLX4_IB_QPT_PROXY_SMI_OWNER | MLX4_IB_QPT_TUN_SMI_OWNER)) &&
	    cap->max_send_sge + 2 > dev->dev->caps.max_sq_sg)
		return -EINVAL;

	s = max(cap->max_send_sge * sizeof (struct mlx4_wqe_data_seg),
		cap->max_inline_data + sizeof (struct mlx4_wqe_inline_seg)) +
		send_wqe_overhead(type, qp->flags);

	if (s > dev->dev->caps.max_sq_desc_sz)
		return -EINVAL;

	/*
	 * Hermon supports shrinking WQEs, such that a single work
	 * request can include multiple units of 1 << wqe_shift.  This
	 * way, work requests can differ in size, and do not have to
	 * be a power of 2 in size, saving memory and speeding up send
	 * WR posting.  Unfortunately, if we do this then the
	 * wqe_index field in CQEs can't be used to look up the WR ID
	 * anymore, so we do this only if selective signaling is off.
	 *
	 * Further, on 32-bit platforms, we can't use vmap() to make
	 * the QP buffer virtually contiguous.  Thus we have to use
	 * constant-sized WRs to make sure a WR is always fully within
	 * a single page-sized chunk.
	 *
	 * Finally, we use NOP work requests to pad the end of the
	 * work queue, to avoid wrap-around in the middle of WR.  We
	 * set NEC bit to avoid getting completions with error for
	 * these NOP WRs, but since NEC is only supported starting
	 * with firmware 2.2.232, we use constant-sized WRs for older
	 * firmware.
	 *
	 * And, since MLX QPs only support SEND, we use constant-sized
	 * WRs in this case.
	 *
	 * We look for the smallest value of wqe_shift such that the
	 * resulting number of wqes does not exceed device
	 * capabilities.
	 *
	 * We set WQE size to at least 64 bytes, this way stamping
	 * invalidates each WQE.
	 */
	if (dev->dev->caps.fw_ver >= MLX4_FW_VER_WQE_CTRL_NEC &&
	    qp->sq_signal_bits && BITS_PER_LONG == 64 &&
	    type != MLX4_IB_QPT_SMI && type != MLX4_IB_QPT_GSI &&
	    !(type & (MLX4_IB_QPT_PROXY_SMI_OWNER | MLX4_IB_QPT_PROXY_SMI |
		      MLX4_IB_QPT_PROXY_GSI | MLX4_IB_QPT_TUN_SMI_OWNER)))
		qp->sq.wqe_shift = ilog2(64);
	else
		qp->sq.wqe_shift = ilog2(roundup_pow_of_two(s));

	for (;;) {
		qp->sq_max_wqes_per_wr = DIV_ROUND_UP(s, 1U << qp->sq.wqe_shift);

		/*
		 * We need to leave 2 KB + 1 WR of headroom in the SQ to
		 * allow HW to prefetch.
		 */
		qp->sq_spare_wqes = (2048 >> qp->sq.wqe_shift) + qp->sq_max_wqes_per_wr;
		qp->sq.wqe_cnt = roundup_pow_of_two(cap->max_send_wr *
						    qp->sq_max_wqes_per_wr +
						    qp->sq_spare_wqes);

		if (qp->sq.wqe_cnt <= dev->dev->caps.max_wqes)
			break;

		if (qp->sq_max_wqes_per_wr <= 1)
			return -EINVAL;

		++qp->sq.wqe_shift;
	}

	qp->sq.max_gs = (min(dev->dev->caps.max_sq_desc_sz,
			     (qp->sq_max_wqes_per_wr << qp->sq.wqe_shift)) -
			 send_wqe_overhead(type, qp->flags)) /
		sizeof (struct mlx4_wqe_data_seg);

	qp->buf_size = (qp->rq.wqe_cnt << qp->rq.wqe_shift) +
		(qp->sq.wqe_cnt << qp->sq.wqe_shift);
	if (qp->rq.wqe_shift > qp->sq.wqe_shift) {
		qp->rq.offset = 0;
		qp->sq.offset = qp->rq.wqe_cnt << qp->rq.wqe_shift;
	} else {
		qp->rq.offset = qp->sq.wqe_cnt << qp->sq.wqe_shift;
		qp->sq.offset = 0;
	}

	cap->max_send_wr  = qp->sq.max_post =
		(qp->sq.wqe_cnt - qp->sq_spare_wqes) / qp->sq_max_wqes_per_wr;
	cap->max_send_sge = min(qp->sq.max_gs,
				min(dev->dev->caps.max_sq_sg,
				    dev->dev->caps.max_rq_sg));
	qp->max_inline_data = cap->max_inline_data;

	return 0;
}



static enum mlx4_qp_state to_mlx4_state(enum ib_qp_state state)
{
	switch (state) {
	case IB_QPS_RESET:	return MLX4_QP_STATE_RST;
	case IB_QPS_INIT:	return MLX4_QP_STATE_INIT;
	case IB_QPS_RTR:	return MLX4_QP_STATE_RTR;
	case IB_QPS_RTS:	return MLX4_QP_STATE_RTS;
	case IB_QPS_SQD:	return MLX4_QP_STATE_SQD;
	case IB_QPS_SQE:	return MLX4_QP_STATE_SQER;
	case IB_QPS_ERR:	return MLX4_QP_STATE_ERR;
	default:		return -1;
	}
}

static void del_gid_entries(struct mlx4_ib_qp *qp)
{
	struct mlx4_ib_gid_entry *ge, *tmp;

	list_for_each_entry_safe(ge, tmp, &qp->gid_list, list) {
		list_del(&ge->list);
		kfree(ge);
	}
}

static void destroy_qp_common(struct mlx4_ib_dev *dev, struct mlx4_ib_qp *qp,
			      struct ib_qp_init_attr *init_attr)
{
	if (qp->state != IB_QPS_RESET)
		if (mlx4_qp_modify(dev->dev, NULL, to_mlx4_state(qp->state),
				   MLX4_QP_STATE_RST, NULL, 0, 0, &qp->mqp))
			printk(KERN_WARNING "mlx4_ib: modify QP %06x to RESET failed.\n",
			       qp->mqp.qpn);

	mlx4_qp_remove(dev->dev, &qp->mqp);
	mlx4_qp_free(dev->dev, &qp->mqp);
	mlx4_mtt_cleanup(dev->dev, &qp->mtt);
	mlx4_qp_release_range(dev->dev, qp->mqp.qpn, 1);
	kfree(qp->sq.wrid);
	kfree(qp->rq.wrid);
	mlx4_buf_free(dev->dev, qp->buf_size, &qp->buf);
	if (qp->max_inline_data)
		mlx4_bf_free(dev->dev, &qp->bf);
	if (!init_attr->srq)
		mlx4_db_free(dev->dev, &qp->db);

	del_gid_entries(qp);
}

static int qp_has_rq(struct ib_qp_init_attr *attr)
{
	if (attr->qp_type == IB_QPT_XRC_INI || attr->qp_type == IB_QPT_XRC_TGT)
		return 0;

	return !attr->srq;
}


static int create_qp_common(struct mlx4_ib_dev *dev, struct ib_pd *pd,
			    struct ib_qp_init_attr *init_attr,
			    struct ib_udata *udata, int sqpn, struct mlx4_ib_qp *qp)
{
	int qpn;
	int err;
	enum mlx4_ib_qp_type qp_type =
			(enum mlx4_ib_qp_type) init_attr->qp_type;
	qp->mlx4_ib_qp_type = qp_type;
	qp->pri.vid = qp->alt.vid = 0xFFFF;
	mutex_init(&qp->mutex);
	spin_lock_init(&qp->sq.lock);
	spin_lock_init(&qp->rq.lock);
	INIT_LIST_HEAD(&qp->gid_list);
	INIT_LIST_HEAD(&qp->steering_rules);
	INIT_LIST_HEAD(&qp->rules_list);

	qp->state	 = IB_QPS_RESET;
	if (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR)
		qp->sq_signal_bits = cpu_to_be32(MLX4_WQE_CTRL_CQ_UPDATE);

	err = set_rq_size(dev, &init_attr->cap, !!pd->uobject,
					  qp_has_rq(init_attr), qp);
	if (err)
		goto err;

	if (pd->uobject) {
	} else {
		qp->sq_no_prefetch = 0;

		if (init_attr->create_flags & IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK)
			qp->flags |= MLX4_IB_QP_BLOCK_MULTICAST_LOOPBACK;

		if (init_attr->create_flags & IB_QP_CREATE_IPOIB_UD_LSO)
			qp->flags |= MLX4_IB_QP_LSO;

		if (init_attr->create_flags & IB_QP_CREATE_NETIF_QP &&
		    dev->dev->caps.steering_mode ==
		    MLX4_STEERING_MODE_DEVICE_MANAGED &&
		    !mlx4_is_mfunc(dev->dev))
			qp->flags |= MLX4_IB_QP_NETIF;

		err = set_kernel_sq_size(dev, &init_attr->cap, qp_type, qp);
		if (err)
			goto err;

		if (qp_has_rq(init_attr)) {
			err = mlx4_db_alloc(dev->dev, &qp->db, 0);
			if (err)
				goto err;

			*qp->db.db = 0;
		}

		if (qp->max_inline_data) {
			err = mlx4_bf_alloc(dev->dev, &qp->bf, 0);
			if (err) {
				mlx4_ib_dbg("failed to allocate blue flame register (%d)", err);
				qp->bf.uar = &dev->priv_uar;
			}
		} else
			qp->bf.uar = &dev->priv_uar;

		if (mlx4_buf_alloc(dev->dev, qp->buf_size,
						   PAGE_SIZE * 2, &qp->buf)) {
			err = -ENOMEM;
			goto err_db;
		}

		err = mlx4_mtt_init(dev->dev, qp->buf.npages, qp->buf.page_shift,
				    &qp->mtt);
		if (err) {
			mlx4_ib_dbg("kernel qp mlx4_mtt_init error (%d)", err);
			goto err_buf;
		}

		err = mlx4_buf_write_mtt(dev->dev, &qp->mtt, &qp->buf);
		if (err) {
			mlx4_ib_dbg("mlx4_buf_write_mtt error (%d)", err);
			goto err_mtt;
		}

		/* these are big chunks that may fail, added __GFP_NOWARN */
		qp->sq.wrid  = kmalloc(qp->sq.wqe_cnt * sizeof (u64),
				       GFP_KERNEL | __GFP_NOWARN);
		qp->rq.wrid  = kmalloc(qp->rq.wqe_cnt * sizeof (u64),
				       GFP_KERNEL | __GFP_NOWARN);

		if (!qp->sq.wrid || !qp->rq.wrid) {
			printk(KERN_WARNING "%s:%d: not enough memory\n",
			       __func__, __LINE__);
			err = -ENOMEM;
			goto err_wrid;
		}
	}

	qpn = sqpn;

	err = mlx4_qp_alloc(dev->dev, qpn, &qp->mqp);
	if (err)
		goto err_qpn;

	if (init_attr->qp_type == IB_QPT_XRC_TGT)
		qp->mqp.qpn |= (1 << 23);

	/*
	 * Hardware wants QPN written in big-endian order (after
	 * shifting) for send doorbell.  Precompute this value to save
	 * a little bit when posting sends.
	 */
	qp->doorbell_qpn = swab32(qp->mqp.qpn << 8);

	qp->mqp.event = mlx4_ib_qp_event;

	return 0;

err_qpn:
err_wrid:
	if (pd->uobject) {
	} else {
		kfree(qp->sq.wrid);
		kfree(qp->rq.wrid);
	}

err_mtt:
	mlx4_mtt_cleanup(dev->dev, &qp->mtt);

err_buf:
	if (pd->uobject)
		ib_umem_release(qp->umem);
	else
		mlx4_buf_free(dev->dev, qp->buf_size, &qp->buf);

err_db:
	if (!pd->uobject && !init_attr->srq
		&& init_attr->qp_type != IB_QPT_XRC_TGT)
		mlx4_db_free(dev->dev, &qp->db);

	if (qp->max_inline_data)
		mlx4_bf_free(dev->dev, &qp->bf);

err:
	return err;
}

#if 0
static int build_mlx_header(struct mlx4_ib_sqp *sqp, struct ib_send_wr *wr,
			    void *wqe, unsigned *mlx_seg_len)
{
	struct ib_device *ib_dev = &to_mdev(sqp->qp.ibqp.device)->ib_dev;
	struct mlx4_wqe_mlx_seg *mlx = wqe;
	struct mlx4_wqe_inline_seg *inl = wqe + sizeof *mlx;
	struct mlx4_ib_ah *ah = to_mah(wr->wr.ud.ah);
	u16 pkey;
	int send_size;
	int header_size;
	int spc;
	int i;
	union ib_gid sgid;
	int is_eth;
	int is_grh;
	int is_vlan = 0;
	int err;
	u16 vlan;

	send_size = 0;
	for (i = 0; i < wr->num_sge; ++i)
		send_size += wr->sg_list[i].length;

	is_eth = rdma_port_get_link_layer(sqp->qp.ibqp.device, sqp->qp.port) == IB_LINK_LAYER_ETHERNET;
	is_grh = mlx4_ib_ah_grh_present(ah);
	err = ib_get_cached_gid(ib_dev, be32_to_cpu(ah->av.ib.port_pd) >> 24,
				ah->av.ib.gid_index, &sgid);
	if (err)
		return err;

	if (is_eth) {
		is_vlan = rdma_get_vlan_id(&sgid) < 0x1000;
		vlan = rdma_get_vlan_id(&sgid);
	}

	ib_ud_header_init(send_size, !is_eth, is_eth, is_vlan, is_grh, 0, &sqp->ud_header);
	if (!is_eth) {
		sqp->ud_header.lrh.service_level =
			be32_to_cpu(ah->av.ib.sl_tclass_flowlabel) >> 28;
		sqp->ud_header.lrh.destination_lid = ah->av.ib.dlid;
		sqp->ud_header.lrh.source_lid = cpu_to_be16(ah->av.ib.g_slid & 0x7f);
	}

	if (is_grh) {
		sqp->ud_header.grh.traffic_class =
			(be32_to_cpu(ah->av.ib.sl_tclass_flowlabel) >> 20) & 0xff;
		sqp->ud_header.grh.flow_label    =
			ah->av.ib.sl_tclass_flowlabel & cpu_to_be32(0xfffff);
		sqp->ud_header.grh.hop_limit     = ah->av.ib.hop_limit;
		ib_get_cached_gid(ib_dev, be32_to_cpu(ah->av.ib.port_pd) >> 24,
				  ah->av.ib.gid_index, &sqp->ud_header.grh.source_gid);
		memcpy(sqp->ud_header.grh.destination_gid.raw,
		       ah->av.ib.dgid, 16);
	}

	mlx->flags &= cpu_to_be32(MLX4_WQE_CTRL_CQ_UPDATE);

	if (!is_eth) {
		mlx->flags |= cpu_to_be32((!sqp->qp.ibqp.qp_num ? MLX4_WQE_MLX_VL15 : 0) |
					  (sqp->ud_header.lrh.destination_lid ==
					   IB_LID_PERMISSIVE ? MLX4_WQE_MLX_SLR : 0) |
					  (sqp->ud_header.lrh.service_level << 8));
		mlx->rlid = sqp->ud_header.lrh.destination_lid;
	}

	switch (wr->opcode) {
	case IB_WR_SEND:
		sqp->ud_header.bth.opcode        = IB_OPCODE_UD_SEND_ONLY;
		sqp->ud_header.immediate_present = 0;
		break;
	case IB_WR_SEND_WITH_IMM:
		sqp->ud_header.bth.opcode        = IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
		sqp->ud_header.immediate_present = 1;
		sqp->ud_header.immediate_data    = wr->ex.imm_data;
		break;
	default:
		return -EINVAL;
	}

	if (is_eth) {
		u8 *smac;

		memcpy(sqp->ud_header.eth.dmac_h, ah->av.eth.mac, 6);
		smac = to_mdev(sqp->qp.ibqp.device)->iboe.netdevs[sqp->qp.port - 1]->dev_addr; /* fixme: cache this value */
		memcpy(sqp->ud_header.eth.smac_h, smac, 6);
		if (!memcmp(sqp->ud_header.eth.smac_h, sqp->ud_header.eth.dmac_h, 6))
			mlx->flags |= cpu_to_be32(MLX4_WQE_CTRL_FORCE_LOOPBACK);
		if (!is_vlan)
			sqp->ud_header.eth.type = cpu_to_be16(MLX4_IBOE_ETHERTYPE);
		else {
			u16 pcp;

			sqp->ud_header.vlan.type = cpu_to_be16(MLX4_IBOE_ETHERTYPE);
			pcp = (be32_to_cpu(ah->av.ib.sl_tclass_flowlabel) >> 27 & 3) << 13;
			sqp->ud_header.vlan.tag = cpu_to_be16(vlan | pcp);
		}
	} else {
		sqp->ud_header.lrh.virtual_lane    = !sqp->qp.ibqp.qp_num ? 15 : 0;
		if (sqp->ud_header.lrh.destination_lid == IB_LID_PERMISSIVE)
			sqp->ud_header.lrh.source_lid = IB_LID_PERMISSIVE;
	}
	sqp->ud_header.bth.solicited_event = !!(wr->send_flags & IB_SEND_SOLICITED);
	if (!sqp->qp.ibqp.qp_num)
		ib_get_cached_pkey(ib_dev, sqp->qp.port, sqp->pkey_index, &pkey);
	else
		ib_get_cached_pkey(ib_dev, sqp->qp.port, wr->wr.ud.pkey_index, &pkey);
	sqp->ud_header.bth.pkey = cpu_to_be16(pkey);
	sqp->ud_header.bth.destination_qpn = cpu_to_be32(wr->wr.ud.remote_qpn);
	sqp->ud_header.bth.psn = cpu_to_be32((sqp->send_psn++) & ((1 << 24) - 1));
	sqp->ud_header.deth.qkey = cpu_to_be32(wr->wr.ud.remote_qkey & 0x80000000 ?
					       sqp->qkey : wr->wr.ud.remote_qkey);
	sqp->ud_header.deth.source_qpn = cpu_to_be32(sqp->qp.ibqp.qp_num);

	header_size = ib_ud_header_pack(&sqp->ud_header, sqp->header_buf);

	if (0) {
		printk(KERN_ERR "built UD header of size %d:\n", header_size);
		for (i = 0; i < header_size / 4; ++i) {
			if (i % 8 == 0)
				printk("  [%02x] ", i * 4);
			printk(" %08x",
			       be32_to_cpu(((__be32 *) sqp->header_buf)[i]));
			if ((i + 1) % 8 == 0)
				printk("\n");
		}
		printk("\n");
	}

	/*
	 * Inline data segments may not cross a 64 byte boundary.  If
	 * our UD header is bigger than the space available up to the
	 * next 64 byte boundary in the WQE, use two inline data
	 * segments to hold the UD header.
	 */
	spc = MLX4_INLINE_ALIGN -
	      ((unsigned long) (inl + 1) & (MLX4_INLINE_ALIGN - 1));
	if (header_size <= spc) {
		inl->byte_count = cpu_to_be32(1 << 31 | header_size);
		memcpy(inl + 1, sqp->header_buf, header_size);
		i = 1;
	} else {
		inl->byte_count = cpu_to_be32(1 << 31 | spc);
		memcpy(inl + 1, sqp->header_buf, spc);

		inl = (void *) (inl + 1) + spc;
		memcpy(inl + 1, sqp->header_buf + spc, header_size - spc);
		/*
		 * Need a barrier here to make sure all the data is
		 * visible before the byte_count field is set.
		 * Otherwise the HCA prefetcher could grab the 64-byte
		 * chunk with this inline segment and get a valid (!=
		 * 0xffffffff) byte count but stale data, and end up
		 * generating a packet with bad headers.
		 *
		 * The first inline segment's byte_count field doesn't
		 * need a barrier, because it comes after a
		 * control/MLX segment and therefore is at an offset
		 * of 16 mod 64.
		 */
		wmb();
		inl->byte_count = cpu_to_be32(1 << 31 | (header_size - spc));
		i = 2;
	}

	*mlx_seg_len =
	ALIGN(i * sizeof (struct mlx4_wqe_inline_seg) + header_size, 16);
	return 0;
}
#endif

static int mlx4_wq_overflow(struct mlx4_ib_wq *wq, int nreq, struct ib_cq *ib_cq)
{
	unsigned cur;
	struct mlx4_ib_cq *cq;

	cur = wq->head - wq->tail;
	if (likely(cur + nreq < wq->max_post))
		return 0;

	cq = to_mcq(ib_cq);
	spin_lock(&cq->lock);
	cur = wq->head - wq->tail;
	spin_unlock(&cq->lock);

	return cur + nreq >= wq->max_post;
}

#if 0
static void set_local_inv_seg(struct mlx4_wqe_local_inval_seg *iseg, u32 rkey)
{
	iseg->flags	= 0;
	iseg->mem_key	= cpu_to_be32(rkey);
	iseg->guest_id	= 0;
	iseg->pa	= 0;
}
#endif

static __always_inline void set_raddr_seg(struct mlx4_wqe_raddr_seg *rseg,
					  u64 remote_addr, u32 rkey)
{
	rseg->raddr    = cpu_to_be64(remote_addr);
	rseg->rkey     = cpu_to_be32(rkey);
	rseg->reserved = 0;
}

#if 0
static void set_atomic_seg(struct mlx4_wqe_atomic_seg *aseg, struct ib_send_wr *wr)
{
	if (wr->opcode == IB_WR_ATOMIC_CMP_AND_SWP) {
		aseg->swap_add = cpu_to_be64(wr->wr.atomic.swap);
		aseg->compare  = cpu_to_be64(wr->wr.atomic.compare_add);
	} else if (wr->opcode == IB_WR_MASKED_ATOMIC_FETCH_AND_ADD) {
		aseg->swap_add = cpu_to_be64(wr->wr.atomic.compare_add);
		aseg->compare  = cpu_to_be64(wr->wr.atomic.compare_add_mask);
	} else {
		aseg->swap_add = cpu_to_be64(wr->wr.atomic.compare_add);
		aseg->compare  = 0;
	}

}
#endif

static void set_datagram_seg(struct mlx4_wqe_datagram_seg *dseg,
			     struct ib_send_wr *wr, __be16 *vlan)
{
	memcpy(dseg->av, &to_mah(wr->wr.ud.ah)->av, sizeof (struct mlx4_av));
	dseg->dqpn = cpu_to_be32(wr->wr.ud.remote_qpn);
	dseg->qkey = cpu_to_be32(wr->wr.ud.remote_qkey);
	dseg->vlan = to_mah(wr->wr.ud.ah)->av.eth.vlan;
	memcpy(dseg->mac, to_mah(wr->wr.ud.ah)->av.eth.mac, 6);
	*vlan = dseg->vlan;
}

#if 0
static void set_mlx_icrc_seg(void *dseg)
{
	u32 *t = dseg;
	struct mlx4_wqe_inline_seg *iseg = dseg;

	t[1] = 0;

	/*
	 * Need a barrier here before writing the byte_count field to
	 * make sure that all the data is visible before the
	 * byte_count field is set.  Otherwise, if the segment begins
	 * a new cacheline, the HCA prefetcher could grab the 64-byte
	 * chunk and get a valid (!= * 0xffffffff) byte count but
	 * stale data, and end up sending the wrong data.
	 */
	wmb();

	iseg->byte_count = cpu_to_be32((1 << 31) | 4);
}
#endif

static void set_data_seg(struct mlx4_wqe_data_seg *dseg, struct ib_sge *sg)
{
	dseg->lkey       = cpu_to_be32(sg->lkey);
	dseg->addr       = cpu_to_be64(sg->addr);

	/*
	 * Need a barrier here before writing the byte_count field to
	 * make sure that all the data is visible before the
	 * byte_count field is set.  Otherwise, if the segment begins
	 * a new cacheline, the HCA prefetcher could grab the 64-byte
	 * chunk and get a valid (!= * 0xffffffff) byte count but
	 * stale data, and end up sending the wrong data.
	 */
	wmb();

	dseg->byte_count = cpu_to_be32(sg->length);
}

static void __set_data_seg(struct mlx4_wqe_data_seg *dseg, struct ib_sge *sg)
{
	dseg->byte_count = cpu_to_be32(sg->length);
	dseg->lkey       = cpu_to_be32(sg->lkey);
	dseg->addr       = cpu_to_be64(sg->addr);
}

static int build_lso_seg(struct mlx4_wqe_lso_seg *wqe, struct ib_send_wr *wr,
			 struct mlx4_ib_qp *qp, unsigned *lso_seg_len,
			 __be32 *lso_hdr_sz, int *blh)
{
	unsigned halign = ALIGN(sizeof *wqe + wr->wr.ud.hlen, 16);

	*blh = unlikely(halign > 64) ? 1 : 0;

	if (unlikely(!(qp->flags & MLX4_IB_QP_LSO) &&
		     wr->num_sge > qp->sq.max_gs - (halign >> 4)))
		return -EINVAL;

	memcpy(wqe->header, wr->wr.ud.header, wr->wr.ud.hlen);

	*lso_hdr_sz  = cpu_to_be32((wr->wr.ud.mss - wr->wr.ud.hlen) << 16 |
				   wr->wr.ud.hlen);
	*lso_seg_len = halign;
	return 0;
}

static __be32 send_ieth(struct ib_send_wr *wr)
{
	switch (wr->opcode) {
	case IB_WR_SEND_WITH_IMM:
	case IB_WR_RDMA_WRITE_WITH_IMM:
		return wr->ex.imm_data;

	case IB_WR_SEND_WITH_INV:
		return cpu_to_be32(wr->ex.invalidate_rkey);

	default:
		return 0;
	}
}

static int lay_inline_data(struct mlx4_ib_qp *qp, struct ib_send_wr *wr,
			   void *wqe, int *sz)
{
	struct mlx4_wqe_inline_seg *seg;
	void *addr;
	int len, seg_len;
	int num_seg;
	int off, to_copy;
	int i;
	int inl = 0;

	seg = wqe; // current segment
	wqe += sizeof *seg; // wqe pointer
	off = ((unsigned long)wqe) & (unsigned long)(MLX4_INLINE_ALIGN - 1);
	num_seg = 0;
	seg_len = 0;

	for (i = 0; i < wr->num_sge; ++i) {
		addr = (void *) (unsigned long)(wr->sg_list[i].addr);
		len  = wr->sg_list[i].length;
		inl += len;

		if (inl > qp->max_inline_data) {
			inl = 0;
			return -1;
		}

		while (len >= MLX4_INLINE_ALIGN - off) {
			to_copy = MLX4_INLINE_ALIGN - off;
			memcpy(wqe, addr, to_copy);
			len -= to_copy;
			wqe += to_copy;
			addr += to_copy;
			seg_len += to_copy;
			wmb(); /* see comment below */
			seg->byte_count = htonl(MLX4_INLINE_SEG | seg_len);
			seg_len = 0;
			seg = wqe;
			wqe += sizeof *seg;
			off = sizeof *seg;
			++num_seg;
		}

		memcpy(wqe, addr, len);
		wqe += len;
		seg_len += len;
		off += len;
	}

	if (seg_len) {
		++num_seg;
		/*
		 * Need a barrier here to make sure
		 * all the data is visible before the
		 * byte_count field is set.  Otherwise
		 * the HCA prefetcher could grab the
		 * 64-byte chunk with this inline
		 * segment and get a valid (!=
		 * 0xffffffff) byte count but stale
		 * data, and end up sending the wrong
		 * data.
		 */
		wmb();
		seg->byte_count = htonl(MLX4_INLINE_SEG | seg_len);
	}

	*sz = (inl + num_seg * sizeof * seg + 15) / 16;

	return 0;
}

/*
 * Avoid using memcpy() to copy to BlueFlame page, since memcpy()
 * implementations may use move-string-buffer assembler instructions,
 * which do not guarantee order of copying.
 */
static void mlx4_bf_copy(unsigned long *dst, unsigned long *src, unsigned bytecnt)
{
	__iowrite64_copy(dst, src, bytecnt / 8);
}

int mlx4_ib_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *wr,
		      struct ib_recv_wr **bad_wr)
{
	struct mlx4_ib_qp *qp = to_mqp(ibqp);
	struct mlx4_wqe_data_seg *scat;
	unsigned long flags;
	int err = 0;
	int nreq;
	int ind;
	int i;

	spin_lock_irqsave(&qp->rq.lock, flags);

	ind = qp->rq.head & (qp->rq.wqe_cnt - 1);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (mlx4_wq_overflow(&qp->rq, nreq, qp->ibqp.recv_cq)) {
			mlx4_ib_dbg("QP 0x%x: WQE overflow", ibqp->qp_num);
			err = -ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->rq.max_gs)) {
			mlx4_ib_dbg("QP 0x%x: too many sg entries (%d)",
				    ibqp->qp_num, wr->num_sge);
			err = -EINVAL;
			*bad_wr = wr;
			goto out;
		}

		scat = get_recv_wqe(qp, ind);

		for (i = 0; i < wr->num_sge; ++i)
			__set_data_seg(scat + i, wr->sg_list + i);

		if (i < qp->rq.max_gs) {
			scat[i].byte_count = 0;
			scat[i].lkey       = cpu_to_be32(MLX4_INVALID_LKEY);
			scat[i].addr       = 0;
		}

		qp->rq.wrid[ind] = wr->wr_id;

		ind = (ind + 1) & (qp->rq.wqe_cnt - 1);
	}

out:
	if (likely(nreq)) {
		qp->rq.head += nreq;

		/*
		 * Make sure that descriptors are written before
		 * doorbell record.
		 */
		wmb();

		*qp->db.db = cpu_to_be32(qp->rq.head & 0xffff);
	}

	spin_unlock_irqrestore(&qp->rq.lock, flags);

	return err;
}

static inline enum ib_qp_state to_ib_qp_state(enum mlx4_qp_state mlx4_state)
{
	switch (mlx4_state) {
	case MLX4_QP_STATE_RST:      return IB_QPS_RESET;
	case MLX4_QP_STATE_INIT:     return IB_QPS_INIT;
	case MLX4_QP_STATE_RTR:      return IB_QPS_RTR;
	case MLX4_QP_STATE_RTS:      return IB_QPS_RTS;
	case MLX4_QP_STATE_SQ_DRAINING:
	case MLX4_QP_STATE_SQD:      return IB_QPS_SQD;
	case MLX4_QP_STATE_SQER:     return IB_QPS_SQE;
	case MLX4_QP_STATE_ERR:      return IB_QPS_ERR;
	default:		     return -1;
	}
}

static inline enum ib_mig_state to_ib_mig_state(int mlx4_mig_state)
{
	switch (mlx4_mig_state) {
	case MLX4_QP_PM_ARMED:		return IB_MIG_ARMED;
	case MLX4_QP_PM_REARM:		return IB_MIG_REARM;
	case MLX4_QP_PM_MIGRATED:	return IB_MIG_MIGRATED;
	default: return -1;
	}
}

static int to_ib_qp_access_flags(int mlx4_flags)
{
	int ib_flags = 0;

	if (mlx4_flags & MLX4_QP_BIT_RRE)
		ib_flags |= IB_ACCESS_REMOTE_READ;
	if (mlx4_flags & MLX4_QP_BIT_RWE)
		ib_flags |= IB_ACCESS_REMOTE_WRITE;
	if (mlx4_flags & MLX4_QP_BIT_RAE)
		ib_flags |= IB_ACCESS_REMOTE_ATOMIC;

	return ib_flags;
}

static void to_ib_ah_attr(struct mlx4_ib_dev *ib_dev, struct ib_ah_attr *ib_ah_attr,
			  struct mlx4_qp_path *path)
{
	struct mlx4_dev *dev = ib_dev->dev;
	int is_eth;

	memset(ib_ah_attr, 0, sizeof *ib_ah_attr);
	ib_ah_attr->port_num	  = path->sched_queue & 0x40 ? 2 : 1;

	if (ib_ah_attr->port_num == 0 || ib_ah_attr->port_num > dev->caps.num_ports)
		return;

	is_eth = rdma_port_get_link_layer(&ib_dev->ib_dev, ib_ah_attr->port_num) ==
		IB_LINK_LAYER_ETHERNET;
	if (is_eth)
		ib_ah_attr->sl = ((path->sched_queue >> 3) & 0x7) |
		((path->sched_queue & 4) << 1);
	else
		ib_ah_attr->sl = (path->sched_queue >> 2) & 0xf;

	ib_ah_attr->dlid	  = be16_to_cpu(path->rlid);

	ib_ah_attr->src_path_bits = path->grh_mylmc & 0x7f;
	ib_ah_attr->static_rate   = path->static_rate ? path->static_rate - 5 : 0;
	ib_ah_attr->ah_flags      = (path->grh_mylmc & (1 << 7)) ? IB_AH_GRH : 0;
	if (ib_ah_attr->ah_flags) {
		ib_ah_attr->grh.sgid_index = path->mgid_index;
		ib_ah_attr->grh.hop_limit  = path->hop_limit;
		ib_ah_attr->grh.traffic_class =
			(be32_to_cpu(path->tclass_flowlabel) >> 20) & 0xff;
		ib_ah_attr->grh.flow_label =
			be32_to_cpu(path->tclass_flowlabel) & 0xfffff;
		memcpy(ib_ah_attr->grh.dgid.raw,
			path->rgid, sizeof ib_ah_attr->grh.dgid.raw);
	}
}

int mlx4_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
		     struct ib_qp_init_attr *qp_init_attr)
{
	struct mlx4_ib_dev *dev = to_mdev(ibqp->device);
	struct mlx4_ib_qp *qp = to_mqp(ibqp);
	struct mlx4_qp_context context;
	int mlx4_state;
	int err = 0;

	mutex_lock(&qp->mutex);

	if (qp->state == IB_QPS_RESET) {
		qp_attr->qp_state = IB_QPS_RESET;
		goto done;
	}

	err = mlx4_qp_query(dev->dev, &qp->mqp, &context);
	if (err) {
		err = -EINVAL;
		goto out;
	}

	mlx4_state = be32_to_cpu(context.flags) >> 28;

	qp->state		     = to_ib_qp_state(mlx4_state);
	qp_attr->qp_state	     = qp->state;
	qp_attr->path_mtu	     = context.mtu_msgmax >> 5;
	qp_attr->path_mig_state	     =
		to_ib_mig_state((be32_to_cpu(context.flags) >> 11) & 0x3);
	qp_attr->qkey		     = be32_to_cpu(context.qkey);
	qp_attr->rq_psn		     = be32_to_cpu(context.rnr_nextrecvpsn) & 0xffffff;
	qp_attr->sq_psn		     = be32_to_cpu(context.next_send_psn) & 0xffffff;
	qp_attr->dest_qp_num	     = be32_to_cpu(context.remote_qpn) & 0xffffff;
	qp_attr->qp_access_flags     =
		to_ib_qp_access_flags(be32_to_cpu(context.params2));

	if (qp->ibqp.qp_type == IB_QPT_RC || qp->ibqp.qp_type == IB_QPT_UC ||
	    qp->ibqp.qp_type == IB_QPT_XRC_TGT) {
		to_ib_ah_attr(dev, &qp_attr->ah_attr, &context.pri_path);
		to_ib_ah_attr(dev, &qp_attr->alt_ah_attr, &context.alt_path);
		qp_attr->alt_pkey_index = context.alt_path.pkey_index & 0x7f;
		qp_attr->alt_port_num	= qp_attr->alt_ah_attr.port_num;
	}

	qp_attr->pkey_index = context.pri_path.pkey_index & 0x7f;
	if (qp_attr->qp_state == IB_QPS_INIT)
		qp_attr->port_num = qp->port;
	else
		qp_attr->port_num = context.pri_path.sched_queue & 0x40 ? 2 : 1;

	/* qp_attr->en_sqd_async_notify is only applicable in modify qp */
	qp_attr->sq_draining = mlx4_state == MLX4_QP_STATE_SQ_DRAINING;

	qp_attr->max_rd_atomic = 1 << ((be32_to_cpu(context.params1) >> 21) & 0x7);

	qp_attr->max_dest_rd_atomic =
		1 << ((be32_to_cpu(context.params2) >> 21) & 0x7);
	qp_attr->min_rnr_timer	    =
		(be32_to_cpu(context.rnr_nextrecvpsn) >> 24) & 0x1f;
	qp_attr->timeout	    = context.pri_path.ackto >> 3;
	qp_attr->retry_cnt	    = (be32_to_cpu(context.params1) >> 16) & 0x7;
	qp_attr->rnr_retry	    = (be32_to_cpu(context.params1) >> 13) & 0x7;
	qp_attr->alt_timeout	    = context.alt_path.ackto >> 3;

done:
	qp_attr->cur_qp_state	     = qp_attr->qp_state;
	qp_attr->cap.max_recv_wr     = qp->rq.wqe_cnt;
	qp_attr->cap.max_recv_sge    = qp->rq.max_gs;

	if (!ibqp->uobject) {
		qp_attr->cap.max_send_wr  = qp->sq.wqe_cnt;
		qp_attr->cap.max_send_sge = qp->sq.max_gs;
	} else {
		qp_attr->cap.max_send_wr  = 0;
		qp_attr->cap.max_send_sge = 0;
	}

	/*
	 * We don't support inline sends for kernel QPs (yet), and we
	 * don't know what userspace's value should be.
	 */
	qp_attr->cap.max_inline_data = 0;

	qp_init_attr->cap	     = qp_attr->cap;

	qp_init_attr->create_flags = 0;
	if (qp->flags & MLX4_IB_QP_BLOCK_MULTICAST_LOOPBACK)
		qp_init_attr->create_flags |= IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK;

	if (qp->flags & MLX4_IB_QP_LSO)
		qp_init_attr->create_flags |= IB_QP_CREATE_IPOIB_UD_LSO;

out:
	mutex_unlock(&qp->mutex);
	return err;
}


int mlx4_ib_create_xrc_rcv_qp(struct ib_qp_init_attr *init_attr,
			      u32 *qp_num)
{
	return -ENOSYS;
}

int mlx4_ib_modify_xrc_rcv_qp(struct ib_xrcd *ibxrcd, u32 qp_num,
			      struct ib_qp_attr *attr, int attr_mask)
{
	return -ENOSYS;
}

int mlx4_ib_query_xrc_rcv_qp(struct ib_xrcd *ibxrcd, u32 qp_num,
			     struct ib_qp_attr *qp_attr, int qp_attr_mask,
			     struct ib_qp_init_attr *qp_init_attr)
{
	return -ENOSYS;
}

int mlx4_ib_reg_xrc_rcv_qp(struct ib_xrcd *xrcd, void *context, u32 qp_num)
{
	return -ENOSYS;
}

int mlx4_ib_unreg_xrc_rcv_qp(struct ib_xrcd *xrcd, void *context, u32 qp_num)
{
	return -ENOSYS;
}

/**** VNIC IB VERBS ****/
int vnic_ib_post_send(struct ib_qp *ibqp,
		      struct ib_send_wr *wr,
		      struct ib_send_wr **bad_wr,
		      u8 ip_off, u8 ip6_off,
		      u8 tcp_off, u8 udp_off)
{
	struct mlx4_ib_qp *qp = to_mqp(ibqp);
	void *wqe;
	struct mlx4_wqe_ctrl_seg *ctrl;
	struct mlx4_wqe_data_seg *dseg;
	__be32 owner_opcode = 0;
	int nreq;
	int err = 0;
	unsigned ind;
	int uninitialized_var(stamp);
	int uninitialized_var(size);
	unsigned uninitialized_var(seglen);
	__be32 dummy;
	__be32 *lso_wqe;
	__be32 uninitialized_var(lso_hdr_sz);
	int i;
	int blh = 0;
	__be16 vlan = 0;
	int inl = 0;

	ind = qp->sq_next_wqe;

	nreq = 0;
	lso_wqe = &dummy;

	if (mlx4_wq_overflow(&qp->sq, nreq, qp->ibqp.send_cq)) {
		mlx4_ib_dbg("QP 0x%x: WQE overflow", ibqp->qp_num);
		err = -ENOMEM;
		*bad_wr = wr;
		goto out;
	}

	if (unlikely(wr->num_sge > qp->sq.max_gs)) {
		mlx4_ib_dbg("QP 0x%x: too many sg entries (%d)",
			    ibqp->qp_num, wr->num_sge);
		err = -EINVAL;
		*bad_wr = wr;
		goto out;
	}

	ctrl = wqe = get_send_wqe(qp, ind & (qp->sq.wqe_cnt - 1));
	*((u32 *) (&ctrl->vlan_tag)) = 0;
	qp->sq.wrid[(qp->sq.head + nreq) & (qp->sq.wqe_cnt - 1)] = wr->wr_id;

	ctrl->srcrb_flags =
		(wr->send_flags & IB_SEND_SIGNALED ?
		 cpu_to_be32(MLX4_WQE_CTRL_CQ_UPDATE) : 0) |
		(wr->send_flags & IB_SEND_SOLICITED ?
		 cpu_to_be32(MLX4_WQE_CTRL_SOLICITED) : 0) |
		qp->sq_signal_bits;

	ctrl->imm = send_ieth(wr);

	wqe += sizeof *ctrl;
	size = sizeof *ctrl / 16;

	set_datagram_seg(wqe, wr, &vlan);
	wqe  += sizeof (struct mlx4_wqe_datagram_seg);
	size += sizeof (struct mlx4_wqe_datagram_seg) / 16;

	if (wr->opcode == IB_WR_LSO) {
		err = build_lso_seg(wqe, wr, qp, &seglen, &lso_hdr_sz, &blh);
		if (unlikely(err)) {
			*bad_wr = wr;
			goto out;
		}
		lso_wqe = (__be32 *) wqe;
		wqe  += seglen;
		size += seglen / 16;
	}
	dseg = wqe;
	dseg += wr->num_sge - 1;

	if (wr->send_flags & IB_SEND_INLINE && wr->num_sge) {
		int sz;

		err = lay_inline_data(qp, wr, wqe, &sz);
		if (!err) {
			inl = 1;
			size += sz;
		}
	} else {
		size += wr->num_sge * (sizeof(struct mlx4_wqe_data_seg) / 16);
		for (i = wr->num_sge - 1; i >= 0; --i, --dseg)
			set_data_seg(dseg, wr->sg_list + i);
	}

	wmb();
	*lso_wqe = lso_hdr_sz;

	ctrl->fence_size = size;

	/* set SWP bits based on ip/ip6/tcp/udp offests */
	if (wr->send_flags & IB_SEND_IP_CSUM) {
		 /* SWP bit */
		owner_opcode |= cpu_to_be32(1 << 24);

		/* IP offset starts from the begining of IB packet
		 * (and not ETH packet) in 2 bytes.
		 * In control segment, we use c & d:
		 * (a) tcp=0, ip=0 => calc TCP/UDP csum over IPv4
		 * (b) tcp=0, ip=1 => calc IP csum only over IPv4
		 * (c) tcp=1, ip=0 => calc TCP/UDP csum over IPv6
		 * (d) tcp=1, ip=1 => calc TCP/UDP and IP csum over IPv4
		 */
		if (ip_off) {
			ip_off += (IB_LRH_BYTES + IB_BTH_BYTES +
				   IB_DETH_BYTES) >> 1;
			ip_off += (to_mah(wr->wr.ud.ah)->av.ib.g_slid
				   & 0x80) ? (IB_GRH_BYTES >> 1) : 0;
			owner_opcode |= cpu_to_be32((ip_off) << 8);
			ctrl->srcrb_flags |=
				cpu_to_be32(MLX4_WQE_CTRL_IP_CSUM);
		} else if (ip6_off) {
			ip6_off += (IB_LRH_BYTES + IB_BTH_BYTES +
				   IB_DETH_BYTES) >> 1;
			ip6_off += (to_mah(wr->wr.ud.ah)->av.ib.g_slid
				   & 0x80) ? (IB_GRH_BYTES >> 1) : 0;
			owner_opcode |= cpu_to_be32((ip6_off) << 8);
		}

		if (udp_off) { /* UDP offset and bit */
			owner_opcode |= cpu_to_be32(udp_off << 16);
			owner_opcode |= cpu_to_be32(1 << 25);
			ctrl->srcrb_flags |=
				cpu_to_be32(MLX4_WQE_CTRL_TCP_UDP_CSUM);
		} else if (tcp_off) { /* TCP offset */
			owner_opcode |= cpu_to_be32(tcp_off << 16);
			ctrl->srcrb_flags |=
				cpu_to_be32(MLX4_WQE_CTRL_TCP_UDP_CSUM);
		}
	}

	/* set opcode, use 0x4e for BIG_LSO */
	if (!blh)
		owner_opcode |= mlx4_ib_opcode[wr->opcode];
	else
		owner_opcode |= cpu_to_be32(0x4e);

	/* set owenership bit */
	owner_opcode |= (ind & qp->sq.wqe_cnt ? cpu_to_be32(1 << 31) : 0);

	/* Make sure descriptor is fully written */
	wmb();
	ctrl->owner_opcode = owner_opcode;

	stamp = ind + qp->sq_spare_wqes;
	ind += DIV_ROUND_UP(size * 16, 1U << qp->sq.wqe_shift);

	/* simulate the for loop */
	nreq++;

out:
	if (nreq == 1 && inl && size > 1 && size < qp->bf.buf_size / 16) {
		ctrl->owner_opcode |= htonl((qp->sq_next_wqe & 0xffff) << 8);
		*(u32 *) (&ctrl->vlan_tag) |= qp->doorbell_qpn;
		/*
		 * Make sure that descriptor is written to memory
		 * before writing to BlueFlame page.
		 */
		wmb();

		++qp->sq.head;

		mlx4_bf_copy(qp->bf.reg + qp->bf.offset, (unsigned long *) ctrl,
			     ALIGN(size * 16, 64));
		wc_wmb();

		qp->bf.offset ^= qp->bf.buf_size;

	} else if (nreq) {
		qp->sq.head += nreq;

		/*
		 * Make sure that descriptors are written before
		 * doorbell record.
		 */
		wmb();

		writel(qp->doorbell_qpn, qp->bf.uar->map + MLX4_SEND_DOORBELL);

		/*
		 * Make sure doorbells don't leak out of SQ spinlock
		 * and reach the HCA out of order.
		 */
		mmiowb();

	}

	stamp_send_wqe(qp, stamp, size * 16);

	ind = pad_wraparound(qp, ind);
	qp->sq_next_wqe = ind;
	return err;
}

int __vnic_ib_create_qp_range(struct ib_pd *pd, struct ib_qp_init_attr *init_attr,
			      struct ib_udata *udata, int nqps,
			      int align, struct ib_qp *list[])
{
	struct mlx4_ib_dev *dev = to_mdev(pd->device);
	struct mlx4_ib_qp *qp;
	int err;
	int base_qpn, qpn;
	int i;

	for (i = 0; i < nqps; ++i) {
		if (init_attr[i].create_flags & ~(IB_QP_CREATE_IPOIB_UD_LSO |
						  IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK))
			return -EINVAL;
		if (init_attr[i].create_flags & (IB_QP_CREATE_IPOIB_UD_LSO |
						 IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK) &&
		    (pd->uobject || init_attr[i].qp_type != IB_QPT_UD))
			return -EINVAL;

		/* Userspace is not allowed to create special QPs: */
		if (pd->uobject && (init_attr[i].qp_type == IB_QPT_SMI ||
				    init_attr[i].qp_type == IB_QPT_GSI))
			return -EINVAL;
 
		if (nqps > 1 && (init_attr[i].qp_type == IB_QPT_SMI ||
				    init_attr[i].qp_type == IB_QPT_GSI))
			return -EINVAL;
	}
 
	err = mlx4_qp_reserve_range(dev->dev, nqps, align, &base_qpn, 0);
	if (err)
		return err;

	for (i = 0, qpn = base_qpn; i < nqps; ++i, ++qpn) {
		qp = kzalloc(sizeof *qp, GFP_KERNEL);
		if (!qp) {
			err = -ENOMEM;
			goto exit_fail;
		}

		err = create_qp_common(dev, pd, init_attr + i, udata, qpn, qp);
		if (err) {
			kfree(qp);
			err = err;
			goto exit_fail;
		}
		qp->xrcdn = 0;
		qp->ibqp.qp_num = qp->mqp.qpn;
		list[i] = &qp->ibqp;
	}
	return 0;

exit_fail:
	for (--i; i >= 0; --i) {
		destroy_qp_common(dev, to_mqp(list[i]), init_attr + i);
		kfree(to_mqp(list[i]));
	}
 
	mlx4_qp_release_range(dev->dev, base_qpn, nqps);
	return err;
}

/* compare with ib_create_qp() in infiniband/core/verbs.c */
int vnic_ib_create_qp_range(struct ib_pd *pd, struct ib_qp_init_attr *init_attr,
			    struct ib_udata *udata, int nqps,
			    int align, struct ib_qp *list[])
{
	struct ib_qp *qp;
	struct ib_qp_init_attr *qp_init_attr;
	int rc, i;

	rc = __vnic_ib_create_qp_range(pd, init_attr, udata ,nqps, align, list);

	if (rc)
		return rc;

	for (i = 0; i < nqps; ++ i) {
		qp = list[i];
		qp_init_attr      = &init_attr[i];
		qp->device        = pd->device;
		qp->real_qp       = qp;
		qp->pd            = pd;
		qp->send_cq       = qp_init_attr->send_cq;
		qp->recv_cq       = qp_init_attr->recv_cq;
		qp->srq           = qp_init_attr->srq;
		qp->uobject       = NULL;
		qp->event_handler = qp_init_attr->event_handler;
		qp->qp_context    = qp_init_attr->qp_context;
		qp->qp_type       = qp_init_attr->qp_type;
		qp->xrcd          = qp->qp_type == IB_QPT_XRC_TGT ?
			qp_init_attr->xrcd : NULL;
		atomic_inc(&pd->usecnt);
		atomic_inc(&qp_init_attr->send_cq->usecnt);
		atomic_inc(&qp_init_attr->recv_cq->usecnt);
		if (qp_init_attr->srq)
			atomic_inc(&qp_init_attr->srq->usecnt);
		if (qp->qp_type == IB_QPT_XRC_TGT)
			atomic_inc(&qp->xrcd->usecnt);
	}
	return 0;
}

