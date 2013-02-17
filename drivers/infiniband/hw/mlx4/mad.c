/*
 * Copyright (c) 2007 Cisco Systems, Inc. All rights reserved.
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

#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_sa.h>
#include <rdma/ib_pma.h>


#include <linux/mlx4/cmd.h>

#include "mlx4_ib.h"
#include "alias_GUID.h"
#include "ib_events.h"

enum {
	MLX4_IB_VENDOR_CLASS1 = 0x9,
	MLX4_IB_VENDOR_CLASS2 = 0xa
};

#define MLX4_TUN_SEND_WRID_SHIFT 34
#define MLX4_TUN_QPN_SHIFT 32
#define MLX4_TUN_WRID_RECV (((u64) 1) << MLX4_TUN_SEND_WRID_SHIFT)
#define MLX4_TUN_SET_WRID_QPN(a) (((u64) ((a) & 0x3)) << MLX4_TUN_QPN_SHIFT)

#define MLX4_TUN_IS_RECV(a)  (((a) >>  MLX4_TUN_SEND_WRID_SHIFT) & 0x1)
#define MLX4_TUN_WRID_QPN(a) (((a) >> MLX4_TUN_QPN_SHIFT) & 0x3)

/* QP and CQ parameters */
#define MLX4_IB_MAD_QP_SEND_SIZE	256
#define MLX4_IB_MAD_QP_RECV_SIZE	256
#define MLX4_IB_MAD_QP_MIN_SIZE		64
#define MLX4_IB_MAD_QP_MAX_SIZE		8192
#define MLX4_IB_MAD_SEND_REQ_MAX_SG	2
#define MLX4_IB_MAD_RECV_REQ_MAX_SG	1

#define MLX4_IB_MAD_SEND_Q_PSN		0

struct mlx4_mad_rcv_buf {
	struct ib_grh grh;
	u8 payload[256];
} __attribute__ ((packed));

struct mlx4_mad_snd_buf {
	u8 payload[256];
} __attribute__ ((packed));

struct mlx4_tunnel_mad {
	struct ib_grh grh;
	struct mlx4_ib_tunnel_header hdr;
	struct ib_mad mad;
} __attribute__ ((packed));

struct mlx4_rcv_tunnel_mad {
	struct mlx4_rcv_tunnel_hdr hdr;
	struct ib_grh grh;
	struct ib_mad mad;
} __attribute__ ((packed));

/* This function should only be called by the master, to get the function
   number */
static inline int get_master_func_num(struct mlx4_ib_dev *dev)
{
#ifdef CONFIG_MLX4_DEBUG
	if (!dev->dev->caps.sqp_demux)
		printk(KERN_ERR "function %s was called by non-master\n",
		       __func__);
#endif /* CONFIG_MLX4_DEBUG */

	return dev->dev->caps.function;
}

static enum rdma_link_layer
mlx4_ib_port_link_layer(struct mlx4_ib_dev *device, u8 port_num)
{
	return device->dev->caps.port_mask[port_num] == MLX4_PORT_TYPE_IB ?
		IB_LINK_LAYER_INFINIBAND : IB_LINK_LAYER_ETHERNET;
}

__be64 mlx4_ib_get_new_demux_tid(struct mlx4_ib_demux_ctx *ctx)
{
	return cpu_to_be64(atomic_inc_return(&ctx->tid)) |
		cpu_to_be64(0xff00000000000000LL);
}

int mlx4_MAD_IFC(struct mlx4_ib_dev *dev, int ignore_mkey, int ignore_bkey,
		 int port, struct ib_wc *in_wc, struct ib_grh *in_grh,
		 void *in_mad, void *response_mad)
{
	struct mlx4_cmd_mailbox *inmailbox, *outmailbox;
	void *inbox;
	int err;
	u32 in_modifier = port;
	u8 op_modifier = 0;

	inmailbox = mlx4_alloc_cmd_mailbox(dev->dev);
	if (IS_ERR(inmailbox))
		return PTR_ERR(inmailbox);
	inbox = inmailbox->buf;

	outmailbox = mlx4_alloc_cmd_mailbox(dev->dev);
	if (IS_ERR(outmailbox)) {
		mlx4_free_cmd_mailbox(dev->dev, inmailbox);
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

	/* Currently, MADs in Dom0 (which is also currently the MAD master)
	 * are not modified in paravirtualization (wrapper) code.  (The Dom0 pkey
	 * paravirt table is a 1-1 mapping which is not modifiable). Therefore,
	 * we can safely set the native flag to 1 (true) for MAD_IFC, so that MAD_IFC
	 * in Dom0 * will be executed directly, and not via the wrapper.
	 * Doing this saves significant time in MAD processing on Dom0.
	 *
	 * TBD -- need to review MAD_IFC paravirtualization, so that when doing MAD_IFC
	 * as part of processing received MADS to generate a response MAD -- no paravirt
	 * should be performed.  However, when MAD_IFC is called inside API calls
	 * (e.g., ib_query_port), paravirt should be done (again, though, in Dom0 the current
	 * paravirt code is a NOP).
	 */
	err = mlx4_cmd_box(dev->dev, inmailbox->dma, outmailbox->dma,
			   in_modifier, op_modifier,
			   MLX4_CMD_MAD_IFC, MLX4_CMD_TIME_CLASS_C, 1);

	if (!err)
		memcpy(response_mad, outmailbox->buf, 256);

	mlx4_free_cmd_mailbox(dev->dev, inmailbox);
	mlx4_free_cmd_mailbox(dev->dev, outmailbox);

	return err;
}

/*
 * Snoop SM MADs for port info and P_Key table sets, so we can
 * synthesize LID change and P_Key change events.
 */
static void propagate_pkey_ev(struct mlx4_ib_dev *dev, int port_num,
			      int block, u32 change_bitmap)
{
	int i, ix, slave, err;
	int have_event = 0;

	for (slave = 0; slave < dev->dev->caps.sqp_demux; slave++) {
		if (slave == dev->dev->caps.function)
			continue;
		if (!mlx4_is_slave_active(dev->dev, slave))
			continue;

		have_event = 0;
		for (i = 0; i < 32; i++) {
			if (!(change_bitmap & (1 << i)))
				continue;
			for (ix = 0;
			     ix < dev->dev->caps.pkey_table_len[port_num]; ix++) {
				if (dev->pkeys.virt2phys_pkey[slave][port_num - 1]
				    [ix] == i + 32 * block) {
					err = mlx4_gen_pkey_eqe(dev->dev, slave, port_num);
					mlx4_ib_dbg("propagate_pkey_ev: slave %d,"
						    " port %d, ix %d (%d)",
						    slave, port_num, ix, err);
					have_event = 1;
					break;
				}
			}
			if (have_event)
				break;
		}
	}
}

static void smp_snoop(struct ib_device *ibdev, u8 port_num, struct ib_mad *mad,
				u16 prev_lid)
{
	struct ib_event event;
	struct ib_port_info *pinfo;
	u16 lid, *base;
	int slave0_gid_changed = 0; /* dummy value. to avoid comp warnings */
	u32 bn, pkey_change_bitmap;
	int i;

	struct mlx4_ib_dev *dev = to_mdev(ibdev);
	if ((mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_LID_ROUTED ||
	     mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) &&
	     mad->mad_hdr.method == IB_MGMT_METHOD_SET)
		switch(mad->mad_hdr.attr_id) {
		case IB_SMP_ATTR_PORT_INFO:
	                pinfo = (struct ib_port_info *) ((struct ib_smp *) mad)->data;
                        lid = be16_to_cpu(pinfo->lid);

                        update_sm_ah(to_mdev(ibdev), port_num,
                                     be16_to_cpu(pinfo->sm_lid),
                                     pinfo->neighbormtu_mastersmsl & 0xf);                      

                        if (pinfo->clientrereg_resv_subnetto & 0x80)
				handle_client_rereg_event(dev, port_num);
                                
                        if (prev_lid != lid)
				handle_lid_change_event(dev, port_num);
                                
			break;

		case IB_SMP_ATTR_PKEY_TABLE:
			event.device	       = ibdev;
			event.event	       = IB_EVENT_PKEY_CHANGE;
			event.element.port_num = port_num;

			if (!mlx4_is_mfunc(dev->dev)) {
				ib_dispatch_event(&event);
				break;
			}

			bn  = be32_to_cpu(((struct ib_smp *)mad)->attr_mod) & 0xFFFF;
			base = (u16 *) &(((struct ib_smp *)mad)->data[0]);
			pkey_change_bitmap = 0;
			for (i = 0; i < 32; i++) {
				mlx4_ib_dbg("PKEY[%d] = x%x",
					    i + bn*32, be16_to_cpu(base[i]));
				if (be16_to_cpu(base[i]) !=
				    dev->pkeys.phys_pkey_cache[port_num - 1][i + bn*32]) {
					pkey_change_bitmap |= (1 << i);
					dev->pkeys.phys_pkey_cache[port_num - 1][i + bn*32] =
						be16_to_cpu(base[i]);
				}
			}
			mlx4_ib_dbg("PKEY Change event: port=%d, "
				    "block=0x%x, change_bitmap=0x%x\n",
				    port_num, bn, pkey_change_bitmap);

			if (pkey_change_bitmap) {
				ib_dispatch_event(&event);
				if (dev->dev->caps.sqp_demux && (!dev->sriov.is_going_down))
					propagate_pkey_ev(dev, port_num, bn, pkey_change_bitmap);
			}
			break;

		case IB_SMP_ATTR_GUID_INFO:
			/* For SRIOV slave IB GID change event will be dispatched
			   only if a value was writen to one of it's GIDs.
			   for slave > 0  this event will only be generated in a
			   relevant GID was changed.
			   for slave 0, the IB event will be dispatched only if a relevant
			   GID was changed, according to slave0_gid_changed value */

			/*if master, notify  relevant slaves*/
			if (dev->dev->caps.sqp_demux && mlx4_is_master(dev->dev) &&
			    (!dev->sriov.is_going_down)) {
				bn = be32_to_cpu(((struct ib_smp *)mad)->attr_mod);
				slave0_gid_changed =
					notify_slaves_on_guid_change(dev, bn, port_num,
								     (u8 *)(&((struct ib_smp *)mad)->data));
				update_cache_on_guid_change(dev, bn, port_num, (u8*)(&((struct ib_smp *)mad)->data));
			}

			/* IB GID change event will be dispached for non-sriov drivers
			   and for sriov slaves, or for sriov master if one of it's GIDs
			   */
			if (!mlx4_is_mfunc(dev->dev) ||
			    (mlx4_is_mfunc(dev->dev) &&
			     (!mlx4_is_master(dev->dev) || slave0_gid_changed))) {
				event.device	       = ibdev;
				event.event	       = IB_EVENT_GID_CHANGE;
				event.element.port_num = port_num;
				ib_dispatch_event(&event);
			}
			break;
		default:
			break;
		}
}

static void node_desc_override(struct ib_device *dev,
			       struct ib_mad *mad)
{
	if ((mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_LID_ROUTED ||
	     mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) &&
	    mad->mad_hdr.method == IB_MGMT_METHOD_GET_RESP &&
	    mad->mad_hdr.attr_id == IB_SMP_ATTR_NODE_DESC) {
		spin_lock(&to_mdev(dev)->sm_lock);
		memcpy(((struct ib_smp *) mad)->data, dev->node_desc, 64);
		spin_unlock(&to_mdev(dev)->sm_lock);
	}
}

static void forward_trap(struct mlx4_ib_dev *dev, u8 port_num, struct ib_mad *mad)
{
	int qpn = mad->mad_hdr.mgmt_class != IB_MGMT_CLASS_SUBN_LID_ROUTED;
	struct ib_mad_send_buf *send_buf;
	struct ib_mad_agent *agent = dev->send_agent[port_num - 1][qpn];
	int ret;

	if (agent) {
		send_buf = ib_create_send_mad(agent, qpn, 0, 0, IB_MGMT_MAD_HDR,
					      IB_MGMT_MAD_DATA, GFP_ATOMIC);
		/*
		 * We rely here on the fact that MLX QPs don't use the
		 * address handle after the send is posted (this is
		 * wrong following the IB spec strictly, but we know
		 * it's OK for our devices).
		 */
		spin_lock(&dev->sm_lock);
		memcpy(send_buf->mad, mad, sizeof *mad);
		if ((send_buf->ah = dev->sm_ah[port_num - 1]))
			ret = ib_post_send_mad(send_buf, NULL);
		else
			ret = -EINVAL;
		spin_unlock(&dev->sm_lock);

		if (ret)
			ib_free_send_mad(send_buf);
	}
}

static int mlx4_ib_demux_sa_handler(struct ib_device *ibdev, int port, int slave,
							     struct ib_sa_mad *sa_mad)
{
	int ret = 0;

	/* dispatch to different sa handlers */
	switch (be16_to_cpu(sa_mad->mad_hdr.attr_id)) {
		case IB_SA_ATTR_MC_MEMBER_REC:
			ret = mlx4_ib_mcg_demux_handler(ibdev, port, slave, sa_mad);
			break;
		default:
			break;
	}
	return ret;
}

int mlx4_ib_find_real_gid(struct ib_device *ibdev, u8 port, __be64 guid)
{
	struct mlx4_ib_dev *dev = to_mdev(ibdev);
	int i;

	/* Look for the guid in all the possibly assigned gids, up to the GIDs table
	   length - there can be gids_per_func gids assigned per slave,
	   and the max number of slaves is sqp_demux. */
	for (i = 0;
	     i < min(dev->dev->caps.sqp_demux * dev->dev->gids_per_func,
		     MLX4_MAX_NUM_GIDS); i++) {
		if (dev->sriov.demux[port - 1].guid_cache[i] == guid)
			return i;
	}
	return -1;
}

static inline int slave_from_gid_idx(struct mlx4_ib_dev *dev,
				     int gid_index)
{
	int index;

	index = slave_gid_index(dev->dev, gid_index);

	return ((index < 0) ? -EINVAL : mlx4_gid_idx_to_slave(dev->dev, index));
}

static int find_slave_port_pkey_ix(struct mlx4_ib_dev *dev, int slave,
				   u8 port, u16 pkey, u16 *ix)
{
	int i, ret;
	u8 unassigned_pkey_ix, pkey_ix, partial_ix = 0xFF;
	u16 slot_pkey;

	if (slave == get_master_func_num(dev))
		return ib_find_cached_pkey(&dev->ib_dev, port, pkey, ix);

	unassigned_pkey_ix = dev->dev->caps.pkey_table_max_len[port] - 1;

	for (i = 0; i < dev->dev->caps.pkey_table_len[port]; i++) {
		if (dev->pkeys.virt2phys_pkey[slave][port - 1][i] == unassigned_pkey_ix)
			continue;

		pkey_ix = dev->pkeys.virt2phys_pkey[slave][port - 1][i];

		ret = ib_get_cached_pkey(&dev->ib_dev, port, pkey_ix, &slot_pkey);
		if (ret)
			continue;
		if ((slot_pkey & 0x7FFF) == (pkey & 0x7FFF)) {
			if (slot_pkey & 0x8000) {
				*ix = (u16) pkey_ix;
				return 0;
			} else {
				/* take first partial pkey index found */
				if (partial_ix == 0xFF)
					partial_ix = pkey_ix;
			}
		}
	}

	if (partial_ix < 0xFF) {
		*ix = (u16) partial_ix;
		return 0;
	}

	return -EINVAL;
}

int mlx4_ib_send_to_slave(struct mlx4_ib_dev *dev, int slave, u8 port,
			  enum ib_qp_type dest_qpt, struct ib_wc *wc,
			  struct ib_grh *grh, struct ib_mad *mad)
{
	struct ib_sge list;
	struct ib_send_wr wr, *bad_wr;
	struct mlx4_ib_demux_pv_ctx *tun_ctx;
	struct mlx4_ib_demux_pv_qp *tun_qp;
	struct mlx4_rcv_tunnel_mad *tun_mad;
	struct ib_ah_attr attr;
	struct ib_ah *ah;
	struct ib_qp *src_qp = NULL;
	unsigned tun_tx_ix = 0;
	int dqpn;
	int ret = 0;
	u16 tun_pkey_ix;
	u16 cached_pkey;

	if (dest_qpt > IB_QPT_GSI)
		return -EINVAL;

	tun_ctx = dev->sriov.demux[port-1].tun[slave];

	/* check if proxy qp created */
	if (!tun_ctx || tun_ctx->state != DEMUX_PV_STATE_ACTIVE)
		return -EAGAIN;

	/* QP0 forwarding only for Dom0 */
	if (!dest_qpt && (get_master_func_num(dev) != slave))
		return -EINVAL;

	if (!dest_qpt)
		tun_qp = &tun_ctx->qp[0];
	else
		tun_qp = &tun_ctx->qp[1];

	/* compute pkey index to put in tunnel header for slave */
	if (dest_qpt) {
		u16 pkey_ix;
		ret = ib_get_cached_pkey(&dev->ib_dev, port, wc->pkey_index, &cached_pkey);
		if (ret)
			return -EINVAL;

		ret = find_slave_port_pkey_ix(dev, slave, port, cached_pkey, &pkey_ix);
		if (ret)
			return -EINVAL;
		tun_pkey_ix = pkey_ix;
	} else
		tun_pkey_ix = dev->pkeys.virt2phys_pkey[slave][port - 1][0];

	dqpn = dev->dev->caps.tunnel_qpn + 8 * (slave + 1) + port + (dest_qpt * 2) - 1;

	/* get tunnel tx data buf for slave */
	src_qp = tun_qp->qp;

	/* create ah */
	memset(&attr, 0, sizeof attr);
	attr.dlid = dev->sriov.local_lid[port - 1]; /* What about dlid path-bits? do we want to integrate them? */
	attr.port_num = port | 0x80;         /* force loopback */
	/* attr.sl = 0;   XXX is that OK?
	   attr.src_path_bits = 0; N.A. - we forward the original source lid
	   attr.static_rate = 0; */
	ah = ib_create_ah(tun_ctx->pd, &attr);
	if (IS_ERR(ah))
		return -ENOMEM;

	/* allocate tunnel tx buf after pass failure returns */
	spin_lock(&tun_qp->tx_lock);
	if (tun_qp->tx_ix_head - tun_qp->tx_ix_tail >=
	    (MLX4_NUM_TUNNEL_BUFS - 1))
		ret = -EAGAIN;
	else
		tun_tx_ix = (++tun_qp->tx_ix_head) & (MLX4_NUM_TUNNEL_BUFS - 1);
	spin_unlock(&tun_qp->tx_lock);
	if (ret)
		goto out;

	tun_mad = (struct mlx4_rcv_tunnel_mad *) (tun_qp->tx_ring[tun_tx_ix].buf.addr);
	if (tun_qp->tx_ring[tun_tx_ix].ah)
		ib_destroy_ah(tun_qp->tx_ring[tun_tx_ix].ah);
	tun_qp->tx_ring[tun_tx_ix].ah = ah;
	ib_dma_sync_single_for_cpu(&dev->ib_dev,
				   tun_qp->tx_ring[tun_tx_ix].buf.map,
				   sizeof (struct mlx4_rcv_tunnel_mad),
				   DMA_TO_DEVICE);

	/* copy over to tunnel buffer */
	if (grh)
		memcpy(&tun_mad->grh, grh, sizeof (*grh));
	memcpy(&tun_mad->mad, mad, sizeof (*mad));

	/* adjust tunnel data */
	tun_mad->hdr.pkey_index = tun_pkey_ix;
	tun_mad->hdr.sl = wc->sl;
	tun_mad->hdr.slid = wc->slid;
	tun_mad->hdr.src_qp = wc->src_qp;
	tun_mad->hdr.wc_flags = (grh) ? wc->wc_flags : 0;

	ib_dma_sync_single_for_device(&dev->ib_dev,
				      tun_qp->tx_ring[tun_tx_ix].buf.map,
				      sizeof (struct mlx4_rcv_tunnel_mad),
				      DMA_TO_DEVICE);

	list.addr = tun_qp->tx_ring[tun_tx_ix].buf.map;
	list.length = sizeof(struct mlx4_rcv_tunnel_mad);
	list.lkey = tun_ctx->mr->lkey;

	wr.wr.ud.ah = ah;
	wr.wr.ud.port_num = port;
	wr.wr.ud.remote_qkey = IB_QP_SET_QKEY;
	wr.wr.ud.remote_qpn = dqpn;
	wr.next = NULL;
	wr.wr_id = ((u64) tun_tx_ix) | MLX4_TUN_SET_WRID_QPN(dest_qpt);
	wr.sg_list = &list;
	wr.num_sge = 1;
	wr.opcode = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	ret = ib_post_send(src_qp, &wr, &bad_wr);
out:
	if (ret)
		ib_destroy_ah(ah);
	return ret;
}

static int mlx4_ib_demux_mad(struct ib_device *ibdev, u8 port,
			struct ib_wc *wc, struct ib_grh *grh,
			struct ib_mad *mad)
{
	struct mlx4_ib_dev *dev = to_mdev(ibdev);
	int err;
	int slave;
	int gid_idx;
	u8 *slave_id;

	/* Initially assume that this mad is for us */
	slave = get_master_func_num(dev);

	/* See if the slave id is encoded in a response mad */
	if (mad->mad_hdr.method & 0x80) {
		slave_id = (u8*) &mad->mad_hdr.tid;
		slave = *slave_id;
		if (slave != 255) /*255 indicates the dom0*/
			*slave_id = 0; /* remap tid */
	}

	/* If a grh is present, we demux according to it */
	if (wc->wc_flags & IB_WC_GRH) {
		gid_idx = mlx4_ib_find_real_gid(ibdev, port, grh->dgid.global.interface_id);
		slave = mlx4_gid_idx_to_slave(dev->dev, gid_idx);
		if ((gid_idx < 0) || (slave < 0)) {
			mlx4_ib_warn(ibdev, "failed matching grh\n");
			return -ENOENT;
		}
	}
	/* Class-specific handling */
	switch (mad->mad_hdr.mgmt_class) {
	case IB_MGMT_CLASS_SUBN_ADM:
		if (mlx4_ib_demux_sa_handler(ibdev, port, slave,
					     (struct ib_sa_mad *) mad))
			return 0;
		break;
	case IB_MGMT_CLASS_CM:
		if (mlx4_ib_demux_cm_handler(ibdev, port, &slave, mad))
			return 0;
		break;
	default:
		/* Drop unsupported classes for slaves in tunnel mode */
		if (slave != get_master_func_num(dev)) {
			mlx4_ib_dbg("dropping unsupported ingress mad from class:%d "
				    "for slave:%d", mad->mad_hdr.mgmt_class, slave);
			return 0;
		}
	}
	/*make sure that no slave==255 was not handled yet.*/
	if (slave > dev->dev->caps.sqp_demux){
		mlx4_ib_warn(ibdev, "slave id: %d is bigger than allowed:%d\n", slave, dev->dev->caps.sqp_demux);
		return -ENOENT;
	}

	err = mlx4_ib_send_to_slave(dev, slave, port, wc->qp->qp_type, wc, grh, mad);
	if (err)
		mlx4_ib_dbg("failed sending to slave %d via tunnel qp (%d)",
			    slave, err);
	return 0;
}

static int ib_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
                          struct ib_wc *in_wc, struct ib_grh *in_grh,
                          struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	u16 slid, prev_lid = 0;
	int err;
	struct ib_port_attr pattr;
	struct mlx4_ib_dev *dev = to_mdev(ibdev);

#ifdef DEBUG
	/* XXX debug - print source of qp1 messages */
	if (in_wc && in_wc->qp->qp_num) {
		mlx4_ib_dbg("received MAD: slid:%d sqpn:%d "
			"dlid_bits:%d dqpn:%d wc_flags:0x%x, cls %x, mtd %x, atr %x",
			in_wc->slid, in_wc->src_qp,
			in_wc->dlid_path_bits,
			in_wc->qp->qp_num,
			in_wc->wc_flags,
		in_mad->mad_hdr.mgmt_class, in_mad->mad_hdr.method, be16_to_cpu(in_mad->mad_hdr.attr_id));
		if (in_wc->wc_flags & IB_WC_GRH) {
			mlx4_ib_dbg("sgid_hi:0x%016llx sgid_lo:0x%016llx",
				 be64_to_cpu(in_grh->sgid.global.subnet_prefix),
				 be64_to_cpu(in_grh->sgid.global.interface_id));
			mlx4_ib_dbg("dgid_hi:0x%016llx dgid_lo:0x%016llx",
				 be64_to_cpu(in_grh->dgid.global.subnet_prefix),
				 be64_to_cpu(in_grh->dgid.global.interface_id));
		}
	}
#endif /*DEBUG*/
	slid = in_wc ? in_wc->slid : be16_to_cpu(IB_LID_PERMISSIVE);

	if (in_mad->mad_hdr.method == IB_MGMT_METHOD_TRAP && slid == 0) {
		forward_trap(dev, port_num, in_mad);
		return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_CONSUMED;
	}

	if (in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_LID_ROUTED ||
	    in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) {
		if (in_mad->mad_hdr.method   != IB_MGMT_METHOD_GET &&
		    in_mad->mad_hdr.method   != IB_MGMT_METHOD_SET &&
		    in_mad->mad_hdr.method   != IB_MGMT_METHOD_TRAP_REPRESS)
			return IB_MAD_RESULT_SUCCESS;

		/*
		 * Don't process SMInfo queries
		 * MADs -- the SMA can't handle them.
		 */
		if (in_mad->mad_hdr.attr_id == IB_SMP_ATTR_SM_INFO)
			return IB_MAD_RESULT_SUCCESS;
	} else if (in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_PERF_MGMT ||
		   in_mad->mad_hdr.mgmt_class == MLX4_IB_VENDOR_CLASS1   ||
		   in_mad->mad_hdr.mgmt_class == MLX4_IB_VENDOR_CLASS2   ||
		   in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_CONG_MGMT) {
		if (in_mad->mad_hdr.method  != IB_MGMT_METHOD_GET &&
		    in_mad->mad_hdr.method  != IB_MGMT_METHOD_SET)
			return IB_MAD_RESULT_SUCCESS;
	} else
		return IB_MAD_RESULT_SUCCESS;

	if ((in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_LID_ROUTED ||
	     in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) &&
	    in_mad->mad_hdr.method == IB_MGMT_METHOD_SET &&
	    in_mad->mad_hdr.attr_id == IB_SMP_ATTR_PORT_INFO &&
	    !ib_query_port(ibdev, port_num, &pattr))
		prev_lid = pattr.lid;

	err = mlx4_MAD_IFC(dev,
			   mad_flags & IB_MAD_IGNORE_MKEY,
			   mad_flags & IB_MAD_IGNORE_BKEY,
			   port_num, in_wc, in_grh, in_mad, out_mad);
	if (err)
		return IB_MAD_RESULT_FAILURE;

	if (!out_mad->mad_hdr.status) {
		if (!dev->dev->is_internal_sma)
			smp_snoop(ibdev, port_num, in_mad, prev_lid);

		node_desc_override(ibdev, out_mad);
	}

	/* set return bit in status of directed route responses */
	if (in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
		out_mad->mad_hdr.status |= cpu_to_be16(1 << 15);

	if (in_mad->mad_hdr.method == IB_MGMT_METHOD_TRAP_REPRESS)
		/* no response for trap repress */
		return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_CONSUMED;

	return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_REPLY;
}

static __be32 be64_to_be32(__be64 b64)
{
	return cpu_to_be32(be64_to_cpu(b64) & 0xffffffff);
}


static void edit_counter(struct mlx4_counters *cnt, void *counters,
             __be16 attr_id)
{
    switch (attr_id) {
    case IB_PMA_PORT_COUNTERS:
    {
        struct ib_pma_portcounters *pma_cnt =
                (struct ib_pma_portcounters *) counters;

        pma_cnt->port_xmit_data =
            cpu_to_be32((be64_to_cpu(cnt->tx_bytes) >> 2));
        pma_cnt->port_rcv_data  =
            cpu_to_be32((be64_to_cpu(cnt->rx_bytes) >> 2));
        pma_cnt->port_xmit_packets =
            cpu_to_be32(be64_to_cpu(cnt->tx_frames));
        pma_cnt->port_rcv_packets  =
            cpu_to_be32(be64_to_cpu(cnt->rx_frames));
        break;
    }
    case IB_PMA_PORT_COUNTERS_EXT:
    {
        struct ib_pma_portcounters_ext *pma_cnt_ext =
                (struct ib_pma_portcounters_ext *) counters;

        pma_cnt_ext->port_xmit_data = cpu_to_be64(be64_to_cpu(cnt->tx_bytes) >> 2);
        pma_cnt_ext->port_rcv_data  = cpu_to_be64(be64_to_cpu(cnt->rx_bytes) >> 2);
        pma_cnt_ext->port_xmit_packets = cnt->tx_frames;
        pma_cnt_ext->port_rcv_packets  = cnt->rx_frames;
        break;
    }
    default:
        pr_warn("Unsupported attr_id 0x%x\n", attr_id);
        break;
    }
}


static void edit_ext_counter(struct mlx4_counters_ext *cnt, void *counters,
             __be16 attr_id)
{
	switch (attr_id) {
	case IB_PMA_PORT_COUNTERS:
	{
		struct ib_pma_portcounters *pma_cnt =
				(struct ib_pma_portcounters *) counters;

		pma_cnt->port_xmit_data =
			cpu_to_be32((be64_to_cpu(cnt->tx_uni_bytes) >> 2));
		pma_cnt->port_rcv_data  =
			cpu_to_be32((be64_to_cpu(cnt->rx_uni_bytes) >> 2));
		pma_cnt->port_xmit_packets =
			cpu_to_be32(be64_to_cpu(cnt->tx_uni_frames));
		pma_cnt->port_rcv_packets  =
			cpu_to_be32(be64_to_cpu(cnt->rx_uni_frames));
		break;
	}
	case IB_PMA_PORT_COUNTERS_EXT:
	{
		struct ib_pma_portcounters_ext *pma_cnt_ext =
				(struct ib_pma_portcounters_ext *) counters;

		pma_cnt_ext->port_xmit_data = cpu_to_be64(be64_to_cpu(cnt->tx_uni_bytes) >> 2);
		pma_cnt_ext->port_rcv_data  = cpu_to_be64(be64_to_cpu(cnt->rx_uni_bytes) >> 2);
		pma_cnt_ext->port_unicast_xmit_packets = cnt->tx_uni_frames;
		pma_cnt_ext->port_unicast_rcv_packets  = cnt->rx_uni_frames;
		break;
	}
	default:
		pr_warn("Unsupported attr_id 0x%x\n", attr_id);
		break;
	}

}

static int rdmaoe_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
                              struct ib_wc *in_wc, struct ib_grh *in_grh,
                              struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	struct mlx4_cmd_mailbox *mailbox;
	struct mlx4_ib_dev *dev = to_mdev(ibdev);
	int err;
	u32 inmod = dev->counters[port_num - 1] & 0xffff;
	int mode;

	mailbox = mlx4_alloc_cmd_mailbox(dev->dev);
	if (IS_ERR(mailbox))
		return IB_MAD_RESULT_FAILURE;

	err = mlx4_cmd_box(dev->dev, 0, mailbox->dma, inmod, 0,
			   MLX4_CMD_QUERY_IF_STAT, MLX4_CMD_TIME_CLASS_C, 0);
	if (err)
		err = IB_MAD_RESULT_FAILURE;
	else {
		memset(&out_mad->data, 0, IB_MGMT_MAD_DATA);
		memcpy(&out_mad->mad_hdr, &in_mad->mad_hdr, sizeof(out_mad->mad_hdr));
		out_mad->mad_hdr.method = 0x81;
		out_mad->mad_hdr.status = 0;
		mode = be32_to_cpu(((struct mlx4_counters *)mailbox->buf)->counter_mode) & 0xf;
		switch (mode) {
		case 0:
			edit_counter(mailbox->buf,
                         (void *)(out_mad->data + 40),
                         in_mad->mad_hdr.attr_id);

			err = IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_REPLY;
			break;
		case 1:
			edit_ext_counter(mailbox->buf,
                         (void *)(out_mad->data + 40),
                         in_mad->mad_hdr.attr_id);
			err = IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_REPLY;
			break;
		default:
			err = IB_MAD_RESULT_FAILURE;
		}
	}

	mlx4_free_cmd_mailbox(dev->dev, mailbox);

	return err;
}

int mlx4_ib_process_mad(struct ib_device *ibdev, int mad_flags,	u8 port_num,
			struct ib_wc *in_wc, struct ib_grh *in_grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	if (mlx4_is_mfunc(to_mdev(ibdev)->dev) && !in_wc &&
	    in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_PERF_MGMT &&
	    in_mad->mad_hdr.method == IB_MGMT_METHOD_GET && (
	    in_mad->mad_hdr.attr_id == IB_PMA_PORT_COUNTERS ||
	    in_mad->mad_hdr.attr_id == IB_PMA_PORT_COUNTERS_EXT /* port counters */ ))
		return rdmaoe_process_mad(ibdev, mad_flags, port_num, in_wc,
					  in_grh, in_mad, out_mad);

	switch (rdma_port_link_layer(ibdev, port_num)) {
	case IB_LINK_LAYER_INFINIBAND:
		return ib_process_mad(ibdev, mad_flags, port_num, in_wc,
				      in_grh, in_mad, out_mad);
	case IB_LINK_LAYER_ETHERNET:
		return rdmaoe_process_mad(ibdev, mad_flags, port_num, in_wc,
					  in_grh, in_mad, out_mad);
	default:
		return -EINVAL;
	}
}

static void send_handler(struct ib_mad_agent *agent,
			 struct ib_mad_send_wc *mad_send_wc)
{
	if (mad_send_wc->send_buf->context[0])
		ib_destroy_ah(mad_send_wc->send_buf->context[0]);
	ib_free_send_mad(mad_send_wc->send_buf);
}

static void mlx4_ib_tunnel_comp_handler(struct ib_cq *cq, void *arg)
{
	unsigned long flags;
	struct mlx4_ib_demux_pv_ctx *ctx = cq->cq_context;
	struct mlx4_ib_dev *dev = to_mdev(ctx->ib_dev);
	spin_lock_irqsave(&dev->sriov.going_down_lock, flags);
	if (!dev->sriov.is_going_down && ctx->state == DEMUX_PV_STATE_ACTIVE)
                queue_work(ctx->wq, &ctx->work);
	spin_unlock_irqrestore(&dev->sriov.going_down_lock, flags);
}

static int mlx4_ib_post_pv_qp_buf(struct mlx4_ib_demux_pv_ctx *ctx,
				  struct mlx4_ib_demux_pv_qp *tun_qp,
				  int index)
{
	struct ib_sge sg_list;
        struct ib_recv_wr recv_wr, *bad_recv_wr;
	int size;

	size = (tun_qp->qp->qp_type == IB_QPT_UD) ?
		sizeof (struct mlx4_tunnel_mad) : sizeof (struct mlx4_mad_rcv_buf);

	sg_list.addr = tun_qp->ring[index].map;
	sg_list.length = size;
	sg_list.lkey = ctx->mr->lkey;

	recv_wr.next = NULL;
	recv_wr.sg_list = &sg_list;
	recv_wr.num_sge = 1;
	recv_wr.wr_id = (u64) index | MLX4_TUN_WRID_RECV |
		MLX4_TUN_SET_WRID_QPN(tun_qp->proxy_qpt);
	ib_dma_sync_single_for_device(ctx->ib_dev, tun_qp->ring[index].map,
				      size, DMA_FROM_DEVICE);
	return ib_post_recv(tun_qp->qp, &recv_wr, &bad_recv_wr);
}

static int mlx4_ib_multiplex_sa_handler(struct ib_device *ibdev, int port,
		int slave, struct ib_sa_mad *sa_mad)
{
	int ret = 0;

	/* dispatch to different sa handlers */
	switch (be16_to_cpu(sa_mad->mad_hdr.attr_id)) {
		case IB_SA_ATTR_MC_MEMBER_REC:
			ret = mlx4_ib_mcg_multiplex_handler(ibdev, port, slave, sa_mad);
			break;
		default:
			break;
	}
	return ret;
}

static int is_proxy_qp0(struct mlx4_ib_dev *dev, int qpn, int slave)
{
	int slave_start = dev->dev->caps.tunnel_qpn + 8 * (slave + 1);

	return (qpn >= slave_start && qpn <= slave_start + 1);
}


int mlx4_ib_send_to_wire(struct mlx4_ib_dev *dev, int slave, u8 port,
			 enum ib_qp_type dest_qpt, u16 pkey_index, u32 remote_qpn,
			 u32 qkey, struct ib_ah_attr *attr, struct ib_mad *mad)
{
	struct ib_sge list;
	struct ib_send_wr wr, *bad_wr;
	struct mlx4_ib_demux_pv_ctx *sqp_ctx;
	struct mlx4_ib_demux_pv_qp *sqp;
	struct mlx4_mad_snd_buf *sqp_mad;
	struct ib_ah *ah;
	struct ib_qp *send_qp = NULL;
	unsigned wire_tx_ix = 0;
	int ret = 0;
	int src_qpnum;
	u16 wire_pkey_ix;
	u8 sgid_index;


	sqp_ctx = dev->sriov.sqps[port-1];

	/* check if proxy qp created */
	if (!sqp_ctx || sqp_ctx->state != DEMUX_PV_STATE_ACTIVE)
		return -EAGAIN;

	/* QP0 forwarding only for Dom0 */
	if (dest_qpt == IB_QPT_SMI && (get_master_func_num(dev) != slave))
		return -EINVAL;

	if (dest_qpt == IB_QPT_SMI) {
		src_qpnum = 0;
		sqp = &sqp_ctx->qp[0];
		wire_pkey_ix = dev->pkeys.virt2phys_pkey[slave][port - 1][0];
	} else {
		src_qpnum = 1;
		sqp = &sqp_ctx->qp[1];
		wire_pkey_ix = dev->pkeys.virt2phys_pkey[slave][port - 1][pkey_index];
	}

	send_qp = sqp->qp;

	/* create ah */
	sgid_index = attr->grh.sgid_index;
	attr->grh.sgid_index = 0;
	ah = ib_create_ah(sqp_ctx->pd, attr);
	if (IS_ERR(ah))
		return -ENOMEM;
	attr->grh.sgid_index = sgid_index;
	to_mah(ah)->av.ib.gid_index = sgid_index;
	/* get rid of force-loopback bit */
	to_mah(ah)->av.ib.port_pd &= cpu_to_be32(0x7FFFFFFF);
	spin_lock(&sqp->tx_lock);
	if (sqp->tx_ix_head - sqp->tx_ix_tail >=
	    (MLX4_NUM_TUNNEL_BUFS - 1))
		ret = -EAGAIN;
	else
		wire_tx_ix = (++sqp->tx_ix_head) & (MLX4_NUM_TUNNEL_BUFS - 1);
	spin_unlock(&sqp->tx_lock);
	if (ret)
		goto out;

	sqp_mad = (struct mlx4_mad_snd_buf *) (sqp->tx_ring[wire_tx_ix].buf.addr);
	if (sqp->tx_ring[wire_tx_ix].ah)
		ib_destroy_ah(sqp->tx_ring[wire_tx_ix].ah);
	sqp->tx_ring[wire_tx_ix].ah = ah;
	ib_dma_sync_single_for_cpu(&dev->ib_dev,
				   sqp->tx_ring[wire_tx_ix].buf.map,
				   sizeof (struct mlx4_mad_snd_buf),
				   DMA_TO_DEVICE);

	memcpy(&sqp_mad->payload, mad, sizeof (*mad));

	ib_dma_sync_single_for_device(&dev->ib_dev,
				      sqp->tx_ring[wire_tx_ix].buf.map,
				      sizeof (struct mlx4_mad_snd_buf),
				      DMA_TO_DEVICE);

	list.addr = sqp->tx_ring[wire_tx_ix].buf.map;
	list.length = sizeof(struct mlx4_mad_snd_buf);
	list.lkey = sqp_ctx->mr->lkey;

	wr.wr.ud.ah = ah;
	wr.wr.ud.port_num = port;
	wr.wr.ud.pkey_index = wire_pkey_ix;
	wr.wr.ud.remote_qkey = qkey;
	wr.wr.ud.remote_qpn = remote_qpn;
	wr.next = NULL;
	wr.wr_id = ((u64) wire_tx_ix) | MLX4_TUN_SET_WRID_QPN(src_qpnum);
	wr.sg_list = &list;
	wr.num_sge = 1;
	wr.opcode = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	ret = ib_post_send(send_qp, &wr, &bad_wr);
out:
	if (ret)
		ib_destroy_ah(ah);
	return ret;
}

static void mlx4_ib_multiplex_mad(struct mlx4_ib_demux_pv_ctx *ctx, struct ib_wc *wc)
{
	struct mlx4_ib_dev *dev = to_mdev(ctx->ib_dev);
	struct mlx4_ib_demux_pv_qp *tun_qp = &ctx->qp[MLX4_TUN_WRID_QPN(wc->wr_id)];
	int wr_ix = wc->wr_id & (MLX4_NUM_TUNNEL_BUFS - 1);
	struct mlx4_tunnel_mad *tunnel = tun_qp->ring[wr_ix].addr;
	struct mlx4_ib_ah ah;
	struct ib_ah_attr ah_attr;
	u8 *slave_id;
	int is_master; /* 1 if master */
	int slave;

	/* Get slave that sent this packet */
	if (wc->src_qp < dev->dev->caps.tunnel_qpn + 8 ||
	    wc->src_qp >= dev->dev->caps.tunnel_qpn + 8 * (dev->dev->caps.sqp_demux + 1) ||
	    (wc->src_qp & 0x1) != ctx->port - 1 ||
	    wc->src_qp & 0x4) {
		mlx4_ib_warn(ctx->ib_dev, "can't multiplex bad sqp:%d\n", wc->src_qp);
		return;
	}
	slave = ((wc->src_qp & ~0x7) - dev->dev->caps.tunnel_qpn) / 8 - 1;
	if (slave != ctx->slave) {
		mlx4_ib_warn(ctx->ib_dev, "can't multiplex bad sqp:%d: "
			     "belongs to another slave\n", wc->src_qp);
		return;
	}

	is_master = (slave == get_master_func_num(dev));

	if (!is_master && !(wc->src_qp & 0x2)) {
		mlx4_ib_warn(ctx->ib_dev, "can't multiplex bad sqp:%d: "
			     "non-master trying to send QP0 packets\n", wc->src_qp);
		return;
	}

	/* Map transaction ID */
	ib_dma_sync_single_for_cpu(ctx->ib_dev, tun_qp->ring[wr_ix].map,
				   sizeof(struct mlx4_tunnel_mad),
				   DMA_FROM_DEVICE);
	switch (tunnel->mad.mad_hdr.method) {
	case IB_MGMT_METHOD_SET:
	case IB_MGMT_METHOD_GET:
	case IB_MGMT_METHOD_REPORT:
	case IB_SA_METHOD_GET_TABLE:
	case IB_SA_METHOD_DELETE:
	case IB_SA_METHOD_GET_MULTI:
	case IB_SA_METHOD_GET_TRACE_TBL:
		slave_id = (u8*) &tunnel->mad.mad_hdr.tid;
		if (*slave_id) {
			/* XXX TODO: hold a mapping instead of failing */
			mlx4_ib_warn(ctx->ib_dev, "egress mad has non-null tid msb:%d "
				     "class:%d slave:%d\n", *slave_id,
				     tunnel->mad.mad_hdr.mgmt_class, slave);
			return;
		} else
			*slave_id = slave;
	default:
		/* nothing */;
	}

	/* Class-specific handling */
	switch (tunnel->mad.mad_hdr.mgmt_class) {
	case IB_MGMT_CLASS_SUBN_ADM:
		if (mlx4_ib_multiplex_sa_handler(ctx->ib_dev, ctx->port, slave,
			      (struct ib_sa_mad *) &tunnel->mad))
			return;
		break;
	case IB_MGMT_CLASS_CM:
		if (mlx4_ib_multiplex_cm_handler(ctx->ib_dev, ctx->port, slave,
			      (struct ib_mad *) &tunnel->mad))
			return;
		break;
	default:
		/* Drop unsupported classes for slaves in tunnel mode */
		if (!is_master) {
			mlx4_ib_warn(ctx->ib_dev, "dropping unsupported egress mad from class:%d "
				     "for slave:%d\n", tunnel->mad.mad_hdr.mgmt_class, slave);
			return;
		}
	}

	/* We are using standard ib_core services to send the mad, so generate a
	 * stadard address handle by decoding the tunnelled mlx4_ah fields */
	memcpy(&ah.av, &tunnel->hdr.av, sizeof (struct mlx4_av));
	ah.ibah.device = ctx->ib_dev;
	mlx4_ib_query_ah(&ah.ibah, &ah_attr);
	if ((ah_attr.ah_flags & IB_AH_GRH) &&
	    (mlx4_gid_idx_to_slave(dev->dev, ah_attr.grh.sgid_index) != slave)) {
		mlx4_ib_warn(ctx->ib_dev, "slave:%d accessed invalid sgid_index:%d\n",
			     slave, ah_attr.grh.sgid_index);
		return;
	}

	mlx4_ib_send_to_wire(dev, slave, ctx->port,
			     is_proxy_qp0(dev, wc->src_qp, slave) ?
			     IB_QPT_SMI : IB_QPT_GSI,
			     tunnel->hdr.pkey_index, tunnel->hdr.remote_qpn,
			     tunnel->hdr.qkey,
			     &ah_attr, &tunnel->mad);
}

static int mlx4_ib_alloc_pv_bufs(struct mlx4_ib_demux_pv_ctx *ctx,
				 enum ib_qp_type qp_type, int is_tun)
{
	int i;
	struct mlx4_ib_demux_pv_qp *tun_qp;
	int rx_buf_size, tx_buf_size;

	if (qp_type > IB_QPT_GSI)
		return -EINVAL;

	tun_qp = &ctx->qp[qp_type];

	tun_qp->ring = kzalloc(sizeof(struct mlx4_ib_buf) * MLX4_NUM_TUNNEL_BUFS,
			       GFP_KERNEL);
	if (!tun_qp->ring)
		return -ENOMEM;

	tun_qp->tx_ring = kzalloc(sizeof(struct mlx4_ib_tun_tx_buf) *
				  MLX4_NUM_TUNNEL_BUFS,
				  GFP_KERNEL);
	if (!tun_qp->tx_ring) {
		kfree(tun_qp->ring);
		tun_qp->ring = NULL;
		return -ENOMEM;
	}

	if (is_tun) {
		rx_buf_size = sizeof (struct mlx4_tunnel_mad);
		tx_buf_size = sizeof (struct mlx4_rcv_tunnel_mad);
	} else {
		rx_buf_size = sizeof (struct mlx4_mad_rcv_buf);
		tx_buf_size = sizeof (struct mlx4_mad_snd_buf);
	}

	for (i = 0; i < MLX4_NUM_TUNNEL_BUFS; i++) {
		tun_qp->ring[i].addr = kmalloc(rx_buf_size, GFP_KERNEL);
		if (!tun_qp->ring[i].addr)
			goto err;
		tun_qp->ring[i].map = ib_dma_map_single(ctx->ib_dev,
							tun_qp->ring[i].addr,
							rx_buf_size,
							DMA_FROM_DEVICE);
	}

	for (i = 0; i < MLX4_NUM_TUNNEL_BUFS; i++) {
		tun_qp->tx_ring[i].buf.addr =
			kmalloc(tx_buf_size, GFP_KERNEL);
		if (!tun_qp->tx_ring[i].buf.addr)
			goto tx_err;
		tun_qp->tx_ring[i].buf.map =
			ib_dma_map_single(ctx->ib_dev,
					  tun_qp->tx_ring[i].buf.addr,
					  tx_buf_size,
					  DMA_TO_DEVICE);
		tun_qp->tx_ring[i].ah = NULL;
	}
	spin_lock_init(&tun_qp->tx_lock);
	tun_qp->tx_ix_head = 0;
	tun_qp->tx_ix_tail = 0;
	tun_qp->proxy_qpt = qp_type;

	return 0;

tx_err:
	while (i > 0) {
		--i;
		ib_dma_unmap_single(ctx->ib_dev, tun_qp->tx_ring[i].buf.map,
				    tx_buf_size, DMA_TO_DEVICE);
		kfree(tun_qp->tx_ring[i].buf.addr);
	}
	kfree(tun_qp->tx_ring);
	tun_qp->tx_ring = NULL;
	i = MLX4_NUM_TUNNEL_BUFS;
err:
	while (i > 0) {
		--i;
		ib_dma_unmap_single(ctx->ib_dev, tun_qp->ring[i].map,
				    rx_buf_size, DMA_FROM_DEVICE);
		kfree(tun_qp->ring[i].addr);
	}
	kfree(tun_qp->ring);
	tun_qp->ring = NULL;
	return -ENOMEM;
}

static void mlx4_ib_free_pv_qp_bufs(struct mlx4_ib_demux_pv_ctx *ctx,
				     enum ib_qp_type qp_type, int is_tun)
{
	int i;
	struct mlx4_ib_demux_pv_qp *tun_qp;
	int rx_buf_size, tx_buf_size;

	if (qp_type > IB_QPT_GSI)
		return;

	tun_qp = &ctx->qp[qp_type];
	if (is_tun) {
		rx_buf_size = sizeof (struct mlx4_tunnel_mad);
		tx_buf_size = sizeof (struct mlx4_rcv_tunnel_mad);
	} else {
		rx_buf_size = sizeof (struct mlx4_mad_rcv_buf);
		tx_buf_size = sizeof (struct mlx4_mad_snd_buf);
	}


	for (i = 0; i < MLX4_NUM_TUNNEL_BUFS; i++) {
		ib_dma_unmap_single(ctx->ib_dev, tun_qp->ring[i].map,
				    rx_buf_size, DMA_FROM_DEVICE);
		kfree(tun_qp->ring[i].addr);
	}

	for (i = 0; i < MLX4_NUM_TUNNEL_BUFS; i++) {
		ib_dma_unmap_single(ctx->ib_dev, tun_qp->tx_ring[i].buf.map,
				    tx_buf_size, DMA_TO_DEVICE);
		kfree(tun_qp->tx_ring[i].buf.addr);
		if (tun_qp->tx_ring[i].ah)
			ib_destroy_ah(tun_qp->tx_ring[i].ah);
	}
	kfree(tun_qp->tx_ring);
	kfree(tun_qp->ring);
}

static void mlx4_ib_tunnel_comp_worker(struct work_struct *work)
{
	struct mlx4_ib_demux_pv_ctx *ctx;
	struct mlx4_ib_demux_pv_qp *tun_qp;
	struct ib_wc wc;
	int ret;
	ctx = container_of(work, struct mlx4_ib_demux_pv_ctx, work);
	ib_req_notify_cq(ctx->cq, IB_CQ_NEXT_COMP);

	while (ib_poll_cq(ctx->cq, 1, &wc) == 1) {
		tun_qp = &ctx->qp[MLX4_TUN_WRID_QPN(wc.wr_id)];
		if (wc.status == IB_WC_SUCCESS) {
			switch (wc.opcode) {
			case IB_WC_RECV:
				mlx4_ib_multiplex_mad(ctx, &wc);
				ret = mlx4_ib_post_pv_qp_buf(ctx, tun_qp,
							     wc.wr_id &
							     (MLX4_NUM_TUNNEL_BUFS - 1));
				if (ret)
					printk(KERN_ERR "Failed reposting tunnel "
							"buf:%lld\n", wc.wr_id);
				break;
			case IB_WC_SEND:
#ifdef DEBUG
				mlx4_ib_dbg("received tunnel send completion:"
				    "wrid=0x%llx, status=0x%x",
				    wc.wr_id, wc.status);
#endif /*DEBUG*/
				ib_destroy_ah(tun_qp->tx_ring[wc.wr_id &
					      (MLX4_NUM_TUNNEL_BUFS - 1)].ah);
				tun_qp->tx_ring[wc.wr_id & (MLX4_NUM_TUNNEL_BUFS - 1)].ah
					= NULL;
				spin_lock(&tun_qp->tx_lock);
				tun_qp->tx_ix_tail++;
				spin_unlock(&tun_qp->tx_lock);

				break;
			default:
				break;
			}
		} else  {
			mlx4_ib_dbg("mlx4_ib: completion error in tunnel: %d."
				    " status = %d, wrid = 0x%llx",
				    ctx->slave, wc.status, wc.wr_id);
			if (!MLX4_TUN_IS_RECV(wc.wr_id)) {
				ib_destroy_ah(tun_qp->tx_ring[wc.wr_id &
					      (MLX4_NUM_TUNNEL_BUFS - 1)].ah);
				tun_qp->tx_ring[wc.wr_id & (MLX4_NUM_TUNNEL_BUFS - 1)].ah
					= NULL;
				spin_lock(&tun_qp->tx_lock);
				tun_qp->tx_ix_tail++;
				spin_unlock(&tun_qp->tx_lock);
			}
		}
	}
}

static void pv_qp_event_handler(struct ib_event *event, void *qp_context)
{
	struct mlx4_ib_demux_pv_ctx *sqp = qp_context;

	/* It's worse than that! He's dead, Jim! */
	printk(KERN_ERR "Fatal error (%d) on a MAD QP on port %d\n",
		event->event, sqp->port);
}

static int create_pv_sqp(struct mlx4_ib_demux_pv_ctx *ctx,
			    enum ib_qp_type qp_type, int create_tun)
{
	int i, ret;
	struct mlx4_ib_demux_pv_qp *tun_qp;
	struct mlx4_ib_qp_tunnel_init_attr qp_init_attr;
	struct ib_qp_attr attr;
	int qp_attr_mask_INIT;

	if (qp_type > IB_QPT_GSI)
		return -EINVAL;

	tun_qp = &ctx->qp[qp_type];

	memset(&qp_init_attr, 0, sizeof qp_init_attr);
	qp_init_attr.init_attr.send_cq = ctx->cq;
	qp_init_attr.init_attr.recv_cq = ctx->cq;
	qp_init_attr.init_attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	qp_init_attr.init_attr.cap.max_send_wr = MLX4_NUM_TUNNEL_BUFS;
	qp_init_attr.init_attr.cap.max_recv_wr = MLX4_NUM_TUNNEL_BUFS;
	qp_init_attr.init_attr.cap.max_send_sge = 1;
	qp_init_attr.init_attr.cap.max_recv_sge = 1;
	if (create_tun) {
		qp_init_attr.init_attr.qp_type = IB_QPT_UD;
		qp_init_attr.init_attr.create_flags = MLX4_IB_QP_TUNNEL;
		qp_init_attr.port = ctx->port;
		qp_init_attr.slave = ctx->slave;
		qp_init_attr.proxy_qp_type = qp_type;
		qp_attr_mask_INIT = IB_QP_STATE | IB_QP_PKEY_INDEX |
			   IB_QP_QKEY | IB_QP_PORT;
	} else {
		qp_init_attr.init_attr.qp_type = qp_type;
		qp_init_attr.init_attr.create_flags = MLX4_IB_SRIOV_SQP;
		qp_attr_mask_INIT = IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_QKEY;
	}
	qp_init_attr.init_attr.port_num = ctx->port;
	qp_init_attr.init_attr.qp_context = ctx;
	qp_init_attr.init_attr.event_handler = pv_qp_event_handler;
	tun_qp->qp = ib_create_qp(ctx->pd, &qp_init_attr.init_attr);
	if (IS_ERR(tun_qp->qp)) {
		ret = PTR_ERR(tun_qp->qp);
		tun_qp->qp = NULL;
		printk(KERN_ERR "Couldn't create %s QP (%d)\n",
		       create_tun ? "tunnel" : "special", ret);
		return ret;
	}

	memset(&attr, 0, sizeof attr);
	attr.qp_state = IB_QPS_INIT;
	attr.pkey_index =
		to_mdev(ctx->ib_dev)->pkeys.virt2phys_pkey[ctx->slave][ctx->port - 1][0];
	attr.qkey = IB_QP1_QKEY;
	attr.port_num = ctx->port;
	ret = ib_modify_qp(tun_qp->qp, &attr, qp_attr_mask_INIT);
	if (ret) {
		printk(KERN_ERR "Couldn't change %s qp state to INIT (%d)\n",
		       create_tun ? "tunnel" : "special", ret);
		goto err_qp;
	}
	attr.qp_state = IB_QPS_RTR;
	ret = ib_modify_qp(tun_qp->qp, &attr, IB_QP_STATE);
	if (ret) {
		printk(KERN_ERR "Couldn't change %s qp state to RTR (%d)\n",
		       create_tun ? "tunnel" : "special", ret);
		goto err_qp;
	}
	attr.qp_state = IB_QPS_RTS;
	attr.sq_psn = 0;
	ret = ib_modify_qp(tun_qp->qp, &attr, IB_QP_STATE | IB_QP_SQ_PSN);
	if (ret) {
		printk(KERN_ERR "Couldn't change %s qp state to RTS (%d)\n",
		       create_tun ? "tunnel" : "special", ret);
		goto err_qp;
	}

	for (i = 0; i < MLX4_NUM_TUNNEL_BUFS; i++) {
		ret = mlx4_ib_post_pv_qp_buf(ctx, tun_qp, i);
		if (ret) {
			printk(KERN_ERR " mlx4_ib_post_pv_buf error"
			       " (err = %d, i = %d)\n", ret, i);
			goto err_qp;
		}
	}
	return 0;

err_qp:
	ib_destroy_qp(tun_qp->qp);
	tun_qp->qp = NULL;
	return ret;
}

/*
 * IB MAD completion callback for real SQPs
 */
static void mlx4_ib_sqp_comp_worker(struct work_struct *work)
{
	struct mlx4_ib_demux_pv_ctx *ctx;
	struct mlx4_ib_demux_pv_qp *sqp;
	struct ib_wc wc;
	struct ib_grh *grh;
	struct ib_mad *mad;

	ctx = container_of(work, struct mlx4_ib_demux_pv_ctx, work);
	ib_req_notify_cq(ctx->cq, IB_CQ_NEXT_COMP);

	while (mlx4_ib_poll_cq(ctx->cq, 1, &wc) == 1) {
		sqp = &ctx->qp[MLX4_TUN_WRID_QPN(wc.wr_id)];
		if (wc.status == IB_WC_SUCCESS) {
			switch (wc.opcode) {
			case IB_WC_SEND:
				ib_destroy_ah(sqp->tx_ring[wc.wr_id &
					      (MLX4_NUM_TUNNEL_BUFS - 1)].ah);
				sqp->tx_ring[wc.wr_id & (MLX4_NUM_TUNNEL_BUFS - 1)].ah
					= NULL;
				spin_lock(&sqp->tx_lock);
				sqp->tx_ix_tail++;
				spin_unlock(&sqp->tx_lock);
				break;
			case IB_WC_RECV:
				mad = (struct ib_mad *) &(((struct mlx4_mad_rcv_buf *)
						(sqp->ring[wc.wr_id &
						(MLX4_NUM_TUNNEL_BUFS - 1)].addr))->payload);
				grh = &(((struct mlx4_mad_rcv_buf *)
						(sqp->ring[wc.wr_id &
						(MLX4_NUM_TUNNEL_BUFS - 1)].addr))->grh);
				mlx4_ib_demux_mad(ctx->ib_dev, ctx->port, &wc, grh, mad);
				if (mlx4_ib_post_pv_qp_buf(ctx, sqp, wc.wr_id &
							   (MLX4_NUM_TUNNEL_BUFS - 1)))
                                        printk(KERN_ERR "Failed reposting SQP "
					       "buf:%lld\n", wc.wr_id);
				break;
			default:
				BUG_ON(1);
				break;
			}
		} else  {
			mlx4_ib_dbg("mlx4_ib: completion error in tunnel: %d."
				    " status = %d, wrid = 0x%llx",
				    ctx->slave, wc.status, wc.wr_id);
			if (!MLX4_TUN_IS_RECV(wc.wr_id)) {
				ib_destroy_ah(sqp->tx_ring[wc.wr_id &
					      (MLX4_NUM_TUNNEL_BUFS - 1)].ah);
				sqp->tx_ring[wc.wr_id & (MLX4_NUM_TUNNEL_BUFS - 1)].ah
					= NULL;
				spin_lock(&sqp->tx_lock);
				sqp->tx_ix_tail++;
				spin_unlock(&sqp->tx_lock);
			}
		}
	}
}

static int alloc_pv_object(struct mlx4_ib_dev *dev, int slave, int port,
			       struct mlx4_ib_demux_pv_ctx **ret_ctx)
{
	struct mlx4_ib_demux_pv_ctx *ctx;

	*ret_ctx = NULL;
	ctx = kzalloc(sizeof(struct mlx4_ib_demux_pv_ctx), GFP_KERNEL);
	if (!ctx) {
		printk(KERN_ERR "failed allocating pv resource context"
		       " for port %d, slave %d\n", port, slave);
		return -ENOMEM;
	}

	ctx->ib_dev = &dev->ib_dev;
	ctx->port = port;
	ctx->slave = slave;
	*ret_ctx = ctx;
	return 0;
}

static void free_pv_object(struct mlx4_ib_dev *dev, int slave, int port)
{
	if (dev->sriov.demux[port - 1].tun[slave]) {
		kfree(dev->sriov.demux[port - 1].tun[slave]);
		dev->sriov.demux[port - 1].tun[slave] = NULL;
	}
}

static int create_pv_resources(struct ib_device *ibdev, int slave, int port,
			       int create_tun, struct mlx4_ib_demux_pv_ctx *ctx)
{
	int ret, cq_size;

	ctx->state = DEMUX_PV_STATE_STARTING;
	if ((ctx->slave == to_mdev(ctx->ib_dev)->dev->caps.function) &&
	    mlx4_ib_port_link_layer(to_mdev(ctx->ib_dev), ctx->port) ==
	    IB_LINK_LAYER_INFINIBAND)
		ctx->has_smi = 1;

	if (ctx->has_smi) {
		ret = mlx4_ib_alloc_pv_bufs(ctx, IB_QPT_SMI, create_tun);
		if (ret) {
			printk(KERN_ERR "Failed allocating qp0 tunnel bufs (%d)\n", ret);
			goto err_out;
		}
	}

	ret = mlx4_ib_alloc_pv_bufs(ctx, IB_QPT_GSI, create_tun);
	if (ret) {
		printk(KERN_ERR "Failed allocating qp1 tunnel bufs (%d)\n", ret);
		goto err_out_qp0;
	}

	cq_size = 2 * MLX4_NUM_TUNNEL_BUFS;
	if (ctx->has_smi)
		cq_size *= 2;

	ctx->cq = ib_create_cq(ctx->ib_dev, mlx4_ib_tunnel_comp_handler,
			       NULL, ctx, cq_size, 0);
	if (IS_ERR(ctx->cq)) {
		ret = PTR_ERR(ctx->cq);
		printk(KERN_ERR "Couldn't create tunnel CQ (%d)\n", ret);
		goto err_buf;
	}

	ctx->pd = ib_alloc_pd(ctx->ib_dev);
	if (IS_ERR(ctx->pd)) {
		ret = PTR_ERR(ctx->pd);
		printk(KERN_ERR "Couldn't create tunnel PD (%d)\n", ret);
		goto err_cq;
	}

	ctx->mr = ib_get_dma_mr(ctx->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(ctx->mr)) {
		ret = PTR_ERR(ctx->mr);
		printk(KERN_ERR "Couldn't get tunnel DMA MR (%d)\n", ret);
		goto err_pd;
	}

	if (ctx->has_smi) {
		ret = create_pv_sqp(ctx, IB_QPT_SMI, create_tun);
		if (ret) {
			printk(KERN_ERR "Couldn't create %s QP0 (%d)\n",
			       create_tun ? "tunnel for" : "",  ret);
			goto err_mr;
		}
	}

	ret = create_pv_sqp(ctx, IB_QPT_GSI, create_tun);
	if (ret) {
		printk(KERN_ERR "Couldn't create %s QP1 (%d)\n",
		       create_tun ? "tunnel for" : "",  ret);
		goto err_qp0;
	}

	if (create_tun)
		INIT_WORK(&ctx->work, mlx4_ib_tunnel_comp_worker);
	else
		INIT_WORK(&ctx->work, mlx4_ib_sqp_comp_worker);

	ctx->wq = to_mdev(ibdev)->sriov.demux[port - 1].wq;

	ret = ib_req_notify_cq(ctx->cq, IB_CQ_NEXT_COMP);
	if (ret) {
		printk(KERN_ERR "Couldn't arm tunnel cq (%d)\n", ret);
		goto err_wq;
	}
	ctx->state = DEMUX_PV_STATE_ACTIVE;
	return 0;

err_wq:
	ctx->wq = NULL;
	ib_destroy_qp(ctx->qp[1].qp);
	ctx->qp[1].qp = NULL;


err_qp0:
	if (ctx->has_smi)
		ib_destroy_qp(ctx->qp[0].qp);
	ctx->qp[0].qp = NULL;

err_mr:
	ib_dereg_mr(ctx->mr);
	ctx->mr = NULL;

err_pd:
	ib_dealloc_pd(ctx->pd);
	ctx->pd = NULL;

err_cq:
	ib_destroy_cq(ctx->cq);
	ctx->cq = NULL;

err_buf:
	mlx4_ib_free_pv_qp_bufs(ctx, IB_QPT_GSI, create_tun);

err_out_qp0:
	if (ctx->has_smi)
		mlx4_ib_free_pv_qp_bufs(ctx, IB_QPT_SMI, create_tun);
err_out:
	ctx->state = DEMUX_PV_STATE_DOWN;
	return ret;
}

void mlx4_ib_tunnels_update_work(struct work_struct *work)
{
	struct mlx4_ib_demux_work *dmxw;

	dmxw = container_of(work, struct mlx4_ib_demux_work, work);
	mlx4_ib_tunnels_update(dmxw->dev, dmxw->slave, (int) dmxw->port, dmxw->do_init, 1);
	kfree(dmxw);
	return;
}

void destroy_pv_resources(struct mlx4_ib_dev *dev, int slave, int port,
			  struct mlx4_ib_demux_pv_ctx *ctx, int flush)
{
	if (!ctx)
		return;
	if (ctx->state > DEMUX_PV_STATE_DOWN) {
		ctx->state = DEMUX_PV_STATE_DOWNING;
		if (flush)
			flush_workqueue(ctx->wq);
		if (ctx->has_smi) {
			ib_destroy_qp(ctx->qp[0].qp);
			ctx->qp[0].qp = NULL;
			mlx4_ib_free_pv_qp_bufs(ctx, IB_QPT_SMI, 1);
		}
		ib_destroy_qp(ctx->qp[1].qp);
		ctx->qp[1].qp = NULL;
		mlx4_ib_free_pv_qp_bufs(ctx, IB_QPT_GSI, 1);
		ib_dereg_mr(ctx->mr);
		ctx->mr = NULL;
		ib_dealloc_pd(ctx->pd);
		ctx->pd = NULL;
		ib_destroy_cq(ctx->cq);
		ctx->cq = NULL;
		ctx->state = DEMUX_PV_STATE_DOWN;
	}
}

int mlx4_ib_tunnels_update(struct mlx4_ib_dev *dev, int slave, int port,
			    int do_init, int from_wq)
{
	int ret = 0;

	if (!do_init) {
		clean_vf_mcast(&dev->sriov.demux[port -1], slave);
		/* for master, destroy real sqp resources */
		if (slave == dev->dev->caps.function)
			destroy_pv_resources(dev, slave, port,
					     dev->sriov.sqps[port - 1], 1);

		destroy_pv_resources(dev, slave, port,
				     dev->sriov.demux[port - 1].tun[slave], 1);
		return 0;
	}

	ret = create_pv_resources(&dev->ib_dev, slave, port, 1,
				  dev->sriov.demux[port - 1].tun[slave]);
	if (!ret && slave == dev->dev->caps.function) {
		ret = create_pv_resources(&dev->ib_dev, slave, port, 0,
					  dev->sriov.sqps[port - 1]);
	}
	return ret;
}

static int mlx4_ib_alloc_demux_ctx(struct mlx4_ib_dev *dev,
				       struct mlx4_ib_demux_ctx *ctx,
				       int port)
{
	char name[12];
	int ret = 0;
	int i;

	ctx->tun = kzalloc(dev->dev->caps.sqp_demux *
			   sizeof(struct mlx4_ib_demux_pv_ctx *), GFP_KERNEL);
	if (!ctx->tun)
		return -ENOMEM;

	ctx->dev = dev;
	ctx->port = port;
	ctx->ib_dev = &dev->ib_dev;

	for (i = 0; i < dev->dev->caps.sqp_demux; i++) {
		ret = alloc_pv_object(dev, i, port, &ctx->tun[i]);
		if (ret) {
			ret = -ENOMEM;
			goto err_mcg;
		}
	}

	ret = mlx4_ib_mcg_port_init(ctx);
	if (ret) {
		printk(KERN_ERR "Failed initializing mcg para-virt (%d)\n", ret);
		goto err_mcg;
	}

	snprintf(name, sizeof name, "mlx4_ibt%d", port);
	ctx->wq = create_singlethread_workqueue(name);
	if (!ctx->wq) {
		printk(KERN_ERR "Failed to create tunnelling WQ for port %d\n", port);
		ret = -ENOMEM;
		goto err_wq;
	}

	snprintf(name, sizeof name, "mlx4_ibud%d", port);
	ctx->ud_wq = create_singlethread_workqueue(name);
	if (!ctx->ud_wq) {
		printk(KERN_ERR "Failed to create up/down WQ for port %d\n", port);
		ret = -ENOMEM;
		goto err_udwq;
	}

	return 0;

err_udwq:
	destroy_workqueue(ctx->wq);
	ctx->wq = NULL;

err_wq:
	mlx4_ib_mcg_port_cleanup(ctx, 1);
err_mcg:
	for (i = 0; i < dev->dev->caps.sqp_demux; i++)
		free_pv_object(dev, i, port);
	kfree(ctx->tun);
	ctx->tun = NULL;
	return ret;
}

static void mlx4_ib_free_sqp_ctx(struct mlx4_ib_demux_pv_ctx *sqp_ctx)
{
	if (sqp_ctx->state > DEMUX_PV_STATE_DOWN) {
		sqp_ctx->state = DEMUX_PV_STATE_DOWNING;
		flush_workqueue(sqp_ctx->wq);
		if (sqp_ctx->has_smi) {
			ib_destroy_qp(sqp_ctx->qp[0].qp);
			sqp_ctx->qp[0].qp = NULL;
			mlx4_ib_free_pv_qp_bufs(sqp_ctx, IB_QPT_SMI, 0);
		}
		ib_destroy_qp(sqp_ctx->qp[1].qp);
		sqp_ctx->qp[1].qp = NULL;
		mlx4_ib_free_pv_qp_bufs(sqp_ctx, IB_QPT_GSI, 0);
		ib_dereg_mr(sqp_ctx->mr);
		sqp_ctx->mr = NULL;
		ib_dealloc_pd(sqp_ctx->pd);
		sqp_ctx->pd = NULL;
		ib_destroy_cq(sqp_ctx->cq);
		sqp_ctx->cq = NULL;
		sqp_ctx->state = DEMUX_PV_STATE_DOWN;
	}
}

static void mlx4_ib_free_demux_ctx(struct mlx4_ib_demux_ctx *ctx)
{
	int i;
	if (ctx) {
		struct mlx4_ib_dev *dev = to_mdev(ctx->ib_dev);
		mlx4_ib_mcg_port_cleanup(ctx, 1);
		for (i = 0; i < dev->dev->caps.sqp_demux; i++) {
			if (!ctx->tun[i])
				continue;
			if (ctx->tun[i]->state > DEMUX_PV_STATE_DOWN)
				ctx->tun[i]->state = DEMUX_PV_STATE_DOWNING;
		}
		flush_workqueue(ctx->wq);
		for (i = 0; i < dev->dev->caps.sqp_demux; i++) {
			destroy_pv_resources(dev, i, ctx->port, ctx->tun[i], 0);
			free_pv_object(dev, i, ctx->port);
		}
		kfree(ctx->tun);
		destroy_workqueue(ctx->ud_wq);
		destroy_workqueue(ctx->wq);
	}
}

void mlx4_ib_master_tunnels(struct mlx4_ib_dev *dev, int do_init)
{
	int i;

	if (!dev->dev->caps.sqp_demux)
		return;
	/* initialize or tear down tunnel QPs for the slave */
	for (i = 0; i < dev->dev->caps.num_ports; i++)
		mlx4_ib_tunnels_update(dev, dev->dev->caps.function, i + 1, do_init, 0);
	return;
}

static inline void set_gids_per_func(struct mlx4_ib_dev *dev)
{
	u8 *gids_per_func = &(dev->dev->gids_per_func);
	u8 max_gids_per_func;

	max_gids_per_func = MLX4_MAX_NUM_GIDS / dev->dev->sr_iov;
	if (mlx4_ib_gids_per_func > max_gids_per_func ||
	    mlx4_ib_gids_per_func < 0) {
		*gids_per_func = 1;

		mlx4_ib_warn(&dev->ib_dev, "Invalid parameter gids_per_func %d. "
					   "value must be between 0 and %d. "
					   "defaulting to %d\n",
					   max_gids_per_func,
					   mlx4_ib_gids_per_func,
					   *gids_per_func);
	/* if the parameter is set to 0 - use as many gids per function as possible */
	} else if (mlx4_ib_gids_per_func == 0)
		*gids_per_func = max_gids_per_func;
	else
		*gids_per_func = mlx4_ib_gids_per_func;

	mlx4_ib_dbg("Requested gids per func: %d, setting gids per func to %d. "
		    "Num VFs is: %d\n", mlx4_ib_gids_per_func, *gids_per_func,
		    dev->dev->sr_iov);

	return;
}


int mlx4_ib_init_sriov(struct mlx4_ib_dev *dev)
{
	int i = 0;
	int err;

	if (!mlx4_is_mfunc(dev->dev))
		return 0;

	dev->sriov.is_going_down = 0;
	spin_lock_init(&dev->sriov.going_down_lock);
	mlx4_ib_cm_paravirt_init(dev);

	/* XXX user-space RDMACM relies on unqie node guids to distinguish among
	 * cma devices. */
	((u8*) &dev->ib_dev.node_guid)[MLX4_SLAVE_ID_NODE_GUID_OFFSET] +=
		mlx4_ib_get_virt2phys_gid(dev, 1, 0);

	mlx4_ib_warn(&dev->ib_dev, "multi-function enabled\n");
	mlx4_ib_warn(&dev->ib_dev, "using node_guid:0x%016llx\n",
		     be64_to_cpu(dev->ib_dev.node_guid));

	if (!dev->dev->caps.sqp_demux)
		mlx4_ib_warn(&dev->ib_dev, "operating in qp1 tunnel mode\n");

	if (dev->dev->caps.sqp_demux) {
		set_gids_per_func(dev);

		err = init_alias_guid_service(dev);
		if (err) {
			mlx4_ib_warn(&dev->ib_dev, "Failed init alias guid process.\n");
			goto paravirt_err;
		}
		err = mlx4_ib_device_register_sysfs(dev);
		if (err) {
			mlx4_ib_warn(&dev->ib_dev, "Failed to register sysfs\n");
			goto sysfs_err;
		}

		/* XXX until we have proper SM support, we mannually assign
		 * additional port guids for guests */
		/*if (mlx4_ib_set_slave_guids(&dev->ib_dev))
			mlx4_ib_warn(&dev->ib_dev, "Failed setting slave guids\n");
		*/
	
		mlx4_ib_warn(&dev->ib_dev, "initializing demux service for %d qp1 clients\n",
			     dev->dev->caps.sqp_demux);
		for (i = 0; i < dev->num_ports; i++) {
			err = alloc_pv_object(dev, dev->dev->caps.function, i + 1,
					      &dev->sriov.sqps[i]);
			if (err)
				goto demux_err;
			err = mlx4_ib_alloc_demux_ctx(dev, &dev->sriov.demux[i], i + 1);
			if (err)
				goto demux_err;
		}
		mlx4_ib_master_tunnels(dev, 1);
	}
	return 0;

demux_err:
	while (i > 0) {
		free_pv_object(dev, dev->dev->caps.function, i + 1);
		mlx4_ib_free_demux_ctx(&dev->sriov.demux[i]);
		--i;
	}
	mlx4_ib_device_unregister_sysfs(dev);

sysfs_err:
	clear_alias_guid_work(dev);

paravirt_err:
	mlx4_ib_cm_paravirt_clean(dev, -1);

	return err;
}

void mlx4_ib_close_sriov(struct mlx4_ib_dev *dev)
{
	int i;
	unsigned long flags;

        if (!mlx4_is_mfunc(dev->dev))
                return;
	spin_lock_irqsave(&dev->sriov.going_down_lock, flags);
	dev->sriov.is_going_down = 1;
	spin_unlock_irqrestore(&dev->sriov.going_down_lock, flags);
	/* flush clean_wq so we can destroy mcgs in mlx4_ib_free_demux_ctx*/
	mlx4_ib_mcg_flush();
	if (dev->dev->caps.sqp_demux) {
		for (i = 0; i < dev->num_ports; i++) {
			flush_workqueue(dev->sriov.demux[i].ud_wq);
			mlx4_ib_free_sqp_ctx(dev->sriov.sqps[i]);
			kfree(dev->sriov.sqps[i]);
			dev->sriov.sqps[i] = NULL;
			mlx4_ib_free_demux_ctx(&dev->sriov.demux[i]);
		}

		mlx4_ib_cm_paravirt_clean(dev, -1);
		clear_alias_guid_work(dev);
		mlx4_ib_device_unregister_sysfs(dev);
		//mlx4_ib_master_tunnels(dev, 0);
	}
}

int mlx4_ib_mad_init(struct mlx4_ib_dev *dev)
{
	struct ib_mad_agent *agent;
	int p, q;
	int ret;
	enum rdma_link_layer ll;

	for (p = 0; p < dev->num_ports; ++p) {
		ll = rdma_port_link_layer(&dev->ib_dev, p + 1);
		for (q = 0; q <= 1; ++q) {
			if (ll == IB_LINK_LAYER_INFINIBAND) {
				agent = ib_register_mad_agent(&dev->ib_dev, p + 1,
							      q ? IB_QPT_GSI : IB_QPT_SMI,
							      NULL, 0, send_handler,
							      NULL, NULL);
				if (IS_ERR(agent)) {
					ret = PTR_ERR(agent);
					goto err;
				}
				dev->send_agent[p][q] = agent;
			} else
				dev->send_agent[p][q] = NULL;
		}
	}


	return 0;

err:
	for (p = 0; p < dev->num_ports; ++p)
		for (q = 0; q <= 1; ++q)
			if (dev->send_agent[p][q])
				ib_unregister_mad_agent(dev->send_agent[p][q]);

	return ret;
}

void mlx4_ib_mad_cleanup(struct mlx4_ib_dev *dev)
{
	struct ib_mad_agent *agent;
	int p, q;
	for (p = 0; p < dev->num_ports; ++p) {
		for (q = 0; q <= 1; ++q) {
			agent = dev->send_agent[p][q];
			if (agent) {
				dev->send_agent[p][q] = NULL;
				ib_unregister_mad_agent(agent);
			}
		}
		spin_lock(&dev->sm_lock);
		if (dev->sm_ah[p])
			ib_destroy_ah(dev->sm_ah[p]);
		spin_unlock(&dev->sm_lock);
	}
}
