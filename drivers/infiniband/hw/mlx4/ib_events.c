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
 /***************************************************************/
/*	This file supports the handling of mlx4_ib events. 	*/
/****************************************************************/

#include <linux/mlx4/device.h>
#include "mlx4_ib.h"
#include "ib_events.h"
#include "alias_GUID.h"

#define GET_BLK_PTR_FROM_EQE(eqe) be32_to_cpu(eqe->event.port_mgmt_change.params.tbl_change_info.block_ptr)
#define GET_MASK_FROM_EQE(eqe) be32_to_cpu(eqe->event.port_mgmt_change.params.tbl_change_info.tbl_entries_mask)
#define NUM_IDX_IN_PKEY_TBL_BLK 32
#define GUID_TBL_ENTRY_SIZE 8 	   /* size in bytes */
#define GUID_TBL_BLK_NUM_ENTRIES 8 
#define GUID_TBL_BLK_SIZE (GUID_TBL_ENTRY_SIZE * GUID_TBL_BLK_NUM_ENTRIES)

#define MSTR_SM_CHANGE_MASK (MLX4_EQ_PORT_INFO_MSTR_SM_SL_CHANGE_MASK | MLX4_EQ_PORT_INFO_MSTR_SM_LID_CHANGE_MASK)

enum {
	MLX4_DEV_PMC_SUBTYPE_GUID_INFO	 = 0x14,
	MLX4_DEV_PMC_SUBTYPE_PORT_INFO	 = 0x15,
	MLX4_DEV_PMC_SUBTYPE_PKEY_TABLE	 = 0x16,
};

enum {
	MLX4_EQ_PORT_INFO_MSTR_SM_LID_CHANGE_MASK	= 1 << 0,
	MLX4_EQ_PORT_INFO_GID_PFX_CHANGE_MASK		= 1 << 1,
	MLX4_EQ_PORT_INFO_LID_CHANGE_MASK		= 1 << 2,
	MLX4_EQ_PORT_INFO_CLIENT_REREG_MASK		= 1 << 3,
	MLX4_EQ_PORT_INFO_MSTR_SM_SL_CHANGE_MASK 	= 1 << 4,
};

void handle_lid_change_event(struct mlx4_ib_dev *dev, u8 port_num)
{
	struct ib_event event;

	event.device	       	= &dev->ib_dev;
	event.element.port_num 	= port_num;
	event.event		= IB_EVENT_LID_CHANGE;

	ib_dispatch_event(&event);

	if (mlx4_is_mfunc(dev->dev) && dev->dev->caps.sqp_demux && (!dev->sriov.is_going_down))
		mlx4_gen_all_sw_eqe(dev->dev, port_num,
				    LID_CHANGE_AVIAL);
}

void handle_client_rereg_event(struct mlx4_ib_dev *dev, u8 port_num)
{
	struct ib_event event;

	event.device	       	= &dev->ib_dev;
	event.element.port_num 	= port_num;
	event.event 		= IB_EVENT_CLIENT_REREGISTER;

	/*also re-configure the alias-guid and mcg's */
	if (dev->dev->caps.sqp_demux) {
		invalidate_all_guid_record(dev, port_num);
                                       
		if (!dev->sriov.is_going_down) {
			mlx4_ib_mcg_port_cleanup(&dev->sriov.demux[port_num - 1], 0);
			mlx4_gen_all_sw_eqe(dev->dev, port_num,
					    CLIENT_REREGISTER_AVIAL);
		}
	}
	ib_dispatch_event(&event);
}

static void propagate_pkey_ev(struct mlx4_ib_dev *dev, int port_num,
			      struct mlx4_ib_eqe *eqe)
{
	int pkey_idx_base;
	int i, ix, slave;
	int have_event = 0;
	int err;
	u32 change_bitmap;

	change_bitmap = GET_MASK_FROM_EQE(eqe);
	pkey_idx_base = (GET_BLK_PTR_FROM_EQE(eqe) * NUM_IDX_IN_PKEY_TBL_BLK);

	for (slave = 0; slave < dev->dev->caps.sqp_demux; slave++) {
		if (slave == dev->dev->caps.function)
			continue;

		if (!mlx4_is_slave_active(dev->dev, slave))
			continue;

		have_event = 0;

		/* go through the bitmap to see which indexes in the pkeys block
		   were modified */
		for (i = 0; i < NUM_IDX_IN_PKEY_TBL_BLK; i++) {
			if (!(change_bitmap & (1 << i)))
				continue;

			for (ix = 0; ix < dev->dev->caps.pkey_table_len[port_num]; ix++) {
				if (dev->pkeys.virt2phys_pkey[slave][port_num - 1][ix] ==
				    (pkey_idx_base + i)) {
					mlx4_ib_dbg("%s: slave %d, port %d, ix %d",
						    __func__, slave, port_num, ix);

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

static void handle_pkey_change_event(struct mlx4_ib_eqe *eqe,
				     struct mlx4_ib_dev *dev)
{
	struct ib_event event;
	u8 port_num = eqe->event.port_mgmt_change.port;

	mlx4_ib_dbg("PKEY Change event: port=%d\n", port_num);

	event.device	       = &dev->ib_dev;
	event.event	       = IB_EVENT_PKEY_CHANGE;
	event.element.port_num = port_num;

	ib_dispatch_event(&event);
	
	if (!mlx4_is_mfunc(dev->dev) || !dev->dev->caps.sqp_demux || dev->sriov.is_going_down)
		return;			

	propagate_pkey_ev(dev, port_num, eqe);
}

static inline void handle_master_sm_change_event(struct mlx4_ib_dev *dev,
						 struct mlx4_ib_eqe *eqe)
{
	u16 lid = be16_to_cpu(eqe->event.port_mgmt_change.params.port_info.mstr_sm_lid);
	u8 sl = eqe->event.port_mgmt_change.params.port_info.mstr_sm_sl & 0xf;
	u8 port_num = eqe->event.port_mgmt_change.port;
	
	update_sm_ah(dev, port_num, lid, sl);	
}

static void handle_slaves_guid_change(struct mlx4_ib_dev *dev, u8 port_num,
				      u32 guid_tbl_blk_num, u32 change_bitmap)
{
	struct ib_smp *in_mad  = NULL;
	struct ib_smp *out_mad  = NULL;
	u16 i;

	if (!mlx4_is_mfunc(dev->dev) || !mlx4_is_master(dev->dev))
		return;

	in_mad  = kmalloc(sizeof *in_mad, GFP_KERNEL);
	out_mad = kmalloc(sizeof *out_mad, GFP_KERNEL);
        if (!in_mad || !out_mad) {
		mlx4_ib_warn(&dev->ib_dev, "failed to allocate memory for guid info mads\n");
		goto out;
	}

	guid_tbl_blk_num  *= 4;

	for (i = 0; i < 4; i++) {
		if (change_bitmap && (!((change_bitmap >> (8 * i)) & 0xff)))
			continue;
		memset(in_mad, 0, sizeof *in_mad);
		memset(out_mad, 0, sizeof *out_mad);

		in_mad->base_version  = 1;
		in_mad->mgmt_class    = IB_MGMT_CLASS_SUBN_LID_ROUTED;
		in_mad->class_version = 1;
		in_mad->method        = IB_MGMT_METHOD_GET;
		in_mad->attr_id       = IB_SMP_ATTR_GUID_INFO;
		in_mad->attr_mod      = cpu_to_be32(guid_tbl_blk_num + i);

		if (mlx4_MAD_IFC(dev, 1, 1, port_num, NULL, NULL,
				 in_mad, out_mad)) {
			mlx4_ib_warn(&dev->ib_dev, "Failed in get GUID INFO MAD_IFC\n");
			goto out;
		}

		update_cache_on_guid_change(dev, guid_tbl_blk_num + i, port_num,
					    (u8*)(&((struct ib_smp *)out_mad)->data));
		notify_slaves_on_guid_change(dev, guid_tbl_blk_num + i, port_num,
					    (u8*)(&((struct ib_smp *)out_mad)->data));
        }

out:
	if (in_mad)
		kfree(in_mad);
	
	if (out_mad)
		kfree(out_mad);
	    
	return;
}

static void handle_guid_change_event(struct mlx4_ib_dev *dev,
				     struct mlx4_ib_eqe *eqe)
{
	struct ib_event event;
	u32 tbl_block;
	u32 change_bitmap;
	u8 port = eqe->event.port_mgmt_change.port;

	/* The mfunc master's GUID is always the default GUID
	   and will never change, so there's no need to dispatch the event */
	if (!mlx4_is_mfunc(dev->dev) || 
	    (mlx4_is_mfunc(dev->dev) && !mlx4_is_master(dev->dev))) {
		event.device	       = &dev->ib_dev;
		event.event	       = IB_EVENT_GID_CHANGE;
		event.element.port_num = port;
		ib_dispatch_event(&event);

		return;
	}

	/*if master, notify  relevant slaves*/
	if (dev->dev->caps.sqp_demux && (!dev->sriov.is_going_down)) {
		tbl_block = GET_BLK_PTR_FROM_EQE(eqe);
		change_bitmap = GET_MASK_FROM_EQE(eqe);

		handle_slaves_guid_change(dev, port, tbl_block, change_bitmap);
	}
}

void handle_port_mgmt_change_event(struct work_struct *work)
{
	struct ib_event event;
	struct ib_event_work *ew = container_of(work, struct ib_event_work, work);
	struct mlx4_ib_dev *dev = ew->ib_dev;
	struct mlx4_ib_eqe *eqe = &(ew->ib_eqe);
	u8 port = eqe->event.port_mgmt_change.port;
	u32 changed_attr;

	switch(eqe->subtype) {
	case MLX4_DEV_PMC_SUBTYPE_PORT_INFO:
		changed_attr = be32_to_cpu(eqe->event.port_mgmt_change.params.port_info.changed_attr);

		/* Update the SM ah - This should be done before handling
		   the other changed attributes*/
		if (changed_attr & MSTR_SM_CHANGE_MASK) {
			mlx4_ib_dbg("Master SM changed on port %d", port);

			handle_master_sm_change_event(dev, eqe);
		}

		/* Check if it is a lid change event */
		if (changed_attr & MLX4_EQ_PORT_INFO_LID_CHANGE_MASK) {
			mlx4_ib_dbg("LID change event on port %d", port);

			handle_lid_change_event(dev, port);
		}

		/* Generate GUID changed event */
		if (changed_attr & MLX4_EQ_PORT_INFO_GID_PFX_CHANGE_MASK) {
			mlx4_ib_dbg("GID prefix changed on port %d", port);

			event.device	       = &dev->ib_dev;
			event.event	       = IB_EVENT_GID_CHANGE;
			event.element.port_num = port;
			ib_dispatch_event(&event);

			if (mlx4_is_mfunc(dev->dev) && mlx4_is_master(dev->dev))
				/*if master, notify all slaves*/
				mlx4_gen_all_sw_eqe(dev->dev, port,
						    GUID_CHANGE_AVIAL);
		}			

		if (changed_attr & MLX4_EQ_PORT_INFO_CLIENT_REREG_MASK) {
			mlx4_ib_dbg("CLIENT REREGISTER event on port %d", port);
			handle_client_rereg_event(dev, port);
		}
		break;

	case MLX4_DEV_PMC_SUBTYPE_PKEY_TABLE:
		mlx4_ib_dbg("PKEY Change event on port=%d", port);
		
		handle_pkey_change_event(eqe, dev);
		break;
	case MLX4_DEV_PMC_SUBTYPE_GUID_INFO:
		mlx4_ib_dbg("GUID change event on port %d", port);

		handle_guid_change_event(dev, eqe);
		break;
	default:
		printk(KERN_WARNING "Unsupported subtype 0x%x for "
				     "Port Management Change event\n", eqe->subtype);
	}

	kfree(ew);
}
