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
 /***********************************************************/
/*This file support the handling of the Alias GUID feature. */
/***********************************************************/
#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_sa.h>
#include <rdma/ib_pack.h>
#include <linux/mlx4/cmd.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <rdma/ib_user_verbs.h>
#include <linux/delay.h>
#include "mlx4_ib.h"
#include "alias_GUID.h"

/*

The driver keeps the current state of all guids, as they are in the HW.
Whenever smp mad for GUIDInfo record came, it will be cached.

*/
void update_cache_on_guid_change(struct mlx4_ib_dev *dev, int block_num, u8 port_num, u8* p_data)
{
	int i;
	u64 guid_indexes;
	int slave_id;
	int gid_index;
	__be64 tmp_cur_ag;
	int port_index = port_num -1;

	if ((!mlx4_is_mfunc(dev->dev)) || (!dev->dev->caps.sqp_demux))
		return;

	if (block_num >= NUM_ALIAS_GUID_REC_IN_PORT) {
		printk(KERN_ERR "Failed to update guid cache. bn %d is out of range", block_num);
		return;
	}

	guid_indexes = be64_to_cpu(dev->sriov.alias_guid.
			     ports_guid[port_num - 1].
			     all_rec_per_port[block_num].
			     guid_indexes);
	mlx4_ib_dbg("%s:port:%d, guid_indexes: 0x%llx\n", __func__, port_num, guid_indexes);

	for (i = 0; i < NUM_ALIAS_GUID_IN_REC; i++) {
		/*the location of the specific index starts from bit number 4 till bit num 11*/
		if (test_bit(i + 4, (unsigned long *)&guid_indexes)) {
			gid_index = (block_num * NUM_ALIAS_GUID_IN_REC) + i;
			slave_id = mlx4_gid_idx_to_slave(dev->dev, gid_index);
			if (slave_id >= dev->dev->num_slaves) {
				mlx4_ib_dbg("%s:The last slave: %d\n", __func__, slave_id);
				goto out;
			}
			tmp_cur_ag = *(__be64*)&p_data[i * GUID_REC_SIZE];

			/*cache the guid:*/
			memcpy(&dev->sriov.demux[port_index].guid_cache[gid_index],
			       &p_data[i * GUID_REC_SIZE],
			       GUID_REC_SIZE);
		}
		else
			mlx4_ib_dbg("%s: Guid number :%d in block :%d"
				    " was not updated\n",
				    __func__, i, block_num);
	}
out:
	return;
}

/*
	Whenever new GUID was set/unset (guid table change) create event and
	notify the relevant slave (master also should be notify)
	If the GUID value is not as we have in the cache the slave will not be updated,
	in this case it waits for the smp_snoop to call the function and to updatea the slave.
	block_number - the index of the block (16 blocks available)
	port_number - 1 or 2

	GUID change event on the master should be handled outside this function.
	the return value of the function should be checked to find out wheather or not
	on of the master's GUIDs was changed.

	return value: 0 - master GUID was not changed.
		      1 - master GUID was changed.
*/
int notify_slaves_on_guid_change(struct mlx4_ib_dev *dev, int block_num, u8 port_num, u8* p_data)
{
	int i;
	u64 guid_indexes;
	int slave_id;
	int gid_index;
	int slave0_gid_changed = 0;
	enum slave_port_state new_state;
	enum slave_port_state prev_state;
	__be64 tmp_cur_ag, form_cache_ag;
	enum slave_port_gen_event gen_event;

	if ((!mlx4_is_mfunc(dev->dev)) || (!dev->dev->caps.sqp_demux))
		return 0; /* dummy value for compilation only */

	guid_indexes = be64_to_cpu(dev->sriov.alias_guid.
			     ports_guid[port_num - 1].
			     all_rec_per_port[block_num].
			     guid_indexes);
	mlx4_ib_dbg("%s:port:%d, guid_indexes: 0x%llx\n", __func__, port_num, guid_indexes);

	/*calculate the slaves and notify them*/
	for (i = 0; i < NUM_ALIAS_GUID_IN_REC; i++) {
		/*the location of the specific index starts from bit number 4 till bit num 11*/
		if (test_bit(i + 4, (unsigned long *)&guid_indexes)) {
			gid_index = (block_num * NUM_ALIAS_GUID_IN_REC) + i;
			slave_id = mlx4_gid_idx_to_slave(dev->dev, gid_index);

			tmp_cur_ag = *(__be64*)&p_data[i * GUID_REC_SIZE];
			form_cache_ag = get_cached_alias_guid(dev, port_num, gid_index);

			if (slave_id >= dev->dev->num_slaves) {
				mlx4_ib_dbg("%s:The last slave: %d\n", __func__, slave_id);
				goto out;
			/* GID change for slave 0 will be handled outside this function */
			} else if (slave_id == 0) {
				mlx4_ib_dbg("%s: GID change event on gid %d of slave0\n",
					    __func__, gid_index);
				if (tmp_cur_ag != form_cache_ag)
					slave0_gid_changed = 1;
				continue;
			}

			/*check if guid is not the same as in the cache, and notify slaves.*/
			if (tmp_cur_ag != form_cache_ag) {
				mlx4_ib_dbg("%s: (tmp_cur_ag: 0x%llx, form_cache_ag: 0x%llx) notifing relevant slaves...\n",
					    __func__, be64_to_cpu(tmp_cur_ag), be64_to_cpu(form_cache_ag));
				mlx4_gen_guid_change_eqe(dev->dev, slave_id, port_num);
			}

			/* The GID at index 0 controls the state of the port -
			 * when it is invalid the port is considered to be down.
			 * No need to further act on GIDs at other indexes */
			if (ACT_GID_TO_SLAVE_GID(dev->dev, gid_index) != 0)
				continue;

			/*2 cases: Valid GUID, and Invalid Guid*/
			if (MLX4_NOT_SET_GUID != tmp_cur_ag) { /*valid GUID*/
				prev_state = mlx4_get_slave_port_state(dev->dev, slave_id, port_num);
				new_state = set_and_calc_slave_port_state(dev->dev, slave_id, port_num,
									  MLX4_PORT_STATE_IB_PORT_STATE_EVENT_GID_VALID,
									  &gen_event);
				mlx4_ib_dbg("%s: slave: %d, port:%d prev_port_state: %d,"
					    " new_port_state: %d, gen_event :%d\n",
					    __func__, slave_id, port_num, prev_state,
					    new_state, gen_event);
				if (SLAVE_PORT_GEN_EVENT_UP == gen_event) {
					mlx4_ib_dbg("%s: sending PORT_UP event to slave: %d, port:%d\n",
						    __func__, slave_id, port_num);
					mlx4_gen_port_state_change_eqe(dev->dev, slave_id,
								       port_num,
								       MLX4_PORT_CHANGE_SUBTYPE_ACTIVE);
				} else {
					mlx4_ib_dbg("%s: GOT: %d event to slave: %d, port:%d\n",
						    __func__, gen_event, slave_id, port_num);
				}
			}
			else { /*Invalidate GUID*/
				set_and_calc_slave_port_state(dev->dev,
							      slave_id,
							      port_num,
							      MLX4_PORT_STATE_IB_EVENT_GID_INVALID,
							      &gen_event);
				mlx4_ib_dbg("%s: sending MLX4_PORT_STATE_IB_EVENT_GID_INVALID"
					    " event to slave: %d, port:%d [got gen_event: %d]\n",
					    __func__, slave_id, port_num, gen_event);
				mlx4_gen_port_state_change_eqe(dev->dev, slave_id,
							       port_num,
							       MLX4_PORT_CHANGE_SUBTYPE_DOWN);
			}
		}
		else
			mlx4_ib_dbg("%s: Guid number :%d in block :%d"
				    " was not updated\n",
				    __func__, i, block_num);
	}
out:
	return slave0_gid_changed;
	
}
/****************************************************************************
* aliasguid_query_handler : callback function whenever we have success/failure/timeout
******************************************************************************/
static void aliasguid_query_handler(int status,
				    struct ib_sa_guidinfo_rec *guid_rec,
				    void *context)
{
	struct mlx4_ib_dev *dev;
	struct mlx4_alias_guid_work_context *cb_ctx = context;
	u8 port_index;
	int i;
	struct mlx4_sriov_alias_guid_info_rec_det *rec;

	/*ib_sa_comp_mask comp_mask = 0;*/
	unsigned long flags, flags1;

	if (!context) {
                printk(KERN_ERR "alias_guid: context is null. This is a BUG!!!\n");
		return;
	}

	dev = cb_ctx->dev;
	port_index = cb_ctx->port - 1;
	rec = &dev->sriov.alias_guid.ports_guid[port_index].all_rec_per_port[cb_ctx->block_num];
	if (status) {
		rec->status = MLX4_GUID_INFO_STATUS_IDLE;
		mlx4_ib_dbg("%s: (port: %d) failed: status = %d\n",
		       __func__, cb_ctx->port, status);
	} else {
		if (guid_rec->block_num == cb_ctx->block_num) {
			mlx4_ib_dbg("%s: lid/port: %d/%d, block_num: %d", __func__,
				    be16_to_cpu(guid_rec->lid), cb_ctx->port, guid_rec->block_num);

			rec = &dev->sriov.alias_guid.ports_guid[port_index].all_rec_per_port[guid_rec->block_num];
			/*update the status on the adminstratively records*/
			rec->status = MLX4_GUID_INFO_STATUS_SET;
			/*update metod to be set (default)*/
			rec->method = MLX4_GUID_INFO_RECORD_SET;
			/*rec->guid_indexes = comp_mask;*/
			
			for (i = 0 ; i < NUM_ALIAS_GUID_IN_REC; i++){
				__be64 tmp_cur_ag;
				tmp_cur_ag = guid_rec->guid_info_list[i];
				if (cb_ctx->method == MLX4_GUID_INFO_RECORD_DELETE) {
						if (MLX4_NOT_SET_GUID == tmp_cur_ag) {
								mlx4_ib_dbg("%s:Record num %d in block_num:%d was deleted by SM, "
											"ownership by %d (0 = driver, 1=sysAdmin, 2=None)\n",
											__func__, i, guid_rec->block_num, rec->ownership);
						} else {
								/* FIXME : in case of record wasn't deleted we only print an error
								   we can't reschedule the task since the next task can be a set and
								   not delete task.*/
								mlx4_ib_dbg("ERROR: %s:Record num %d in block_num:%d was Not deleted "
											"by SM, ownership by %d (0 = driver, 1=sysAdmin, 2=None)\n",
										   __func__, i, guid_rec->block_num, rec->ownership);
						}
						/* turn OFF the block index bit so it won't be modified in next tasks */
						rec->guid_indexes = rec->guid_indexes &  ~get_alias_guid_comp_mask_from_index(i);
						continue;
				}

				/*
				check if the SM didn't assign one of the records.
				if it didn't, if it was not sysadmin request:
				asks the SM to give a new GUID, (instead of the driver request).
				*/
				if (MLX4_NOT_SET_GUID == tmp_cur_ag) {
					mlx4_ib_dbg("%s:Record num %d in block_num:%d was declined by SM, "
								   "ownership by %d (0 = driver, 1=sysAdmin, 2=None)\n",
						      __func__, i, guid_rec->block_num,rec->ownership);
                                         if (MLX4_GUID_DRIVER_ASSIGN == rec->ownership) {
						/*if it is driver assign, asks for new GUID from SM*/
						rec->all_recs[i] = MLX4_NOT_SET_GUID;
						/*Mark the record as it wasn't assined, and let it to be sent again
						in the next work sched.*/
						rec->status = MLX4_GUID_INFO_STATUS_IDLE;
						rec->guid_indexes = rec->guid_indexes | get_alias_guid_comp_mask_from_index(i);
					}
				}
				else { /*properly assigned record*/
					/*We save the GUID we just got from the SM in the admin_guid in order to be
					 persistance, and in the request from the sm the process will ask for the same GUID */
					if (MLX4_GUID_SYSADMIN_ASSIGN == rec->ownership &&
					    tmp_cur_ag != rec->all_recs[i]) {
							/*the case the sysadmin assignment failed.*/
							mlx4_ib_dbg("%s: Failed to set admin guid after SysAdmin configuration "
									   "Record num %d in block_num:%d was declined by SM "
									   "new val(0x%llx) was kept\n",
							      __func__, i, guid_rec->block_num,
							     be64_to_cpu(rec->all_recs[i]));
					} else
						rec->all_recs[i] = guid_rec->guid_info_list[i];
				}
			}
			/*
			the func is called here to close the cases when the sm doesn't send smp,
			so in the sa response the driver notifies the slave.

			GUID change of one of the master GUIDs is not handled here.
			the assumption is that it this scenario GID0 won't be changed (as
			it can't) and GID1 is only used by the vnic, which will be closed
			and re-opened in this case. so it's ok not to notify the master
			about the change
			*/
			notify_slaves_on_guid_change(dev, guid_rec->block_num, cb_ctx->port, (u8*)guid_rec->guid_info_list);
		} else
			printk(KERN_ERR "block num mismatch: %d != %d",
				    cb_ctx->block_num, guid_rec->block_num);
	}

	spin_lock_irqsave(&dev->sriov.going_down_lock, flags);
	spin_lock_irqsave(&dev->sriov.alias_guid.ag_work_lock, flags1);
	if (!dev->sriov.is_going_down)
                queue_delayed_work(dev->sriov.alias_guid.ports_guid[port_index].wq,
				   &dev->sriov.alias_guid.ports_guid[port_index].alias_guid_work, 0);
	if (cb_ctx->sa_query) {
		list_del(&cb_ctx->list);
		kfree(cb_ctx);
	} else
		complete(&cb_ctx->done);
	spin_unlock_irqrestore(&dev->sriov.alias_guid.ag_work_lock, flags1);
	spin_unlock_irqrestore(&dev->sriov.going_down_lock, flags);
}

static void invalidate_guid_record(struct mlx4_ib_dev *dev, u8 port, int index)
{
	int i;
	__be64 cur_admin_val;
	ib_sa_comp_mask comp_mask = 0;

	dev->sriov.alias_guid.ports_guid[port - 1].all_rec_per_port[index].status
		= MLX4_GUID_INFO_STATUS_IDLE;
	dev->sriov.alias_guid.ports_guid[port - 1].all_rec_per_port[index].method
		= MLX4_GUID_INFO_RECORD_SET;

	/* calculate the comp_mask for that record.*/
	for (i = 0; i < NUM_ALIAS_GUID_IN_REC; i++) {
		cur_admin_val = dev->sriov.alias_guid.ports_guid[port - 1].all_rec_per_port[index].all_recs[i];
		/*
		check the admin value: if it for delete (~00LL) or
		we are in the first guid (hw guid)dont put it for assigment or
		the records isnot in ownership of he sysadmin and the sm doesn't
		need to assign GUIDs.
		*/
		if (MLX4_GUID_FOR_DELETE_VAL == cur_admin_val ||
		    (!index && i == 0) ||
		    MLX4_GUID_NONE_ASSIGN == dev->sriov.alias_guid.ports_guid[port - 1].all_rec_per_port[index].ownership)
			continue;

		comp_mask = comp_mask | get_alias_guid_comp_mask_from_index(i);
	}
	dev->sriov.alias_guid.ports_guid[port - 1].all_rec_per_port[index].guid_indexes = comp_mask;
}

static int mlx4_ib_set_guid_rec(struct ib_device *ibdev,
				u8 port, int index,
				struct mlx4_sriov_alias_guid_info_rec_det *rec_det)
{
	int err;
	struct mlx4_ib_dev *dev = to_mdev(ibdev);
	struct ib_sa_guidinfo_rec guid_info_rec;
	ib_sa_comp_mask comp_mask;
	struct ib_port_attr attr;
	struct mlx4_alias_guid_work_context *callback_context;
	unsigned long resched_delay, flags, flags1;
	struct list_head *head = &dev->sriov.alias_guid.ports_guid[port - 1].cb_list;

	err = mlx4_ib_query_port(ibdev, port, &attr);
	if (err) {
		mlx4_ib_dbg( "failed to mlx4_ib_query_port (err:%d), port:%d !!!\n",
			 err, port);
		return err;
	}
	/*check the port was configured by the sm, otherwise no need to send */
	if (attr.state != IB_PORT_ACTIVE) {
		mlx4_ib_dbg("port: %d not active...rescheduling", port);
		resched_delay = 5 * HZ;
		err = -EAGAIN;
		goto new_schedule;
	}

	callback_context = kmalloc(sizeof *callback_context, GFP_KERNEL);
	if (!callback_context) {
		err = -ENOMEM;
		mlx4_ib_dbg("mlx4_ib_set_guid_rec: no Mem\n");
		resched_delay = HZ * 5;
		goto new_schedule;
	}
	callback_context->port = port;
	callback_context->dev = dev;
	callback_context->block_num = index;
	callback_context->method = rec_det->method;

	memset(&guid_info_rec, 0, sizeof guid_info_rec);

	guid_info_rec.lid = cpu_to_be16(attr.lid);
	guid_info_rec.block_num = index;

	memcpy(guid_info_rec.guid_info_list, rec_det->all_recs, sizeof rec_det->all_recs);
	comp_mask = IB_SA_GUIDINFO_REC_LID |
			IB_SA_GUIDINFO_REC_BLOCK_NUM |
			rec_det->guid_indexes;

	init_completion(&callback_context->done);
	spin_lock_irqsave(&dev->sriov.alias_guid.ag_work_lock, flags1);
	list_add_tail(&callback_context->list, head);
	spin_unlock_irqrestore(&dev->sriov.alias_guid.ag_work_lock, flags1);

	callback_context->query_id = ib_sa_guid_info_rec_query(&dev->sriov.alias_guid.sa_client, ibdev, port,
						       &guid_info_rec, comp_mask,
						       rec_det->method, 1000/*timeout*/,
						       GFP_KERNEL,
						       aliasguid_query_handler, callback_context,
						       &callback_context->sa_query);
	if (callback_context->query_id < 0) {
		mlx4_ib_dbg("mlx4_ib_set_guid_rec: failed to ib_sa_guid_info_rec_query,"
		       "query_id: %d will reschedule to the next 1 sec.\n", callback_context->query_id);
		spin_lock_irqsave(&dev->sriov.alias_guid.ag_work_lock, flags1);
		list_del(&callback_context->list);
		kfree(callback_context);
		spin_unlock_irqrestore(&dev->sriov.alias_guid.ag_work_lock, flags1);
		resched_delay = 1 * HZ;
		err = -EAGAIN;
		goto new_schedule;
	}
	err = 0;
	goto out;

new_schedule:
	spin_lock_irqsave(&dev->sriov.going_down_lock, flags);
	spin_lock_irqsave(&dev->sriov.alias_guid.ag_work_lock, flags1);
	invalidate_guid_record(dev, port, index);
	if (!dev->sriov.is_going_down) {
		queue_delayed_work(dev->sriov.alias_guid.ports_guid[port - 1].wq,
				   &dev->sriov.alias_guid.ports_guid[port - 1].alias_guid_work,
				   resched_delay);
        }
	spin_unlock_irqrestore(&dev->sriov.alias_guid.ag_work_lock, flags1);
	spin_unlock_irqrestore(&dev->sriov.going_down_lock, flags);

out:
	return err;
}

void invalidate_all_guid_record(struct mlx4_ib_dev *dev, int port)
{
	int i;
	unsigned long flags, flags1;

        mlx4_ib_dbg("%s: port %d", __func__, port);

	spin_lock_irqsave(&dev->sriov.going_down_lock, flags);
	spin_lock_irqsave(&dev->sriov.alias_guid.ag_work_lock, flags1);
	for (i = 0; i < NUM_ALIAS_GUID_REC_IN_PORT; i++)
		invalidate_guid_record(dev, port, i);

	if ((!mlx4_is_mfunc(dev->dev)) || (!dev->dev->caps.sqp_demux))
		goto out;
	if (!dev->sriov.is_going_down) {
		/*
		make sure no work waits in the queue, if the work is already queued(not on the timer)
		the cancel will faild, it is not a problem because that is excactly what we want, 
		the work started..
		*/
		__cancel_delayed_work(&dev->sriov.alias_guid.ports_guid[port - 1].alias_guid_work);
		queue_delayed_work(dev->sriov.alias_guid.ports_guid[port - 1].wq,
				   &dev->sriov.alias_guid.ports_guid[port - 1].alias_guid_work,
				   0);
	}
out:
	spin_unlock_irqrestore(&dev->sriov.alias_guid.ag_work_lock, flags1);
	spin_unlock_irqrestore(&dev->sriov.going_down_lock, flags);
}
/* The function returns the next record that was not configured (or failed to configured)*/
int get_next_record_to_update(struct mlx4_ib_dev *dev, u8 port, struct mlx4_next_alias_guid_work *rec)
{
	int j;
	unsigned long flags;

	for (j = 0; j < NUM_ALIAS_GUID_REC_IN_PORT; j++ ) {
		spin_lock_irqsave(&dev->sriov.alias_guid.ag_work_lock, flags);
		if (dev->sriov.alias_guid.ports_guid[port].all_rec_per_port[j].status == MLX4_GUID_INFO_STATUS_IDLE) {
			memcpy(&rec->rec_det, &dev->sriov.alias_guid.ports_guid[port].all_rec_per_port[j],
			       sizeof(struct mlx4_sriov_alias_guid_info_rec_det));
			rec->port = port;
			rec->block_num = j;
			dev->sriov.alias_guid.ports_guid[port].all_rec_per_port[j].status = MLX4_GUID_INFO_STATUS_PENDING;
			spin_unlock_irqrestore(&dev->sriov.alias_guid.ag_work_lock, flags);
			return 0;
		}
		spin_unlock_irqrestore(&dev->sriov.alias_guid.ag_work_lock, flags);
	}
	mlx4_ib_dbg("no more work to do");
	return -ENOENT;
}

void set_administratively_guid_record(struct mlx4_ib_dev *dev, int port,
				      int rec_index,
				      struct mlx4_sriov_alias_guid_info_rec_det *rec_det)
{
	dev->sriov.alias_guid.ports_guid[port].all_rec_per_port[rec_index].guid_indexes =
		rec_det->guid_indexes;
        memcpy(dev->sriov.alias_guid.ports_guid[port].all_rec_per_port[rec_index].all_recs,
	       rec_det->all_recs,
	       sizeof rec_det->all_recs);
	dev->sriov.alias_guid.ports_guid[port].all_rec_per_port[rec_index].status =
		rec_det->status;
}

int mlx4_ib_set_all_slaves_guids(struct mlx4_ib_dev *dev, int port)
{
	int j;
	int is_first_rec = 1;  /* The first guid in the first rec is RO */
	struct mlx4_sriov_alias_guid_info_rec_det rec_det ;

	for (j = 0 ; j < NUM_ALIAS_GUID_REC_IN_PORT ; j++) {
		memset(rec_det.all_recs, 0, sizeof rec_det.all_recs);
		rec_det.guid_indexes = (is_first_rec ? 0 :IB_SA_COMPMASK_GID0) |
			IB_SA_COMPMASK_GID1 | IB_SA_COMPMASK_GID2 |
			IB_SA_COMPMASK_GID3 | IB_SA_COMPMASK_GID4 |
			IB_SA_COMPMASK_GID5 | IB_SA_COMPMASK_GID6 |
			IB_SA_COMPMASK_GID7;
		rec_det.status = MLX4_GUID_INFO_STATUS_IDLE;
		is_first_rec = 0;
		set_administratively_guid_record(dev, port, j, &rec_det);
	}
	is_first_rec = 1;
	return 0;
}

ib_sa_comp_mask get_alias_guid_comp_mask_from_index(int index)
{
		return IB_SA_COMP_MASK(4 + index);
}

int mlx4_ib_process_get_response_set_GUID(struct ib_device *ibdev,
					   u8 port_num, struct ib_mad *in_mad)
{
	mlx4_ib_dbg("processing GETRESP");
	return 0;
}

static void alias_guid_work(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	int ret = 0;
	struct mlx4_next_alias_guid_work *rec;
	struct mlx4_sriov_alias_guid_port_rec_det *sriov_alias_port =
		container_of(delay, struct mlx4_sriov_alias_guid_port_rec_det,
			     alias_guid_work);
	struct mlx4_sriov_alias_guid *sriov_alias_guid = sriov_alias_port->parent;
	struct mlx4_ib_sriov *ib_sriov = container_of(sriov_alias_guid,
						struct mlx4_ib_sriov,
						alias_guid);
	struct mlx4_ib_dev *dev = container_of(ib_sriov, struct mlx4_ib_dev, sriov);

	rec = kzalloc(sizeof *rec, GFP_KERNEL);
	if (!rec) {
		printk(KERN_ERR "alias_guid_work: No Memory\n");
		return;
	}

	mlx4_ib_dbg("starting [port: %d]...", sriov_alias_port->port + 1);
	ret = get_next_record_to_update(dev, sriov_alias_port->port, rec);
	if (ret) {
		mlx4_ib_dbg("No more records to update.");
		goto out;
	}

	mlx4_ib_set_guid_rec(&dev->ib_dev, rec->port + 1, rec->block_num,
			     &rec->rec_det);

out:
	kfree(rec);
}


int init_alias_guid_work(struct mlx4_ib_dev *dev, int port)
{
	unsigned long flags, flags1;
	if ((!mlx4_is_mfunc(dev->dev)) || (!dev->dev->caps.sqp_demux))
		return 0;
	spin_lock_irqsave(&dev->sriov.going_down_lock, flags);
	spin_lock_irqsave(&dev->sriov.alias_guid.ag_work_lock, flags1);
	if (!dev->sriov.is_going_down) {
		queue_delayed_work(dev->sriov.alias_guid.ports_guid[port].wq,
			   &dev->sriov.alias_guid.ports_guid[port].alias_guid_work, 0);
        }
	spin_unlock_irqrestore(&dev->sriov.alias_guid.ag_work_lock, flags1);
	spin_unlock_irqrestore(&dev->sriov.going_down_lock, flags);
	mlx4_ib_dbg("queue work for port: %d", port);
	return 0;
}

/*new function for Oracle only: driver setting the even GUIDs*/
/*
 * generate the GUID using the following formula:
 * change the fourth byte to be: the GUID index in the port GUID table.
 * For example:
 *  00:02:C9:03:YY:XX:XX:XX
 * Where:
 *  00:02:C9:03 - Mellanox prefix GUID
 *  YY          - is the GUID index in the GUID table
 *  XX:XX:XX    - rest of the original GUID
 */
__be64 get_generated_guid(struct mlx4_ib_dev *dev, int port_num, int record_index, int guid_index_in_rec)
{
	static union ib_gid gid = {.raw={0}};
	__be64 gen_guid = 0;
	static int queried_port = 1;

	/* if the gid of this port was not already queried -
	   query and act accordingly */
	if ((!gid.global.interface_id || (queried_port != port_num)) &&
	    dev->ib_dev.query_gid(&dev->ib_dev, port_num, 0, &gid))
		goto exit;

	queried_port = port_num;
	gen_guid = gid.global.interface_id;
	((u8 *)(&gen_guid))[4] = record_index * NUM_ALIAS_GUID_IN_REC +
				guid_index_in_rec + mlx4_ib_guid_gen_magic;

	mlx4_ib_dbg("record: %d, index:%d, port_guid: 0x%llx got: 0x%llx",
		    record_index, guid_index_in_rec, gid.global.interface_id, gen_guid);

exit:
	return gen_guid;
}

void clear_alias_guid_work(struct mlx4_ib_dev *dev)
{
	int i;
	struct mlx4_ib_sriov *sriov = &dev->sriov;
	struct mlx4_alias_guid_work_context *cb_ctx;
	struct mlx4_sriov_alias_guid_port_rec_det *det;
	struct ib_sa_query *sa_query;
	unsigned long flags;

	for (i = 0 ; i < MLX4_MAX_PORTS; i++) {
		cancel_delayed_work(&dev->sriov.alias_guid.ports_guid[i].alias_guid_work);
		det = &sriov->alias_guid.ports_guid[i];
		spin_lock_irqsave(&sriov->alias_guid.ag_work_lock, flags);
		while(!list_empty(&det->cb_list)) {
			cb_ctx = list_entry(det->cb_list.next,
					    struct mlx4_alias_guid_work_context,
					    list);
			sa_query = cb_ctx->sa_query;
			cb_ctx->sa_query = NULL;
			list_del(&cb_ctx->list);
			spin_unlock_irqrestore(&sriov->alias_guid.ag_work_lock, flags);
			ib_sa_cancel_query(cb_ctx->query_id, sa_query);
			wait_for_completion(&cb_ctx->done);
			kfree(cb_ctx);
			spin_lock_irqsave(&sriov->alias_guid.ag_work_lock, flags);
		}
		spin_unlock_irqrestore(&sriov->alias_guid.ag_work_lock, flags);
	}
	for (i = 0 ; i < MLX4_MAX_PORTS; i++) {
		/*force flush anyway.*/
		flush_workqueue(dev->sriov.alias_guid.ports_guid[i].wq);
		destroy_workqueue(dev->sriov.alias_guid.ports_guid[i].wq);
	}
	ib_sa_unregister_client(&dev->sriov.alias_guid.sa_client);
}

int init_alias_guid_service(struct mlx4_ib_dev *dev)
{
	char alias_wq_name[15];
	int ret = 0;
	int i, j, k;
	int curr_gid;
	int slave_gid_idx;
	struct mlx4_sriov_alias_guid *ag;
	struct mlx4_sriov_alias_guid_port_rec_det *pg;
	__be64 gen_guid;

	if ((!mlx4_is_mfunc(dev->dev)) || (!dev->dev->caps.sqp_demux))
		return 0;

	ag = &dev->sriov.alias_guid;
	ib_sa_register_client(&ag->sa_client);

	spin_lock_init(&ag->ag_work_lock);

	for (i = 0 ; i < MLX4_MAX_PORTS; ++i) {
		pg = &ag->ports_guid[i];
		INIT_LIST_HEAD(&pg->cb_list);
		/* Check if the SM doesn't need to assign the GUIDs */
		for (j = 0; j < NUM_ALIAS_GUID_REC_IN_PORT; ++j) {
			if (mlx4_ib_sm_guid_assign)
				pg->all_rec_per_port[j].ownership = MLX4_GUID_DRIVER_ASSIGN;
			else {
				pg->all_rec_per_port[j].ownership = MLX4_GUID_SYSADMIN_ASSIGN;

				/* mark each val as it was deleted, till the sysAdmin will give it valid val */
				for (k = 0; k < NUM_ALIAS_GUID_IN_REC; ++k) {
					/* Oracle request for guid-0 driver assignment:
					   all GUIDs at index 0 and Dom0 GUID-1 */
					curr_gid = j * NUM_ALIAS_GUID_IN_REC + k;
					slave_gid_idx = ACT_GID_TO_SLAVE_GID(dev->dev, curr_gid);
					if (slave_gid_idx == 0 ||
					    (slave_gid_idx == 1 &&
					     mlx4_gid_idx_to_slave(dev->dev, curr_gid) == 0)) {
						gen_guid = get_generated_guid(dev, i + 1, j, k);
						if (!gen_guid) {
							ret = -EINVAL;
							goto err;
						}
					} else
						gen_guid = MLX4_GUID_FOR_DELETE_VAL;

					pg->all_rec_per_port[j].all_recs[k] = gen_guid;
				}
			}

			/* prepare the records, set them to be allocated by sm */
			invalidate_guid_record(dev, i + 1, j);
		}

		pg->parent = ag;
		pg->port  = i;
		if (mlx4_ib_sm_guid_assign)
			mlx4_ib_set_all_slaves_guids(dev, i);

		snprintf(alias_wq_name, sizeof alias_wq_name, "alias_guid%d", i);
		pg->wq =
			create_singlethread_workqueue(alias_wq_name);
		if (!pg->wq) {
			ret = -ENOMEM;
			goto err;
		}
		INIT_DELAYED_WORK(&pg->alias_guid_work, alias_guid_work);
	}
	return 0;
err:
	printk(KERN_ERR "init_alias_guid_service: Failed. (ret:%d)\n", ret);
	return ret;
}

static void init_query_mad(struct ib_smp *mad)
{
	mad->base_version  = 1;
	mad->mgmt_class    = IB_MGMT_CLASS_SUBN_LID_ROUTED;
	mad->class_version = 1;
	mad->method	   = IB_MGMT_METHOD_GET;
}

int mlx4_ib_get_indexed_gid(struct ib_device *ibdev, u8 port, int index,
			       union ib_gid *gid)
{
	struct ib_smp *in_mad  = NULL;
	struct ib_smp *out_mad = NULL;
	int err = -ENOMEM;
	struct mlx4_ib_dev *dev = to_mdev(ibdev);

	in_mad  = kzalloc(sizeof *in_mad, GFP_KERNEL);
	out_mad = kmalloc(sizeof *out_mad, GFP_KERNEL);
	if (!in_mad || !out_mad)
		goto out;

	init_query_mad(in_mad);
	in_mad->attr_id  = IB_SMP_ATTR_PORT_INFO;
	in_mad->attr_mod = cpu_to_be32(port);

	err = mlx4_MAD_IFC(dev, 1, 1, port, NULL, NULL, in_mad, out_mad);
	if (err)
		goto out;

	memcpy(gid->raw, out_mad->data + 8, 8);

	init_query_mad(in_mad);
	in_mad->attr_id  = IB_SMP_ATTR_GUID_INFO;
	in_mad->attr_mod = cpu_to_be32(index / 8);

	err = mlx4_MAD_IFC(dev, 1, 1, port, NULL, NULL, in_mad, out_mad);
	if (err)
		goto out;
	memcpy(gid->raw + 8, out_mad->data + (index % 8) * 8, 8);
out:
	kfree(in_mad);
	kfree(out_mad);
	return err;
}

__be64 get_cached_alias_guid(struct mlx4_ib_dev *dev, int port, int index)
{
	__be64 cur_admin_val;

	if (index >= NUM_ALIAS_GUID_PER_PORT) {
		printk(KERN_ERR "%s: BUG: asked for index:%d\n", __func__, index);
		return -1;
	}
	cur_admin_val = *(__be64*)&dev->sriov.demux[port - 1].guid_cache[index];

/*	cur_admin_val =	*(__be64*)&dev->sriov.alias_guid.ports_guid[port - 1].
		all_rec_per_port[record_num].all_recs[GUID_REC_SIZE * guid_index_in_rec];
*/
	return cur_admin_val;
}

enum mlx4_guid_alias_rec_status get_record_status(struct mlx4_ib_dev *dev, int port, int index)
{
	int record_num; 

	record_num = index / 8;
	if (record_num >= NUM_ALIAS_GUID_REC_IN_PORT) {
		printk(KERN_ERR "%s: BUG: asked for index:%d (record:%d)\n", __func__, index, record_num);
		return MLX4_GUID_INFO_STATUS_IDLE;
	}
	return dev->sriov.alias_guid.ports_guid[port - 1].all_rec_per_port[record_num].status;
}
