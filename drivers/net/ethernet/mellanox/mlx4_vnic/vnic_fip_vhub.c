/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
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

#include "vnic.h"
#include "vnic_fip.h"
#include "vnic_fip_discover.h"
#include "vnic_fip_pkt.h"

/*
 * construct an mgid address based on vnic login information and the type
 * variable (data mcast / vhub update / vhub table). The resulting mgid
 * is returned in *mgid.
 */
void vhub_mgid_create(const char *mgid_prefix,
		      const char *mmac, /* mcast mac for bcast 0xFF.. */
		      u64 n_mac,	/* bits to take from mmac */
		      u32 vhub_id,
		      enum vhub_mgid_type type,
		      u8 rss_hash,
		      union vhub_mgid *mgid)
{
	u32 vhub_id_be;
	u64 mac_mask;
	u64 *mac_ptr;
	u64 one = 1; /* must do that for shift bitwise operation */

	memcpy(mgid->mgid.mgid_prefix, mgid_prefix,
	       sizeof(mgid->mgid.mgid_prefix));
	mgid->mgid.type = (u8)type;
	memcpy(mgid->mgid.dmac, mmac, sizeof(mgid->mgid.dmac));
	mac_mask = cpu_to_le64(((one << n_mac) - one) | 0xFFFF000000000000ULL);
	mac_ptr = (u64*)(mgid->mgid.dmac);
	*mac_ptr &= mac_mask;
	mgid->mgid.rss_hash = rss_hash;
	vhub_id_be = cpu_to_be32(vhub_id);
	memcpy(mgid->mgid.vhub_id, ((u8 *) &vhub_id_be) + 1,
	       sizeof(mgid->mgid.vhub_id));
};

/*
 * Init the vnic's vHub table data structures, before using them
 */
void vhub_ctx_init(struct fip_vnic_data *vnic)
{
	INIT_LIST_HEAD(&vnic->vhub_table.main_list.vnic_list);
	vnic->vhub_table.main_list.tusn = 0;
	vnic->vhub_table.main_list.count = 0;
	vnic->vhub_table.main_list.total_count = 0;

	INIT_LIST_HEAD(&vnic->vhub_table.update_list.vnic_list);
	vnic->vhub_table.update_list.tusn = 0;
	vnic->vhub_table.update_list.count = 0;
	vnic->vhub_table.update_list.total_count = 0;

	vnic->vhub_table.checksum = 0;
	vnic->vhub_table.tusn = 0;
	vnic->vhub_table.state = VHUB_TBL_INIT;
}

/* print vhub context table */
static void vhub_ctx_prnt(struct fip_vnic_data *vnic,
			  struct vhub_elist *vhub_list, int level)
{
	struct vnic_table_entry *vnic_entry;

	if (!(vnic_msglvl & VNIC_DEBUG_VHUB_V))
		return;

	vnic_dbg_vhub_v(vnic->name, "Dumping context table. Count %d tusn %d\n",
			vhub_list->count, vhub_list->tusn);

	list_for_each_entry(vnic_entry, &vhub_list->vnic_list, list) {
		vnic_dbg_vhub_v(vnic->name, "lid 0x%04x qpn 0x%06x, mac "
				MAC_6_PRINT_FMT"\n", vnic_entry->lid,
				vnic_entry->qpn,
				MAC_6_PRINT_ARG(vnic_entry->mac));
	}
}

void vhub_table_free(struct vhub_elist *elist)
{
	struct vnic_table_entry *del_vnic, *tmp_vnic;

	list_for_each_entry_safe(del_vnic, tmp_vnic, &elist->vnic_list, list) {
		list_del(&del_vnic->list);
		kfree(del_vnic);
	}
}

/*
 * Clear and free the vnic's vHub context table data structures.
 */
void vhub_ctx_free(struct fip_vnic_data *vnic)
{
	vnic_dbg_fip_v(vnic->name, "vhub_ctx_free called\n");

	vhub_table_free(&vnic->vhub_table.main_list);
	vhub_table_free(&vnic->vhub_table.update_list);

	vhub_ctx_init(vnic);
}

static struct vnic_table_entry *vhub_find_entry(struct vhub_elist *vnic_list,
					       u16 lid, u32 qpn)
{
	struct vnic_table_entry *tmp_vnic;

	list_for_each_entry(tmp_vnic, &vnic_list->vnic_list, list) {
		if (tmp_vnic->lid == lid && tmp_vnic->qpn == qpn)
			return tmp_vnic;
	}
	return NULL;
}

/*
 * Move vHub context entries from the update list to the main list. The update
 * list is used during the wait for the main table to be updated. Once
 * the table update is completed the entries need to be moved from the update
 * table to the main table. This function does this.
*/
static int vhub_update_main(struct fip_vnic_data *vnic,
			    struct vhub_elist *main_list,
			    struct vhub_elist *update_list)
{
	struct vnic_table_entry *new_entry, *tmp_vnic, *del_vnic;
	int first_tusn = (u32) update_list->tusn - (update_list->count - 1);
	int extra_tusn;

	/* update list is usually empty */
	if (likely(update_list->count == 0))
		return 0;

	if (first_tusn > main_list->tusn + 1) {
		vnic_warn(vnic->name, "Info, vhub_to_main_tbl sync main to"
			  " update list failed. update tusn %d update "
			  "first %d main %d\n",
			  update_list->tusn, first_tusn, main_list->tusn);
		return -1;
	}

	extra_tusn = main_list->tusn + 1 - first_tusn;

	/* go over update list and move / remove entries in it */
	list_for_each_entry_safe(new_entry, tmp_vnic,
				 &update_list->vnic_list, list) {
		if (extra_tusn > 0) {
			list_del(&new_entry->list);
			kfree(new_entry);
			extra_tusn--;
		} else {
			/* remove from update list and apply to main list */
			list_del(&new_entry->list);
			main_list->tusn++;

			/* Check valid bit, if set add to main list */
			if (new_entry->valid) {
				list_add_tail(&new_entry->list,
					      &main_list->vnic_list);
				main_list->count++;
			} else {	/* remove from main list */
				del_vnic = vhub_find_entry(main_list,
							   new_entry->lid,
							   new_entry->qpn);
				if (del_vnic) {
					list_del(&del_vnic->list);
					kfree(del_vnic);

					main_list->count--;
				}
				vnic_dbg_fip_v(vnic->name,
					       "vhub_to_main_tbl removed "
					       "vnic lid %d qpn 0x%x found %d\n",
					       (int)new_entry->lid,
					       (int)new_entry->qpn,
					       (del_vnic != 0));
				kfree(new_entry);
			}
		}
		update_list->count--;
	}
	return 0;
}

int fip_vnic_search_mac(struct fip_vnic_data *vnic, struct vhub_elist *elist)
{
	struct vnic_table_entry *vlist_entry;

	list_for_each_entry(vlist_entry, &elist->vnic_list, list)
		/* find matching entry based on mac */
		if(!memcmp(vnic->login_data.mac, vlist_entry->mac, ETH_ALEN)) {
			/* verify lid/qpn match */
			if (vnic->port->attr.lid == vlist_entry->lid &&
			    vnic->qp_base_num == vlist_entry->qpn)
				return 1;
			else {
				vnic_dbg_vhub(vnic->name,
					      "vnic LID=0x%x or QPN=0x%x "
					      "in vhub tbl is different than "
					      "expected LID=0x%x, QPN=0x%x\n",
					      vlist_entry->lid,
					      vlist_entry->qpn,
					      vnic->port->attr.lid, 
					      vnic->qp_base_num);
				break;
			}
		}

	return 0;
}

/*
 * This function handles a vhub context table packet. The table will
 * be processed only if we do not have an up to date local copy of
 * our own. The table update supports multi-packet tables so care
 * must be taken in building the complete table.
 */
int vhub_handle_tbl(struct fip_vnic_data *vnic, struct fip_content *fc,
		    u32 vhub_id, u32 tusn)
{
	struct context_table_entry *entry;
	struct vnic_table_entry *new_entry;
	struct vhub_elist *table;
	int i, j, count_in_pkt;
	int reason = 0;
	int hdr_type;

	/* we already have a table. disregard this one */
	if (vnic->vhub_table.state != VHUB_TBL_INIT) {
		vnic_dbg_vhub_v(vnic->name,
			       "vhub_handle_tbl context not in init\n");
		return 0;
	}

	/* compute the number of vnic entries in the packet.
	 * don't forget the checksum
	 */
	count_in_pkt = fc->cte.num;
	table = &vnic->vhub_table.main_list;
	hdr_type = be16_to_cpu(fc->fvt->hdr) >> 14;

	/* first or only packet in sequence */
	if (hdr_type == FIP_TABLE_HDR_FIRST || hdr_type == FIP_TABLE_HDR_ONLY) {
		table->total_count = be16_to_cpu(fc->fvt->table_size);
		table->tusn = tusn;
	}
	if (table->tusn != tusn) {
		vnic_warn(vnic->name, "Info, vhub_handle_tbl got unexpected "
			  "tusn. Expect=%d received=%d\n", table->tusn, tusn);
		if (!table->tusn)
			goto drop_silently;
		reason = 1;
		goto reset_table;
	}

	if ((table->count + count_in_pkt > table->total_count) ||
	    ((table->count + count_in_pkt < table->total_count) &&
	     (hdr_type == FIP_TABLE_HDR_LAST || hdr_type == FIP_TABLE_HDR_ONLY))) {
		vnic_dbg_vhub(vnic->name,
			      "vhub_handle_tbl got unexpected entry count. "
			      "count %d, in packet %d total expected %d\n",
			      table->count, count_in_pkt, table->total_count);
		reason = 2;
		goto reset_table;
	}

	entry = fc->cte.cte;
	for (i = 0; i < count_in_pkt; ++i, ++entry) {
		new_entry = kzalloc(sizeof *new_entry, GFP_KERNEL);
		if (!new_entry)
			goto reset_table;

		for (j = 0; j < (sizeof *entry) >> 2; ++j)
			vnic->vhub_table.checksum += ((u32 *) entry)[j];

		new_entry->lid = be16_to_cpu(entry->lid);
		new_entry->qpn = be32_to_cpu(entry->qpn) & 0xffffff;
		new_entry->sl = entry->sl & 0xf;
		new_entry->rss = !!(entry->v_rss_type & FIP_CONTEXT_RSS_FLAG);
		new_entry->valid = !!(entry->v_rss_type & FIP_CONTEXT_V_FLAG);
		memcpy(new_entry->mac, entry->mac, sizeof(new_entry->mac));

		list_add_tail(&new_entry->list, &table->vnic_list);
		table->count++;
	}

	/* last packet */
	if (hdr_type == FIP_TABLE_HDR_LAST || hdr_type == FIP_TABLE_HDR_ONLY) {
		ASSERT(table->count == table->total_count);
		if (vnic->vhub_table.checksum != be32_to_cpu(*(u32 *) entry)) {
			vnic_dbg_fip_v(vnic->name,
				       "vhub_handle_tbl checksum mismatch. "
				       "expected 0x%x, in packet 0x%x\n",
				       vnic->vhub_table.checksum,
				       be32_to_cpu(*(u32 *) entry));
			/* TODO: request checksum match in final code */
			/* goto reset_table; */
		}

		if (vhub_update_main(vnic, &vnic->vhub_table.main_list,
				     &vnic->vhub_table.update_list)) {
			vnic_dbg_fip_v(vnic->name,
				       "vhub_handle_tbl moving update list to main "
				       "list failed\n");
			reason = 3;
			goto reset_table;
		}

		/* we are done receiving the context table */
		vnic_dbg_fip_v(vnic->name,
			       "vhub_handle_tbl updated with %d entries\n",
			       vnic->vhub_table.main_list.count);
		vhub_ctx_prnt(vnic, &vnic->vhub_table.main_list, 0);

		/* we are not in the main vHub list close ourselves */
		if (!fip_vnic_search_mac(vnic, &vnic->vhub_table.main_list)) {
			vnic_dbg_fip_p0(vnic->name, "We are not in the main table close our selves\n");
			fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
			reason = 4;
			goto reset_table;
		}

		if (fip_vnic_tbl_done(vnic)) {
			vnic_warn(vnic->name, "vhub_handle_tbl done failed, reseting table\n");
			reason = 5;
			goto reset_table;
		}
	}

drop_silently:
	return 0;

reset_table:
	vnic_dbg_fip_p0(vnic->name, "We are not in the main table close our selves reason=%d\n", reason);
	vhub_ctx_free(vnic);
	/* TODO renable tx of update request, fip_update_send() */
	return -EINVAL;
}

/*
 * This function writes the main vhub table to the data (login) vnic.
 * You should call it when the data vnic is ready for it and after the
 * table is up to date (and the update list was applied to the main list)
 */
int fip_vnic_write_tbl(struct fip_vnic_data *vnic)
{
	struct vnic_table_entry *vlist_entry;
	int rc;

	if (vnic->login)
		sprintf(vnic->name, "%s", vnic->login->name);

	/* update table in neigh tree */
	list_for_each_entry(vlist_entry,
			    &vnic->vhub_table.main_list.vnic_list, list) {
		rc = vnic_vhube_add(vnic, vlist_entry);
		if (rc) {
			vnic_warn(vnic->name, "vnic_vhube_add failed for mac "
				  MAC_6_PRINT_FMT" (rc %d)\n",
				  MAC_6_PRINT_ARG(vlist_entry->mac), rc);
			vhub_ctx_free(vnic);
			vnic_vhube_flush(vnic);
			return -1;
		}
	}

	vnic_dbg_fip(vnic->name, "fip_vnic_tbl_done: creation of vnic done\n");

	vnic->vhub_table.tusn = vnic->vhub_table.main_list.tusn;
	vnic->vhub_table.state = VHUB_TBL_UPDATED;

	/* free table memory */
	vhub_table_free(&vnic->vhub_table.main_list);
	return 0;
}

/*
 * This function handles a vhub context update packets received AFTER
 * we have a valid vhub table. For update additions the code adds an
 * entry to the neighbour tree. For update removals we either remove
 * the entry from the neighbour list or if the removed entry is "this vnic"
 * we remove the vnic.
*/
static int vhub_update_updated(struct fip_vnic_data *vnic,
			       u32 vhub_id, u32 pkt_tusn,
			       struct vnic_table_entry *data)
{
	int curr_tusn;

	curr_tusn = vnic->vhub_table.tusn;

	/* if vnic is being flushed, return */
	if (vnic->flush)
		return 0;

	/* we got a GW keep alive packet */
	if (pkt_tusn == curr_tusn)
		return 0;

	/* if we got an out of order update clear list and request new table */
	if (pkt_tusn != curr_tusn + 1) {
		vnic_warn(vnic->name, "Info, vhub_update_up2date received out"
			  " of order update. Recvd=%d Expect=%d\n",
			  pkt_tusn, curr_tusn);
		goto error_in_update;
	}

	/* new entry added */
	if (data->valid) {
		if (vnic_vhube_add(vnic, data)) {
			vnic_dbg_fip(vnic->name, "vnic_vhube_add "
				     "failed to update vnic neigh tree\n");
			goto error_in_update;
		}
	} else {		/* remove entry */
		/* the remove request is for this vnic :-o */
		if (!memcmp(vnic->login_data.mac, data->mac, ETH_ALEN)) {
			vnic_dbg_fip_p0(vnic->name, "remove this vnic "MAC_6_PRINT_FMT"\n",
				     MAC_6_PRINT_ARG(vnic->login_data.mac));
			fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
		} else {
			vnic_dbg_fip(vnic->name, "remove neigh vnic\n");
			vnic_vhube_del(vnic, data->mac);
		}
	}

	vnic->vhub_table.tusn = pkt_tusn;

	return 0;

error_in_update:
	vhub_ctx_free(vnic);
	vnic_vhube_flush(vnic);
	fip_update_send(vnic, 1 /* new */, 0 /* logout */);
	return -1;
}

/*
 * This function handles a vhub context update packets received BEFORE
 * we have a valid vhub table. The function adds the update request
 * to an update list to be processed after the entire vhub table is received
 * and processed.
 */
static int vhub_update_init(struct fip_vnic_data *vnic,
			     u32 vhub_id, u32 pkt_tusn,
			     struct vnic_table_entry *data)
{
	struct vnic_table_entry *new_vnic;
	struct vhub_elist *vnic_list;
	int curr_tusn;

	vnic_list = &vnic->vhub_table.update_list;
	curr_tusn = vnic_list->tusn;

	/* if we got an out of order update clear list and request new table */
	if ((pkt_tusn < curr_tusn || pkt_tusn > curr_tusn + 1)
	    && curr_tusn != 0) {
		vnic_warn(vnic->name, "Info, vhub_update_init received out of"
			  " order update. got %d my %d\n", pkt_tusn, curr_tusn);
		goto error_in_update;
	}

	/* we got a GW keep alive packet */
	if (pkt_tusn == curr_tusn) {
		vnic_dbg_fip_v(vnic->name, "Received GW keep alive update."
			       " tusn %d\n", curr_tusn);
		return 0;
	}

	/* got remove request for this vnic don't wait */
	if (!(data->valid) &&
	    !memcmp(vnic->login_data.mac, data->mac, ETH_ALEN)) {
		vhub_ctx_free(vnic);
		vnic_dbg_fip_p0(vnic->name, "got request to close vNic vhub_update_init\n");
		fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
		goto err;
	}

	new_vnic = kzalloc(sizeof *new_vnic, GFP_KERNEL);
	if (!new_vnic)
		goto error_in_update;

	memcpy(new_vnic, data, sizeof *data);
	list_add_tail(&new_vnic->list, &vnic_list->vnic_list);
	vnic_list->count++;
	vnic_list->tusn = pkt_tusn;
	vhub_ctx_prnt(vnic, vnic_list, 0);
	return 0;

error_in_update:
	vhub_ctx_free(vnic);
	fip_update_send(vnic, 1 /* new */, 0 /* logout */);
err:
	return -1;
}

/*
 * This function handles a vhub context update packets received after
 * we have a valid vhub table but  before it was passed to the data rbtree.
 * The function applies the update request to the main vhub table.
 */
static int vhub_update_inter(struct fip_vnic_data *vnic,
			     u32 vhub_id, u32 pkt_tusn,
			     struct vnic_table_entry *data)
{
	struct vnic_table_entry *new_vnic, *del_vnic;
	struct vhub_elist *vnic_list;
	int curr_tusn;

	vnic_list = &vnic->vhub_table.main_list;
	curr_tusn = vnic_list->tusn;

	/* if we got an out of order update clear list and request new table */
	if ((pkt_tusn < curr_tusn || pkt_tusn > curr_tusn + 1)
	    && curr_tusn != 0) {
		vnic_warn(vnic->name, "Info, vhub_update_init received out"
			  " of order update. got %d my %d\n", pkt_tusn, curr_tusn);
		goto error_in_update;
	}

	/* we got a GW keep alive packet */
	if (pkt_tusn == curr_tusn) {
		vnic_dbg_fip_v(vnic->name, "Received GW keep alive update."
			       " tusn %d\n", curr_tusn);
		return 0;
	}

	/* we got an add request */
	if (data->valid) {
		new_vnic = kzalloc(sizeof *new_vnic, GFP_KERNEL);
		if (!new_vnic)
			goto error_in_update;

		memcpy(new_vnic, data, sizeof *data);
		list_add_tail(&new_vnic->list, &vnic_list->vnic_list);
		vnic_list->count++;
		vnic_list->tusn = pkt_tusn;
	} else { /* we got a remove request */
		/* remove is for this vnic */
		if (!memcmp(vnic->login_data.mac, data->mac, ETH_ALEN)) {
			vhub_ctx_free(vnic);
			vnic_dbg_fip_p0(vnic->name, "got request to close vNic vhub_update_inter\n");
			fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
			goto err;
		}

		/* search and delete the vnic */
		del_vnic = vhub_find_entry(vnic_list,
					   data->lid,
					   data->qpn);
		if (del_vnic) {
			list_del(&del_vnic->list);
			kfree(del_vnic);
			vnic_list->count--;
		}
		vnic_dbg_fip_v(vnic->name,
			       "vhub_update_inter removed "
			       "vnic lid %d qpn 0x%x found %d\n",
			       (int)data->lid, (int)data->qpn,
			       (del_vnic != 0));
	}

	vhub_ctx_prnt(vnic, vnic_list, 0);
	return 0;

error_in_update:
	vhub_ctx_free(vnic);
	fip_update_send(vnic, 1 /* new */, 0 /* logout */);
err:
	return -1;
}

/*
 * This function handles a vhub context update packets. There are three flows
 * in handeling update packets. The first is before the main table is up
 * to date, the second is after the table is up to date but before it was
 * passed to the ownership of the data vnic (login struct) and the local
 * lists are freed, and the last is when the table maintanence is done
 * by the data vnic. This function handles all cases.
*/
int vhub_handle_update(struct fip_vnic_data *vnic,
		       u32 vhub_id, u32 tusn,
		       struct vnic_table_entry *data)
{
	int ret = 0;

	/*
	 * if we do not have an up to date table to use the update list.
	 * if we have an up to date table apply the updates to the
	 * main table list.
	 */
	switch (vnic->vhub_table.state) {
	case VHUB_TBL_INIT:	/* No full table yet, keep updates for later */
		ret = vhub_update_init(vnic, vhub_id, tusn, data);
		break;
	case VHUB_TBL_UP2DATE:  /* full table available, not writen to data half */
		ret = vhub_update_inter(vnic, vhub_id, tusn, data);
		break;
	case VHUB_TBL_UPDATED:  /* full table available and writen to data half */
		ret = vhub_update_updated(vnic, vhub_id, tusn, data);
		break;
	default:
		break;
	}

        return ret;
}
