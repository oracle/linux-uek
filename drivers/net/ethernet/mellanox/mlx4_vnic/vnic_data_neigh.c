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
#include "vnic_data.h"

void vnic_neighe_dealloc_task(struct work_struct *work)
{
	struct vnic_neigh *neighe =
		container_of(work, struct vnic_neigh, destroy_task.work);
	if (IS_NEIGH_QUERY_RUNNING(neighe))
		ib_sa_cancel_query(neighe->query_id, neighe->pquery);
	wait_for_completion(&neighe->query_comp);
	if (neighe->ah && !IS_ERR(neighe->ah))
		ib_destroy_ah(neighe->ah);
	kfree(neighe);
}

void vnic_neighe_dealloc(struct vnic_neigh *neighe)
{
	ASSERT(neighe);
	/* calls vnic_neighe_dealloc_task */
	queue_delayed_work(neighe->login->neigh_wq, &neighe->destroy_task, 0);
}

struct ib_ah *vnic_ah_alloc(struct vnic_login *login, u16 dlid)
{
	struct ib_ah_attr av;
	struct ib_ah *ah;

	memset(&av, 0, sizeof(av));
	av.dlid = dlid;
	av.port_num = login->port->num;
	av.sl = login->sl; /* PATH Query is need here to allocate the data sl*/
	ah = ib_create_ah(login->port->pd, &av);
	if (IS_ERR(ah)) {
		return ERR_PTR(-ENOMEM);
	}
	return(ah);
}

struct vnic_neigh *vnic_neighe_alloc(struct vnic_login *login,
				     const u8 *mac,
				     u16 dlid, u32 dqpn, u8 rss)
{
	struct vnic_neigh *neighe;
	neighe = kzalloc(sizeof *neighe, GFP_ATOMIC);
	if (!neighe)
		return ERR_PTR(-ENOMEM);
	INIT_DELAYED_WORK(&neighe->destroy_task, vnic_neighe_dealloc_task);
	skb_queue_head_init(&neighe->pkt_queue);
	if (mac)
		memcpy(neighe->mac, mac, ETH_ALEN);
	neighe->rss = rss;
	neighe->ah = ERR_PTR(-ENODATA);
	if (!vnic_sa_query) {
		neighe->ah = vnic_ah_alloc(login, dlid);
		if (IS_ERR(neighe->ah)) {
			   kfree(neighe);
			   return ERR_PTR(-ENOMEM);
		}
	}
	init_completion(&neighe->query_comp);
	complete(&neighe->query_comp); /* mark as complete since no query is running */
	neighe->pquery = ERR_PTR(-ENODATA);
	neighe->query_id = -1;
	neighe->qpn = dqpn;
	neighe->lid = dlid;
	neighe->login = login;

	return neighe;
}

void vnic_neighe_del(struct vnic_login *login, struct vnic_neigh *neighe)
{
	ASSERT(neighe);
	rb_erase(&neighe->rb_node, &login->neigh_tree);
}

int vnic_neighe_add(struct vnic_login *login, struct vnic_neigh *neighe)
{
	struct rb_node **n = &login->neigh_tree.rb_node, *pn = NULL;
	struct vnic_neigh *neighe_t;
	int rc;

	while (*n) {
		pn = *n;
		neighe_t = rb_entry(pn, struct vnic_neigh, rb_node);
		rc = memcmp(neighe->mac, neighe_t->mac, ETH_ALEN);
		if (rc < 0)
			n = &pn->rb_left;
		else if (rc > 0)
			n = &pn->rb_right;
		else {
			rc = -EEXIST;
			goto out;
		}
	}

	rb_link_node(&neighe->rb_node, pn, n);
	rb_insert_color(&neighe->rb_node, &login->neigh_tree);
	rc = 0;

out:
	return rc;
}

struct vnic_neigh *vnic_neighe_search(struct vnic_login *login, u8 *mac)
{
	struct rb_node *n = login->neigh_tree.rb_node;
	struct vnic_neigh *neighe_t;
	int rc;

	while (n) {
		neighe_t = rb_entry(n, struct vnic_neigh, rb_node);
		rc = memcmp(mac, neighe_t->mac, ETH_ALEN);
		if (rc < 0)
			n = n->rb_left;
		else if (rc > 0)
			n = n->rb_right;
		else {
			vnic_dbg_data(login->name,
				      "found: mac "MAC_6_PRINT_FMT" vid %d "
				      "qpn 0x%06x lid 0x%02x\n",
				      MAC_6_PRINT_ARG(neighe_t->mac),
				      be16_to_cpu(login->vid), neighe_t->qpn,
				      neighe_t->lid);
			goto out;
		}
	}
	neighe_t = ERR_PTR(-ENODATA);

out:
	return neighe_t;
}

void vnic_neigh_del_all(struct vnic_login *login)
{
	struct rb_node *n;
	struct vnic_neigh *neighe;

	ASSERT(login);
	n = rb_first(&login->neigh_tree);
	while (n) {
		neighe = rb_entry(n, struct vnic_neigh, rb_node);
		vnic_neighe_del(login, neighe);
		n = rb_first(&login->neigh_tree);
		vnic_neighe_dealloc(neighe);
	}
}

void vnic_neigh_invalidate(struct vnic_login *login)
{
	struct vnic_neigh *neighe;
	struct rb_node *n;
	int i;

	if (login->gw_neigh && !IS_ERR(login->gw_neigh))
		login->gw_neigh->valid = 0;

	n = rb_first(&login->neigh_tree);
	while (n) {
		neighe = rb_entry(n, struct vnic_neigh, rb_node);
		neighe->valid = 0;
		n = rb_next(n);
	}

	if (login->is_lag)
		for (i=0; i<MAX_LAG_MEMBERS; i++)
			login->lag_gw_neigh[i].neigh.valid = 0;
}
