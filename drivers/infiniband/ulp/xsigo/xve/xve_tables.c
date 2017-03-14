/*
 * Copyright (c) 2011-2012 Xsigo Systems. All rights reserved
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

#include "xve.h"
#include "xve_compat.h"

#include <linux/pkt_sched.h>
#include <linux/random.h>


u32 xve_hash_salt __read_mostly;
static struct kmem_cache *xve_fwt_cache __read_mostly;

struct xve_advert_hdr {
	__be16 type;
	__be16 count;
	union ib_gid gid;
	u32 qpn;
} __attribute__ ((__packed__));

int xve_tables_init(void)
{
	get_random_bytes(&xve_hash_salt, sizeof(xve_hash_salt));
	xve_fwt_cache =
	    kmem_cache_create("xve_fwt_cache", sizeof(struct xve_fwt_entry), 0,
			      SLAB_HWCACHE_ALIGN, NULL);
	if (!xve_fwt_cache)
		return -ENOMEM;

	return 0;
}

void xve_fwt_init(struct xve_fwt_s *xve_fwt)
{

	int i;

	spin_lock_init(&xve_fwt->lock);
	for (i = 0; i < XVE_FWT_HASH_LISTS; i++)
		INIT_HLIST_HEAD(&xve_fwt->fwt[i]);
	xve_fwt->num = 0;

}

static int xve_mac_hash(const unsigned char *mac, int size, u16 vlan)
{
	return hash_bytes(mac, ETH_ALEN, vlan ^ xve_hash_salt) & (size - 1);
}

static struct xve_fwt_entry *xve_fwt_find_entry(struct hlist_head *head,
						const unsigned char *mac,
						u16 vlan)
{
	struct xve_fwt_entry *fwt_entry;

	hlist_for_each_entry(fwt_entry, head, hlist) {
		if (fwt_entry->vlan == vlan
		    && ether_addr_equal(fwt_entry->smac_addr, mac))
			return fwt_entry;
	}
	return NULL;
}

bool xve_fwt_entry_valid(struct xve_fwt_s *xve_fwt,
			 struct xve_fwt_entry *fwt_entry)
{
	int ret = true;
	unsigned long flags;

	spin_lock_irqsave(&xve_fwt->lock, flags);
	if ((fwt_entry != NULL)
	    && test_bit(XVE_FWT_ENTRY_VALID, &fwt_entry->state))
		atomic_inc(&fwt_entry->ref_cnt);
	else
		ret = false;
	spin_unlock_irqrestore(&xve_fwt->lock, flags);

	return ret;
}

int xve_aging_task_machine(struct xve_dev_priv *priv)
{
	unsigned long flags;
	struct xve_fwt_entry *fwt_entry;
	struct xve_path *path;
	struct xve_fwt_s *xve_fwt = &priv->xve_fwt;
	int i;
	char *smac;
	struct hlist_head *head;
	struct hlist_node *n;

	spin_lock_irqsave(&priv->lock, flags);
	if (!test_bit(XVE_OS_ADMIN_UP, &priv->state) ||
	    test_bit(XVE_DELETING, &priv->state)) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return 0;
	}
	spin_unlock_irqrestore(&priv->lock, flags);

	priv->counters[XVE_MAC_AGED_CHECK]++;
	for (i = 0; i < XVE_FWT_HASH_LISTS; i++) {
		head = &xve_fwt->fwt[i];
		hlist_for_each_entry_safe(fwt_entry, n, head, hlist) {
			if (xve_fwt_entry_valid(xve_fwt, fwt_entry) == true) {
				smac = fwt_entry->smac_addr;
				spin_lock_irqsave(&priv->lock, flags);
				if (!test_and_clear_bit
				    (XVE_FWT_ENTRY_REFRESH, &fwt_entry->state)
				    && ((jiffies - fwt_entry->last_refresh) >=
					priv->aging_delay)) {
					xve_info(priv,
							"MAC %pM vlan %d Aged[D] out",
							smac, fwt_entry->vlan);
					atomic_set(&fwt_entry->del_inprogress,
							1);
					path = fwt_entry->path;
					if (path) {
						spin_unlock_irqrestore(
							&priv->lock, flags);
						xve_flush_single_path_by_gid(
							priv->netdev,
							&path->pathrec.dgid,
							fwt_entry);
						spin_lock_irqsave(&priv->lock,
							 flags);
						xve_fwt_put_ctx(xve_fwt,
								fwt_entry);
						xve_fwt_entry_free(priv,
								fwt_entry);
					} else
						xve_remove_fwt_entry(priv,
								fwt_entry);

					priv->counters[XVE_MAC_AGED_COUNTER]++;
				} else {
					priv->counters[XVE_MAC_STILL_INUSE]++;
					xve_fwt_put_ctx(xve_fwt, fwt_entry);
				}
				spin_unlock_irqrestore(&priv->lock, flags);
			} else {
				priv->counters[XVE_MAC_AGED_NOMATCHES]++;
			}
		}
	}

	return 0;
}

struct xve_fwt_entry *xve_fwt_lookup(struct xve_dev_priv *priv, char *mac,
				     u16 vlan, int refresh)
{
	struct xve_fwt_s *xve_fwt = &priv->xve_fwt;
	struct xve_fwt_entry *fwt_entry;
	unsigned long flags;
	struct hlist_head *head;

	spin_lock_irqsave(&xve_fwt->lock, flags);
	head = &xve_fwt->fwt[xve_mac_hash(mac, XVE_FWT_HASH_LISTS, vlan)];
	xve_debug(DEBUG_TABLE_INFO, priv,
			 "Hash value%d %pM vlan %d entries %d",
			 xve_mac_hash(mac, XVE_FWT_HASH_LISTS, vlan),
			 mac, vlan,
			 xve_fwt->num);
	fwt_entry = xve_fwt_find_entry(head, mac, vlan);

	if (fwt_entry) {
		if (atomic_read(&fwt_entry->del_inprogress)) {
			xve_info(priv, "%p Table delete in progress mac%pM",
					fwt_entry, mac);
			spin_unlock_irqrestore(&xve_fwt->lock, flags);
			return NULL;
		}
		atomic_inc(&fwt_entry->ref_cnt);
		if (refresh)
			set_bit(XVE_FWT_ENTRY_REFRESH, &fwt_entry->state);
		fwt_entry->last_refresh = jiffies;
	}
	spin_unlock_irqrestore(&xve_fwt->lock, flags);
	return fwt_entry;
}

void xve_fwt_put_ctx(struct xve_fwt_s *xve_fwt, struct xve_fwt_entry *fwt_entry)
{
	if (fwt_entry)
		atomic_dec(&fwt_entry->ref_cnt);
}

void xve_fwt_insert(struct xve_dev_priv *priv, struct xve_cm_ctx *ctx,
		    union ib_gid *gid, u32 qpn, char *smac, u16 vlan)
{
	struct hlist_head *head;
	struct xve_fwt_entry *fwt_entry;
	unsigned long flags, flags1;
	struct xve_fwt_s *xve_fwt = &priv->xve_fwt;
	struct xve_path *path;
	char from[64], to[64];

	if (xve_is_uplink(priv) &&
			!memcmp(&gid->raw, &priv->gw.t_gid.raw, sizeof(*gid)))
		qpn = priv->gw.t_data_qp;

	/* Get a FWT entry for this mac and vlan */
	spin_lock_irqsave(&priv->lock, flags);
	fwt_entry = xve_fwt_lookup(priv, smac, vlan, 1);
	spin_unlock_irqrestore(&priv->lock, flags);

	if (fwt_entry) {
		if (unlikely
		    (memcmp
		     (fwt_entry->dgid.raw, gid->raw, sizeof(union ib_gid)))) {
			print_mgid_buf(from, (char *)fwt_entry->dgid.raw);
			print_mgid_buf(to, (char *)gid->raw);
			xve_debug(DEBUG_FWTABLE_INFO, priv,
					"XVE: %s MAC %pM ",
					priv->xve_name, smac);
			xve_debug(DEBUG_FWTABLE_INFO, priv,
					"vlan %d moved from GID %s to GID %s\n",
					fwt_entry->vlan, from, to);
			priv->counters[XVE_MAC_MOVED_COUNTER]++;

			memcpy(fwt_entry->dgid.raw, gid->raw,
			       sizeof(union ib_gid));
			/*
			 * We need to hold priv->lock
			 */
			spin_lock_irqsave(&priv->lock, flags);
			spin_lock_irqsave(&xve_fwt->lock, flags1);
			if (fwt_entry->path)
				list_del(&fwt_entry->list);
			fwt_entry->path = NULL;
			path = __path_find(priv->netdev, gid->raw);
			if (path) {
				fwt_entry->path = path;
				list_add_tail(&fwt_entry->list,
					      &path->fwt_list);
			}
			spin_unlock_irqrestore(&xve_fwt->lock, flags1);
			spin_unlock_irqrestore(&priv->lock, flags);
		}
		if (qpn && unlikely(fwt_entry->dqpn != qpn))
			fwt_entry->dqpn = qpn;
		/* Insert CM rx in the path */
		if (fwt_entry->path && ctx)
			fwt_entry->path->cm_ctx_rx = ctx;
		xve_fwt_put_ctx(xve_fwt, fwt_entry);
	} else {
		fwt_entry =
		    kmem_cache_alloc(xve_fwt_cache, GFP_ATOMIC | __GFP_ZERO);
		if (!fwt_entry) {
			pr_warn("xve_fwt_entry_alloc() failed\n");
			return;
		}
		memset(fwt_entry, 0, sizeof(struct xve_fwt_entry));
		print_mgid_buf(from, (char *)gid->raw);
		xve_debug(DEBUG_FWTABLE_INFO, priv,
			"XVE: %s MAC %pM", priv->xve_name, smac);
		xve_debug(DEBUG_FWTABLE_INFO, priv,
			"vlan %d learned from GID %s, mode: %s QPN %x Fwt %p\n",
			vlan, from, qpn ? "UD" : "RC", qpn, fwt_entry);
		priv->counters[XVE_MAC_LEARN_COUNTER]++;
		memcpy(fwt_entry->dgid.raw, gid->raw, sizeof(union ib_gid));
		fwt_entry->dqpn = qpn;
		ether_addr_copy(fwt_entry->smac_addr, smac);
		fwt_entry->vlan = vlan;
		set_bit(XVE_FWT_ENTRY_REFRESH, &fwt_entry->state);
		fwt_entry->last_refresh = jiffies;
		set_bit(XVE_FWT_ENTRY_VALID, &fwt_entry->state);
		spin_lock_irqsave(&xve_fwt->lock, flags);
		fwt_entry->hash_value =
		    xve_mac_hash(smac, XVE_FWT_HASH_LISTS, vlan);
		head =
		    &xve_fwt->fwt[xve_mac_hash(smac, XVE_FWT_HASH_LISTS, vlan)];
		hlist_add_head(&fwt_entry->hlist, head);
		xve_fwt->num++;
		spin_unlock_irqrestore(&xve_fwt->lock, flags);
	}
}

void xve_remove_fwt_entry(struct xve_dev_priv *priv,
			  struct xve_fwt_entry *fwt_entry)
{
	struct xve_fwt_s *xve_fwt = &priv->xve_fwt;
	unsigned long flags = 0;

	spin_lock_irqsave(&xve_fwt->lock, flags);
	xve_debug(DEBUG_FLUSH_INFO, priv, "%s Deleting FWT[%d] From list %p",
		  __func__, xve_fwt->num, fwt_entry);
	if (fwt_entry->path)
		list_del(&fwt_entry->list);
	hlist_del(&fwt_entry->hlist);
	xve_fwt->num--;
	spin_unlock_irqrestore(&xve_fwt->lock, flags);
}

void xve_fwt_entry_free(struct xve_dev_priv *priv,
			struct xve_fwt_entry *fwt_entry)
{
	unsigned long begin;
	unsigned long flags = 0;
	/*
	 * Wait for refernce count to goto zero (Use kref which is better)
	 */
	begin = jiffies;

	xve_debug(DEBUG_FLUSH_INFO, priv, "%s Free cache ,FWT %p cnt%d",
		  __func__, fwt_entry, atomic_read(&fwt_entry->ref_cnt));
	while (atomic_read(&fwt_entry->ref_cnt)) {
		if (time_after(jiffies, begin + 5 * HZ)) {
			xve_warn(priv,
				 "timing out fwt_entry still in use %p",
				 fwt_entry);
			break;
		}
		/* We are sure that this is called in a single context*/
		if (spin_is_locked(&priv->lock)) {
			spin_unlock_irqrestore(&priv->lock, flags);
			msleep(20);
			spin_lock_irqsave(&priv->lock, flags);
		} else
			msleep(20);
	}
	kmem_cache_free(xve_fwt_cache, fwt_entry);
}

void xve_fwt_entry_destroy(struct xve_dev_priv *priv,
			   struct xve_fwt_entry *fwt_entry)
{
	xve_remove_fwt_entry(priv, fwt_entry);
	xve_fwt_entry_free(priv, fwt_entry);
}

void xve_fwt_cleanup(struct xve_dev_priv *priv)
{
	struct xve_fwt_s *xve_fwt = &priv->xve_fwt;
	int i;
	struct hlist_head *head;
	struct hlist_node *n;
	struct xve_fwt_entry *fwt_entry;
	unsigned long flags;

	spin_lock_irqsave(&xve_fwt->lock, flags);
	for (i = 0; i < XVE_FWT_HASH_LISTS; i++) {
		head = &xve_fwt->fwt[i];
		hlist_for_each_entry_safe(fwt_entry, n, head, hlist) {
			hlist_del(&fwt_entry->hlist);
			kmem_cache_free(xve_fwt_cache, fwt_entry);
			xve_fwt->num--;
		}
	}
	xve_info(priv, "Forwarding table cleaned up entries:%d",
			xve_fwt->num);
	spin_unlock_irqrestore(&xve_fwt->lock, flags);
}

void xve_prepare_skb(struct xve_dev_priv *priv, struct sk_buff *skb)
{
	skb->protocol = eth_type_trans(skb, priv->netdev);
	skb->dev = priv->netdev;
	skb_pkt_type(skb, PACKET_HOST);
	if (xve_is_ovn(priv) && test_bit(XVE_FLAG_CSUM, &priv->flags))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
}

void xve_tables_exit(void)
{
	kmem_cache_destroy(xve_fwt_cache);
}
