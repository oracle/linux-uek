// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU switch driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/switchdev.h>
#include <net/netevent.h>
#include <net/arp.h>
#include <net/nexthop.h>

#include "../otx2_reg.h"
#include "../otx2_common.h"
#include "../otx2_struct.h"
#include "../cn10k.h"
#include "sw_nb.h"

#if !IS_ENABLED(CONFIG_OCTEONTX_SWITCH)
int sw_fl_setup_ft_block_ingress_cb(enum tc_setup_type type,
				    void *type_data, void *cb_priv)
{
	return -EOPNOTSUPP;
}

#else

static DEFINE_SPINLOCK(sw_fl_lock);
static LIST_HEAD(sw_fl_lh);

struct sw_fl_list_entry {
	struct list_head list;
	u64 flags;
	unsigned long cookie;
	struct otx2_nic *pf;
	struct fl_tuple tuple;
};

static struct workqueue_struct *sw_fl_wq;
static struct work_struct sw_fl_work;

static int sw_fl_msg_send(struct otx2_nic *pf,
			  struct fl_tuple *tuple,
			  u64 flags,
			  unsigned long cookie)
{
	struct fl_notify_req *req;
	int rc;

	mutex_lock(&pf->mbox.lock);
	req = otx2_mbox_alloc_msg_fl_notify(&pf->mbox);
	if (!req) {
		rc = -ENOMEM;
		goto out;
	}

	req->tuple = *tuple;
	req->flags = flags;
	req->cookie = cookie;

	rc = otx2_sync_mbox_msg(&pf->mbox);
out:
	mutex_unlock(&pf->mbox.lock);
	return rc;
}

static void sw_fl_wq_handler(struct work_struct *work)
{
	struct sw_fl_list_entry *entry;
	LIST_HEAD(tlist);

	spin_lock(&sw_fl_lock);
	list_splice_init(&sw_fl_lh, &tlist);
	spin_unlock(&sw_fl_lock);

	while ((entry =
		list_first_entry_or_null(&tlist,
					 struct sw_fl_list_entry,
					 list)) != NULL) {
		list_del_init(&entry->list);
		sw_fl_msg_send(entry->pf, &entry->tuple,
			       entry->flags, entry->cookie);
		kfree(entry);
	}

	spin_lock(&sw_fl_lock);
	if (!list_empty(&sw_fl_lh))
		queue_work(sw_fl_wq, &sw_fl_work);
	spin_unlock(&sw_fl_lock);
}

static int
sw_fl_add_to_list(struct otx2_nic *pf, struct fl_tuple *tuple,
		  unsigned long cookie, bool add_fl)
{
	struct sw_fl_list_entry *entry;

	entry = kcalloc(1, sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	entry->pf = pf;
	entry->flags = add_fl ? FL_ADD : FL_DEL;
	if (add_fl)
		entry->tuple = *tuple;
	entry->cookie = cookie;

	spin_lock(&sw_fl_lock);
	list_add_tail(&entry->list, &sw_fl_lh);
	queue_work(sw_fl_wq, &sw_fl_work);
	spin_unlock(&sw_fl_lock);

	return 0;
}

static int sw_fl_parse_actions(struct otx2_nic *nic,
			       struct flow_action *flow_action,
			       struct flow_cls_offload *f,
			       struct fl_tuple *tuple)
{
	struct flow_action_entry *act;
	struct otx2_nic *out_nic;

	u64 op = 0;
	int used = 0;
	int i;

	if (!flow_action_has_entries(flow_action))
		return -EINVAL;

	flow_action_for_each(i, act, flow_action) {
		WARN_ON(used >= MANGLE_ARR_SZ);

		switch (act->id) {
		case FLOW_ACTION_REDIRECT:
			tuple->in_pf = nic->pcifunc;
			out_nic = netdev_priv(act->dev);
			tuple->xmit_pf = out_nic->pcifunc;
			op |= BIT_ULL(FLOW_ACTION_REDIRECT);
			break;

		case FLOW_ACTION_MANGLE:
			tuple->mangle[used].type = act->mangle.htype;
			tuple->mangle[used].val = act->mangle.val;
			tuple->mangle[used].mask = act->mangle.mask;
			tuple->mangle[used].offset = act->mangle.offset;
			tuple->mangle_map[act->mangle.htype] |= BIT(used);
			used++;
			break;

		default:
			break;
		}
	}

	tuple->mangle_cnt = used;

	if (!op) {
		pr_debug("%s:%d Op is not valid\n", __func__, __LINE__);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int sw_fl_get_route(struct fib_result *res, __be32 addr)
{
	struct flowi4 fl4;

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = addr;
	return fib_lookup(&init_net, &fl4, res, 0);
}

static int sw_fl_get_pcifunc(__be32 dst, u16 *pcifunc, struct fl_tuple *ftuple, bool is_in_dev)
{
	struct fib_nh_common *fib_nhc;
	struct net_device *dev, *br;
	struct otx2_nic *nic;
	struct fib_result res;
	struct list_head *lh;
	int err;

	rcu_read_lock();

	err = sw_fl_get_route(&res, dst);
	if (err) {
		pr_err("%s:%d Failed to find route to dst %pI4\n",
		       __func__, __LINE__, &dst);
		goto done;
	}

	if (res.fi->fib_type != RTN_UNICAST) {
		pr_err("%s:%d Not unicast  route to dst %pi4\n",
		       __func__, __LINE__, &dst);
		err = -EFAULT;
		goto done;
	}

	fib_nhc = fib_info_nhc(res.fi, 0);
	if (!fib_nhc) {
		err = -EINVAL;
		pr_err("%s:%d Could not get fib_nhc for %pI4\n",
		       __func__, __LINE__, &dst);
		goto done;
	}

	if (unlikely(netif_is_bridge_master(fib_nhc->nhc_dev))) {
		br = fib_nhc->nhc_dev;

		if (is_in_dev)
			ftuple->is_indev_br = 1;
		else
			ftuple->is_xdev_br = 1;

		lh = &br->adj_list.lower;
		if (list_empty(lh)) {
			pr_err("%s:%d Unable to find any slave device\n",
			       __func__, __LINE__);
			err = -EINVAL;
			goto done;
		}
		dev = netdev_next_lower_dev_rcu(br, &lh);

	} else {
		dev = fib_nhc->nhc_dev;
	}

	if (!sw_nb_is_valid_dev(dev)) {
		pr_err("%s:%d flow acceleration support is only for cavium devices\n",
		       __func__, __LINE__);
		err = -EOPNOTSUPP;
		goto done;
	}

	nic = netdev_priv(dev);
	*pcifunc = nic->pcifunc;

done:
	rcu_read_unlock();
	return err;
}

static void sw_fl_dump_tuple(struct fl_tuple *tuple)
{
	pr_debug("smac=%pM dmac=%pM eth_type=%#x\n",
		 tuple->smac, tuple->dmac, ntohs(tuple->eth_type));

	pr_debug("sip=%pI4 dip=%pI4 proto=%u\n",
		 &tuple->ip4src, &tuple->ip4dst, tuple->proto);

	pr_debug("sport=%u dport=%u\n",
		 tuple->sport, tuple->dport);
}

static int sw_fl_parse_flow(struct otx2_nic *nic, struct flow_cls_offload *f,
			    struct fl_tuple *tuple, u64 *features)
{
	struct flow_dissector *dissector;
	struct flow_rule *rule;
	u8 ip_proto = 0;

	*features = 0;

	rule = flow_cls_offload_flow_rule(f);
	dissector = rule->match.dissector;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);

		/* All EtherTypes can be matched, no hw limitation */

		if (match.mask->n_proto) {
			tuple->eth_type = match.key->n_proto;
			tuple->m_eth_type = match.key->n_proto;
			*features |= BIT_ULL(NPC_ETYPE);
		}

		if (match.mask->ip_proto &&
		    (match.key->ip_proto != IPPROTO_TCP &&
		     match.key->ip_proto != IPPROTO_UDP)) {
			netdev_dbg(nic->netdev,
				   "ip_proto=0x%x not supported\n",
				   match.key->ip_proto);
		}

		if (match.mask->ip_proto)
			ip_proto = match.key->ip_proto;

		if (ip_proto == IPPROTO_UDP) {
			*features |= BIT_ULL(NPC_IPPROTO_UDP);
		} else if (ip_proto == IPPROTO_TCP) {
			*features |= BIT_ULL(NPC_IPPROTO_TCP);
		} else {
			netdev_dbg(nic->netdev,
				   "ip_proto=0x%x not supported\n",
				   match.key->ip_proto);
		}

		tuple->proto = ip_proto;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);

		if (!is_zero_ether_addr(match.key->dst)) {
			ether_addr_copy(tuple->dmac,
					match.key->dst);

			ether_addr_copy(tuple->m_dmac,
					match.mask->dst);

			*features |= BIT_ULL(NPC_DMAC);
		}

		if (!is_zero_ether_addr(match.key->src)) {
			ether_addr_copy(tuple->smac,
					match.key->src);
			ether_addr_copy(tuple->m_smac,
					match.mask->src);
			*features |= BIT_ULL(NPC_SMAC);
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);

		if (match.mask->dst) {
			tuple->ip4dst = match.key->dst;
			tuple->m_ip4dst = match.mask->dst;
			*features |= BIT_ULL(NPC_DIP_IPV4);
		}

		if (match.mask->src) {
			tuple->ip4src = match.key->src;
			tuple->m_ip4src = match.mask->src;
			*features |= BIT_ULL(NPC_SIP_IPV4);
		}
	}

	if (!(*features & BIT_ULL(NPC_DMAC))) {
		if (!tuple->ip4src || !tuple->ip4dst) {
			pr_err("%s:%d Invalid src=%pI4 and dst=%pI4 addresses\n",
			       __func__, __LINE__, &tuple->ip4src, &tuple->ip4dst);
			return -EINVAL;
		}

		if ((tuple->ip4src & tuple->m_ip4src) == (tuple->ip4dst & tuple->m_ip4dst)) {
			pr_err("%s:%d Masked values are same; Invalid src=%pI4 and dst=%pI4 addresses\n",
			       __func__, __LINE__, &tuple->ip4src, &tuple->ip4dst);
			return -EINVAL;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);

		if (ip_proto == IPPROTO_UDP) {
			if (match.mask->dst)
				*features |= BIT_ULL(NPC_DPORT_UDP);

			if (match.mask->src)
				*features |= BIT_ULL(NPC_SPORT_UDP);
		} else if (ip_proto == IPPROTO_TCP) {
			if (match.mask->dst)
				*features |= BIT_ULL(NPC_DPORT_TCP);

			if (match.mask->src)
				*features |= BIT_ULL(NPC_SPORT_TCP);
		}

		if (match.mask->src) {
			tuple->sport = match.key->src;
			tuple->m_sport = match.mask->src;
		}

		if (match.mask->dst) {
			tuple->dport = match.key->dst;
			tuple->m_dport = match.mask->dst;
		}
	}

	if (!(*features & (BIT_ULL(NPC_DMAC) |
			   BIT_ULL(NPC_SMAC) |
			   BIT_ULL(NPC_DIP_IPV4) |
			   BIT_ULL(NPC_SIP_IPV4) |
			   BIT_ULL(NPC_DPORT_UDP) |
			   BIT_ULL(NPC_SPORT_UDP) |
			   BIT_ULL(NPC_DPORT_TCP) |
			   BIT_ULL(NPC_SPORT_TCP)))) {
		return -EINVAL;
	}

	tuple->features = *features;

	return 0;
}

static int sw_fl_add(struct otx2_nic *nic, struct flow_cls_offload *f)
{
	struct fl_tuple tuple = { 0 };
	struct flow_rule *rule;
	u64 features = 0;
	int rc;

	rule = flow_cls_offload_flow_rule(f);

	rc = sw_fl_parse_actions(nic, &rule->action, f, &tuple);
	if (rc) {
		pr_debug("%s:%d Error in parsing action\n", __func__, __LINE__);
		return rc;
	}

	rc  = sw_fl_parse_flow(nic, f, &tuple, &features);
	if (rc) {
		pr_debug("%s:%d Error in parsing flow\n", __func__, __LINE__);
		return -EFAULT;
	}

	if (!netif_is_ovs_port(nic->netdev)) {
		rc = sw_fl_get_pcifunc(tuple.ip4src, &tuple.in_pf, &tuple, true);
		if (rc) {
			pr_debug("%s:%d Error in parsing src pcifunc\n", __func__, __LINE__);
			return rc;
		}

		rc = sw_fl_get_pcifunc(tuple.ip4dst, &tuple.xmit_pf, &tuple, false);
		if (rc) {
			pr_debug("%s:%d Error in parsing dst pcifunc\n", __func__, __LINE__);
			return rc;
		}
	}

	sw_fl_dump_tuple(&tuple);
	sw_fl_add_to_list(nic, &tuple, f->cookie, true);
	return 0;
}

static int sw_fl_del(struct otx2_nic *nic, struct flow_cls_offload *f)
{
	sw_fl_add_to_list(nic, NULL, f->cookie, false);
	return 0;
}

static int sw_fl_stats(struct otx2_nic *nic, struct flow_cls_offload *f)
{
	struct fl_get_stats_req *req;
	struct fl_get_stats_rsp *rsp;
	u64 pkts_diff;
	int rc = 0;

	mutex_lock(&nic->mbox.lock);

	req = otx2_mbox_alloc_msg_fl_get_stats(&nic->mbox);
	if (!req) {
		pr_err("%s:%d Error happened while mcam alloc req\n", __func__, __LINE__);
		rc = -ENOMEM;
		goto fail;
	}
	req->cookie = f->cookie;

	if (otx2_sync_mbox_msg(&nic->mbox))
		goto fail;

	rsp = (struct fl_get_stats_rsp *)otx2_mbox_get_rsp
		(&nic->mbox.mbox, 0, &req->hdr);
	pkts_diff = rsp->pkts_diff;
	mutex_unlock(&nic->mbox.lock);

	if (pkts_diff) {
		flow_stats_update(&f->stats, 0x0, pkts_diff,
				  0x0, jiffies,
				  FLOW_ACTION_HW_STATS_IMMEDIATE);
	}
	return 0;
fail:
	mutex_unlock(&nic->mbox.lock);
	return rc;
}

static bool init_done;

int sw_fl_setup_ft_block_ingress_cb(enum tc_setup_type type,
				    void *type_data, void *cb_priv)
{
	struct flow_cls_offload *cls = type_data;
	struct otx2_nic *nic = cb_priv;

	if (!init_done)
		return 0;

	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		return sw_fl_add(nic, cls);
	case FLOW_CLS_DESTROY:
		return sw_fl_del(nic, cls);
	case FLOW_CLS_STATS:
		return sw_fl_stats(nic, cls);
	default:
		break;
	}

	return -EOPNOTSUPP;
}

int sw_fl_init(void)
{
	INIT_WORK(&sw_fl_work, sw_fl_wq_handler);
	sw_fl_wq = alloc_workqueue("sw_fl_wq", 0, 0);
	if (!sw_fl_wq)
		return -ENOMEM;

	init_done = true;
	return 0;
}

void sw_fl_deinit(void)
{
	flush_workqueue(sw_fl_wq);
	destroy_workqueue(sw_fl_wq);
}
#endif
