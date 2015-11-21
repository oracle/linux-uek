/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
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
 *
 */
#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <net/arp.h>
#include <linux/delay.h>
#include <rdma/ib_cache.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/inet_common.h>
#include <net/ipoib/if_ipoib.h>
#include <linux/rtnetlink.h>

#include "rds.h"
#include "ib.h"
#include "tcp.h"
#include <linux/time.h>

unsigned int rds_ib_fmr_1m_pool_size = RDS_FMR_1M_POOL_SIZE;
unsigned int rds_ib_fmr_8k_pool_size = RDS_FMR_8K_POOL_SIZE;
unsigned int rds_ib_retry_count = RDS_IB_DEFAULT_RETRY_COUNT;
#if RDMA_RDS_APM_SUPPORTED
unsigned int rds_ib_apm_enabled = 0;
unsigned int rds_ib_apm_fallback = 1;
#endif
unsigned int rds_ib_active_bonding_enabled = 0;
unsigned int rds_ib_active_bonding_fallback = 1;
unsigned int rds_ib_active_bonding_reconnect_delay = 1;
unsigned int rds_ib_active_bonding_trigger_delay_max_msecs; /* = 0; */
unsigned int rds_ib_active_bonding_trigger_delay_min_msecs; /* = 0; */
#if RDMA_RDS_APM_SUPPORTED
unsigned int rds_ib_apm_timeout = RDS_IB_DEFAULT_TIMEOUT;
#endif
unsigned int rds_ib_rnr_retry_count = RDS_IB_DEFAULT_RNR_RETRY_COUNT;
#if IB_RDS_CQ_VECTOR_SUPPORTED
unsigned int rds_ib_cq_balance_enabled = 1;
#endif
static char *rds_ib_active_bonding_failover_groups = NULL;
unsigned int rds_ib_active_bonding_arps = RDS_IB_DEFAULT_NUM_ARPS;
static char *rds_ib_active_bonding_excl_ips = "169.254/16,172.10/16";

module_param(rds_ib_fmr_1m_pool_size, int, 0444);
MODULE_PARM_DESC(rds_ib_fmr_1m_pool_size, " Max number of 1m fmr per HCA");
module_param(rds_ib_fmr_8k_pool_size, int, 0444);
MODULE_PARM_DESC(rds_ib_fmr_8k_pool_size, " Max number of 8k fmr per HCA");
module_param(rds_ib_retry_count, int, 0444);
MODULE_PARM_DESC(rds_ib_retry_count, " Number of hw retries before reporting an error");
#if RDMA_RDS_APM_SUPPORTED
module_param(rds_ib_apm_enabled, int, 0444);
MODULE_PARM_DESC(rds_ib_apm_enabled, " APM Enabled");
#endif
module_param(rds_ib_active_bonding_enabled, int, 0444);
MODULE_PARM_DESC(rds_ib_active_bonding_enabled, " Active Bonding enabled");
#if RDMA_RDS_APM_SUPPORTED
module_param(rds_ib_apm_timeout, int, 0444);
MODULE_PARM_DESC(rds_ib_apm_timeout, " APM timeout");
#endif
module_param(rds_ib_rnr_retry_count, int, 0444);
MODULE_PARM_DESC(rds_ib_rnr_retry_count, " QP rnr retry count");
#if RDMA_RDS_APM_SUPPORTED
module_param(rds_ib_apm_fallback, int, 0444);
MODULE_PARM_DESC(rds_ib_apm_fallback, " APM failback enabled");
#endif
module_param(rds_ib_active_bonding_fallback, int, 0444);
MODULE_PARM_DESC(rds_ib_active_bonding_fallback, " Active Bonding failback Enabled");
module_param(rds_ib_active_bonding_failover_groups, charp, 0444);
MODULE_PARM_DESC(rds_ib_active_bonding_failover_groups,
	"<ifname>[,<ifname>]*[;<ifname>[,<ifname>]*]*");
module_param(rds_ib_active_bonding_reconnect_delay, int, 0444);
MODULE_PARM_DESC(rds_ib_active_bonding_reconnect_delay, " Active Bonding reconnect delay");
module_param(rds_ib_active_bonding_trigger_delay_max_msecs, int, 0444);
MODULE_PARM_DESC(rds_ib_active_bonding_trigger_delay_max_msecs,
		" Active Bonding Max delay before active bonding is triggered(msecs)");
module_param(rds_ib_active_bonding_trigger_delay_min_msecs, int, 0444);
MODULE_PARM_DESC(rds_ib_active_bonding_trigger_delay_min_msecs,
		 " Active Bonding Min delay before active "
		 "bonding is triggered(msecs)");
#if IB_RDS_CQ_VECTOR_SUPPORTED
module_param(rds_ib_cq_balance_enabled, int, 0444);
MODULE_PARM_DESC(rds_ib_cq_balance_enabled, " CQ load balance Enabled");
#endif
module_param(rds_ib_active_bonding_arps, int, 0444);
MODULE_PARM_DESC(rds_ib_active_bonding_arps, " Num ARPs to be sent when IP moved");
module_param(rds_ib_active_bonding_excl_ips, charp, 0444);
MODULE_PARM_DESC(rds_ib_active_bonding_excl_ips,
	"[<IP>/<prefix>][,<IP>/<prefix>]*");

/*
 * we have a clumsy combination of RCU and a rwsem protecting this list
 * because it is used both in the get_mr fast path and while blocking in
 * the FMR flushing path.
 */
DECLARE_RWSEM(rds_ib_devices_lock);
struct list_head rds_ib_devices;

/* NOTE: if also grabbing ibdev lock, grab this first */
DEFINE_SPINLOCK(ib_nodev_conns_lock);
LIST_HEAD(ib_nodev_conns);

struct workqueue_struct *rds_aux_wq;

struct socket	*rds_ib_inet_socket;

static struct rds_ib_port *ip_config;
static u8	ip_port_cnt = 0;
static u8	ip_port_max = RDS_IB_MAX_PORTS;

static struct rds_ib_excl_ips excl_ips_tbl[RDS_IB_MAX_EXCL_IPS];
static u8       excl_ips_cnt = 0;

static int ip_config_init_phase_flag; /* = 0 */
static int initial_failovers_iterations; /* = 0 */

static void rds_ib_initial_failovers(struct work_struct *workarg);
DECLARE_DELAYED_WORK(riif_dlywork, rds_ib_initial_failovers);
static int timeout_until_initial_failovers;

/*
 * rds_detected_linklayer_up
 *
 * Test for link layer UP derived from how the
 * LOWER_UP flag is set for 'ip' CLI command
 * (which talks to kernel via netlink sockets).
 *
 * Note: IPv6 addrconf uses  an alternative test
 * "!qdisc_tx_is_noop(dev)" to signal an UP
 * link layer. Any pros/cons of the two
 * different tests for an UP link layer?
 */
static inline int
rds_detected_link_layer_up(const struct net_device *dev)
{
	return (netif_running(dev)) && (netif_carrier_ok(dev));
}

static inline int
rds_ibp_all_layers_up(struct rds_ib_port *rds_ibp)
{
	if ((rds_ibp->port_layerflags & RDSIBP_STATUS_ALLUP) ==
	    RDSIBP_STATUS_ALLUP)
		return 1;
	return 0;
}

void rds_ib_nodev_connect(void)
{
	struct rds_ib_connection *ic;

	rds_rtd(RDS_RTD_CM_EXT, "check & build all connections\n");

	spin_lock(&ib_nodev_conns_lock);
	list_for_each_entry(ic, &ib_nodev_conns, ib_node)
		rds_conn_connect_if_down(ic->conn);
	spin_unlock(&ib_nodev_conns_lock);
}

void rds_ib_dev_shutdown(struct rds_ib_device *rds_ibdev)
{
	struct rds_ib_connection *ic;
	unsigned long flags;

	rds_rtd(RDS_RTD_CM_EXT,
		"calling rds_conn_drop to drop all connections.\n");

	spin_lock_irqsave(&rds_ibdev->spinlock, flags);
	list_for_each_entry(ic, &rds_ibdev->conn_list, ib_node) {
		ic->conn->c_drop_source = 80;
		rds_conn_drop(ic->conn);
	}
	spin_unlock_irqrestore(&rds_ibdev->spinlock, flags);
}

/*
 * rds_ib_destroy_mr_pool() blocks on a few things and mrs drop references
 * from interrupt context so we push freing off into a work struct in krdsd.
 */

/* free up rds_ibdev->dev related resource. We have to wait until freeing
 * work is done to avoid the racing with freeing in mlx4_remove_one ->
 * mlx4_cleanup_mr_table path
 */
static void rds_ib_dev_free_dev(struct rds_ib_device *rds_ibdev)
{
	mutex_lock(&rds_ibdev->free_dev_lock);
	if (!atomic_dec_and_test(&rds_ibdev->free_dev))
		goto out;

	if (rds_ibdev->srq) {
		rds_ib_srq_exit(rds_ibdev);
		kfree(rds_ibdev->srq);
	}

	if (rds_ibdev->mr_8k_pool)
		rds_ib_destroy_mr_pool(rds_ibdev->mr_8k_pool);
	if (rds_ibdev->mr_1m_pool)
		rds_ib_destroy_mr_pool(rds_ibdev->mr_1m_pool);
	if (rds_ibdev->mr)
		ib_dereg_mr(rds_ibdev->mr);
	if (rds_ibdev->pd)
		ib_dealloc_pd(rds_ibdev->pd);
out:
	mutex_unlock(&rds_ibdev->free_dev_lock);
}

static void rds_ib_dev_free(struct work_struct *work)
{
	struct rds_ib_ipaddr *i_ipaddr, *i_next;
	struct rds_ib_device *rds_ibdev = container_of(work,
					struct rds_ib_device, free_work);

	rds_ib_dev_free_dev(rds_ibdev);

	list_for_each_entry_safe(i_ipaddr, i_next, &rds_ibdev->ipaddr_list, list) {
		list_del(&i_ipaddr->list);
		kfree(i_ipaddr);
	}

	if (rds_ibdev->vector_load)
		kfree(rds_ibdev->vector_load);

	kfree(rds_ibdev);
}

void rds_ib_dev_put(struct rds_ib_device *rds_ibdev)
{
	BUG_ON(atomic_read(&rds_ibdev->refcount) <= 0);
	if (atomic_dec_and_test(&rds_ibdev->refcount))
		queue_work(rds_wq, &rds_ibdev->free_work);
}

/*
 * New connections use this to find the device to associate with the
 * connection.  It's not in the fast path so we're not concerned about the
 * performance of the IB call.  (As of this writing, it uses an interrupt
 * blocking spinlock to serialize walking a per-device list of all registered
 * clients.)
 *
 * RCU is used to handle incoming connections racing with device teardown.
 * Rather than use a lock to serialize removal from the client_data and
 * getting a new reference, we use an RCU grace period.  The destruction
 * path removes the device from client_data and then waits for all RCU
 * readers to finish.
 *
 * A new connection can get NULL from this if its arriving on a
 * device that is in the process of being removed.
 */
struct rds_ib_device *rds_ib_get_client_data(struct ib_device *device)
{
	struct rds_ib_device *rds_ibdev;

	rcu_read_lock();
	rds_ibdev = ib_get_client_data(device, &rds_ib_client);
	if (rds_ibdev)
		atomic_inc(&rds_ibdev->refcount);
	rcu_read_unlock();
	return rds_ibdev;
}

/*
 * The IB stack is letting us know that a device is going away.  This can
 * happen if the underlying HCA driver is removed or if PCI hotplug is removing
 * the pci function, for example.
 *
 * This can be called at any time and can be racing with any other RDS path.
 */
void rds_ib_remove_one(struct ib_device *device, void *client_data)
{
	struct rds_ib_device *rds_ibdev;
	int i;

	rds_ibdev = ib_get_client_data(device, &rds_ib_client);
	if (!rds_ibdev) {
		rds_rtd(RDS_RTD_ACT_BND, "rds_ibdev is NULL, ib_device %p\n",
			device);
		return;
	}

	if (rds_ib_active_bonding_enabled) {
		for (i = 1; i <= ip_port_cnt; i++) {
			if (ip_config[i].rds_ibdev == rds_ibdev)
				ip_config[i].rds_ibdev = NULL;
		}
		ib_unregister_event_handler(&rds_ibdev->event_handler);
	}

	rds_rtd(RDS_RTD_ACT_BND,
		"calling rds_ib_dev_shutdown, ib_device %p, rds_ibdev %p\n",
		device, rds_ibdev);
	rds_ib_dev_shutdown(rds_ibdev);

	/* stop connection attempts from getting a reference to this device. */
	ib_set_client_data(device, &rds_ib_client, NULL);

	down_write(&rds_ib_devices_lock);
	list_del_rcu(&rds_ibdev->list);
	up_write(&rds_ib_devices_lock);

	/*
	 * This synchronize rcu is waiting for readers of both the ib
	 * client data and the devices list to finish before we drop
	 * both of those references.
	 */
	synchronize_rcu();
	rds_ib_dev_put(rds_ibdev);
	/* free up lower layer resource since it may be the last change */
	rds_ib_dev_free_dev(rds_ibdev);
	rds_ib_dev_put(rds_ibdev);
}

struct ib_client rds_ib_client = {
	.name   = "rds_ib",
	.add    = rds_ib_add_one,
	.remove = rds_ib_remove_one
};

static int rds_ib_conn_info_visitor(struct rds_connection *conn,
				    void *buffer)
{
	struct rds_info_rdma_connection *iinfo = buffer;
	struct rds_ib_connection *ic = conn->c_transport_data;

	/* We will only ever look at IB transports */
	if (conn->c_trans != &rds_ib_transport)
		return 0;

	iinfo->src_addr = conn->c_laddr;
	iinfo->dst_addr = conn->c_faddr;

	memset(&iinfo->src_gid, 0, sizeof(iinfo->src_gid));
	memset(&iinfo->dst_gid, 0, sizeof(iinfo->dst_gid));

	if (ic) {
		iinfo->tos = conn->c_tos;
		iinfo->sl = ic->i_sl;
		iinfo->frag = ic->i_frag_sz;
	}

	if (rds_conn_state(conn) == RDS_CONN_UP) {
		struct rds_ib_device *rds_ibdev;
		struct rdma_dev_addr *dev_addr;

		ic = conn->c_transport_data;
#if RDMA_RDS_APM_SUPPORTED
		if (rds_ib_apm_enabled) {
			memcpy((union ib_gid *) &iinfo->src_gid,
				&ic->i_cur_path.p_sgid, sizeof(union ib_gid));
			memcpy((union ib_gid *) &iinfo->dst_gid,
				&ic->i_cur_path.p_dgid, sizeof(union ib_gid));
		} else
#endif
		{
			dev_addr = &ic->i_cm_id->route.addr.dev_addr;
			rdma_addr_get_sgid(dev_addr,
				(union ib_gid *) &iinfo->src_gid);
			rdma_addr_get_dgid(dev_addr,
				(union ib_gid *) &iinfo->dst_gid);
		}

		rds_ibdev = ic->rds_ibdev;
		iinfo->max_send_wr = ic->i_send_ring.w_nr;
		iinfo->max_recv_wr = ic->i_recv_ring.w_nr;
		iinfo->max_send_sge = rds_ibdev->max_sge;
		rds_ib_get_mr_info(rds_ibdev, iinfo);
		iinfo->cache_allocs = atomic_read(&ic->i_cache_allocs);
	}
	return 1;
}

static void rds_ib_ic_info(struct socket *sock, unsigned int len,
			   struct rds_info_iterator *iter,
			   struct rds_info_lengths *lens)
{
	rds_for_each_conn_info(sock, len, iter, lens,
				rds_ib_conn_info_visitor,
				sizeof(struct rds_info_rdma_connection));
}


/*
 * Early RDS/IB was built to only bind to an address if there is an IPoIB
 * device with that address set.
 *
 * If it were me, I'd advocate for something more flexible.  Sending and
 * receiving should be device-agnostic.  Transports would try and maintain
 * connections between peers who have messages queued.  Userspace would be
 * allowed to influence which paths have priority.  We could call userspace
 * asserting this policy "routing".
 */
static int rds_ib_laddr_check(struct net *net, __be32 addr)
{
	int ret;
	struct rdma_cm_id *cm_id;
	struct sockaddr_in sin;

	/* Create a CMA ID and try to bind it. This catches both
	 * IB and iWARP capable NICs.
	 */
	cm_id = rdma_create_id(net, NULL, NULL, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(cm_id))
		return -EADDRNOTAVAIL;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;

	/* rdma_bind_addr will only succeed for IB & iWARP devices */
	ret = rdma_bind_addr(cm_id, (struct sockaddr *)&sin);
	/* due to this, we will claim to support iWARP devices unless we
	   check node_type. */
	if (ret || !cm_id->device || cm_id->device->node_type != RDMA_NODE_IB_CA)
		ret = -EADDRNOTAVAIL;

	rdsdebug("addr %pI4 ret %d node type %d\n",
		&addr, ret,
		cm_id->device ? cm_id->device->node_type : -1);

	rdma_destroy_id(cm_id);

	return ret;
}

/*
 * Get a failover port for port argument ('port')
 * based on failover group and pkey match.
 */
static u8 rds_ib_get_failover_port(u8 port)
{
	u8	i;

	for (i = 1; i <= ip_port_cnt; i++) {
		if ((i != port) &&
		    (ip_config[i].failover_group ==
		     ip_config[port].failover_group) &&
		    (ip_config[i].pkey == ip_config[port].pkey) &&
		    (ip_config[i].port_state == RDS_IB_PORT_UP)) {
			return i;
		}
	}

	/*
	 * Note: Failover across HCAs/Failover groups
	 * is experimental code that causes instabilities
	 * in some applications and disabled by
	 * default.
	 */
#define RDS_EXPERIMENTAL_FAILOVER_ACROSS_HCAS_FAILOVER_GROUPS 0
#if RDS_EXPERIMENTAL_FAILOVER_ACROSS_HCAS_FAILOVER_GROUPS
	for (i = 1; i <= ip_port_cnt; i++) {
		if ((i != port) &&
		    (ip_config[i].pkey == ip_config[port].pkey) &&
		    (ip_config[i].port_state == RDS_IB_PORT_UP)) {
			return i;
		}
	}
#endif
	return 0;
}

static void rds_ib_send_gratuitous_arp(struct net_device	*out_dev,
					unsigned char		*dev_addr,
					__be32			ip_addr)
{
	int i;

	/* Send multiple ARPs to improve reliability */
	for (i = 0; i < rds_ib_active_bonding_arps; i++) {
		arp_send(ARPOP_REPLY, ETH_P_ARP,
			ip_addr, out_dev,
			ip_addr, NULL,
			dev_addr, NULL);
	}
}

static int rds_ib_set_ip(struct net_device	*out_dev,
			unsigned char		*dev_addr,
			char			*if_name,
			__be32			addr,
			__be32			bcast,
			__be32			mask)
{
	struct ifreq		*ir;
	struct sockaddr_in	*sin;
	struct page		*page;
	int			ret = 0;

	page = alloc_page(GFP_HIGHUSER);
	if (!page) {
		printk(KERN_ERR "RDS/IB: alloc_page failed .. NO MEM\n");
		return 1;
	}

	ir = (struct ifreq *)kmap(page);
	memset(ir, 0, sizeof(struct ifreq));
	sin = (struct sockaddr_in *)&ir->ifr_addr;
	sin->sin_family = AF_INET;

	strcpy(ir->ifr_ifrn.ifrn_name, if_name);

	sin->sin_addr.s_addr = addr;
	ret = inet_ioctl(rds_ib_inet_socket, SIOCSIFADDR, (unsigned long) ir);
	if (ret && addr) {
		printk(KERN_ERR
			"RDS/IB: inet_ioctl(SIOCSIFADDR) on %s failed (%d)\n",
			if_name, ret);
		goto out;
	}

	if (!addr)
		goto out;

	sin->sin_addr.s_addr = bcast;
	ret = inet_ioctl(rds_ib_inet_socket, SIOCSIFBRDADDR,
			(unsigned long) ir);
	if (ret) {
		printk(KERN_ERR
			"RDS/IB: inet_ioctl(SIOCSIFBRDADDR) on %s failed (%d)\n",
			if_name, ret);
		goto out;
	}

	sin->sin_addr.s_addr = mask;
	ret = inet_ioctl(rds_ib_inet_socket, SIOCSIFNETMASK,
			(unsigned long) ir);
	if (ret) {
		printk(KERN_ERR
			"RDS/IB: inet_ioctl(SIOCSIFNETMASK) on %s failed (%d)\n",
			if_name, ret);
		goto out;
	}

	rds_ib_send_gratuitous_arp(out_dev, dev_addr, addr);

out:
	kunmap(page);
	__free_page(page);

	return ret;
}

static int rds_ib_addr_exist(struct net_device *ndev,
				__be32		addr,
				char		*if_name)
{
	struct in_device        *in_dev;
	struct in_ifaddr        *ifa;
	struct in_ifaddr        **ifap;
	int			found = 0;

	rtnl_lock();
	in_dev = in_dev_get(ndev);
	if (in_dev) {
		for (ifap = &in_dev->ifa_list; (ifa = *ifap);
			ifap = &ifa->ifa_next) {
			if (ifa->ifa_address == addr) {
				found = 1;
				if (if_name)
					strcpy(if_name, ifa->ifa_label);
				break;
			}
		}
		in_dev_put(in_dev);
	}
	rtnl_unlock();

	return found;
}

static void rds_ib_update_arp_cache(struct net_device      *out_dev,
					unsigned char      *dev_addr,
					__be32             ip_addr)
{
	int ret = 0;
	struct neighbour *neigh;

	neigh = __neigh_lookup_errno(&arp_tbl, &ip_addr, out_dev);
	if (!IS_ERR(neigh)) {
		ret = neigh_update(neigh, dev_addr, NUD_STALE,
				   NEIGH_UPDATE_F_OVERRIDE |
				   NEIGH_UPDATE_F_ADMIN,
				   0);
		if (ret)
			printk(KERN_ERR "RDS/IB: neigh_update failed (%d) "
				"for out_dev %s IP %pI4\n",
				ret, out_dev->name, &ip_addr);
		neigh_release(neigh);
	}
}

static void rds_ib_conn_drop(struct work_struct *_work)
{
	struct rds_ib_conn_drop_work    *work =
		container_of(_work, struct rds_ib_conn_drop_work, work.work);
	struct rds_connection   *conn = (struct rds_connection *)work->conn;

	rds_rtd(RDS_RTD_CM_EXT,
		"conn: %p, calling rds_conn_drop\n", conn);

	conn->c_drop_source = 81;
	rds_conn_drop(conn);

	kfree(work);
}

static void rds_ib_notify_addr_change(struct work_struct *_work)
{
	struct rds_ib_addr_change_work  *work =
		container_of(_work, struct rds_ib_addr_change_work, work.work);
	struct sockaddr_in      sin;
	int ret;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = work->addr;
	sin.sin_port = 0;

	ret = rdma_notify_addr_change((struct sockaddr *)&sin);

	kfree(work);
}

static int rds_ib_move_ip(char			*from_dev,
			char			*to_dev,
			u8			from_port,
			u8			to_port,
			u8			arp_port,
			__be32			addr,
			__be32			bcast,
			__be32			mask,
			int			event_type,
			int                     alias,
			int			failover)
{
	struct ifreq		*ir;
	struct sockaddr_in	*sin;
	struct page		*page;
	char			from_dev2[2*IFNAMSIZ + 1];
	char			to_dev2[2*IFNAMSIZ + 1];
	char                    *tmp_str;
	int			ret = 0;
	u8			active_port, i, j, port = 0;
	struct in_device	*in_dev;
	struct rds_ib_connection *ic, *ic2;
	struct rds_ib_device *rds_ibdev;
	struct rds_ib_conn_drop_work *work;
	struct rds_ib_addr_change_work *work_addrchange;

	page = alloc_page(GFP_HIGHUSER);
	if (!page) {
		printk(KERN_ERR "RDS/IP: alloc_page failed .. NO MEM\n");
		return 1;
	}

	ir = (struct ifreq *)kmap(page);
	memset(ir, 0, sizeof(struct ifreq));
	sin = (struct sockaddr_in *)&ir->ifr_addr;
	sin->sin_family = AF_INET;

	/* Set the primary IP if it hasn't been set */
	if (ip_config[to_port].ip_addr) {
		strcpy(ir->ifr_ifrn.ifrn_name, ip_config[to_port].dev->name);
		ret = inet_ioctl(rds_ib_inet_socket, SIOCGIFADDR,
					(unsigned long) ir);
		if (ret == -EADDRNOTAVAIL) {
			/* Set the IP on new port */
			ret = rds_ib_set_ip(ip_config[arp_port].dev,
				ip_config[to_port].dev->dev_addr,
				ip_config[to_port].dev->name,
				ip_config[to_port].ip_addr,
				ip_config[to_port].ip_bcast,
				ip_config[to_port].ip_mask);

			if (ret) {
				printk(KERN_ERR
					"RDS/IP: failed to set IP %pI4 "
					"on %s failed (%d)\n",
					&ip_config[to_port].ip_addr,
					ip_config[to_port].dev->name, ret);
				goto out;
			}
		} else if (ret) {
			printk(KERN_ERR
				"RDS/IP: inet_ioctl(SIOCGIFADDR) "
				"failed (%d)\n", ret);
			goto out;
		}
	}

	if (failover) {
		in_dev = in_dev_get(ip_config[to_port].dev);
		if (in_dev && !in_dev->ifa_list) {
			strcpy(to_dev2, to_dev);
		} else {
			strcpy(to_dev2, to_dev);
			strcat(to_dev2, ":");
			strcat(to_dev2, ip_config[from_port].port_label);
			if (alias) {
				tmp_str = strchr(from_dev, ':');
				strcat(to_dev2, tmp_str);
			}
			to_dev2[IFNAMSIZ-1] = 0;
		}
		if (in_dev)
			in_dev_put(in_dev);

		/* Bailout if IP already exists on target port */
		if (rds_ib_addr_exist(ip_config[to_port].dev, addr, NULL))
			goto out;

		active_port = ip_config[from_port].ip_active_port;
		if (alias || active_port == from_port) {
			strcpy(from_dev2, from_dev);
		} else if (ip_config[active_port].port_state ==
				RDS_IB_PORT_UP) {
			if (!rds_ib_addr_exist(ip_config[active_port].dev,
						addr, from_dev2)) {
				strcpy(from_dev2,
					ip_config[active_port].dev->name);
				strcat(from_dev2, ":");
				strcat(from_dev2,
					ip_config[from_port].port_label);
				from_dev2[IFNAMSIZ-1] = 0;
			}
		} else {
			strcpy(from_dev2, from_dev);
		}
	} else {
		if (!rds_ib_addr_exist(ip_config[from_port].dev,
						addr, from_dev2)) {
			strcpy(from_dev2, from_dev);
			strcat(from_dev2, ":");
			strcat(from_dev2, ip_config[to_port].port_label);
			from_dev2[IFNAMSIZ-1] = 0;
		}
		strcpy(to_dev2, to_dev);
	}

	/* Clear the IP on old port */
	ret = rds_ib_set_ip(NULL, NULL, from_dev2, 0, 0, 0);

	/* Set the IP on new port */
	ret = rds_ib_set_ip(ip_config[arp_port].dev,
				ip_config[to_port].dev->dev_addr,
				to_dev2, addr, bcast, mask);

	if (ret) {
		printk(KERN_NOTICE
		       "RDS/IP: failed to move IP %pI4 "
		       "from %s to %s\n",
		       &addr, from_dev2, to_dev2);
	} else {
		if (strcmp(from_dev2, to_dev2) == 0) {
			/* from_dev2, to_dev2 are identical */
			printk(KERN_NOTICE
			       "RDS/IP: IP %pI4 resurrected on migrated "
			       "interface %s\n",
			       &addr, to_dev2);
		} else {
			/* from_dev2, to_dev2 are different! */
			printk(KERN_NOTICE
			       "RDS/IP: IP %pI4 migrated from %s to %s\n",
			       &addr, from_dev2, to_dev2);
		}

		rds_ibdev = ip_config[from_port].rds_ibdev;
		if (!rds_ibdev)
			goto out;

		spin_lock_bh(&rds_ibdev->spinlock);
		list_for_each_entry(ic, &rds_ibdev->conn_list, ib_node) {
			if (ic->conn->c_laddr == addr) {
#if RDMA_RDS_APM_SUPPORTED
				if (rds_ib_apm_enabled) {
					if (!memcmp(
						&ic->i_cur_path.p_sgid,
						&ip_config[to_port].gid,
						sizeof(union ib_gid))) {
						continue;
					}
				}
#endif
				/* if local connection, update the ARP cache */
				if (ic->conn->c_loopback) {
					for (i = 1; i <= ip_port_cnt; i++) {
						if (ip_config[i].ip_addr ==
							ic->conn->c_faddr) {
							port = i;
							break;
						}

						for (j = 0; j < ip_config[i].alias_cnt; j++) {
							if (ip_config[i].aliases[j].ip_addr == ic->conn->c_faddr) {
								port = i;
								break;
							}
						}
					}

					BUG_ON(!port);

					rds_ib_update_arp_cache(
						ip_config[from_port].dev,
						ip_config[port].dev->dev_addr,
						ic->conn->c_faddr);

					rds_ib_update_arp_cache(
						ip_config[to_port].dev,
						ip_config[port].dev->dev_addr,
						ic->conn->c_faddr);

					rds_ib_update_arp_cache(
						ip_config[from_port].dev,
						ip_config[to_port].dev->dev_addr,
						ic->conn->c_laddr);

					rds_ib_update_arp_cache(
						ip_config[to_port].dev,
						ip_config[to_port].dev->dev_addr,
						ic->conn->c_laddr);

					list_for_each_entry(ic2,
						&rds_ibdev->conn_list,
							ib_node) {
						if (ic2->conn->c_laddr ==
							ic->conn->c_faddr &&
							ic2->conn->c_faddr ==
							ic->conn->c_laddr) {
							rds_rtd(RDS_RTD_CM_EXT_P,
								"conn:%p, tos %d, calling rds_conn_drop\n",
								ic2->conn,
								ic2->conn->c_tos);
							ic2->conn->c_drop_source = 82;
							rds_conn_drop(ic2->conn);
						}
					}
				}

				/*
				 * For failover from HW PORT event, do
				 * delayed connection drop, else call
				 * inline
				 */
				if (event_type == RDS_IB_PORT_EVENT_IB &&
					failover) {
					work = kzalloc(sizeof *work, GFP_ATOMIC);
					if (!work) {
						printk(KERN_ERR
							"RDS/IP: failed to allocate connection drop work\n");
							spin_unlock_bh(&rds_ibdev->spinlock);
							goto out;
					}

					work->conn = ic->conn;
					INIT_DELAYED_WORK(&work->work, rds_ib_conn_drop);
					queue_delayed_work(rds_aux_wq, &work->work,
						msecs_to_jiffies(1000 * rds_ib_active_bonding_reconnect_delay));
				} else {
					rds_rtd(RDS_RTD_CM_EXT,
						"conn: %p, tos %d, calling rds_conn_drop\n",
						ic->conn, ic->conn->c_tos);
					ic->conn->c_drop_source = 83;
					rds_conn_drop(ic->conn);
				}
			}
		}
		spin_unlock_bh(&rds_ibdev->spinlock);

		work_addrchange = kzalloc(sizeof *work, GFP_ATOMIC);
		if (!work_addrchange) {
			printk(KERN_WARNING "RDS/IP: failed to allocate work\n");
			goto out;
		}
		work_addrchange->addr = addr;
		INIT_DELAYED_WORK(&work_addrchange->work, rds_ib_notify_addr_change);
		queue_delayed_work(rds_wq, &work_addrchange->work, 10);
	}

out:
	kunmap(page);
	__free_page(page);

	return ret;
}

static u8 rds_ib_init_port(struct rds_ib_device	*rds_ibdev,
			   struct net_device	*net_dev,
			   u8			port_num,
			   union ib_gid		gid,
			   uint16_t		pkey)
{
	const char *digits = "0123456789";

	if (ip_port_cnt >= ip_port_max) {
		printk(KERN_ERR
			"RDS/IB: Exceeded max ports (%d) for device %s\n",
				ip_port_max, rds_ibdev->dev->name);
		return 0;
	}

	ip_port_cnt++;
	ip_config[ip_port_cnt].port_num = port_num;
	ip_config[ip_port_cnt].port_label[0] = 'P';
	ip_config[ip_port_cnt].port_label[1] = digits[ip_port_cnt / 10];
	ip_config[ip_port_cnt].port_label[2] = digits[ip_port_cnt % 10];
	ip_config[ip_port_cnt].port_label[3] = 0;
	ip_config[ip_port_cnt].dev = net_dev;
	ip_config[ip_port_cnt].rds_ibdev = rds_ibdev;
	ip_config[ip_port_cnt].ip_active_port = 0;
	strcpy(ip_config[ip_port_cnt].if_name, net_dev->name);
	memcpy(&ip_config[ip_port_cnt].gid, &gid, sizeof(union ib_gid));
	ip_config[ip_port_cnt].pkey = pkey;
	ip_config[ip_port_cnt].port_state = RDS_IB_PORT_INIT;
	ip_config[ip_port_cnt].port_layerflags = 0x0; /* all clear to begin */

	/*
	 * We check for the link UP state and use it to set
	 * both LINK and HW status to UP.
	 * (Note: Reverse is not true: Link DOWN does NOT necessarily
	 *        imply HW port is down!)
	 *
	 * On a VM reboot or module load (after unload), there
	 * will be no separate HW UP/DOWN event, so its UP
	 * status is derived from the link layer status!
	 *
	 */
	if (rds_detected_link_layer_up(net_dev)) {
		ip_config[ip_port_cnt].port_layerflags =
			(RDSIBP_STATUS_LINKUP | RDSIBP_STATUS_HWPORTUP);
	}

	/*
	 * Note: Only HW and LINK status determined in this routine during
	 * module initialization path. Status of netdev layer will be
	 * determined by subsequent  NETDEV_UP (or lack of NETDEV_UP)
	 * events - which are generated  on loading of rds_rdma module!
	 */
	return ip_port_cnt;
}

static void rds_ib_set_port(struct rds_ib_device	*rds_ibdev,
				struct net_device	*net_dev,
				char			*if_name,
				u8			port,
				__be32			ip_addr,
				__be32			ip_bcast,
				__be32			ip_mask)
{
	unsigned int	idx, i;
	__be32          excl_addr = 0;

	for (i = 0; i < excl_ips_cnt; i++) {
		if (!((excl_ips_tbl[i].ip ^ ip_addr) &
			excl_ips_tbl[i].mask)) {
			excl_addr = 1;
			break;
		}
	}

	if (!strcmp(net_dev->name, if_name)) {
		if (excl_addr)
			ip_addr = ip_bcast = ip_mask = 0;

		strcpy(ip_config[port].if_name, if_name);
		ip_config[port].ip_addr = ip_addr;
		ip_config[port].ip_bcast = ip_bcast;
		ip_config[port].ip_mask = ip_mask;
		ip_config[port].ip_active_port = port;
	} else if (!excl_addr) {
		idx = ip_config[port].alias_cnt++;
		strcpy(ip_config[port].aliases[idx].if_name, if_name);
		ip_config[port].aliases[idx].ip_addr = ip_addr;
		ip_config[port].aliases[idx].ip_bcast = ip_bcast;
		ip_config[port].aliases[idx].ip_mask = ip_mask;
	}
}

static int rds_ib_testset_ip(u8 port)
{
	struct ifreq		*ir;
	struct sockaddr_in	*sin;
	struct page		*page;
	int			ret = 0;
	int                     ii;

	if (!ip_config[port].ip_addr) {
		printk(KERN_WARNING "RDS/IB: no port index %u IP available!\n",
		       port);
		return 0;
	}

	page = alloc_page(GFP_HIGHUSER);
	if (!page) {
		printk(KERN_ERR "RDS/IB: alloc_page failed .. NO MEM\n");
		return 1;
	}

	ir = (struct ifreq *)kmap(page);
	memset(ir, 0, sizeof(struct ifreq));
	sin = (struct sockaddr_in *)&ir->ifr_addr;
	sin->sin_family = AF_INET;


	/*
	 * If the primary IP is not set revive it
	 * and also the IP addrs on aliases
	 */

	strcpy(ir->ifr_ifrn.ifrn_name, ip_config[port].dev->name);
	ret = inet_ioctl(rds_ib_inet_socket, SIOCGIFADDR,
			 (unsigned long) ir);
	if (ret == -EADDRNOTAVAIL) {
		/* Set the IP on this port */
		ret = rds_ib_set_ip(ip_config[port].dev,
				    ip_config[port].dev->dev_addr,
				    ip_config[port].dev->name,
				    ip_config[port].ip_addr,
				    ip_config[port].ip_bcast,
				    ip_config[port].ip_mask);
		if (ret) {
			printk(KERN_ERR "RDS/IB: failed to resurrect "
			       "IP %pI4 on %s failed (%d)\n",
			       &ip_config[port].ip_addr,
			       ip_config[port].dev->name, ret);
			goto out;
		}
		printk(KERN_NOTICE
		       "RDS/IB: IP %pI4 resurrected on interface %s\n",
		       &ip_config[port].ip_addr,
		       ip_config[port].dev->name);
		for (ii = 0; ii < ip_config[port].alias_cnt; ii++) {
			ret = rds_ib_set_ip(ip_config[port].dev,
					ip_config[port].dev->dev_addr,
					ip_config[port].aliases[ii].if_name,
					ip_config[port].aliases[ii].ip_addr,
					ip_config[port].aliases[ii].ip_bcast,
					ip_config[port].aliases[ii].ip_mask);
			if (ret) {
				printk(KERN_ERR "RDS/IB: failed to resurrect "
				       "IP %pI4 "
				       "on alias %s failed (%d)\n",
				       &ip_config[port].aliases[ii].ip_addr,
				       ip_config[port].aliases[ii].if_name,
				       ret);
				goto out;
			}
			printk(KERN_NOTICE
			       "RDS/IB: IP %pI4 resurrected"
			       " on alias %s on interface %s\n",
			       &ip_config[port].ip_addr,
			       ip_config[port].aliases[ii].if_name,
			       ip_config[port].dev->name);
		}
	} else if (ret) {
		printk(KERN_ERR	"RDS/IB: inet_ioctl(SIOCGIFADDR) "
		       "failed (%d)\n", ret);
	} else {
		rdsdebug("Primary addr already set on port index %u, "
			 "devname %s\n",
			 port, ip_config[port].dev->name);
	}
out:
	kunmap(page);
	__free_page(page);

	return ret;
}


static void rds_ib_do_failover(u8 from_port, u8 to_port, u8 arp_port,
				int event_type)
{
	u8      j;
	int	ret;

	if (!from_port) {
		printk(KERN_ERR "RDS/IB: port failover request from invalid port!\n");
		return;
	}

	if (!ip_config[from_port].ip_addr)
		return;

	if (!to_port) {
		/* get a port to failover to */
		to_port = rds_ib_get_failover_port(from_port);

		if (!to_port) {
			/* we tried, but did not get a failover port! */
			rds_rtd(RDS_RTD_ERR,
				"RDS/IB: IP %pI4 failed to migrate from %s: no matching dest port avail!\n",
				&ip_config[from_port].ip_addr,
				ip_config[from_port].if_name);
			return;
		}
	} else {
		/*
		 * to_port != 0 => caller explicitly specified failover port
		 * validate pkey and flag error if we were passed incorrect
		 * pkey match port. And ignore the request !
		 */
		if (ip_config[from_port].pkey != ip_config[to_port].pkey) {
			printk(KERN_ERR "RDS/IB: port failover request to "
			       "ports with mismatched pkeys - ignoring request!");
			return;
		}
	}

	if (!arp_port)
		arp_port = to_port;

	BUG_ON(!to_port);

	if (!rds_ib_move_ip(
			ip_config[from_port].if_name,
			ip_config[to_port].if_name,
			from_port,
			to_port,
			arp_port,
			ip_config[from_port].ip_addr,
			ip_config[from_port].ip_bcast,
			ip_config[from_port].ip_mask,
			event_type,
			0,
			1)) {

		ip_config[from_port].ip_active_port = to_port;
		for (j = 0; j < ip_config[from_port].
			     alias_cnt; j++) {

			ret = rds_ib_move_ip(
					ip_config[from_port].aliases[j].if_name,
					ip_config[to_port].if_name,
					from_port,
					to_port,
					arp_port,
					ip_config[from_port].
					aliases[j].ip_addr,
					ip_config[from_port].
					aliases[j].ip_bcast,
					ip_config[from_port].
					aliases[j].ip_mask,
					event_type,
					1,
					1);
		}
	}
}

static void rds_ib_do_failback(u8 port, int event_type)
{
	u8      ip_active_port = ip_config[port].ip_active_port;
	u8      j;
	int     ret;

	if (!ip_config[port].ip_addr)
		return;

	if (port != ip_config[port].ip_active_port) {
		if (!rds_ib_move_ip(
			ip_config[ip_active_port].if_name,
			ip_config[port].if_name,
			ip_active_port,
			port,
			ip_active_port,
			ip_config[port].ip_addr,
			ip_config[port].ip_bcast,
			ip_config[port].ip_mask,
			event_type,
			0,
			0)) {

			ip_config[port].ip_active_port = port;
			for (j = 0; j < ip_config[port].
				alias_cnt; j++) {

				ret = rds_ib_move_ip(
					ip_config[ip_active_port].
						if_name,
					ip_config[port].
						aliases[j].if_name,
					ip_active_port,
					port,
					ip_active_port,
					ip_config[port].
						aliases[j].ip_addr,
					ip_config[port].
						aliases[j].ip_bcast,
					ip_config[port].
						aliases[j].ip_mask,
					event_type,
					1,
					0);
			}
		}
	} else {
		/*
		 * Our 'active_port' is parked at its home base so 'failback'
		 * is just an interface coming UP.
		 *
		 * We get here in two cases.
		 * (1) When a startup script (such as during boot) brings up
		 *     the interface the IP address is set by it and we dont
		 *     do anything here!
		 * (2) When this port went DOWN, it tried but did not succeed
		 *     in failing over(no UP ports or compatible pkey ports
		 *     left to failover to!) so the 'failover' failed and
		 *     our 'active port' stayed parked at its original place.
		 *     If such as port is being resurrected, it will not have
		 *     an IP address set we resurrect it here!
		 */
		/* Test IP addresses and set them if not already set */
		ret = rds_ib_testset_ip(port);
		if (ret) {
			rds_rtd(RDS_RTD_ACT_BND,
				"RDS/IB: failed to ressrt port idx %u dev %s or one of its aliases\n",
				port, ip_config[port].dev->name);
		}
	}
}

static void rds_ib_failover(struct work_struct *_work)
{
	struct rds_ib_port_ud_work	*work =
		container_of(_work, struct rds_ib_port_ud_work, work.work);
	int				ret;
	u8				i;
	char				if_name[IFNAMSIZ];

	if (ip_config[work->port].port_state == RDS_IB_PORT_INIT) {
		printk(KERN_ERR "RDS/IB: devname %s failover request "
		       "with port_state in INIT state!",
		       ip_config[work->port].dev->name);
		goto out;
	}

	for (i = 1; i <= ip_port_cnt; i++) {
		if (i != work->port &&
			ip_config[i].port_state == RDS_IB_PORT_DOWN &&
			ip_config[i].ip_active_port == work->port) {

			strcpy(if_name, ip_config[work->port].if_name);
			strcat(if_name, ":");
			strcat(if_name, ip_config[i].port_label);
			if_name[IFNAMSIZ-1] = 0;
			ret = rds_ib_set_ip(NULL, NULL, if_name, 0, 0, 0);

			rds_ib_do_failover(i, 0, 0, work->event_type);
		}
	}

	if (ip_config[work->port].ip_addr)
		rds_ib_do_failover(work->port, 0, 0, work->event_type);

	if (ip_config[work->port].ip_active_port == work->port) {
		ret = rds_ib_set_ip(NULL, NULL,
				ip_config[work->port].if_name,
				0, 0, 0);
	}

 out:
	kfree(work);
}

static void rds_ib_failback(struct work_struct *_work)
{
	struct rds_ib_port_ud_work	*work =
		container_of(_work, struct rds_ib_port_ud_work, work.work);
	u8				i, ip_active_port, port = work->port;

	if (ip_config[port].port_state == RDS_IB_PORT_INIT) {
		printk(KERN_ERR "RDS/IB: devname %s failback request "
		       "with port_state in INIT state!",
		       ip_config[port].dev->name);
		goto out;
	}

	ip_active_port = ip_config[port].ip_active_port;

	rds_ib_do_failback(port, work->event_type);

	for (i = 1; i <= ip_port_cnt; i++) {
		if (i == port ||
			ip_config[i].port_state == RDS_IB_PORT_UP ||
			!ip_config[i].ip_addr)
			continue;

		if (ip_config[i].ip_active_port == i) {
			rds_ib_do_failover(i, 0, ip_active_port,
						work->event_type);
		} else if ((ip_config[i].ip_active_port == port) &&
			   (ip_config[i].pkey == ip_config[port].pkey)) {
			rds_ib_do_failover(i, port, ip_active_port,
					   work->event_type);
		} else if (ip_config[ip_config[i].ip_active_port].port_state ==
			   RDS_IB_PORT_DOWN) {
			rds_ib_do_failover(i, 0, ip_active_port,
					   work->event_type);
		} else if ((ip_config[port].failover_group ==
				ip_config[i].failover_group) &&
			   (ip_config[i].pkey == ip_config[port].pkey)) {
			rds_ib_do_failover(i, port, ip_active_port,
					   work->event_type);
		}
	}

	if (ip_active_port != ip_config[port].ip_active_port) {
		for (i = 1; i <= ip_port_cnt; i++) {
			if (ip_config[i].port_state == RDS_IB_PORT_DOWN &&
			    i != ip_active_port && ip_config[i].ip_addr &&
			    ip_config[i].ip_active_port == ip_active_port &&
			    ip_config[i].pkey ==
			    ip_config[ip_active_port].pkey) {

				rds_ib_do_failover(i, ip_active_port,
						   ip_active_port,
						   work->event_type);
			}
		}
	}

out:
	kfree(work);
}


static void rds_ib_event_handler(struct ib_event_handler *handler,
				struct ib_event *event)
{
	struct rds_ib_device	*rds_ibdev =
		container_of(handler, typeof(*rds_ibdev), event_handler);
	u8	port;
	struct rds_ib_port_ud_work	*work;

	if (!rds_ib_active_bonding_enabled || !ip_port_cnt) {
		rds_rtd(RDS_RTD_ACT_BND, "ip_port_cnt %d, event %d\n",
			ip_port_cnt, event->event);
		return;
	}

	if (event->event != IB_EVENT_PORT_ACTIVE &&
		event->event != IB_EVENT_PORT_ERR)
		return;

	/*
	 * For the affected endpoints the failover/failback
	 * is queued to happen in delayed worker threads.
	 * HOWEVER, the state maintenance of status of
	 * port layers and port_status is done right here
	 * in this handler (and NOT as delayed work!)
	 */
	for (port = 1; port <= ip_port_cnt; port++) {
		int this_port_transition = RDSIBP_TRANSITION_NOOP;

		if (ip_config[port].port_num != event->element.port_num ||
			ip_config[port].rds_ibdev != rds_ibdev)
			continue;

		rdsdebug("RDS/IB: PORT %s/port_%d/%s "
			 "received PORT-EVENT %s%s\n",
			 rds_ibdev->dev->name,
			 event->element.port_num,
			 ip_config[port].if_name,
			 (event->event == IB_EVENT_PORT_ACTIVE ?
			  "ACTIVE" : "ERROR"),
			 (ip_config_init_phase_flag ?
			  " during initialization phase!" : ""));
		/*
		 * Do layerflag state maintenance and
		 * update port_state status if needed!
		 */

		/* First: HW layer state update! */
		if (event->event == IB_EVENT_PORT_ACTIVE) {
			ip_config[port].port_layerflags |=
			  RDSIBP_STATUS_HWPORTUP;
		} else {
			/* event->event == IB_EVENT_PORT_ERROR */
			ip_config[port].port_layerflags &=
			  ~RDSIBP_STATUS_HWPORTUP;
		}

		/* Second: check and update link layer status */
		if (rds_detected_link_layer_up(ip_config[port].dev))
			ip_config[port].port_layerflags |= RDSIBP_STATUS_LINKUP;
		else
			ip_config[port].port_layerflags &=
				~RDSIBP_STATUS_LINKUP;

		/* Third: check the netdev layer */
		if (ip_config[port].dev->flags & IFF_UP)
			ip_config[port].port_layerflags |=
				RDSIBP_STATUS_NETDEVUP;
		else
			ip_config[port].port_layerflags &=
				~RDSIBP_STATUS_NETDEVUP;

		/*
		 * Do state transitions now!
		 */
		switch (ip_config[port].port_state) {
		case RDS_IB_PORT_INIT:
			if (ip_config_init_phase_flag) {
				/*
				 * For INIT port_state during module
				 * initialization, deferred state transition
				 * processing* happens after all NETDEV and
				 * IB ports come up and event handlers have
				 * run and task doing initial failovers
				 * after module loading has run - which
				 * ends the "init_phase and clears the flag.
				 */

				this_port_transition = RDSIBP_TRANSITION_NOOP;
				break;
			}

			/*
			 * We are in INIT state but not during module
			 * initialization. This can happens when
			 * a new port is detected and initialized
			 * in rds_ib_joining_ip().
			 *
			 * It can also happen via init script
			 * 'stop' invocation -which (temporarily?)
			 * disables active bonding by unsetting
			 * rds_ib_sysctl_active_bonding)
			 * and returns ports to INIT state.
			 *
			 * And then we received this PORT ACTIVE/ERROR
			 * event.
			 *
			 * If rds_ib_sysctl_active_bonding is set,
			 * we transition port_state to UP/DOWN, else
			 * we do not do any transitions here.
			 */
			if (rds_ib_sysctl_active_bonding) {
				if (rds_ibp_all_layers_up(&ip_config[port])) {
					ip_config[port].port_state =
						RDS_IB_PORT_UP;
					this_port_transition =
						RDSIBP_TRANSITION_UP;
				} else {
					ip_config[port].port_state =
						RDS_IB_PORT_DOWN;
					this_port_transition =
						RDSIBP_TRANSITION_DOWN;
				}
			} else {
				this_port_transition = RDSIBP_TRANSITION_NOOP;
				printk(KERN_WARNING
				       "RDS/IB: PORT %s/port_%d/%s "
				       "received PORT-EVENT %s ignored: "
				       "active bonding transitions "
				       "disabled using sysctl\n",
				       rds_ibdev->dev->name,
				       event->element.port_num,
				       ip_config[port].if_name,
				       (event->event == IB_EVENT_PORT_ACTIVE ?
					"ACTIVE" : "ERROR"));
			}
			break;

		case RDS_IB_PORT_DOWN:
			if (rds_ibp_all_layers_up(&ip_config[port])) {
				ip_config[port].port_state = RDS_IB_PORT_UP;
				this_port_transition = RDSIBP_TRANSITION_UP;
			}
			break;

		case RDS_IB_PORT_UP:
			if (!rds_ibp_all_layers_up(&ip_config[port])) {
				ip_config[port].port_state = RDS_IB_PORT_DOWN;
				this_port_transition = RDSIBP_TRANSITION_DOWN;
			}
			break;

		default:
			printk(KERN_ERR "RDS/IB: INVALID port_state %d, "
			       "port index %u, devname %s\n",
			       ip_config[port].port_state,
			       port,
			       ip_config[port].dev->name);
			return;
		}

		/*
		 * Log the event details and its disposition
		 */
		printk(KERN_NOTICE "RDS/IB: PORT-EVENT: %s%s, PORT: "
		       "%s/port_%d/%s : %s%s (portlayers 0x%x)\n",
		       (event->event == IB_EVENT_PORT_ACTIVE ? "ACTIVE" :
			"ERROR"),
		       (ip_config_init_phase_flag ? "(init phase)" : ""),
		       rds_ibdev->dev->name,
		       event->element.port_num,
		       ip_config[port].if_name,
		       (this_port_transition == RDSIBP_TRANSITION_UP ?
		       "port state transition to " :
			(this_port_transition == RDSIBP_TRANSITION_DOWN ?
			 "port state transition to " :
			 "port state transition NONE - "
			 "port retained in state ")),
		       (ip_config[port].port_state == RDS_IB_PORT_UP ? "UP" :
			(ip_config[port].port_state == RDS_IB_PORT_DOWN ?
			 "DOWN" : "INIT")),
		       ip_config[port].port_layerflags);

		if (this_port_transition == RDSIBP_TRANSITION_NOOP) {
			/*
			 * This event causes no transition do nothing!
			 */
			continue;
		}

		work = kzalloc(sizeof *work, GFP_ATOMIC);
		if (!work) {
			printk(KERN_ERR
				"RDS/IB: failed to allocate port work\n");
			return;
		}

		work->port = port;
		work->event_type = RDS_IB_PORT_EVENT_IB;

		if (this_port_transition == RDSIBP_TRANSITION_UP) {
			if (rds_ib_active_bonding_fallback) {
				rds_rtd(RDS_RTD_ACT_BND,
					"active bonding fallback enabled\n");
				INIT_DELAYED_WORK(&work->work, rds_ib_failback);
				queue_delayed_work(rds_wq, &work->work, 0);
			} else
				kfree(work);
		} else {
			/* this_port_transition == RDSIBP_TRANSITION_DOWN */
			INIT_DELAYED_WORK(&work->work, rds_ib_failover);
			queue_delayed_work(rds_wq, &work->work, 0);
		}
	}
}

static void
rds_ib_do_initial_failovers(void)
{
	unsigned int ii;
	unsigned int ports_deactivated = 0;
	int ret = 0;

	/*
	 * Scan all ports and mark them UP/DOWN based on
	 * detections of port_layerflags!
	 */
	for (ii = 1; ii <= ip_port_cnt; ii++) {
		/*
		 * Assert - all ports should be in INIT state!
		 */
		if (ip_config[ii].port_state != RDS_IB_PORT_INIT) {
			printk(KERN_ERR "RDS/IB: port index %u interface %s not "
			       "in INIT state!\n",
			       ii, ip_config[ii].dev->name);
		}

		if (rds_ibp_all_layers_up(&ip_config[ii])) {
			ip_config[ii].port_state = RDS_IB_PORT_UP;
			printk(KERN_NOTICE "RDS/IB port index %u interface %s "
			       "transitioned from INIT to UP state(portlayers 0x%x)\n",
			       ii, ip_config[ii].dev->name,
			       ip_config[ii].port_layerflags);
		} else {
			ip_config[ii].port_state = RDS_IB_PORT_DOWN;
			printk(KERN_NOTICE "RDS/IB: port index %u interface %s "
			       "transitioned from INIT to DOWN state(portlayers 0x%x).\n",
			       ii, ip_config[ii].dev->name,
			       ip_config[ii].port_layerflags);
		}
		ip_config[ii].ip_active_port = ii; /* starting at home base! */
	}

	/*
	 * Now do failover for ports that are down!
	 */
	for (ii = 1; ii <= ip_port_cnt; ii++) {
		/* Failover the port */
		if ((ip_config[ii].port_state == RDS_IB_PORT_DOWN) &&
		    (ip_config[ii].ip_addr)) {

			rds_ib_do_failover(ii, 0, 0,
					   RDS_IB_PORT_EVENT_INITIAL_FAILOVERS);

			/*
			 * reset IP addr of DOWN port to 0 if the
			 * failover did not suceed !
			 * Note: rds_ib_do_failover() logs successful migrations
			 * but not unsuccesful ones. We log unsuccessfull
			 * attempts for this instance here and deactivate the
			 * port by its IP address!
			 */
			if (ip_config[ii].ip_active_port == ii) {
				printk(KERN_NOTICE "RDS/IB: IP %pI4 "
				       "deactivated on interface %s "
				       "(no suitable failover target available)\n",
				       &ip_config[ii].ip_addr,
				       ip_config[ii].dev->name);

				ret = rds_ib_set_ip(NULL, NULL,
						    ip_config[ii].if_name,
						    0, 0, 0);
				ports_deactivated++;

			}
		}
	}

	ip_config_init_phase_flag = 0; /* done with initial phase! */
}

static void
rds_ib_initial_failovers(struct work_struct *workarg)
{

	if (rds_ib_sysctl_trigger_active_bonding == 0) {
		/*
		 * Normally trigger set by network init
		 * script as signal that network devices
		 * config/setup scripts have been run and
		 * we can proceed with active bonding failovers
		 * etc now!
		 * If trigger not set, defer, unless we have
		 * reached a max timeout!
		 */
		if (timeout_until_initial_failovers > 0) {
			timeout_until_initial_failovers -=
			  msecs_to_jiffies(100);
			queue_delayed_work(rds_wq,
					   &riif_dlywork,
					   msecs_to_jiffies(100));
			initial_failovers_iterations++;
			return;
		}
		/*
		 * timeout exceeed, we set the trigger to a
		 * distinctive value to indicated that
		 * we did it due to timeout exceeded (network
		 * init script normally sets it to 1)
		 */
		rds_ib_sysctl_trigger_active_bonding = 999;
		printk(KERN_NOTICE "RDS/IB: Triggering active bonding "
		       "failovers after max interval(itercount %d)\n",
		       initial_failovers_iterations);
	} else {
		printk(KERN_NOTICE "RDS/IB: Triggering active bonding "
		       "failovers(itercount %d)\n",
		       initial_failovers_iterations);
	}
	rds_ib_do_initial_failovers();
}

static void rds_ib_dump_ip_config(void)
{
	int	i, j;

	if (!rds_ib_active_bonding_enabled || !ip_port_cnt) {
		rds_rtd(RDS_RTD_ACT_BND, "ip_port_cnt %d\n", ip_port_cnt);
		return;
	}

	for (i = 1; i <= ip_port_cnt; i++) {
		printk(KERN_INFO "RDS/IB: %s/port_%d/%s: "
			"IP %pI4/%pI4/%pI4 "
			"state %s\n",
			((ip_config[i].rds_ibdev) ?
				((ip_config[i].rds_ibdev->dev) ?
					ip_config[i].rds_ibdev->dev->name :
						"No IB device") :
							"No RDS device"),
			ip_config[i].port_num,
			ip_config[i].if_name,
			&ip_config[i].ip_addr,
			&ip_config[i].ip_bcast,
			&ip_config[i].ip_mask,
			(ip_config[i].port_state ==
			 RDS_IB_PORT_UP ? "UP" :
			 (ip_config[i].port_state ==
			  RDS_IB_PORT_DOWN ? "DOWN" : "INIT")));

		for (j = 0; j < ip_config[i].alias_cnt; j++) {
			printk(KERN_INFO "Alias %s "
				"IP %pI4/%pI4/%pI4\n",
				ip_config[i].aliases[j].if_name,
				&ip_config[i].aliases[j].ip_addr,
				&ip_config[i].aliases[j].ip_bcast,
				&ip_config[i].aliases[j].ip_mask);
		}
	}
}


/*
 * Scheduling initial failovers. The ASCII art below documents the startup
 * timeline of events of significance related to activation of active
 * bonding initial failovers after reboot.
 *               ---
 *                V
 *                |
 *             t0 | <reboot>
 *                |
 *             t1 |<-- (1) openibd(OL5) or rdma (OL6+) init script
 *                |    (run as S05openibd or S05rdma) inits IB
 *                |    interfaces. Scripts
 *                |    /etc/sysconfig/network-scripts/ifcfg-*
 *                |    are run to bring interfaces UP.
 *             t2 |<-- (2) rds_rdma module init code runs on module
 *                |    load which initializes ip_config[] array based
 *                |    on IB device based on kernel global &init_net
 *                |    list; "initialization phase" is started  and
 *                |    rds_ib_initial_failovers() scheduled to run
 *                |    first time!
 *             t3 |<-- (3) network init script (S10network) runs which
 *                |    also inits all networking devices (including IB).
 *                |    Scripts /etc/sysconfig/network-scripts/ifcfg-*
 *                |    are run AGAIN!
 *             t4 |<-- (4) sysctl rds_ib_sysctl_trigger_active_bonding
 *                |    is run in network init script(S10network) *after*
 *                |    attempting bringing up regular IB and VLAN
 *                |    devices as part of step(3) above.
 *             t5 |<-- As scheduled in step(2)
 *                |    rds_ib_initial_failovers() runs at t5. If t5 < t4
 *                |    (rds_ib_sysctl_trigger_active_bonding is NOT set)
 *                |    it reschedules itself after short duration
 *                |    (100 jiffies) until t5 > t4 (i.e.
 *                |    rds_ib_sysctl_trigger_active_bonding IS set).
 *                |    Then it calls rds_ib_do_initial_failovers() to
 *                |    actually do the failovers and ends the
 *                |    "initialization phase". [ Note: to take care of
 *                |    cases where older init scripts are run with
 *                |    newer kernels (not recommended!)
 *                |    rds_ib_do_initial_failovers() runs anyway after
 *                |    a conservative max timeout interval expires. ]
 *                .
 *                .
 *                .
 *                V
 */
static void
sched_initial_failovers(unsigned int tot_devs,
			unsigned int tot_ibdevs)
{
	unsigned int trigger_delay_max_jiffies;
	unsigned int trigger_delay_min_jiffies;

	if (rds_ib_active_bonding_trigger_delay_max_msecs == 0) {
		/*
		 * Derive guestimate of max time before we trigger the
		 * initial failovers for devices.
		 *
		 * This is upper bound on time between when
		 * rds_rdma module is loaded (and its init script
		 * run including this code!) in rdma (openibd in OL5)
		 * script and the network init script *after* all
		 * the interfaces are initialized with their setup
		 * scripts (ifcfg-ibN etc).
		 *
		 * This is a max time which should normally not be
		 * hit. Normally the network startup script
		 * will set rds_ib_sysctl_trigger_active_bonding
		 * (initialized to 0) and we will not hit the
		 * max time.
		 *
		 * Based on some empirical experiments, we put
		 * upper bound to be 60sec(60000msecs) and up.
		 * And we put min to be 20sec (20000msecs).
		 */
		rds_ib_active_bonding_trigger_delay_max_msecs = 60000+
			tot_ibdevs*1200+(tot_devs-tot_ibdevs)*1000;
	}

	if (rds_ib_active_bonding_trigger_delay_min_msecs == 0) {
		/*
		 * Derive guestimate of minimum time before we trigger the
		 * initial failovers for devices.
		 */
		rds_ib_active_bonding_trigger_delay_min_msecs =
			msecs_to_jiffies(20000); /* 20 sec */
	}

	if (rds_ib_active_bonding_trigger_delay_min_msecs >=
	    rds_ib_active_bonding_trigger_delay_max_msecs) {
		/*
		 * If these parameters are set inconsistently using
		 * module parameters, try to recover from it by deriving
		 * reasonable values such that max > min and log
		 * warning.
		 */
		printk(KERN_WARNING
		       "RDS/IB: rds active bonding trigger max delay(%u msecs)"
		       " is set less than min the minimum delay(%u msecs).\n",
		       rds_ib_active_bonding_trigger_delay_max_msecs,
		       rds_ib_active_bonding_trigger_delay_min_msecs);

		/* set max slightly higher than min! */
		rds_ib_active_bonding_trigger_delay_max_msecs =
			rds_ib_active_bonding_trigger_delay_min_msecs + 10;

		printk(KERN_WARNING "RDS/IB: rds active bonding trigger max "
		       "delay adjusted to %u msecs.\n",
		       rds_ib_active_bonding_trigger_delay_max_msecs);
	}

	trigger_delay_max_jiffies =
		msecs_to_jiffies(rds_ib_active_bonding_trigger_delay_max_msecs);

	trigger_delay_min_jiffies =
		msecs_to_jiffies(rds_ib_active_bonding_trigger_delay_min_msecs);

	timeout_until_initial_failovers = trigger_delay_max_jiffies;

	queue_delayed_work(rds_wq,
			   &riif_dlywork,
			   trigger_delay_min_jiffies);
}

static int rds_ib_ip_config_init(void)
{
	struct net_device	*dev;
	struct in_ifaddr	*ifa;
	struct in_ifaddr	**ifap;
	struct in_device	*in_dev;
	struct rds_ib_device	*rds_ibdev;
	union ib_gid            gid;
	int                     ret = 0;
	u8                      port_num;
	u8                      port;
	unsigned int            tot_devs = 0;
	unsigned int            tot_ibdevs = 0;

	if (!rds_ib_active_bonding_enabled) {
		rds_rtd(RDS_RTD_ACT_BND, "active bonding not enabled\n");
		return 0;
	}

	ip_config = kzalloc(sizeof(struct rds_ib_port) *
				(ip_port_max + 1), GFP_KERNEL);
	if (!ip_config) {
		printk(KERN_ERR "RDS/IB: failed to allocate IP config\n");
		return 1;
	}

	/*
	 * This flag is set here to mark start of active
	 * bonding IP failover/failback config.
	 * It ends when we are done doing the initial
	 * failovers after the init.
	 */
	ip_config_init_phase_flag = 1;

	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, dev) {
		in_dev = in_dev_get(dev);
		tot_devs++;
		/*
		 * Note: Enumerate all Infiniband devices
		 *       that are:
		 *                - UP
		 *                - not part of a bond(master or slave)
		 */
		if ((dev->type == ARPHRD_INFINIBAND) &&
			(dev->flags & IFF_UP) &&
			!(dev->flags & IFF_SLAVE) &&
			!(dev->flags & IFF_MASTER) &&
			in_dev) {
			u16 pkey = 0;

			if (ipoib_get_netdev_pkey(dev, &pkey) != 0) {
				printk(KERN_ERR "RDS/IB: failed to get pkey "
				       "for devname %s\n", dev->name);
			}

			memcpy(&gid, dev->dev_addr + 4, sizeof gid);

			tot_ibdevs++;
			list_for_each_entry_rcu(rds_ibdev,
					&rds_ib_devices, list) {
				ret = ib_find_cached_gid(rds_ibdev->dev, &gid,
							 IB_GID_TYPE_IB, NULL,
							 &port_num, NULL);
				if (!ret)
					break;
			}

			if (ret) {
				printk(KERN_ERR "RDS/IB: GID "RDS_IB_GID_FMT
					" has no associated port\n",
					RDS_IB_GID_ARG(gid));
			} else {
				port = rds_ib_init_port(rds_ibdev, dev,
							port_num, gid, pkey);
				if (port > 0) {
					for (ifap = &in_dev->ifa_list;
						(ifa = *ifap);
						ifap = &ifa->ifa_next) {
						rds_ib_set_port(rds_ibdev, dev,
							ifa->ifa_label,
							port,
							ifa->ifa_address,
							ifa->ifa_broadcast,
							ifa->ifa_mask);
					}
				}
			}
		}
		if (in_dev)
			in_dev_put(in_dev);
	}

	printk(KERN_INFO "RDS/IB: IP configuration..\n");
	rds_ib_dump_ip_config();
	read_unlock(&dev_base_lock);
	sched_initial_failovers(tot_devs, tot_ibdevs);
	return ret;
}

static int rds_ib_excl_ip(char *str)
{
	char *tok, *nxt_tok, *end, *prefix_str;
	unsigned int octet_cnt = 0;
	unsigned long prefix = 0;
	__be32  ip = 0;

	prefix_str = strchr(str, '/');
	if (prefix_str) {
		*prefix_str = '\0';
		prefix_str++;
		prefix = simple_strtol(prefix_str, &end, 0);
		if (*end) {
			printk(KERN_WARNING "RDS/IP: Warning: IP prefix "
				"%s improperly formatted\n", prefix_str);
			goto err;
		} else if (prefix > 32) {
			printk(KERN_WARNING "RDS/IP: Warning: IP prefix "
				"%lu out of range\n", prefix);
			goto err;
		} else {
			tok = str;
			while (tok && octet_cnt < 4) {
				unsigned long octet;

				nxt_tok = strchr(tok, '.');
				if (nxt_tok) {
					*nxt_tok = '\0';
					nxt_tok++;
				}
				octet = simple_strtoul(tok, &end, 0);
				if (*end) {
					printk(KERN_WARNING "RDS/IP: Warning: "
						"IP octet %s improperly "
						" formatted\n", tok);
					goto err;
				} else if (octet > 255) {
					printk(KERN_WARNING "RDS/IP: Warning: "
						"IP octet %lu out of range\n",
						octet);
					goto err;
				} else {
					((unsigned char *)&ip)[octet_cnt] =
						(unsigned char)octet;
					octet_cnt++;
				}
				tok = nxt_tok;
			}

			if (tok) {
				printk(KERN_WARNING "RDS/IP: Warning: IP "
					"%s is improperly formatted\n", str);
				goto err;
			}
		}
	} else {
		printk(KERN_WARNING "RDS/IP: Warning: IP prefix not "
			"specified\n");
		goto err;
	}

	excl_ips_tbl[excl_ips_cnt].ip = ip;
	excl_ips_tbl[excl_ips_cnt].prefix = prefix;
	excl_ips_tbl[excl_ips_cnt].mask = inet_make_mask(prefix);

	excl_ips_cnt++;

	return 0;
err:
	return 1;
}

void rds_ib_ip_excl_ips_init(void)
{
	char *tok, *nxt_tok;
	char str[1024];

	if (rds_ib_active_bonding_excl_ips == NULL)
		return;

	strcpy(str, rds_ib_active_bonding_excl_ips);

	tok = str;
	while (tok) {
		nxt_tok = strchr(tok, ',');
		if (nxt_tok) {
			*nxt_tok = '\0';
			nxt_tok++;
		}

		if (rds_ib_excl_ip(tok))
			return;

		tok = nxt_tok;
	}
}

void rds_ib_ip_failover_groups_init(void)
{
	char *tok, *grp, *nxt_tok, *nxt_grp;
	char str[1024];
	unsigned int	grp_id = 1;
	int i;
	struct rds_ib_device *rds_ibdev;

	if (!rds_ib_active_bonding_enabled) {
		rds_rtd(RDS_RTD_ACT_BND, "active bonding not enabled\n");
		return;
	}

	if (rds_ib_active_bonding_failover_groups == NULL) {
		list_for_each_entry_rcu(rds_ibdev, &rds_ib_devices, list) {
			for (i = 1; i <= ip_port_cnt; i++) {
				if (ip_config[i].rds_ibdev == rds_ibdev)
					ip_config[i].failover_group = grp_id;
			}
			grp_id++;
		}
		return;
	}

	strcpy(str, rds_ib_active_bonding_failover_groups);
	nxt_grp = strchr(str, ';');
	if (nxt_grp) {
		*nxt_grp = '\0';
		nxt_grp++;
	}
	grp = str;
	while (grp) {
		tok = grp;
		nxt_tok = strchr(tok, ',');
		if (nxt_tok) {
			*nxt_tok = '\0';
			nxt_tok++;
		}
		while (tok) {
			for (i = 1; i <= ip_port_cnt; i++) {
				if (!strcmp(tok, ip_config[i].if_name)) {
					if (!ip_config[i].failover_group)
						ip_config[i].failover_group =
							grp_id;
					else
						printk(KERN_WARNING "RDS/IB: %s is already part of another failover group\n", tok);
					break;
				}
			}
			tok = nxt_tok;
			nxt_tok = strchr(str, ',');
			if (nxt_tok) {
				*nxt_tok = '\0';
				nxt_tok++;
			}
		}

		grp = nxt_grp;
		nxt_grp = strchr(str, ';');
		if (nxt_grp) {
			*nxt_grp = '\0';
			nxt_grp++;
		}
		grp_id++;
	}
}

void rds_ib_add_one(struct ib_device *device)
{
	struct rds_ib_device *rds_ibdev;
	struct ib_device_attr *dev_attr;

	/* Only handle IB (no iWARP) devices */
	if (device->node_type != RDMA_NODE_IB_CA)
		return;

	dev_attr = kmalloc(sizeof *dev_attr, GFP_KERNEL);
	if (!dev_attr)
		return;

	if (ib_query_device(device, dev_attr)) {
		rds_rtd(RDS_RTD_ERR, "Query device failed for %s\n",
			device->name);
		goto free_attr;
	}

	rds_ibdev = kzalloc_node(sizeof(struct rds_ib_device), GFP_KERNEL,
				ibdev_to_node(device));
	if (!rds_ibdev)
		goto free_attr;

	atomic_set(&rds_ibdev->free_dev, 1);
	mutex_init(&rds_ibdev->free_dev_lock);
	spin_lock_init(&rds_ibdev->spinlock);
	atomic_set(&rds_ibdev->refcount, 1);
	INIT_WORK(&rds_ibdev->free_work, rds_ib_dev_free);

	rds_ibdev->max_wrs = dev_attr->max_qp_wr;
	rds_ibdev->max_sge = min(dev_attr->max_sge, RDS_IB_MAX_SGE);

	rds_ibdev->fmr_max_remaps = dev_attr->max_map_per_fmr?: 32;

	rds_ibdev->max_1m_fmrs = dev_attr->max_fmr ?
		min_t(unsigned int, dev_attr->max_fmr,
			rds_ib_fmr_1m_pool_size) :
			rds_ib_fmr_1m_pool_size;

	rds_ibdev->max_8k_fmrs = dev_attr->max_fmr ?
		min_t(unsigned int, dev_attr->max_fmr,
			rds_ib_fmr_8k_pool_size) :
			rds_ib_fmr_8k_pool_size;

	rds_ibdev->max_initiator_depth = dev_attr->max_qp_init_rd_atom;
	rds_ibdev->max_responder_resources = dev_attr->max_qp_rd_atom;

	rds_ibdev->dev = device;
	rds_ibdev->pd = ib_alloc_pd(device, 0);
	if (IS_ERR(rds_ibdev->pd)) {
		rds_ibdev->pd = NULL;
		goto put_dev;
	}

	if (rds_ib_active_bonding_enabled) {
		INIT_IB_EVENT_HANDLER(&rds_ibdev->event_handler,
				rds_ibdev->dev, rds_ib_event_handler);
		ib_register_event_handler(&rds_ibdev->event_handler);
	}

	rds_ibdev->vector_load = kzalloc(sizeof(int) *
					device->num_comp_vectors, GFP_KERNEL);
	if (!rds_ibdev->vector_load) {
		printk(KERN_ERR "RDS/IB: failed to allocate vector memoru\n");
		goto put_dev;
	}

	rds_ibdev->mr = ib_get_dma_mr(rds_ibdev->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(rds_ibdev->mr)) {
		rds_ibdev->mr = NULL;
		goto put_dev;
	}

	rds_ibdev->mr_1m_pool =
		rds_ib_create_mr_pool(rds_ibdev, RDS_IB_MR_1M_POOL);
	if (IS_ERR(rds_ibdev->mr_1m_pool)) {
		rds_ibdev->mr_1m_pool = NULL;
		goto put_dev;
	}

	rds_ibdev->mr_8k_pool =
		rds_ib_create_mr_pool(rds_ibdev, RDS_IB_MR_8K_POOL);
	if (IS_ERR(rds_ibdev->mr_8k_pool)) {
		rds_ibdev->mr_8k_pool = NULL;
		goto put_dev;
	}

	INIT_LIST_HEAD(&rds_ibdev->ipaddr_list);
	INIT_LIST_HEAD(&rds_ibdev->conn_list);

	if (rds_ib_srq_init(rds_ibdev))
		goto put_dev;

	down_write(&rds_ib_devices_lock);
	list_add_tail_rcu(&rds_ibdev->list, &rds_ib_devices);
	up_write(&rds_ib_devices_lock);
	atomic_inc(&rds_ibdev->refcount);

	ib_set_client_data(device, &rds_ib_client, rds_ibdev);
	atomic_inc(&rds_ibdev->refcount);

	rds_ib_nodev_connect();
put_dev:
	rds_ib_dev_put(rds_ibdev);
free_attr:
	kfree(dev_attr);
}

static void rds_ib_unregister_client(void)
{
	ib_unregister_client(&rds_ib_client);
	/* wait for rds_ib_dev_free() to complete */
	flush_workqueue(rds_wq);
	flush_workqueue(rds_local_wq);
}

static void rds_ib_update_ip_config(void)
{
	struct net_device	*dev;
	struct in_device	*in_dev;
	int			i;

	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, dev) {
		in_dev = in_dev_get(dev);
		if (in_dev) {
			for (i = 1; i <= ip_port_cnt; i++) {
				if (!strcmp(dev->name, ip_config[i].if_name)) {
					if (ip_config[i].dev != dev) {
						ip_config[i].dev = dev;
						printk(KERN_NOTICE "RDS/IB: "
							"dev %s/port_%d/%s updated",
							ip_config[i].rds_ibdev->dev->name,
							ip_config[i].port_num,
							dev->name);
					}
				}
			}
			in_dev_put(in_dev);
		}
	}
	read_unlock(&dev_base_lock);
}

static void rds_ib_joining_ip(struct work_struct *_work)
{
	struct rds_ib_port_ud_work      *work =
		container_of(_work, struct rds_ib_port_ud_work, work.work);
	struct net_device *ndev = work->dev;
	struct in_ifaddr        *ifa;
	struct in_ifaddr        **ifap;
	struct in_device        *in_dev;
	union ib_gid            gid;
	struct rds_ib_device    *rds_ibdev;
	int                     ret = 0;
	u8                      port_num;
	u8                      port;

	read_lock(&dev_base_lock);
	in_dev = in_dev_get(ndev);
	if (in_dev && !in_dev->ifa_list && work->timeout > 0) {
		INIT_DELAYED_WORK(&work->work, rds_ib_joining_ip);
		work->timeout -= msecs_to_jiffies(100);
		queue_delayed_work(rds_wq, &work->work, msecs_to_jiffies(100));
	} else if (in_dev && in_dev->ifa_list) {
		u16 pkey = 0;

		if (ipoib_get_netdev_pkey(ndev, &pkey) != 0) {
			printk(KERN_ERR "RDS/IB: failed to get pkey "
			       "for devname %s\n", ndev->name);
		}

		memcpy(&gid, ndev->dev_addr + 4, sizeof gid);
		list_for_each_entry_rcu(rds_ibdev,
				&rds_ib_devices, list) {
			ret = ib_find_cached_gid(rds_ibdev->dev, &gid,
						 IB_GID_TYPE_IB, NULL,
						 &port_num, NULL);
			if (!ret)
				break;
		}
		if (ret) {
			printk(KERN_ERR "RDS/IB: GID "RDS_IB_GID_FMT
					" has no associated port\n",
					RDS_IB_GID_ARG(gid));
		} else {
			port = rds_ib_init_port(rds_ibdev, ndev,
						port_num, gid, pkey);
			if (port > 0) {
				for (ifap = &in_dev->ifa_list;
						(ifa = *ifap);
						ifap = &ifa->ifa_next) {
					rds_ib_set_port(rds_ibdev, ndev,
							ifa->ifa_label,
							port,
							ifa->ifa_address,
							ifa->ifa_broadcast,
							ifa->ifa_mask);
				}
				/*
				 * Processing triggered by a NETDEV_UP event
				 * mark the NETDEV layer UP.
				 * (No failback/failover processing done for
				 * this initial NETDEV_UP event for a new
				 * device!)
				 */
				ip_config[port].port_layerflags |=
					RDSIBP_STATUS_NETDEVUP;
				if (!(ip_config[port].dev->flags & IFF_UP)) {
					printk(KERN_WARNING "RDS/IB: Device %s "
					       "flag NOT marked UP in "
					       "NETDEV_UP(joining ip) "
					       "processing!\n",
					       ip_config[port].dev->name);
				}
			}
		}
		printk(KERN_INFO "RDS/IB: Updated IP configuration..\n");
		rds_ib_ip_failover_groups_init();
		rds_ib_dump_ip_config();
		kfree(work);
	} else if (!work->timeout)
		kfree(work);

	if (in_dev)
		in_dev_put(in_dev);
	read_unlock(&dev_base_lock);
}


static int rds_ib_netdev_callback(struct notifier_block *self, unsigned long event, void *ctx)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ctx);
	u8 port = 0;
	u8 i;
	struct rds_ib_port_ud_work *work = NULL;
	int port_transition = RDSIBP_TRANSITION_NOOP;

	if (!rds_ib_active_bonding_enabled) {
		rds_rtd(RDS_RTD_ACT_BND, "active bonding not enabled\n");
		return NOTIFY_DONE;
	}

	if (event != NETDEV_UP &&
	    event != NETDEV_DOWN &&
	    event != NETDEV_CHANGE)
		return NOTIFY_DONE;

	/*
	 * Find the port by netdev->name
	 * (Update config if name exists but ndev has changed)
	 */
	for (i = 1; i <= ip_port_cnt; i++) {
		if (!strcmp(ndev->name, ip_config[i].if_name) &&
			ip_config[i].rds_ibdev) {
			if (event == NETDEV_UP && ip_config[i].dev != ndev)
				rds_ib_update_ip_config();
			port = i;
			break;
		}
	}

	/*
	 * If no port by netdev->name found, then
	 * see if we have a newly instantiated
	 * IB device.
	 * Note: For this UP event, nothing will
	 * 'failback' to this interface since its new,
	 * (since no 'failovers' of it have happened),
	 * We just initiate its state in our data
	 * structures.
	 */
	if (!port && event == NETDEV_UP) {
		if ((ndev->type == ARPHRD_INFINIBAND) &&
				(ndev->flags & IFF_UP) &&
				!(ndev->flags & IFF_SLAVE) &&
				!(ndev->flags & IFF_MASTER)) {
			work = kzalloc(sizeof *work, GFP_ATOMIC);
			if (work) {
				work->dev = ndev;
				work->timeout = msecs_to_jiffies(10000);
				INIT_DELAYED_WORK(&work->work, rds_ib_joining_ip);
				queue_delayed_work(rds_wq, &work->work,
						msecs_to_jiffies(100));
			}
		}
		return NOTIFY_DONE;
	}

	/*
	 * No matching port found by netdev->name and
	 * no newly instantiated device found nothing
	 * matching found. This probably is a callback
	 * from a non-infiniband or active-active
	 * supported (e.g. bond) device - so we have
	 * nothing more to do!
	 */
	if (!port)
		return NOTIFY_DONE;

	/*
	 * If we are racing with device teardown
	 * we are done!
	 */
	if (ip_config[port].rds_ibdev == NULL)
		return NOTIFY_DONE;

	rdsdebug("RDS/IB: PORT %s/port_%d/%s received NET-EVENT %s%s\n",
	       ip_config[port].rds_ibdev->dev->name,
	       ip_config[port].port_num, ndev->name,
	       (event == NETDEV_UP ? "NETDEV_UP" :
		(event == NETDEV_DOWN ? "NETDEV_DOWN" : "NETDEV_CHANGE")),
	       (ip_config_init_phase_flag ?
		" during initialization phase!" : ""));

	/*
	 * Do layer state maintenance and update
	 * port status if needed!
	 */

	/*
	 * Check link layer: if its UP, we also
	 * mark HW layer UP! (Since on VM reboots etc
	 * we may not get a separate event for HW ports!)
	 */
	if (rds_detected_link_layer_up(ip_config[port].dev)) {
		ip_config[port].port_layerflags |= RDSIBP_STATUS_LINKUP;
		ip_config[port].port_layerflags |= RDSIBP_STATUS_HWPORTUP;
	} else {
		ip_config[port].port_layerflags &= ~RDSIBP_STATUS_LINKUP;
	}

	/*
	 * Mark NETDEV layer state based on event (verify IFF_UP flag and
	 * warn!)
	 */
	if (event == NETDEV_UP) {
		ip_config[port].port_layerflags |= RDSIBP_STATUS_NETDEVUP;
		if (!(ip_config[port].dev->flags & IFF_UP)) {
			printk(KERN_WARNING "RDS/IB: Device %s flag NOT "
			       "marked UP in NETDEV_UP processing!\n",
			       ip_config[port].dev->name);
		}
	} else if (event == NETDEV_DOWN) {
		ip_config[port].port_layerflags &= ~RDSIBP_STATUS_NETDEVUP;
		if (ip_config[port].dev->flags & IFF_UP) {
			printk(KERN_WARNING "RDS/IB: Device %s flag marked "
			       "UP in NETDEV_DOWN processing!\n",
			       ip_config[port].dev->name);
		}
	} else { /* event == NETDEV_CHANGE */
		/*
		 * Link layer changes - that trigger NETDEV_CHANGE
		 * already handled above - just print kernel notice
		 */
		rdsdebug("RDS/IB:(NETDEV_CHANGE) port layer "
		       "detections: devname: %s, HW_PORT: %s, LINK: %s, "
		       "NETDEV: %s\n", ip_config[port].dev->name,
		       ((ip_config[port].port_layerflags &
			 RDSIBP_STATUS_HWPORTUP) ? "UP" : "DOWN"),
		       ((ip_config[port].port_layerflags &
			 RDSIBP_STATUS_LINKUP) ? "UP" : "DOWN"),
		       ((ip_config[port].port_layerflags &
			 RDSIBP_STATUS_NETDEVUP) ? "UP" : "DOWN"));
	}

	/*
	 * Do state transitions now
	 */
	switch (ip_config[port].port_state) {
	case RDS_IB_PORT_INIT:

		if (ip_config_init_phase_flag) {
			/*
			 * For INIT port_state during module initialization,
			 * deferred state transition processing* happens after
			 * all NETDEV and IB ports come up and event
			 * handlers have run and task doing initial failovers
			 * after module loading has run - which ends the
			 * "init_phase and clears the flag.
			 */
			port_transition = RDSIBP_TRANSITION_NOOP;
			break;
		}

		/*
		 * We are in INIT state but not during module
		 * initialization. This can happens when
		 * a new port is detected and initialized
		 * in rds_ib_joining_ip().
		 *
		 * It can also happen via init script
		 * 'stop' invocation -which (temporarily?)
		 * disables active bonding by unsetting
		 * rds_ib_sysctl_active_bonding)
		 * and returns ports to INIT state.
		 *
		 * And then we received this NETDEV
		 * UP/DOWN/CHANGE event.
		 *
		 * If rds_ib_sysctl_active_bonding is set,
		 * we transition port_state to UP/DOWN, else
		 * we do not do any transitions here.
		 */
		if (rds_ib_sysctl_active_bonding) {
			if (rds_ibp_all_layers_up(&ip_config[port])) {
				ip_config[port].port_state = RDS_IB_PORT_UP;
				port_transition = RDSIBP_TRANSITION_UP;
			} else {
				ip_config[port].port_state = RDS_IB_PORT_DOWN;
				port_transition = RDSIBP_TRANSITION_DOWN;
			}
		} else {
			port_transition = RDSIBP_TRANSITION_NOOP;
			printk(KERN_WARNING "RDS/IB: PORT %s/port_%d/%s "
			       "received PORT-EVENT %s ignored: "
			       "active bonding transitions "
			       "disabled using sysctl\n",
			       ip_config[port].rds_ibdev->dev->name,
			       ip_config[port].port_num, ndev->name,
			       (event == NETDEV_UP ? "NETDEV_UP" :
				(event == NETDEV_DOWN ? "NETDEV_DOWN" :
				 "NETDEV_CHANGE")));
		}

		break;
	case RDS_IB_PORT_DOWN:
		if (rds_ibp_all_layers_up(&ip_config[port])) {
			ip_config[port].port_state = RDS_IB_PORT_UP;
			port_transition = RDSIBP_TRANSITION_UP;
		}
		break;
	case RDS_IB_PORT_UP:
		if (!rds_ibp_all_layers_up(&ip_config[port])) {
			ip_config[port].port_state = RDS_IB_PORT_DOWN;
			port_transition = RDSIBP_TRANSITION_DOWN;
		}
		break;
	default:
		printk(KERN_ERR "RDS/IB: INVALID port_state %d, "
		       "port index %u, devname %s\n",
		       ip_config[port].port_state,
		       port,
		       ip_config[port].dev->name);
		return NOTIFY_DONE;
	}


	/*
	 * Log the event details and its disposition
	 */
	printk(KERN_NOTICE "RDS/IB: NET-EVENT: %s%s, PORT %s/port_%d/%s : "
	       "%s%s (portlayers 0x%x)\n",
	       (event == NETDEV_UP ? "NETDEV-UP" :
		(event == NETDEV_DOWN ? "NETDEV-DOWN" : "NETDEV-CHANGE")),
	       (ip_config_init_phase_flag ? "(init phase)" : ""),
	       ip_config[port].rds_ibdev->dev->name,
	       ip_config[port].port_num, ndev->name,
	       (port_transition == RDSIBP_TRANSITION_UP ?
		"port state transition to " :
		(port_transition == RDSIBP_TRANSITION_DOWN ?
		 "port state transition to " :
		 "port state transition NONE - port retained in state ")),
	       (ip_config[port].port_state == RDS_IB_PORT_UP ? "UP" :
		(ip_config[port].port_state == RDS_IB_PORT_DOWN ?
		 "DOWN" : "INIT")),
	       ip_config[port].port_layerflags);

	if (port_transition == RDSIBP_TRANSITION_NOOP) {
		/*
		 * This event causes no transition do nothing!
		 */
		return NOTIFY_DONE;
	}

	work = kzalloc(sizeof *work, GFP_ATOMIC);
	if (!work) {
		printk(KERN_ERR "RDS/IB: failed to allocate port work\n");
		return NOTIFY_DONE;
	}

	work->dev = ndev;
	work->port = port;
	work->event_type = RDS_IB_PORT_EVENT_NET;

	switch (port_transition) {
	case RDSIBP_TRANSITION_UP:
		if (rds_ib_active_bonding_fallback) {
			rds_rtd(RDS_RTD_ACT_BND,
				"active bonding fallback enabled\n");
			INIT_DELAYED_WORK(&work->work, rds_ib_failback);
			queue_delayed_work(rds_wq, &work->work, 0);
		} else
			kfree(work);
		break;

	case RDSIBP_TRANSITION_DOWN:
		if (rds_ib_sysctl_active_bonding) {
			INIT_DELAYED_WORK(&work->work, rds_ib_failover);
			queue_delayed_work(rds_wq, &work->work, 0);
		} else {
			/*
			 * Note: Active bonding disabled by override
			 * setting rds_ib_sysctl_active_bonding
			 * to zero (normally done in
			 * init script 'stop' invocation).
			 * We do not want to bother with failover
			 * when we are bring devices down one-by-one
			 * during 'stop' of init script.
			 */
			ip_config[port].port_state = RDS_IB_PORT_INIT;
			ip_config[port].ip_active_port = port;
			kfree(work);
		}
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block rds_ib_nb = {
	.notifier_call = rds_ib_netdev_callback
};

int rds_ib_init(void)
{
	int ret;

	INIT_LIST_HEAD(&rds_ib_devices);

	ret = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			       &rds_ib_inet_socket);
	if (ret < 0) {
		printk(KERN_ERR "RDS/IB: can't create TCP transport socket (%d).\n", -ret);
		goto out;
	}

	sock_net_set(rds_ib_inet_socket->sk, &init_net);

	ret = rds_ib_fmr_init();
	if (ret)
		goto out;

	ret = rds_ib_sysctl_init();
	if (ret)
		goto out_fmr_exit;

	ret = rds_ib_recv_init();
	if (ret)
		goto out_sysctl;

	ret = ib_register_client(&rds_ib_client);
	if (ret)
		goto out_recv;

	rds_aux_wq = create_singlethread_workqueue("krdsd_aux");
	if (!rds_aux_wq) {
		printk(KERN_ERR "RDS/IB: failed to create aux workqueue\n");
		goto out_ibreg;
	}

	ret = rds_trans_register(&rds_ib_transport);
	if (ret)
		goto out_ibreg;

	rds_info_register_func(RDS_INFO_IB_CONNECTIONS, rds_ib_ic_info);

	rds_ib_ip_excl_ips_init();

	ret = rds_ib_ip_config_init();
	if (ret) {
		printk(KERN_ERR "RDS/IB: failed to init port\n");
		goto out_ibreg;
	}

	rds_ib_ip_failover_groups_init();

	register_netdevice_notifier(&rds_ib_nb);

	goto out;

out_ibreg:
	rds_ib_unregister_client();
out_recv:
	rds_ib_recv_exit();
out_sysctl:
	rds_ib_sysctl_exit();
out_fmr_exit:
	rds_ib_fmr_exit();
out:
	return ret;
}


void rds_ib_exit(void)
{
	unregister_netdevice_notifier(&rds_ib_nb);
	rds_info_deregister_func(RDS_INFO_IB_CONNECTIONS, rds_ib_ic_info);
	rds_ib_unregister_client();
	rds_ib_destroy_nodev_conns();
	rds_ib_sysctl_exit();
	rds_ib_recv_exit();
	flush_workqueue(rds_aux_wq);
	destroy_workqueue(rds_aux_wq);
	rds_trans_unregister(&rds_ib_transport);
	rds_ib_fmr_exit();

	if (ip_config)
		kfree(ip_config);
}

struct rds_transport rds_ib_transport = {
	.laddr_check		= rds_ib_laddr_check,
	.xmit_complete		= rds_ib_xmit_complete,
	.xmit			= rds_ib_xmit,
	.xmit_rdma		= rds_ib_xmit_rdma,
	.xmit_atomic		= rds_ib_xmit_atomic,
	.recv			= rds_ib_recv,
	.conn_alloc		= rds_ib_conn_alloc,
	.conn_free		= rds_ib_conn_free,
	.conn_connect		= rds_ib_conn_connect,
	.conn_shutdown		= rds_ib_conn_shutdown,
	.inc_copy_to_user	= rds_ib_inc_copy_to_user,
	.inc_free		= rds_ib_inc_free,
	.inc_to_skb		= rds_ib_inc_to_skb,
	.skb_local		= rds_skb_local,
	.cm_initiate_connect	= rds_ib_cm_initiate_connect,
	.cm_handle_connect	= rds_ib_cm_handle_connect,
	.cm_connect_complete	= rds_ib_cm_connect_complete,
	.stats_info_copy	= rds_ib_stats_info_copy,
	.exit			= rds_ib_exit,
	.get_mr			= rds_ib_get_mr,
	.sync_mr		= rds_ib_sync_mr,
	.free_mr		= rds_ib_free_mr,
	.flush_mrs		= rds_ib_flush_mrs,
#if RDMA_RDS_APM_SUPPORTED
	.check_migration        = rds_ib_check_migration,
#endif
	.t_owner		= THIS_MODULE,
	.t_name			= "infiniband",
	.t_type			= RDS_TRANS_IB
};

int rds_ib_inc_to_skb(struct rds_incoming *inc, struct sk_buff *skb)
{
	skb_frag_t *frag;
	int ret = 0, slen;
	u32 len;
	int i;
	struct rds_ib_incoming *ibinc;
	struct rds_page_frag *ibfrag;

	/* pull out initial pointers */
	ibinc  = container_of(inc, struct rds_ib_incoming, ii_inc);
	ibfrag = list_entry(ibinc->ii_frags.next, struct rds_page_frag, f_item);
	len    = be32_to_cpu(inc->i_hdr.h_len);
	slen   = len;
	i      = 0;

	/* run through the entire ib fragment list and save off the buffers */
	while (NULL != ibfrag && slen > 0) {
		/* one to one mapping of frags to sg structures */
		frag = &skb_shinfo(skb)->frags[i];

		/* save off all the sg pieces to the skb frags we are creating */
		frag->size        = ibfrag->f_sg.length;
		frag->page_offset = ibfrag->f_sg.offset;
		frag->page.p      = sg_page(&ibfrag->f_sg);

		/* AA:  do we need to bump up the page reference */
		/* get_page(frag->page); */

		/* dec the amount of data we are consuming */
		slen -= frag->size;

		/* bump to the next entry */
		ibfrag = list_entry(ibfrag->f_item.next, struct rds_page_frag, f_item);
		i++;

		/* for now we will only have a single chain of fragments in the skb */
		if (i >= MAX_SKB_FRAGS) {
			rdsdebug("too many fragments in op %u > max %u, skb %p",
				 i, (int)MAX_SKB_FRAGS, skb);
			goto done;
		}
	}

	/* track the full message length too */
	skb->len = len;

	/* all good */
	ret = 1;

done:
	/* track all the fragments we saved */
	skb_shinfo(skb)->nr_frags = i;

	return ret;
}

MODULE_LICENSE("GPL");

