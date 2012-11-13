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
#include <net/inet_common.h>
#include <linux/rtnetlink.h>

#include "rds.h"
#include "ib.h"
#include <linux/time.h>

unsigned int rds_ib_fmr_1m_pool_size = RDS_FMR_1M_POOL_SIZE;
unsigned int rds_ib_fmr_8k_pool_size = RDS_FMR_8K_POOL_SIZE;
unsigned int rds_ib_retry_count = RDS_IB_DEFAULT_RETRY_COUNT;
unsigned int rds_ib_apm_enabled = 0;
unsigned int rds_ib_apm_fallback = 1;
unsigned int rds_ib_haip_enabled = 0;
unsigned int rds_ib_haip_fallback = 1;
unsigned int rds_ib_apm_timeout = RDS_IB_DEFAULT_TIMEOUT;
unsigned int rds_ib_rnr_retry_count = RDS_IB_DEFAULT_RNR_RETRY_COUNT;

module_param(rds_ib_fmr_1m_pool_size, int, 0444);
MODULE_PARM_DESC(rds_ib_fmr_1m_pool_size, " Max number of 1m fmr per HCA");
module_param(rds_ib_fmr_8k_pool_size, int, 0444);
MODULE_PARM_DESC(rds_ib_fmr_8k_pool_size, " Max number of 8k fmr per HCA");
module_param(rds_ib_retry_count, int, 0444);
MODULE_PARM_DESC(rds_ib_retry_count, " Number of hw retries before reporting an error");
module_param(rds_ib_apm_enabled, int, 0444);
MODULE_PARM_DESC(rds_ib_apm_enabled, " APM Enabled");
module_param(rds_ib_haip_enabled, int, 0444);
MODULE_PARM_DESC(rds_ib_haip_enabled, " High Availability IP enabled");
module_param(rds_ib_apm_timeout, int, 0444);
MODULE_PARM_DESC(rds_ib_apm_timeout, " APM timeout");
module_param(rds_ib_rnr_retry_count, int, 0444);
MODULE_PARM_DESC(rds_ib_rnr_retry_count, " QP rnr retry count");
module_param(rds_ib_apm_fallback, int, 0444);
MODULE_PARM_DESC(rds_ib_apm_fallback, " APM failback enabled");
module_param(rds_ib_haip_fallback, int, 0444);
MODULE_PARM_DESC(rds_ib_haip_fallback, " HAIP failback Enabled");



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
EXPORT_SYMBOL_GPL(rds_aux_wq);

struct socket	*rds_ib_inet_socket;

void rds_ib_nodev_connect(void)
{
	struct rds_ib_connection *ic;

	spin_lock(&ib_nodev_conns_lock);
	list_for_each_entry(ic, &ib_nodev_conns, ib_node)
		rds_conn_connect_if_down(ic->conn);
	spin_unlock(&ib_nodev_conns_lock);
}

void rds_ib_dev_shutdown(struct rds_ib_device *rds_ibdev)
{
	struct rds_ib_connection *ic;
	unsigned long flags;

	spin_lock_irqsave(&rds_ibdev->spinlock, flags);
	list_for_each_entry(ic, &rds_ibdev->conn_list, ib_node)
		rds_conn_drop(ic->conn);
	spin_unlock_irqrestore(&rds_ibdev->spinlock, flags);
}

/*
 * rds_ib_destroy_mr_pool() blocks on a few things and mrs drop references
 * from interrupt context so we push freing off into a work struct in krdsd.
 */
static void rds_ib_dev_free(struct work_struct *work)
{
	struct rds_ib_ipaddr *i_ipaddr, *i_next;
	struct rds_ib_device *rds_ibdev = container_of(work,
					struct rds_ib_device, free_work);

	if (rds_ibdev->mr_8k_pool)
		rds_ib_destroy_mr_pool(rds_ibdev->mr_8k_pool);
	if (rds_ibdev->mr_1m_pool)
		rds_ib_destroy_mr_pool(rds_ibdev->mr_1m_pool);
	if (rds_ibdev->mr)
		ib_dereg_mr(rds_ibdev->mr);
	if (rds_ibdev->pd)
		ib_dealloc_pd(rds_ibdev->pd);
	kfree(rds_ibdev->srq);

	list_for_each_entry_safe(i_ipaddr, i_next, &rds_ibdev->ipaddr_list, list) {
		list_del(&i_ipaddr->list);
		kfree(i_ipaddr);
	}

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

	rds_ibdev = ib_get_client_data(device, &rds_ib_client);
	if (!rds_ibdev)
		return;

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
	struct rds_ib_connection *ic;

	/* We will only ever look at IB transports */
	if (conn->c_trans != &rds_ib_transport)
		return 0;

	iinfo->src_addr = conn->c_laddr;
	iinfo->dst_addr = conn->c_faddr;

	memset(&iinfo->src_gid, 0, sizeof(iinfo->src_gid));
	memset(&iinfo->dst_gid, 0, sizeof(iinfo->dst_gid));
	if (rds_conn_state(conn) == RDS_CONN_UP) {
		struct rds_ib_device *rds_ibdev;
		struct rdma_dev_addr *dev_addr;

		ic = conn->c_transport_data;
		dev_addr = &ic->i_cm_id->route.addr.dev_addr;

		rdma_addr_get_sgid(dev_addr, (union ib_gid *) &iinfo->src_gid);
		rdma_addr_get_dgid(dev_addr, (union ib_gid *) &iinfo->dst_gid);

		rds_ibdev = ic->rds_ibdev;
		iinfo->max_send_wr = ic->i_send_ring.w_nr;
		iinfo->max_recv_wr = ic->i_recv_ring.w_nr;
		iinfo->max_send_sge = rds_ibdev->max_sge;
		rds_ib_get_mr_info(rds_ibdev, iinfo);
		iinfo->tos = ic->conn->c_tos;
		iinfo->sl = ic->i_sl;
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
static int rds_ib_laddr_check(__be32 addr)
{
	int ret;
	struct rdma_cm_id *cm_id;
	struct sockaddr_in sin;

	/* Create a CMA ID and try to bind it. This catches both
	 * IB and iWARP capable NICs.
	 */
	cm_id = rdma_create_id(&init_net, NULL, NULL, RDMA_PS_TCP, IB_QPT_RC);
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

static void rds_ib_send_gratuitous_arp(struct net_device *out_dev,
					unsigned char *dev_addr,
					__be32 ip_addr)
{
	arp_send(ARPOP_REQUEST, ETH_P_ARP,
		ip_addr, out_dev,
		ip_addr, NULL,
		dev_addr, NULL);
}

static int rds_ib_set_ip(struct net_device *out_dev,
			unsigned char *dev_addr,
			char *if_name,
			__be32 addr,
			__be32 bcast,
			__be32 mask)
{
	struct ifreq *ir;
	struct sockaddr_in *sin;
	struct page *page;
	int ret = 0;

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
	if (ret) {
		printk(KERN_ERR
			"RDS/IB: inet_ioctl(SIOCSIFADDR) failed (%d)\n",
			ret);
		goto out;
	}

	if (!addr)
		goto out;

	sin->sin_addr.s_addr = bcast;
	ret = inet_ioctl(rds_ib_inet_socket, SIOCSIFBRDADDR,
			(unsigned long) ir);
	if (ret) {
		printk(KERN_ERR
			"RDS/IB: inet_ioctl(SIOCSIFBRDADDR) failed (%d)\n",
			ret);
		goto out;
	}

	sin->sin_addr.s_addr = mask;
	ret = inet_ioctl(rds_ib_inet_socket, SIOCSIFNETMASK,
			(unsigned long) ir);
	if (ret) {
		printk(KERN_ERR
			"RDS/IB: inet_ioctl(SIOCSIFBRDADDR) failed (%d)\n",
			ret);
		goto out;
	}

	rds_ib_send_gratuitous_arp(out_dev, dev_addr, addr);

out:
	kunmap(page);
	__free_page(page);

	return ret;
}

static int rds_ib_move_ip(struct net_device *out_dev,
			unsigned char *dev_addr,
			char *from_dev,
			char *to_dev,
			__be32 addr,
			__be32 bcast,
			__be32 mask,
			int failover)
{
	struct rds_ib_device *rds_ibdev;
	struct ifreq *ir;
	struct sockaddr_in *sin;
	struct page *page;
	char from_dev2[2*IFNAMSIZ + 1];
	char to_dev2[2*IFNAMSIZ + 1];
	int i, ret = 0;
	char *from_colon, *to_colon;
	int from_passive = 0, to_passive = 0;

	page = alloc_page(GFP_HIGHUSER);
	if (!page) {
		printk(KERN_ERR "RDS/IB: alloc_page failed .. NO MEM\n");
		return 1;
	}

	ir = (struct ifreq *)kmap(page);
	memset(ir, 0, sizeof(struct ifreq));
	sin = (struct sockaddr_in *)&ir->ifr_addr;

	from_colon = strchr(from_dev, ':');
	to_colon = strchr(to_dev, ':');
	if (!from_colon && !to_colon) {
		rcu_read_lock();
		list_for_each_entry(rds_ibdev, &rds_ib_devices, list) {
			for (i = 1; i <= rds_ibdev->dev->phys_port_cnt; i++) {
				if (!strcmp(from_dev,
					rds_ibdev->ports[i].if_name) &&
					!rds_ibdev->ports[i].ip_addr) {
					from_passive = 1;
				}

				if (!strcmp(to_dev,
					rds_ibdev->ports[i].if_name) &&
					!rds_ibdev->ports[i].ip_addr) {
					to_passive = 1;
				}
			}
		}
		rcu_read_unlock();
	}

	if (failover) {
		if (to_passive) {
			strcpy(to_dev2, to_dev);
		} else {
			strcpy(to_dev2, to_dev);
			strcat(to_dev2, ":");
			strcat(to_dev2, from_dev);
			to_dev2[IFNAMSIZ-1] = 0;
		}
		strcpy(from_dev2, from_dev);
	} else {
		if (from_passive) {
			strcpy(from_dev2, from_dev);
		} else {
			strcpy(from_dev2, from_dev);
			strcat(from_dev2, ":");
			strcat(from_dev2, to_dev);
			from_dev2[IFNAMSIZ-1] = 0;
		}
		strcpy(to_dev2, to_dev);
	}

	/* Clear IP on from Interface */
	sin->sin_addr.s_addr = 0;
	sin->sin_family = AF_INET;
	strcpy(ir->ifr_ifrn.ifrn_name, from_dev2);
	ret = inet_ioctl(rds_ib_inet_socket, SIOCSIFADDR, (unsigned long) ir);
	if (ret) {
		printk(KERN_ERR
			"RDS/IB: inet_ioctl(SIOCSIFADDR,%s) failed (%d)\n",
			ir->ifr_ifrn.ifrn_name, ret);
	}

	ret = rds_ib_set_ip(out_dev, dev_addr, to_dev2, addr, bcast, mask);

	if (ret) {
		if (failover)
			printk(KERN_NOTICE
				"RDS/IP: failed to move IP %pI4 "
				"from %s to %s\n",
				&addr, from_dev2, to_dev2);
		else
			printk(KERN_NOTICE
				"RDS/IP: failed to move IP %pI4 "
				"from %s back to %s\n",
				&addr, from_dev2, to_dev2);
	} else {
		if (failover)
			printk(KERN_NOTICE
				"RDS/IB: IP %pI4 migrated over to %s\n",
				&addr, to_dev2);
		else
			printk(KERN_NOTICE
				"RDS/IB: IP %pI4 migrated back to %s\n",
				&addr, to_dev2);
	}

	kunmap(page);
	__free_page(page);

	return ret;
}

static void rds_ib_init_port(struct rds_ib_device *rds_ibdev,
				struct net_device *net_dev,
				u8 port_num)
{
	strcpy(rds_ibdev->ports[port_num].if_name, net_dev->name);
	rds_ibdev->ports[port_num].dev = net_dev;
	rds_ibdev->ports[port_num].ip_active_port = 0;

	if (net_dev->operstate == IF_OPER_UP)
		rds_ibdev->ports[port_num].port_state = RDS_IB_PORT_UP;
	else
		rds_ibdev->ports[port_num].port_state = RDS_IB_PORT_DOWN;
}

static void rds_ib_set_port(struct rds_ib_device *rds_ibdev,
				struct net_device *net_dev,
				char *if_name, u8 port_num,
				__be32 ip_addr,
				__be32 ip_bcast,
				__be32 ip_mask)
{
	unsigned int	idx;

	if (!strcmp(net_dev->name, if_name)) {
		strcpy(rds_ibdev->ports[port_num].if_name, if_name);
		rds_ibdev->ports[port_num].ip_addr = ip_addr;
		rds_ibdev->ports[port_num].ip_bcast = ip_bcast;
		rds_ibdev->ports[port_num].ip_mask = ip_mask;
		rds_ibdev->ports[port_num].ip_active_port = port_num;
	} else {
		idx = rds_ibdev->ports[port_num].alias_cnt++;
		strcpy(rds_ibdev->ports[port_num].
			aliases[idx].if_name, if_name);
		rds_ibdev->ports[port_num].
			aliases[idx].ip_addr = ip_addr;
		rds_ibdev->ports[port_num].
			aliases[idx].ip_bcast = ip_bcast;
		rds_ibdev->ports[port_num].
			aliases[idx].ip_mask = ip_mask;
	}
}

static void rds_ib_do_failover(struct rds_ib_device *rds_ibdev,
				u8 from_port,
				u8 to_port)
{
	u8      i, j;
	int	ret;

	for (i = 1; i <= rds_ibdev->dev->phys_port_cnt; i++) {
		if ((from_port != i &&
			i == rds_ibdev->ports[i].ip_active_port) ||
			i == to_port) {

			if (!rds_ib_move_ip(
				rds_ibdev->ports[i].dev,
				rds_ibdev->ports[i].dev->dev_addr,
				rds_ibdev->ports[from_port].if_name,
				rds_ibdev->ports[i].if_name,
				rds_ibdev->ports[from_port].ip_addr,
				rds_ibdev->ports[from_port].ip_bcast,
				rds_ibdev->ports[from_port].ip_mask,
				1)) {

				rds_ibdev->ports[from_port].ip_active_port = i;
				for (j = 0; j < rds_ibdev->ports[from_port].
					alias_cnt; j++) {

					ret = rds_ib_move_ip(
						rds_ibdev->ports[i].dev,
						rds_ibdev->ports[i].
							dev->dev_addr,
						rds_ibdev->ports[from_port].
							aliases[j].if_name,
						rds_ibdev->ports[i].if_name,
						rds_ibdev->ports[from_port].
							aliases[j].ip_addr,
						rds_ibdev->ports[from_port].
							aliases[j].ip_bcast,
						rds_ibdev->ports[from_port].
							aliases[j].ip_mask,
						1);
				}
				break;
			}
		}
	}
}

static void rds_ib_do_set_ip(struct rds_ib_device *rds_ibdev,
				u8 port)
{
	int     ret;
	u8      j;

	ret = rds_ib_set_ip(rds_ibdev->ports[port].dev,
			rds_ibdev->ports[port].dev->dev_addr,
			rds_ibdev->ports[port].if_name,
			rds_ibdev->ports[port].ip_addr,
			rds_ibdev->ports[port].ip_bcast,
			rds_ibdev->ports[port].ip_mask);

	for (j = 0; j < rds_ibdev->ports[port].alias_cnt; j++) {
		ret = rds_ib_set_ip(rds_ibdev->ports[port].dev,
				rds_ibdev->ports[port].dev->dev_addr,
				rds_ibdev->ports[port].aliases[j].if_name,
				rds_ibdev->ports[port].aliases[j].ip_addr,
				rds_ibdev->ports[port].aliases[j].ip_bcast,
				rds_ibdev->ports[port].aliases[j].ip_mask);
	}
}

static void rds_ib_do_failback(struct rds_ib_device *rds_ibdev,
				u8 port)
{
	u8      ip_active_port = rds_ibdev->ports[port].ip_active_port;
	u8      j;
	int     ret;

	if (port != rds_ibdev->ports[port].ip_active_port) {
		if (!rds_ib_move_ip(
			rds_ibdev->ports[ip_active_port].dev,
			rds_ibdev->ports[port].dev->dev_addr,
			rds_ibdev->ports[ip_active_port].if_name,
			rds_ibdev->ports[port].if_name,
			rds_ibdev->ports[port].ip_addr,
			rds_ibdev->ports[port].ip_bcast,
			rds_ibdev->ports[port].ip_mask,
			0)) {

			for (j = 0; j < rds_ibdev->ports[port].
				alias_cnt; j++) {

				ret = rds_ib_move_ip(
					rds_ibdev->ports[ip_active_port].dev,
					rds_ibdev->ports[port].
						dev->dev_addr,
					rds_ibdev->ports[ip_active_port].
						if_name,
					rds_ibdev->ports[port].
						aliases[j].if_name,
					rds_ibdev->ports[port].
						aliases[j].ip_addr,
					rds_ibdev->ports[port].
						aliases[j].ip_bcast,
					rds_ibdev->ports[port].
						aliases[j].ip_mask,
					0);
			}
		}
	}
}

static void rds_ib_failover(struct work_struct *_work)
{
	struct rds_ib_port_ud_work *work =
		container_of(_work, struct rds_ib_port_ud_work, work.work);
	struct rds_ib_device *rds_ibdev = work->rds_ibdev;
	int ret;

	if (rds_ibdev->ports[work->port].ip_addr)
		rds_ib_do_failover(rds_ibdev, work->port, 0);

	if (rds_ibdev->ports[work->port].ip_active_port == work->port) {
		ret = rds_ib_set_ip(rds_ibdev->ports[work->port].dev,
				rds_ibdev->ports[work->port].dev->dev_addr,
				rds_ibdev->ports[work->port].if_name,
				0, 0, 0);
	}

	kfree(work);
}

static void rds_ib_failback(struct work_struct *_work)
{
	struct rds_ib_port_ud_work *work =
		container_of(_work, struct rds_ib_port_ud_work, work.work);
	struct rds_ib_device *rds_ibdev = work->rds_ibdev;
	u8 i, port = work->port;
	struct in_device *in_dev;

	if (rds_ibdev->ports[port].ip_addr &&
		rds_ibdev->ports[port].ip_active_port != port) {

		rds_ib_do_failback(rds_ibdev, port);
	}

	rds_ibdev->ports[port].ip_active_port = port;
	in_dev = in_dev_get(rds_ibdev->ports[port].dev);

	for (i = 1; i <= rds_ibdev->dev->phys_port_cnt; i++) {
		if (rds_ibdev->ports[i].port_state == RDS_IB_PORT_DOWN &&
			i != port && rds_ibdev->ports[i].ip_addr) {

			if (rds_ibdev->ports[i].ip_active_port == i) {
				rds_ib_do_failover(rds_ibdev, i, 0);
			} else if (rds_ibdev->ports[i].ip_active_port == port) {
				if (in_dev && !in_dev->ifa_list &&
					rds_ibdev->ports[port].ip_addr) {

					rds_ib_do_set_ip(rds_ibdev, port);
				}

				rds_ib_do_failover(rds_ibdev, i, port);
			}
		}
	}

	kfree(work);
}

static void rds_ib_event_handler(struct ib_event_handler *handler,
				struct ib_event *event)
{
	struct rds_ib_device *rds_ibdev =
		container_of(handler, typeof(*rds_ibdev), event_handler);
	u8 port = event->element.port_num;
	struct rds_ib_port_ud_work *work;

	if (!rds_ib_haip_enabled)
		return;

	if (event->event != IB_EVENT_PORT_ACTIVE &&
		event->event != IB_EVENT_PORT_ERR)
		return;

	printk(KERN_NOTICE "RDS/IB: %s/port_%d/%s is %s\n",
		rds_ibdev->dev->name, port,
		rds_ibdev->ports[port].if_name,
		(event->event == IB_EVENT_PORT_ACTIVE) ?
			"ACTIVE" : "ERROR");

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work) {
		printk(KERN_ERR "RDS/IB: failed to allocate port work\n");
		return;
	}

	work->rds_ibdev = rds_ibdev;
	work->port = port;

	if (event->event == IB_EVENT_PORT_ACTIVE) {
		if (rds_ib_haip_fallback) {
			INIT_DELAYED_WORK(&work->work, rds_ib_failback);
			queue_delayed_work(rds_wq, &work->work, 0);
		} else
			kfree(work);
		rds_ibdev->ports[port].port_state = RDS_IB_PORT_UP;
	} else {
		INIT_DELAYED_WORK(&work->work, rds_ib_failover);
		queue_delayed_work(rds_wq, &work->work, 0);
		rds_ibdev->ports[port].port_state = RDS_IB_PORT_DOWN;
	}
}

static void rds_ib_check_down_port(void)
{
	struct rds_ib_device *rds_ibdev;
	struct rds_ib_port_ud_work *work;
	u8 i;

	list_for_each_entry(rds_ibdev, &rds_ib_devices, list) {
		for (i = 1; i <= rds_ibdev->dev->phys_port_cnt; i++) {
			if (rds_ibdev->ports[i].port_state != RDS_IB_PORT_UP &&
				rds_ibdev->ports[i].ip_addr) {
				printk(KERN_NOTICE
					"RDS/IB: port %s/%d is NOT UP\n",
					rds_ibdev->dev->name, i);

				work = kzalloc(sizeof *work, GFP_KERNEL);
				if (!work) {
					printk(KERN_ERR
						"RDS/IB: failed to allocate port work\n");
					return;
				}

				work->rds_ibdev = rds_ibdev;
				work->port = i;
				INIT_DELAYED_WORK(&work->work, rds_ib_failover);				queue_delayed_work(rds_wq, &work->work, 0);
			}
		}
	}
	flush_workqueue(rds_wq);
}

static void rds_ib_dump_ip_config(void)
{
	struct rds_ib_device *rds_ibdev;
	int i, j;

	if (!rds_ib_haip_enabled)
		return;

	printk(KERN_ERR "RDS/IB: IP configuration ...\n");
	list_for_each_entry(rds_ibdev, &rds_ib_devices, list) {
		for (i = 1; i <= rds_ibdev->dev->phys_port_cnt; i++) {
			printk(KERN_ERR "RDS/IB: %s/port_%d/%s: "
				"IP %pI4/%pI4/%pI4 "
				"state %s\n",
				rds_ibdev->dev->name, i,
				rds_ibdev->ports[i].if_name,
				&rds_ibdev->ports[i].ip_addr,
				&rds_ibdev->ports[i].ip_bcast,
				&rds_ibdev->ports[i].ip_mask,
				(rds_ibdev->ports[i].port_state == RDS_IB_PORT_UP ? "UP" : "DOWN"));

			for (j = 0; j < rds_ibdev->ports[i].alias_cnt; j++) {
				printk(KERN_ERR "Alias %s "
					"IP %pI4/%pI4/%pI4\n",
					rds_ibdev->ports[i].aliases[j].if_name,
					&rds_ibdev->ports[i].aliases[j].ip_addr,
					&rds_ibdev->ports[i].aliases[j].ip_bcast,
					&rds_ibdev->ports[i].aliases[j].ip_mask);
			}
		}
	}
}

static int rds_ib_setup_ports(void)
{
	struct net_device *dev;
	struct in_ifaddr *ifa;
	struct in_ifaddr **ifap;
	struct in_device *in_dev;
	struct rds_ib_device *rds_ibdev;
	u8      port_num;
	int     ret = 0;

	if (!rds_ib_haip_enabled)
		return ret;

	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, dev) {
		in_dev = in_dev_get(dev);
		if ((dev->type == ARPHRD_INFINIBAND) &&
			!(dev->flags & IFF_SLAVE) &&
			!(dev->flags & IFF_MASTER) &&
			in_dev) {
			union ib_gid gid;

			memcpy(&gid, dev->dev_addr + 4, sizeof gid);

			rcu_read_lock();
			list_for_each_entry_rcu(rds_ibdev,
					&rds_ib_devices, list) {
				ret = ib_find_cached_gid(rds_ibdev->dev, &gid,
							 IB_GID_TYPE_IB, NULL,
							 &port_num, NULL);
				if (!ret)
					break;
			}
			rcu_read_unlock();

			if (!port_num) {
				printk(KERN_ERR "RDS/IB: GID "RDS_IB_GID_FMT
					" has no associated port\n",
					RDS_IB_GID_ARG(gid));
				ret = 1;
				goto out;
			}

			rds_ib_init_port(rds_ibdev, dev, port_num);

			for (ifap = &in_dev->ifa_list; (ifa = *ifap);
				ifap = &ifa->ifa_next) {
				rds_ib_set_port(rds_ibdev, dev,
					ifa->ifa_label, port_num,
					ifa->ifa_address,
					ifa->ifa_broadcast,
					ifa->ifa_mask);
			}
		}
	}

	rds_ib_check_down_port();
	rds_ib_dump_ip_config();
out:
	read_unlock(&dev_base_lock);
	return ret;
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
		rdsdebug("Query device failed for %s\n", device->name);
		goto free_attr;
	}

	rds_ibdev = kzalloc_node(sizeof(struct rds_ib_device), GFP_KERNEL,
				ibdev_to_node(device));
	if (!rds_ibdev)
		goto free_attr;

	spin_lock_init(&rds_ibdev->spinlock);
	atomic_set(&rds_ibdev->refcount, 1);
	INIT_WORK(&rds_ibdev->free_work, rds_ib_dev_free);

	rds_ibdev->max_wrs = dev_attr->max_qp_wr;
	rds_ibdev->max_sge = min(dev_attr->max_sge, RDS_IB_MAX_SGE);

	rds_ibdev->fmr_max_remaps = dev_attr->max_map_per_fmr?: 32;

	rds_ibdev->max_1m_fmrs = dev_attr->max_fmr ?
		min_t(unsigned int, dev_attr->max_fmr,
			RDS_FMR_1M_POOL_SIZE) :
			RDS_FMR_1M_POOL_SIZE;

	rds_ibdev->max_8k_fmrs = dev_attr->max_fmr ?
		min_t(unsigned int, dev_attr->max_fmr,
			RDS_FMR_8K_POOL_SIZE) :
			RDS_FMR_8K_POOL_SIZE;

	rds_ibdev->max_initiator_depth = dev_attr->max_qp_init_rd_atom;
	rds_ibdev->max_responder_resources = dev_attr->max_qp_rd_atom;

	rds_ibdev->dev = device;
	rds_ibdev->pd = ib_alloc_pd(device, 0);
	if (IS_ERR(rds_ibdev->pd)) {
		rds_ibdev->pd = NULL;
		goto put_dev;
	}

	if (rds_ib_haip_enabled) {
		rds_ibdev->ports = kzalloc(sizeof(struct rds_ib_port) *
					(device->phys_port_cnt + 1), GFP_KERNEL);
		if (!rds_ibdev->ports) {
			printk(KERN_ERR
				"RDS/IB: failed to allocate ports\n");
			goto put_dev;
		}

		INIT_IB_EVENT_HANDLER(&rds_ibdev->event_handler,
				rds_ibdev->dev, rds_ib_event_handler);
		ib_register_event_handler(&rds_ibdev->event_handler);
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

	rds_ibdev->srq = kmalloc(sizeof(struct rds_ib_srq), GFP_KERNEL);
	if (!rds_ibdev->srq)
		goto free_attr;

	INIT_LIST_HEAD(&rds_ibdev->ipaddr_list);
	INIT_LIST_HEAD(&rds_ibdev->conn_list);

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
}

void rds_ib_exit(void)
{
	rds_info_deregister_func(RDS_INFO_IB_CONNECTIONS, rds_ib_ic_info);
	rds_ib_unregister_client();
	rds_ib_destroy_nodev_conns();
	rds_ib_sysctl_exit();
	rds_ib_srqs_exit();
	rds_ib_recv_exit();
	rds_trans_unregister(&rds_ib_transport);
	rds_ib_fmr_exit();
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
	.cm_initiate_connect	= rds_ib_cm_initiate_connect,
	.cm_handle_connect	= rds_ib_cm_handle_connect,
	.cm_connect_complete	= rds_ib_cm_connect_complete,
	.stats_info_copy	= rds_ib_stats_info_copy,
	.exit			= rds_ib_exit,
	.get_mr			= rds_ib_get_mr,
	.sync_mr		= rds_ib_sync_mr,
	.free_mr		= rds_ib_free_mr,
	.flush_mrs		= rds_ib_flush_mrs,
	.check_migration        = rds_ib_check_migration,
	.t_owner		= THIS_MODULE,
	.t_name			= "infiniband",
	.t_type			= RDS_TRANS_IB
};

static int rds_ib_netdev_callback(struct notifier_block *self, unsigned long event, void *ctx)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ctx);
	u8 port = 0;
	u8 i;
	struct rds_ib_device	*rds_ibdev;
	struct rds_ib_port_ud_work *work;

	if (!rds_ib_haip_enabled)
		return NOTIFY_DONE;

	if (event != NETDEV_UP && event != NETDEV_DOWN)
		return NOTIFY_DONE;

	rcu_read_lock();
	list_for_each_entry(rds_ibdev, &rds_ib_devices, list) {
		for (i = 1; i <= rds_ibdev->dev->phys_port_cnt; i++) {
			if (!strcmp(ndev->name,
				rds_ibdev->ports[i].if_name)) {
					port = i;
					goto out;
				}
		}
	}
	rcu_read_unlock();
out:
	if (!port)
		return NOTIFY_DONE;


	printk(KERN_NOTICE "RDS/IB: %s/port_%d/%s is %s\n",
		rds_ibdev->dev->name, port, ndev->name,
		(event == NETDEV_UP) ? "UP" : "DOWN");

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work) {
		printk(KERN_ERR "RDS/IB: failed to allocate port work\n");
		return NOTIFY_DONE;
	}

	work->rds_ibdev = rds_ibdev;
	work->dev = ndev;
	work->port = port;

	switch (event) {
	case NETDEV_UP:
		if (rds_ib_haip_fallback) {
			INIT_DELAYED_WORK(&work->work, rds_ib_failback);
			queue_delayed_work(rds_wq, &work->work, msecs_to_jiffies(100));
		} else
			kfree(work);

		rds_ibdev->ports[port].port_state = NETDEV_UP;
		break;
	case NETDEV_DOWN:
		INIT_DELAYED_WORK(&work->work, rds_ib_failover);
		queue_delayed_work(rds_wq, &work->work, 0);
		rds_ibdev->ports[port].port_state = RDS_IB_PORT_DOWN;
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

	ret = ib_register_client(&rds_ib_client);
	if (ret)
		goto out_fmr_exit;

	ret = rds_ib_sysctl_init();
	if (ret)
		goto out_ibreg;

	ret = rds_ib_recv_init();
	if (ret)
		goto out_sysctl;

	ret = rds_ib_srqs_init();
	if (ret) {
		printk(KERN_ERR "RDS/IB: Failed to init SRQ\n");
		goto out_recv;
	}

	ret = rds_trans_register(&rds_ib_transport);
	if (ret)
		goto out_srq;

	rds_info_register_func(RDS_INFO_IB_CONNECTIONS, rds_ib_ic_info);

	ret = rds_ib_setup_ports();
	if (ret) {
		printk(KERN_ERR "RDS/IB: failed to init port\n");
		goto out_srq;
	}

	rds_aux_wq = create_singlethread_workqueue("krdsd_aux");
	if (!rds_aux_wq) {
		printk(KERN_ERR "RDS/IB: failed to create aux workqueue\n");
		goto out_srq;
	}

	register_netdevice_notifier(&rds_ib_nb);

	goto out;

out_srq:
	rds_ib_srqs_exit();
out_recv:
	rds_ib_recv_exit();
out_sysctl:
	rds_ib_sysctl_exit();
out_ibreg:
	rds_ib_unregister_client();
out_fmr_exit:
	rds_ib_fmr_exit();
out:
	return ret;
}

MODULE_LICENSE("GPL");

