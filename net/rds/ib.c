/*
 * Copyright (c) 2006, 2019 Oracle and/or its affiliates. All rights reserved.
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
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <net/addrconf.h>
#include <net/inet_common.h>

#include "ib.h"
#include "rds_single_path.h"

unsigned int rds_ib_fmr_1m_pool_size = RDS_FMR_1M_POOL_SIZE;
unsigned int rds_ib_fmr_8k_pool_size = RDS_FMR_8K_POOL_SIZE;
unsigned int rds_ib_retry_count = RDS_IB_DEFAULT_RETRY_COUNT;
bool prefer_frwr;
unsigned int rds_ib_rnr_retry_count = RDS_IB_DEFAULT_RNR_RETRY_COUNT;

module_param(rds_ib_fmr_1m_pool_size, int, 0444);
MODULE_PARM_DESC(rds_ib_fmr_1m_pool_size, " Max number of 1m fmr per HCA");
module_param(rds_ib_fmr_8k_pool_size, int, 0444);
MODULE_PARM_DESC(rds_ib_fmr_8k_pool_size, " Max number of 8k fmr per HCA");
module_param(rds_ib_retry_count, int, 0444);
MODULE_PARM_DESC(rds_ib_retry_count, " Number of hw retries before reporting an error");
module_param(prefer_frwr, bool, 0444);
MODULE_PARM_DESC(prefer_frwr, "Preference of FRWR over FMR for memory registration(Y/N)");
module_param(rds_ib_rnr_retry_count, int, 0444);
MODULE_PARM_DESC(rds_ib_rnr_retry_count, " QP rnr retry count");

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

static struct socket *rds_rdma_rtnl_sk;

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
		rds_conn_drop(ic->conn, DR_IB_UMMOD);
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
	if (rds_ibdev->use_fastreg) {
		cancel_work_sync(&rds_ibdev->fastreg_reset_w);
		down_write(&rds_ibdev->fastreg_lock);
		rds_ib_destroy_fastreg(rds_ibdev);
	}
	if (rds_ibdev->mr)
		ib_dereg_mr(rds_ibdev->mr);
	if (rds_ibdev->pd)
		ib_dealloc_pd(rds_ibdev->pd);
	if (rds_ibdev->rid_hdrs_pool)
		dma_pool_destroy(rds_ibdev->rid_hdrs_pool);
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

	rds_rtd(RDS_RTD_RDMA_IB, "Removing ib_device: %p name: %s num_ports: %u\n",
		device, device->name, device->phys_port_cnt);

	rds_ibdev = ib_get_client_data(device, &rds_ib_client);
	if (!rds_ibdev) {
		rds_rtd(RDS_RTD_ACT_BND, "rds_ibdev is NULL, ib_device %p\n",
			device);
		return;
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

/* Remove IB connection information.  This function only reports IPv4
 * connections for backward compatibility.
 */
static int rds_ib_conn_info_visitor(struct rds_connection *conn,
				    void *buffer)
{
	struct rds_info_rdma_connection *iinfo = buffer;
	struct rds_ib_connection *ic = conn->c_transport_data;

	/* We will only ever look at IB transports */
	if (conn->c_trans != &rds_ib_transport)
		return 0;
	if (conn->c_isv6)
		return 0;

	iinfo->src_addr = conn->c_laddr.s6_addr32[3];
	iinfo->dst_addr = conn->c_faddr.s6_addr32[3];

	memset(&iinfo->src_gid, 0, sizeof(iinfo->src_gid));
	memset(&iinfo->dst_gid, 0, sizeof(iinfo->dst_gid));

	if (ic) {
		iinfo->tos = conn->c_tos;
		iinfo->sl = ic->i_sl;
		iinfo->frag = ic->i_frag_sz;
	}

	if (rds_conn_state(conn) == RDS_CONN_UP) {
		struct rds_ib_device *rds_ibdev;

		rdma_read_gids(ic->i_cm_id, (union ib_gid *)&iinfo->src_gid,
			       (union ib_gid *)&iinfo->dst_gid);

		rds_ibdev = ic->rds_ibdev;
		iinfo->max_send_wr = ic->i_send_ring.w_nr;
		iinfo->max_recv_wr = ic->i_recv_ring.w_nr;
		iinfo->max_send_sge = rds_ibdev->max_sge;
		iinfo->qp_num = ic->i_cm_id->qp->qp_num;
		iinfo->w_alloc_ctr = ic->i_recv_ring.w_alloc_ctr;
		iinfo->w_free_ctr =
			(u32)atomic_read(&ic->i_recv_ring.w_free_ctr);
		iinfo->flow_ctl_post_credit =
			IB_GET_POST_CREDITS(atomic_read(&ic->i_credits));
		iinfo->flow_ctl_send_credit =
			IB_GET_SEND_CREDITS(atomic_read(&ic->i_credits));
		rds_ib_get_mr_info(rds_ibdev, iinfo);
		iinfo->cache_allocs = atomic_read(&ic->i_cache_allocs);
	}
	return 1;
}

#if IS_ENABLED(CONFIG_IPV6)
/* IPv6 version of rds_ib_conn_info_visitor(). */
static int rds6_ib_conn_info_visitor(struct rds_connection *conn,
				     void *buffer)
{
	struct rds6_info_rdma_connection *iinfo6 = buffer;
	struct rds_ib_connection *ic = conn->c_transport_data;

	/* We will only ever look at IB transports */
	if (conn->c_trans != &rds_ib_transport)
		return 0;

	iinfo6->src_addr = conn->c_laddr;
	iinfo6->dst_addr = conn->c_faddr;

	memset(&iinfo6->src_gid, 0, sizeof(iinfo6->src_gid));
	memset(&iinfo6->dst_gid, 0, sizeof(iinfo6->dst_gid));

	if (ic) {
		iinfo6->tos = conn->c_tos;
		iinfo6->sl = ic->i_sl;
		iinfo6->frag = ic->i_frag_sz;
	}

	if (rds_conn_state(conn) == RDS_CONN_UP) {
		struct rds_ib_device *rds_ibdev;

		rdma_read_gids(ic->i_cm_id, (union ib_gid *)&iinfo6->src_gid,
			       (union ib_gid *)&iinfo6->dst_gid);
		rds_ibdev = ic->rds_ibdev;
		iinfo6->max_send_wr = ic->i_send_ring.w_nr;
		iinfo6->max_recv_wr = ic->i_recv_ring.w_nr;
		iinfo6->max_send_sge = rds_ibdev->max_sge;
		iinfo6->qp_num = ic->i_cm_id->qp->qp_num;
		iinfo6->w_alloc_ctr = ic->i_recv_ring.w_alloc_ctr;
		iinfo6->w_free_ctr =
			(u32)atomic_read(&ic->i_recv_ring.w_free_ctr);
		iinfo6->flow_ctl_post_credit =
			IB_GET_POST_CREDITS(atomic_read(&ic->i_credits));
		iinfo6->flow_ctl_send_credit =
			IB_GET_SEND_CREDITS(atomic_read(&ic->i_credits));
		rds6_ib_get_mr_info(rds_ibdev, iinfo6);
		iinfo6->cache_allocs = atomic_read(&ic->i_cache_allocs);
	}
	return 1;
}
#endif

static void rds_ib_ic_info(struct socket *sock, unsigned int len,
			   struct rds_info_iterator *iter,
			   struct rds_info_lengths *lens)
{
	u64 buffer[(sizeof(struct rds_info_rdma_connection) + 7) / 8];

	rds_for_each_conn_info(sock, len, iter, lens,
			       rds_ib_conn_info_visitor, buffer,
			       sizeof(struct rds_info_rdma_connection));
}

#if IS_ENABLED(CONFIG_IPV6)
/* IPv6 version of rds_ib_ic_info(). */
static void rds6_ib_ic_info(struct socket *sock, unsigned int len,
			    struct rds_info_iterator *iter,
			    struct rds_info_lengths *lens)
{
	u64 buffer[(sizeof(struct rds6_info_rdma_connection) + 7) / 8];

	rds_for_each_conn_info(sock, len, iter, lens,
			       rds6_ib_conn_info_visitor, buffer,
			       sizeof(struct rds6_info_rdma_connection));
}
#endif

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
static int rds_ib_laddr_check(struct net *net, const struct in6_addr *addr,
			      __u32 scope_id)
{
	int ret;
	struct rds_ib_connection dummy_ic;
	struct rdma_cm_id *cm_id;
#if IS_ENABLED(CONFIG_IPV6)
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr_in sin;
	struct sockaddr *sa;
	bool isv4;

	isv4 = ipv6_addr_v4mapped(addr);
	/* Link-local addresses don't play well with IB */
	if (isv4 && ipv4_is_linklocal_169(addr->s6_addr32[3])) {
		pr_info_once("\n");
		pr_info_once("****************************************************\n");
		pr_info_once("** WARNING WARNING WARNING WARNING WARNING        **\n");
		pr_info_once("**                                                **\n");
		pr_info_once("** RDS/IB: Link local address %pI6c NOT SUPPORTED  **\n",
			     addr);
		pr_info_once("**                                                **\n");
		pr_info_once("** HAIP IP addresses should not be used on ORACLE **\n");
		pr_info_once("** engineered systems                             **\n");
		pr_info_once("**                                                **\n");
		pr_info_once("** If you see this message, Please refer to       **\n");
		pr_info_once("** cluster_interconnects in MOS note #1274318.1   **\n");
		pr_info_once("****************************************************\n");
	}

	/* Create a CMA ID and try to bind it. This catches both
	 * IB and iWARP capable NICs.
	 */
	cm_id = rds_ib_rdma_create_id(net, rds_rdma_cm_event_handler, &dummy_ic,
				      NULL, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(cm_id))
		return -EADDRNOTAVAIL;

	if (isv4) {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = addr->s6_addr32[3];
		sa = (struct sockaddr *)&sin;
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = *addr;
		sin6.sin6_scope_id = scope_id;
		sa = (struct sockaddr *)&sin6;

		/* XXX Do a special IPv6 link local address check here.  The
		 * reason is that rdma_bind_addr() always succeeds with IPv6
		 * link local address regardless if it is configured or not in
		 * a system.
		 */
		if (ipv6_addr_type(addr) & IPV6_ADDR_LINKLOCAL) {
			struct net_device *dev;

			if (scope_id == 0) {
				ret = -EADDRNOTAVAIL;
				goto out;
			}

			/* Use init_net for now as RDS is not network
			 * name space aware.
			 */
			dev = dev_get_by_index(&init_net, scope_id);
			if (!dev) {
				ret = -EADDRNOTAVAIL;
				goto out;
			}
			if (!ipv6_chk_addr(&init_net, addr, dev, 1)) {
				dev_put(dev);
				ret = -EADDRNOTAVAIL;
				goto out;
			}
			dev_put(dev);
		}
#else
		ret = -EADDRNOTAVAIL;
		goto out;
#endif
	}

	/* rdma_bind_addr will only succeed for IB & iWARP devices */
	ret = rdma_bind_addr(cm_id, sa);
	/* due to this, we will claim to support iWARP devices unless we
	   check node_type. */
	if (ret || !cm_id->device || cm_id->device->node_type != RDMA_NODE_IB_CA)
		ret = -EADDRNOTAVAIL;

	rdsdebug("addr %pI6c%%%u ret %d node type %d\n",
		 addr, scope_id, ret,
		 cm_id->device ? cm_id->device->node_type : -1);

out:
	rds_ib_rdma_destroy_id(cm_id);

	return ret;
}

/* Detect possible link-layers in order to flush ARP correctly */
static void detect_link_layers(struct ib_device *ibdev)
{
	if (ibdev->get_link_layer) {
		u8 port;

		for (port = 1; port <= ibdev->phys_port_cnt; ++port) {
			switch (ibdev->get_link_layer(ibdev, port)) {
			case IB_LINK_LAYER_UNSPECIFIED:
				rds_ib_transport.t_ll_ib_detected = true;
				rds_ib_transport.t_ll_eth_detected = true;
				break;

			case IB_LINK_LAYER_INFINIBAND:
				rds_ib_transport.t_ll_ib_detected = true;
				break;

			case IB_LINK_LAYER_ETHERNET:
				rds_ib_transport.t_ll_eth_detected = true;
				break;
			}
		}
	} else {
		rds_ib_transport.t_ll_ib_detected = true;
		rds_ib_transport.t_ll_eth_detected = true;
	}
}

void rds_ib_add_one(struct ib_device *device)
{
	struct rds_ib_device *rds_ibdev;
	struct ib_device_attr *dev_attr;
	bool has_frwr, has_fmr;

	rds_rtd(RDS_RTD_RDMA_IB,
		"Adding ib_device: %p name: %s num_ports: %u\n",
		device, device->name, device->phys_port_cnt);

	/* Only handle IB (no iWARP) devices */
	if (device->node_type != RDMA_NODE_IB_CA)
		return;

	detect_link_layers(device);

	dev_attr = kmalloc(sizeof(*dev_attr), GFP_KERNEL);
	if (!dev_attr)
		return;

	if (ib_query_device(device, dev_attr)) {
		rds_rtd(RDS_RTD_ERR, "Query device failed for %s\n",
			device->name);
		goto free_attr;
	}

	rds_ibdev = kzalloc_node(sizeof(*rds_ibdev), GFP_KERNEL,
				 ibdev_to_node(device));
	if (!rds_ibdev)
		goto free_attr;

	INIT_LIST_HEAD(&rds_ibdev->ipaddr_list);
	INIT_LIST_HEAD(&rds_ibdev->conn_list);

	atomic_set(&rds_ibdev->free_dev, 1);
	mutex_init(&rds_ibdev->free_dev_lock);
	spin_lock_init(&rds_ibdev->spinlock);
	atomic_set(&rds_ibdev->refcount, 1);
	INIT_WORK(&rds_ibdev->free_work, rds_ib_dev_free);

	rds_ibdev->max_wrs = dev_attr->max_qp_wr;
	rds_ibdev->max_sge = min(dev_attr->max_sge, RDS_IB_MAX_SGE);

	WARN_ON(rds_ibdev->max_sge < 2);
	rds_ibdev->fmr_max_remaps = dev_attr->max_map_per_fmr ?: 32;

	rds_ibdev->max_1m_fmrs = dev_attr->max_mr ?
		min_t(unsigned int, dev_attr->max_mr,
		      rds_ib_fmr_1m_pool_size) :
		      rds_ib_fmr_1m_pool_size;

	rds_ibdev->max_8k_fmrs = dev_attr->max_mr ?
		min_t(unsigned int, dev_attr->max_mr,
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
	rds_ibdev->rid_hdrs_pool = dma_pool_create(device->name,
						   device->dma_device,
						   sizeof(struct rds_header),
						   L1_CACHE_BYTES, 0);
	if (!rds_ibdev->rid_hdrs_pool)
		goto put_dev;

	rds_ibdev->vector_load = kzalloc(sizeof(int) *
					device->num_comp_vectors, GFP_KERNEL);
	if (!rds_ibdev->vector_load) {
		pr_err("RDS/IB: failed to allocate vector memory\n");
		goto put_dev;
	}
	mutex_init(&rds_ibdev->vector_load_lock);

	rds_ibdev->mr = ib_get_dma_mr(rds_ibdev->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(rds_ibdev->mr)) {
		rds_ibdev->mr = NULL;
		goto put_dev;
	}

	has_frwr = (dev_attr->device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS);
	has_fmr = (device->alloc_fmr && device->dealloc_fmr &&
		   device->map_phys_fmr && device->unmap_fmr);
	rds_ibdev->use_fastreg = (has_frwr && (!has_fmr || prefer_frwr));

	pr_info("RDS/IB: %s will be used for ib_device: %s\n",
		rds_ibdev->use_fastreg ? "FRWR" : "FMR", device->name);

	if (rds_ibdev->use_fastreg) {
		INIT_WORK(&rds_ibdev->fastreg_reset_w, rds_ib_reset_fastreg);
		init_rwsem(&rds_ibdev->fastreg_lock);
		atomic_set(&rds_ibdev->fastreg_wrs, RDS_IB_DEFAULT_FREG_WR);
		if (rds_ib_setup_fastreg(rds_ibdev)) {
			pr_err("RDS/IB: Failed to setup fastreg resources\n");
			goto put_dev;
		}
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
	int i;

	ib_unregister_client(&rds_ib_client);
	flush_workqueue(rds_wq);

	for (i = 0; i < RDS_NMBR_CP_WQS; ++i)
		flush_workqueue(rds_cp_wqs[i]);
}

int rds_ib_init(void)
{
	int ret;

	INIT_LIST_HEAD(&rds_ib_devices);

	ret = sock_create_kern(&init_net, PF_NETLINK, SOCK_RAW, NETLINK_ROUTE,
			       &rds_rdma_rtnl_sk);
	if (ret < 0) {
		pr_err("RDS/IB: can't create netlink socket (%d).\n", -ret);
		goto out;
	}

	/* Initialise the RDS IB fragment size */
	rds_ib_init_frag(RDS_PROTOCOL_VERSION);

	ret = rds_ib_fmr_init();
	if (ret)
		goto kernel_sock;

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
		pr_err("RDS/IB: failed to create aux workqueue\n");
		goto out_ibreg;
	}

	ret = rds_trans_register(&rds_ib_transport);
	if (ret)
		goto out_aux_wq;

	rds_info_register_func(RDS_INFO_IB_CONNECTIONS, rds_ib_ic_info);
#if IS_ENABLED(CONFIG_IPV6)
	rds_info_register_func(RDS6_INFO_IB_CONNECTIONS, rds6_ib_ic_info);
#endif

	goto out;

out_aux_wq:
	destroy_workqueue(rds_aux_wq);
out_ibreg:
	rds_ib_unregister_client();
out_recv:
	rds_ib_recv_exit();
out_sysctl:
	rds_ib_sysctl_exit();
out_fmr_exit:
	rds_ib_fmr_exit();
kernel_sock:
	sock_release(rds_rdma_rtnl_sk);
	rds_rdma_rtnl_sk = NULL;
out:
	return ret;
}


void rds_ib_exit(void)
{
	rds_info_deregister_func(RDS_INFO_IB_CONNECTIONS, rds_ib_ic_info);
#if IS_ENABLED(CONFIG_IPV6)
	rds_info_deregister_func(RDS6_INFO_IB_CONNECTIONS, rds6_ib_ic_info);
#endif
	rds_ib_unregister_client();
	rds_ib_destroy_nodev_conns();
	rds_ib_sysctl_exit();
	rds_ib_recv_exit();
	destroy_workqueue(rds_aux_wq);
	rds_trans_unregister(&rds_ib_transport);
	rds_ib_fmr_exit();

	if (rds_rdma_rtnl_sk) {
		sock_release(rds_rdma_rtnl_sk);
		rds_rdma_rtnl_sk = NULL;
	}
}

struct rds_transport rds_ib_transport = {
	.laddr_check		= rds_ib_laddr_check,
	.xmit_path_complete	= rds_ib_xmit_path_complete,
	.xmit			= rds_ib_xmit,
	.xmit_rdma		= rds_ib_xmit_rdma,
	.xmit_atomic		= rds_ib_xmit_atomic,
	.recv_path		= rds_ib_recv_path,
	.conn_alloc		= rds_ib_conn_alloc,
	.conn_free		= rds_ib_conn_free,
	.conn_path_connect	= rds_ib_conn_path_connect,
	.conn_path_shutdown	= rds_ib_conn_path_shutdown,
	.inc_copy_to_user	= rds_ib_inc_copy_to_user,
	.inc_free		= rds_ib_inc_free,
	.inc_to_skb		= rds_ib_inc_to_skb,
	.skb_local		= rds_skb_local,
	.cm_initiate_connect	= rds_ib_cm_initiate_connect,
	.cm_handle_connect	= rds_ib_cm_handle_connect,
	.cm_connect_complete	= rds_ib_cm_connect_complete,
	.stats_info_copy	= rds_ib_stats_info_copy,
	.get_mr			= rds_ib_get_mr,
	.sync_mr		= rds_ib_sync_mr,
	.free_mr		= rds_ib_free_mr,
	.flush_mrs		= rds_ib_flush_mrs,
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
	struct scatterlist *sg;

	/* pull out initial pointers */
	ibinc  = container_of(inc, struct rds_ib_incoming, ii_inc);
	ibfrag = list_entry(ibinc->ii_frags.next, struct rds_page_frag, f_item);
	len    = be32_to_cpu(inc->i_hdr.h_len);
	sg     = ibfrag->f_sg;
	slen   = len;
	i      = 0;

	/* run through the entire ib fragment list and save off the buffers */
	while (NULL != ibfrag && slen > 0) {
		/* one to one mapping of frags to sg structures */
		frag = &skb_shinfo(skb)->frags[i];
		/* save off all the sg pieces to the skb frags we are creating */
		frag->size        = sg->length;
		frag->page_offset = sg->offset;
		frag->page.p      = sg_page(sg);

		/* AA:  do we need to bump up the page reference */
		/* get_page(frag->page); */

		/* dec the amount of data we are consuming */
		slen -= frag->size;

		sg  = sg_next(sg);
		if (!sg) {
			/* bump to the next entry */
			ibfrag = list_entry(ibfrag->f_item.next, struct rds_page_frag, f_item);
			sg = ibfrag->f_sg;
		}
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

/* How long the same cache can be flushed again (in msec). */
static unsigned int neigh_flush_interval = 750;

/* Should be large enough to hold the flush message. */
static unsigned int flush_buf_len = 48;

/* Given an rds_connection, flush the peer address' neighbor cache entry.
 * If the peer is not in the same network as us, nothing will be flushed.
 *
 * @net: the connection's namespace
 * @conn: pointer to the connection
 */
void rds_ib_flush_neigh(struct net *net,
			struct rds_connection *conn)
{
	struct sockaddr_nl nlsa = { .nl_family = AF_NETLINK };
	static struct in6_addr last_laddr = { { { 0 } } };
	static struct in6_addr last_faddr = { { { 0 } } };
	static DEFINE_SPINLOCK(last_lock);
	u8 buf[flush_buf_len], *sndbuf;
	const struct in6_addr *laddr;
	const struct in6_addr *faddr;
	static u64 last_jiffies = 1;
	struct msghdr msg = { 0 };
	struct nlmsghdr *nlh;
	unsigned long flags;
	struct nlattr *nla;
	struct ndmsg *ndm;
	bool isv4, alloc;
	struct kvec vec;
	size_t buflen;
	int addrlen;
	int ret;
	int idx;

	laddr = &conn->c_laddr;
	faddr = &conn->c_faddr;

	/* Should not flush the same cache again and again.  This can happen
	 * when an interface is brought down so that all the connections
	 * (say with different TOS hence same local/peer address pair) using
	 * that interface are notified.  This is just a small optimization as
	 * only the last flushed pair is remembered.
	 */
	spin_lock_irqsave(&last_lock, flags);
	if (ipv6_addr_equal(laddr, &last_laddr) &&
	    ipv6_addr_equal(faddr, &last_faddr) &&
	    jiffies_to_msecs(get_jiffies_64() - last_jiffies) <
	    neigh_flush_interval) {
		spin_unlock_irqrestore(&last_lock, flags);
		return;
	}

	last_laddr = *laddr;
	last_faddr = *faddr;
	last_jiffies = get_jiffies_64();
	spin_unlock_irqrestore(&last_lock, flags);

	isv4 = ipv6_addr_v4mapped(faddr);
	/* Use our local address to find the right interface to flush the
	 * neighbor address.
	 */
	if (isv4) {
		idx = __rds_find_ifindex_v4(net, laddr->s6_addr32[3]);
		addrlen = sizeof(faddr->s6_addr32[3]);
	} else {
		idx = __rds_find_ifindex_v6(net, laddr);
		addrlen = sizeof(*faddr);
	}

	if (!idx) {
		pr_err_ratelimited("%s: cannot find %pI6c interface\n",
				   __func__, laddr);
		return;
	}

	buflen = nlmsg_total_size(sizeof(*ndm) +
				  nla_total_size(addrlen));
	if (buflen > sizeof(buf)) {
		flush_buf_len = buflen;
		sndbuf = kmalloc(buflen, GFP_ATOMIC);
		if (!sndbuf) {
			last_jiffies = 1;
			pr_err("%s: failed: buflen %zd idx %d %pI6c,%pI6c\n",
			       __func__, buflen, idx, laddr, faddr);
			return;
		}
		alloc = true;
	} else {
		sndbuf = buf;
		alloc = false;
	}

	nlh = (struct nlmsghdr *)sndbuf;
	ndm = nlmsg_data(nlh);
	nla = (struct nlattr *)((u8 *)ndm + NLMSG_ALIGN(sizeof(*ndm)));
	nlh->nlmsg_len = buflen;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = RTM_DELNEIGH;
	ndm->ndm_family = isv4 ? AF_INET : AF_INET6;
	ndm->ndm_ifindex = idx;
	ndm->ndm_state = NUD_PERMANENT;
	ndm->ndm_flags = 0;
	nla->nla_type = NDA_DST;
	nla->nla_len = nla_attr_size(addrlen);
	if (isv4)
		memcpy(nla_data(nla), &faddr->s6_addr32[3], addrlen);
	else
		memcpy(nla_data(nla), faddr, addrlen);

	msg.msg_name = &nlsa;
	msg.msg_namelen = sizeof(nlsa);
	vec.iov_base = (void *)sndbuf;
	vec.iov_len = nlh->nlmsg_len;

	ret = kernel_sendmsg(rds_rdma_rtnl_sk, &msg, &vec, 1, vec.iov_len);
	if (ret < 0)
		pr_err("%s: kernel_sendmsg %d\n", __func__, ret);

	if (alloc)
		kfree(sndbuf);
}

MODULE_LICENSE("GPL");
