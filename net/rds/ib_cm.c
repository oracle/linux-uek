/*
 * Copyright (c) 2006, 2021 Oracle and/or its affiliates.
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
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/cacheinfo.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/kconfig.h>
#include <linux/sizes.h>
#include <rdma/rdma_cm_ib.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_cm.h>
#include <net/addrconf.h>

#include "trace.h"

#include "rds.h"
#include "ib.h"
#include "rds_single_path.h"

static unsigned int rds_ib_max_frag = RDS_MAX_FRAG_SIZE;
static unsigned int ib_init_frag_size = RDS_FRAG_SIZE;

module_param(rds_ib_max_frag, int, 0444);
MODULE_PARM_DESC(rds_ib_max_frag, " RDS IB maximum fragment size");

static char *rds_ib_event_type_strings[] = {
#define RDS_IB_EVENT_STRING(foo) \
		[IB_EVENT_##foo] = __stringify(IB_EVENT_##foo)
	RDS_IB_EVENT_STRING(CQ_ERR),
	RDS_IB_EVENT_STRING(QP_FATAL),
	RDS_IB_EVENT_STRING(QP_REQ_ERR),
	RDS_IB_EVENT_STRING(QP_ACCESS_ERR),
	RDS_IB_EVENT_STRING(COMM_EST),
	RDS_IB_EVENT_STRING(SQ_DRAINED),
	RDS_IB_EVENT_STRING(PATH_MIG),
	RDS_IB_EVENT_STRING(PATH_MIG_ERR),
	RDS_IB_EVENT_STRING(DEVICE_FATAL),
	RDS_IB_EVENT_STRING(PORT_ACTIVE),
	RDS_IB_EVENT_STRING(PORT_ERR),
	RDS_IB_EVENT_STRING(LID_CHANGE),
	RDS_IB_EVENT_STRING(PKEY_CHANGE),
	RDS_IB_EVENT_STRING(SM_CHANGE),
	RDS_IB_EVENT_STRING(SRQ_ERR),
	RDS_IB_EVENT_STRING(SRQ_LIMIT_REACHED),
	RDS_IB_EVENT_STRING(QP_LAST_WQE_REACHED),
	RDS_IB_EVENT_STRING(CLIENT_REREGISTER),
	RDS_IB_EVENT_STRING(GID_CHANGE),
#undef RDS_IB_EVENT_STRING
};

static char *rds_ib_event_str(enum ib_event_type type)
{
	return rds_str_array(rds_ib_event_type_strings,
			     ARRAY_SIZE(rds_ib_event_type_strings), type);
};

void set_ib_conn_flag(unsigned long nr, struct rds_ib_connection *ic)
{
	/* set_bit() does not imply a memory barrier */
	smp_mb__before_atomic();
	set_bit(nr, &ic->i_flags);
	/* set_bit() does not imply a memory barrier */
	smp_mb__after_atomic();
}

#define ROUNDED_HDR_SIZE roundup_pow_of_two(sizeof(struct rds_header))
#define HDRS_PER_PAGE 	(PAGE_SIZE / ROUNDED_HDR_SIZE)
#define NMBR_SEND_HDR_PAGES \
	((ic->i_send_ring.w_nr + HDRS_PER_PAGE - 1) / HDRS_PER_PAGE)
#define NMBR_RECV_HDR_PAGES \
	((ic->i_recv_ring.w_nr + HDRS_PER_PAGE - 1) / HDRS_PER_PAGE)

static void rds_ib_cancel_cm_watchdog(struct rds_ib_connection *ic, char *reason);

/*
 * Set the selected protocol version
 */
static void rds_ib_set_protocol(struct rds_connection *conn, unsigned int version)
{
	conn->c_version = version;
}

/*
 * Set up flow control
 */
static void rds_ib_set_flow_control(struct rds_connection *conn, u32 credits)
{
	struct rds_ib_connection *ic = conn->c_transport_data;

	if (rds_ib_sysctl_flow_control && credits != 0) {
		/* We're doing flow control */
		ic->i_flowctl = 1;
		rds_ib_send_add_credits(conn, credits);
	} else {
		ic->i_flowctl = 0;
	}
}

static inline u16 rds_ib_get_frag(unsigned int version, u16 ib_frag)
{
	u16 frag = RDS_FRAG_SIZE;

	if (version < RDS_PROTOCOL_4_1) {
		pr_err("RDS/IB: Protocol %x default frag %uKB\n",
			 version, frag / SZ_1K);
		return frag;
	}

	switch (ib_frag) {
	case RDS_MAX_FRAG_SIZE:
		frag = RDS_MAX_FRAG_SIZE;
		break;
	case SZ_8K:
		frag = SZ_8K;
		break;
	default:
		frag = RDS_FRAG_SIZE;
	}

	return frag;
}

/* Initialise the RDS IB frag size with host_ib_max_frag */
void rds_ib_init_frag(unsigned int version)
{
	/* Initialise using Host module parameter */
	ib_init_frag_size = rds_ib_get_frag(version, rds_ib_max_frag);

	pr_debug("RDS/IB: fragment size initialised to %uKB\n",
		 ib_init_frag_size / SZ_1K);
}

/* Update the RDS IB frag size */
static u16 rds_ib_set_frag_size(struct rds_connection *conn, u16 dp_frag)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	u16 current_frag = ic->i_frag_sz;
	u16 frag;

	frag = min_t(unsigned int, ib_init_frag_size,
		     PAGE_ALIGN((ic->i_hca_sge - 1) * PAGE_SIZE));

	if (frag != dp_frag) {
		frag = min_t(unsigned int, dp_frag, frag);
		ic->i_frag_sz = rds_ib_get_frag(conn->c_version, frag);
	} else {
		ic->i_frag_sz = frag;
	}

	ic->i_frag_pages =  ceil(ic->i_frag_sz, PAGE_SIZE);
	ic->i_frag_cache_inx = ilog2(ic->i_frag_pages);

	pr_debug("RDS/IB: conn <%pI6c, %pI6c,%d>, Frags <init,ic,dp>: {%d,%d,%d}, updated {%d -> %d}\n",
		 &conn->c_laddr, &conn->c_faddr, conn->c_tos,
		 ib_init_frag_size / SZ_1K, ic->i_frag_sz / SZ_1K, dp_frag /  SZ_1K,
		 current_frag / SZ_1K, ic->i_frag_sz / SZ_1K);

	return ic->i_frag_sz;
}

/* Init per IC frag size */
static inline void rds_ib_init_ic_frag(struct rds_ib_connection *ic)
{
	if (ic)
		ic->i_frag_sz = ib_init_frag_size;
}

#ifdef CONFIG_RDS_ACL

/*
*  0 - all good
*  1 - acl is not enabled
* -1 - acl match failed
*/
static int rds_ib_match_acl(struct rdma_cm_id *cm_id,
			    const struct in6_addr *saddr)
{
	struct ib_cm_acl *acl = 0;
	struct ib_cm_acl_elem *acl_elem = 0;
	__be64 fguid = cm_id->route.path_rec->dgid.global.interface_id;
	__be64 fsubnet = cm_id->route.path_rec->dgid.global.subnet_prefix;
	struct ib_cm_dpp dpp;

	ib_cm_dpp_init(&dpp, cm_id->device, cm_id->port_num,
		       ntohs(cm_id->route.path_rec->pkey));
	acl = ib_cm_dpp_acl_lookup(&dpp);
	if (!acl)
		return 0;

	if (!acl->enabled)
		return 0;

	acl_elem = ib_cm_acl_lookup(acl, be64_to_cpu(fsubnet),
				    be64_to_cpu(fguid));
	if (!acl_elem) {
		pr_err_ratelimited("RDS/IB: GUID ib_cm_acl_lookup() failed\n");
		goto out;
	}

	acl_elem = ib_cm_acl_lookup_uuid_ip(acl, acl_elem->uuid, saddr);
	if (!acl_elem) {
		pr_err_ratelimited("RDS/IB: IP %pI6c ib_cm_acl_lookup_uuid_ip() failed\n",
				   saddr);
		goto out;
	}

	return 1;
out:
	pr_err_ratelimited("RDS/IB: %s failed due to ACLs. Check ACLs\n",
			    __func__);
	return -1;
}

#endif /* CONFIG_RDS_ACL */

static void
rds_ib_check_rnr_timer(struct rds_ib_connection *ic)
{
	struct ib_qp_init_attr qp_init_attr;
	struct ib_qp_attr attr;
	int nmbr_checks = 1;
	int sts;

	/* RNR Retry Timer check with firmware version */
	if (!(ic->rds_ibdev->i_work_arounds & RDS_IB_DEV_WA_INCORRECT_RNR_TIMER))
		return;

check_again:
	sts = ib_query_qp(ic->i_cm_id->qp, &attr, IB_QP_MIN_RNR_TIMER, &qp_init_attr);

	if (sts) {
		printk(KERN_NOTICE "ib_query_qp(IB_QP_MIN_RNR_TIMER): err=%d\n", -sts);
	} else if (attr.min_rnr_timer != IB_RNR_TIMER_000_32) {
		struct rds_connection *conn = ic->conn;
		const int max_nmbr_checks = 5;

		printk(KERN_NOTICE "WRONG RNR Retry Timer value: %d: Attempt: %d RDS/IB: %s conn %p i_cm_id %p, frag %dKB, connected <%pI6c,%pI6c,%d> version %u.%u\n",
		       attr.min_rnr_timer, nmbr_checks, ic->i_active_side ? "Active " : "Passive",
		       conn, ic->i_cm_id, ic->i_frag_sz / SZ_1K,
		       &conn->c_laddr, &conn->c_faddr, conn->c_tos,
		       RDS_PROTOCOL_MAJOR(conn->c_version),
		       RDS_PROTOCOL_MINOR(conn->c_version));

		if (++nmbr_checks > max_nmbr_checks)
			return;

		attr.min_rnr_timer = IB_RNR_TIMER_000_32;
		sts = ib_modify_qp(ic->i_cm_id->qp, &attr, IB_QP_MIN_RNR_TIMER);
		if (sts)
			printk(KERN_NOTICE "ib_modify_qp(IB_QP_MIN_RNR_TIMER): err=%d\n", -sts);
		else
			goto check_again;
	}
}

/*
 * Connection established.
 * We get here for both outgoing and incoming connection.
 */
void rds_ib_cm_connect_complete(struct rds_connection *conn, struct rdma_cm_event *event)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	const union rds_ib_conn_priv *dp = NULL;
	__be16 frag_sz = 0;
	__be64 ack_seq = 0;
	__be32 credit = 0;
	u8 major = 0;
	u8 minor = 0;
	int err;

	dp = event->param.conn.private_data;
	if (conn->c_isv6) {
		if (event->param.conn.private_data_len >=
		    sizeof(struct rds6_ib_connect_private)) {
			major = dp->ricp_v6.dp_protocol_major;
			minor = dp->ricp_v6.dp_protocol_minor;
			credit = dp->ricp_v6.dp_credit;
			frag_sz = dp->ricp_v6.dp_frag_sz;
			/* dp structure start is not guaranteed to be 8 bytes
			 * aligned.  Since dp_ack_seq is 64-bit extended load
			 * operations can be used so go through get_unaligned
			 * to avoid unaligned errors.
			 */
			ack_seq = get_unaligned(&dp->ricp_v6.dp_ack_seq);
		}
	} else if (event->param.conn.private_data_len >=
		   sizeof(struct rds_ib_connect_private)) {
		major = dp->ricp_v4.dp_protocol_major;
		minor = dp->ricp_v4.dp_protocol_minor;
		credit = dp->ricp_v4.dp_credit;
		frag_sz = dp->ricp_v4.dp_frag_sz;
		ack_seq = get_unaligned(&dp->ricp_v4.dp_ack_seq);
	}

	/* make sure it isn't empty data */
	if (major) {
		rds_ib_set_protocol(conn, RDS_PROTOCOL(major, minor));
		rds_ib_set_flow_control(conn, be32_to_cpu(credit));
		rds_ib_set_frag_size(conn, be16_to_cpu(frag_sz));
	}

	if (conn->c_version < RDS_PROTOCOL_VERSION) {
		if (conn->c_version != RDS_PROTOCOL_COMPAT_VERSION) {
			printk(KERN_NOTICE "RDS/IB: Connection to %pI6c version %u.%u failed, no longer supported\n",
			       &conn->c_faddr,
			       RDS_PROTOCOL_MAJOR(conn->c_version),
			       RDS_PROTOCOL_MINOR(conn->c_version));
			rds_ib_conn_destroy_init(conn);
			return;
		}
	}

	pr_notice("RDS/IB: %s conn %p i_cm_id %p, frag %dKB, connected <%pI6c,%pI6c,%d> version %u.%u%s%s"
		 ", scq_vector=%d, preferred_send_cpu=%d, rcq_vector=%d, preferred_recv_cpu=%d\n",
		  ic->i_active_side ? "Active " : "Passive",
		  conn, ic->i_cm_id, ic->i_frag_sz / SZ_1K,
		  &conn->c_laddr, &conn->c_faddr, conn->c_tos,
		  RDS_PROTOCOL_MAJOR(conn->c_version),
		  RDS_PROTOCOL_MINOR(conn->c_version),
		  ic->i_flowctl ? ", flow control" : "",
		  conn->c_acl_en ? ", ACL Enabled" : "",
		  ic->i_scq_vector,
		  ic->i_preferred_send_cpu != WORK_CPU_UNBOUND ? ic->i_preferred_send_cpu : -1,
		  ic->i_rcq_vector,
		  ic->i_preferred_recv_cpu != WORK_CPU_UNBOUND ? ic->i_preferred_recv_cpu : -1);

	/* The connection might have been dropped under us*/
	if (!ic->i_cm_id) {
		rds_conn_drop(conn, DR_IB_CONN_DROP_RACE, 0);
		return;
	}

	ic->i_sl = ic->i_cm_id->route.path_rec->sl;
	clear_bit_mb(RDS_IB_CQ_ERR, &ic->i_flags);

	/*
	 * Init rings and fill recv. this needs to wait until protocol negotiation
	 * is complete, since ring layout is different from 3.0 to 3.1.
	 */
	rds_ib_send_init_ring(ic);
	rds_ib_check_rnr_timer(ic);

	/* update ib_device with this local ipaddr */
	err = rds_ib_update_ipaddr(ic->rds_ibdev, &conn->c_laddr);
	if (err)
		printk(KERN_ERR "rds_ib_update_ipaddr failed (%d)\n",
			err);

	/* If the peer gave us the last packet it saw, process this as if
	 * we had received a regular ACK. */
	if (dp) {
		if (ack_seq)
			rds_send_drop_acked(conn, be64_to_cpu(ack_seq),
					    NULL);
	}

	/* Save the qp number information in the connection details. */
	ic->i_qp_num = ic->i_cm_id->qp->qp_num;
	if (event->param.conn.qp_num)
		ic->i_dst_qp_num = event->param.conn.qp_num;

	rds_ib_cancel_cm_watchdog(ic, "connect complete");

	rds_connect_complete(conn);

	atomic64_set(&ic->i_connecting_ts, ktime_get());
}

void rds_ib_conn_ha_changed(struct rds_connection *conn,
			    const unsigned char *ha,
			    unsigned ha_len)
{
	struct rds_ib_connection *ic;
	struct rdma_cm_id *cm_id;
	int gid_ofs, gid_len;
	const unsigned char *old_ha;
	bool drop_it;

	ic = conn->c_transport_data;
	if (!ic)
		return;

	/* if we can't acquire a read-lock, ic->i_cm_id is being destroyed */
	if (!down_read_trylock(&ic->i_cm_id_free_lock))
		return;

	cm_id = ic->i_cm_id;
	if (cm_id) {
		old_ha = cm_id->route.addr.dev_addr.dst_dev_addr;
		gid_ofs = rdma_addr_gid_offset(&cm_id->route.addr.dev_addr);
		gid_len = ha_len - gid_ofs;

		if (gid_len > 0)
			drop_it =
				memchr_inv(old_ha + gid_ofs, 0, gid_len) != NULL &&
				memcmp(old_ha + gid_ofs, ha + gid_ofs, gid_len) != 0;
		else
			drop_it = false;
	} else
		drop_it = false;

	up_read(&ic->i_cm_id_free_lock);

	if (drop_it)
		rds_conn_drop(conn, DR_IB_PEER_ADDR_CHANGE, 0);
}

static void rds_ib_cm_fill_conn_param(struct rds_connection *conn,
				      struct rdma_conn_param *conn_param,
				      union rds_ib_conn_priv *dp,
				      u32 protocol_version,
				      u32 max_responder_resources,
				      u32 max_initiator_depth, u16 frag,
				      bool isv6)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rds_ib_device *rds_ibdev = ic->rds_ibdev;

	memset(conn_param, 0, sizeof(struct rdma_conn_param));

	conn_param->responder_resources =
		min_t(u32, rds_ibdev->max_responder_resources, max_responder_resources);
	conn_param->initiator_depth =
		min_t(u32, rds_ibdev->max_initiator_depth, max_initiator_depth);
	/* As per IBTA, the following two counters are three bits wide */
	conn_param->retry_count = min_t(unsigned int, rds_ib_retry_count, 7);
	conn_param->rnr_retry_count = min_t(unsigned int, rds_ib_rnr_retry_count, 7);

	if (dp) {
		memset(dp, 0, sizeof(*dp));
		if (isv6) {
			dp->ricp_v6.dp_saddr = conn->c_laddr;
			dp->ricp_v6.dp_daddr = conn->c_faddr;
			dp->ricp_v6.dp_protocol_major =
			    RDS_PROTOCOL_MAJOR(protocol_version);
			dp->ricp_v6.dp_protocol_minor =
			    RDS_PROTOCOL_MINOR(protocol_version);
			dp->ricp_v6.dp_protocol_minor_mask =
			    cpu_to_be16(RDS_IB_SUPPORTED_PROTOCOLS);
			dp->ricp_v6.dp_ack_seq =
			    cpu_to_be64(rds_ib_piggyb_ack(ic));
			dp->ricp_v6.dp_tos = conn->c_tos;
			dp->ricp_v6.dp_frag_sz = cpu_to_be16(frag);

			conn_param->private_data = &dp->ricp_v6;
			conn_param->private_data_len = sizeof(dp->ricp_v6);
		} else {
			dp->ricp_v4.dp_saddr = conn->c_laddr.s6_addr32[3];
			dp->ricp_v4.dp_daddr = conn->c_faddr.s6_addr32[3];
			dp->ricp_v4.dp_protocol_major =
			    RDS_PROTOCOL_MAJOR(protocol_version);
			dp->ricp_v4.dp_protocol_minor =
			    RDS_PROTOCOL_MINOR(protocol_version);
			dp->ricp_v4.dp_protocol_minor_mask =
			    cpu_to_be16(RDS_IB_SUPPORTED_PROTOCOLS);
			dp->ricp_v4.dp_ack_seq =
			    cpu_to_be64(rds_ib_piggyb_ack(ic));
			dp->ricp_v4.dp_tos = conn->c_tos;
			dp->ricp_v4.dp_frag_sz = cpu_to_be16(frag);

			conn_param->private_data = &dp->ricp_v4;
			conn_param->private_data_len = sizeof(dp->ricp_v4);
		}

		/* Advertise flow control */
		if (ic->i_flowctl) {
			unsigned int credits;

			credits = IB_GET_POST_CREDITS(
			    atomic_read(&ic->i_credits));
			if (isv6)
				dp->ricp_v6.dp_credit = cpu_to_be32(credits);
			else
				dp->ricp_v4.dp_credit = cpu_to_be32(credits);
			atomic_sub(IB_SET_POST_CREDITS(credits),
				   &ic->i_credits);
		}
	}
}

static void rds_ib_cq_event_handler(struct ib_event *event, void *data)
{
	struct rds_connection *conn = data;
	struct rds_ib_connection *ic = conn->c_transport_data;

	pr_info("RDS/IB: event %u (%s) conn %p <%pI6c,%pI6c,%d> ic %p cm_id %p\n",
		event->event, rds_ib_event_str(event->event), conn,
		&conn->c_laddr, &conn->c_faddr, conn->c_tos, ic, ic->i_cm_id);

	set_bit_mb(RDS_IB_CQ_ERR, &ic->i_flags);
	if (waitqueue_active(&rds_ib_ring_empty_wait))
		wake_up(&rds_ib_ring_empty_wait);
	if (test_bit(RDS_SHUTDOWN_WAITING, &conn->c_flags))
		mod_delayed_work(conn->c_wq, &conn->c_down_wait_w, 0);
}

static void rds_ib_cq_event_handler_fastreg(struct ib_event *event, void *data)
{
	struct rds_ib_device *rds_ibdev = data;

	pr_info("RDS/IB: event %u (%s) rds_ibdev %p\n", event->event,
		rds_ib_event_str(event->event), data);

	if (rds_ibdev->use_fastreg)
		queue_work(rds_wq, &rds_ibdev->fastreg_reset_w);
}

static void rds_ib_cq_comp_handler_fastreg(struct ib_cq *cq, void *context)
{
	struct rds_ib_device *rds_ibdev = context;

	if (rds_ib_preferred_cpu & RDS_IB_PREFER_CPU_TASKLET)
		tasklet_schedule(&rds_ibdev->fastreg_tasklet);
	else
		queue_work_on(smp_processor_id(),
			      rds_evt_wq, &rds_ibdev->fastreg_w);
}


/* Only follow CQ affinity if exactly one bit is set
 * in the IRQ affinity mask that's consistent
 * with other restrictions (e.g. NUMA) of
 * module parameter "rds_ib_preferred_cpu"
 */
static void rds_ib_cq_follow_affinity(struct rds_ib_connection *ic,
				      bool in_send_path)
{
	int *preferred_cpu_p, preferred_cpu, cq_vector, irqn;
	bool *cq_isolate_warned_p;
	const char *preferred_cpu_name;
	struct cpumask preferred_cpu_mask;
	unsigned long flags;

	if (!(rds_ib_preferred_cpu & RDS_IB_PREFER_CPU_CQ))
		return;

	if (in_send_path) {
		preferred_cpu_p = &ic->i_preferred_send_cpu;
		cq_vector = ic->i_scq_vector;
		cq_isolate_warned_p = &ic->i_scq_isolate_warned;
		preferred_cpu_name = "i_preferred_send_cpu";
	} else {
		preferred_cpu_p = &ic->i_preferred_recv_cpu;
		cq_vector = ic->i_rcq_vector;
		cq_isolate_warned_p = &ic->i_rcq_isolate_warned;
		preferred_cpu_name = "i_preferred_recv_cpu";
	}

	preferred_cpu = *preferred_cpu_p;
	if (preferred_cpu == WORK_CPU_UNBOUND ||
	    preferred_cpu == smp_processor_id())
		return;

	if (system_state > SYSTEM_RUNNING)
		return;

	irqn = ib_get_vector_irqn(ic->rds_ibdev->dev, cq_vector);
	if (irqn < 0)
		return;

	rds_ib_get_preferred_cpu_mask(&preferred_cpu_mask,
				      irqn, rdsibdev_to_node(ic->rds_ibdev));
	if (cpumask_weight(&preferred_cpu_mask) != 1 ||
	    cpumask_first(&preferred_cpu_mask) != smp_processor_id()) {
		if (!*cq_isolate_warned_p) {
			*cq_isolate_warned_p = true;
			pr_warn("RDS/IB: CQ affinity mismatch: can't isolate single CPU (irqn=%d, cpus=%*pbl)\n",
				irqn, cpumask_pr_args(&preferred_cpu_mask));
		}
		return;
	}

	spin_lock_irqsave(&rds_ib_preferred_cpu_load_lock, flags);

	if (*preferred_cpu_p != WORK_CPU_UNBOUND)
		rds_ib_preferred_cpu_load[*preferred_cpu_p]--;
	*preferred_cpu_p = smp_processor_id();
	rds_ib_preferred_cpu_load[*preferred_cpu_p]++;

	spin_unlock_irqrestore(&rds_ib_preferred_cpu_load_lock, flags);

	pr_warn("RDS/IB: CQ affinity mismatch: changed %s from=%d to=%d (irqn=%d)\n",
		preferred_cpu_name, preferred_cpu, smp_processor_id(), irqn);

	*cq_isolate_warned_p = false;
}

static void rds_ib_cq_follow_send_affinity(struct work_struct *work)
{
	struct rds_ib_connection *ic = container_of(work,
						    struct rds_ib_connection,
						    i_cq_follow_send_affinity_w.work);

	rds_ib_cq_follow_affinity(ic, true);
}

static void rds_ib_cq_comp_handler_send(struct ib_cq *cq, void *context)
{
	struct rds_connection *conn = context;
	struct rds_ib_connection *ic = conn->c_transport_data;

	rdsdebug("conn %p cq %p\n", conn, cq);

	rds_ib_stats_inc(s_ib_evt_handler_call);

	queue_delayed_work_on(smp_processor_id(),
			      rds_evt_wq,
			      &ic->i_cq_follow_send_affinity_w,
			      msecs_to_jiffies(RDS_IB_CQ_FOLLOW_AFFINITY_THROTTLE));

	if (rds_ib_preferred_cpu & RDS_IB_PREFER_CPU_TASKLET)
		tasklet_schedule(&ic->i_stasklet);
	else
		queue_work_on(ic->i_preferred_send_cpu,
			      rds_evt_wq, &ic->i_send_w);
}

static void rds_ib_cq_follow_recv_affinity(struct work_struct *work)
{
	struct rds_ib_connection *ic = container_of(work,
						    struct rds_ib_connection,
						    i_cq_follow_recv_affinity_w.work);

	rds_ib_cq_follow_affinity(ic, false);
}

static void rds_ib_cq_comp_handler_recv(struct ib_cq *cq, void *context)
{
	struct rds_connection *conn = context;
	struct rds_ib_connection *ic = conn->c_transport_data;

	rdsdebug("conn %p cq %p\n", conn, cq);

	rds_ib_stats_inc(s_ib_evt_handler_call);

	queue_delayed_work_on(smp_processor_id(),
			      rds_evt_wq,
			      &ic->i_cq_follow_recv_affinity_w,
			      msecs_to_jiffies(RDS_IB_CQ_FOLLOW_AFFINITY_THROTTLE));

	if (rds_ib_preferred_cpu & RDS_IB_PREFER_CPU_TASKLET)
		tasklet_schedule(&ic->i_rtasklet);
	else
		queue_work_on(ic->i_preferred_recv_cpu,
			      rds_evt_wq, &ic->i_recv_w);
}

static void poll_fcq(struct rds_ib_device *rds_ibdev, struct ib_cq *cq,
		     struct ib_wc *wcs)
{
	int nr, i;
	struct ib_wc *wc;

	while ((nr = ib_poll_cq(cq, RDS_WC_MAX, wcs)) > 0) {
		for (i = 0; i < nr; i++) {
			wc = wcs + i;
			rds_ib_fcq_handler(rds_ibdev, wc);
		}
	}
}

static void poll_scq(struct rds_ib_connection *ic, struct ib_cq *cq,
		     struct ib_wc *wcs)
{
	int nr, i;
	struct ib_wc *wc;

	ic->i_tx_poll_ts = jiffies;
	atomic64_inc(&ic->i_tx_poll_cnt);

	while ((nr = ib_poll_cq(cq, RDS_WC_MAX, wcs)) > 0) {
		for (i = 0; i < nr; i++) {
			wc = wcs + i;
			rdsdebug("wc wr_id 0x%llx status %u byte_len %u imm_data %u\n",
				 (unsigned long long)wc->wr_id, wc->status, wc->byte_len,
				 be32_to_cpu(wc->ex.imm_data));

			if (wc->wr_id < (u64)ic->i_send_ring.w_nr ||
			    wc->wr_id == RDS_IB_ACK_WR_ID)
				rds_ib_send_cqe_handler(ic, wc);
			else
				rds_ib_mr_cqe_handler(ic, wc);
		}
	}
}

static void poll_rcq(struct rds_ib_connection *ic, struct ib_cq *cq,
		     struct ib_wc *wcs,
		     struct rds_ib_ack_state *ack_state)
{
	int nr, i;
	struct ib_wc *wc;

	ic->i_rx_poll_ts = jiffies;
	atomic64_inc(&ic->i_rx_poll_cnt);

	while ((nr = ib_poll_cq(cq, RDS_WC_MAX, wcs)) > 0) {
		for (i = 0; i < nr; i++) {
			if ((++ic->i_rx_poll_cq % RDS_IB_RX_LIMIT) == 0) {
				rdsdebug("connection <%pI6c,%pI6c,%d> RX poll_cq processed %d\n",
					 &ic->conn->c_laddr,
					 &ic->conn->c_faddr,
					 ic->conn->c_tos,
					 ic->i_rx_poll_cq);
			}
			wc = wcs + i;
			rdsdebug("wc wr_id 0x%llx status %u byte_len %u imm_data %u\n",
				 (unsigned long long)wc->wr_id, wc->status,
				 wc->byte_len, be32_to_cpu(wc->ex.imm_data));
			rds_ib_recv_cqe_handler(ic, wc, ack_state);
		}

		if (ic->i_rx_poll_cq >= RDS_IB_RX_LIMIT)
			break;
	}
}

static void rds_ib_tasklet_fn_fastreg(unsigned long data)
{
	struct rds_ib_device *rds_ibdev = (struct rds_ib_device *)data;

	poll_fcq(rds_ibdev, rds_ibdev->fastreg_cq, rds_ibdev->fastreg_wc);
	ib_req_notify_cq(rds_ibdev->fastreg_cq, IB_CQ_NEXT_COMP);
	poll_fcq(rds_ibdev, rds_ibdev->fastreg_cq, rds_ibdev->fastreg_wc);
}

static void rds_ib_cq_comp_handler_fastreg_w(struct work_struct *work)
{
	struct rds_ib_device *rds_ibdev = container_of(work,
						       struct rds_ib_device,
						       fastreg_w);

	poll_fcq(rds_ibdev, rds_ibdev->fastreg_cq, rds_ibdev->fastreg_wc);
	ib_req_notify_cq(rds_ibdev->fastreg_cq, IB_CQ_NEXT_COMP);
	poll_fcq(rds_ibdev, rds_ibdev->fastreg_cq, rds_ibdev->fastreg_wc);
}

/* poll send completion queue and re-arm the completion queue */
static void rds_ib_tx(struct rds_ib_connection *ic)
{
	spin_lock_bh(&ic->i_tx_lock);
	poll_scq(ic, ic->i_scq, ic->i_send_wc);
	ib_req_notify_cq(ic->i_scq, IB_CQ_NEXT_COMP);
	poll_scq(ic, ic->i_scq, ic->i_send_wc);
	spin_unlock_bh(&ic->i_tx_lock);
}

static void rds_ib_send_cb(struct rds_ib_connection *ic)
{
	struct rds_connection *conn = ic->conn;

	rds_ib_stats_inc(s_ib_tasklet_call);

	/* if send cq has been destroyed, ignore incoming cq event */
	if (!ic->i_scq)
		return;

	rds_ib_tx(ic);

	if (rds_conn_up(conn) &&
	   (!test_bit(RDS_LL_SEND_FULL, &conn->c_flags) ||
	    test_bit(RCMQ_BITOFF_CONGU_PENDING, &conn->c_map_queued)))
		rds_send_xmit(&ic->conn->c_path[0]);
}

void rds_ib_tasklet_fn_send(unsigned long data)
{
	struct rds_ib_connection *ic = (struct rds_ib_connection *) data;

	rds_ib_send_cb(ic);
}

static void rds_ib_send_w(struct work_struct *work)
{
	struct rds_ib_connection *ic = container_of(work,
						    struct rds_ib_connection,
						    i_send_w);

	rds_ib_send_cb(ic);
}

/*
 * Note: rds_ib_rx(): don't call with irqs disabled.
 * It calls rds_send_drop_acked() which calls other
 * routines that reach into rds_rdma_free_op()
 * where irqs_disabled() warning is asserted!
 */
static void rds_ib_rx(struct rds_ib_connection *ic)
{
	struct rds_connection *conn = ic->conn;
	struct rds_ib_ack_state ack_state;

	rds_ib_stats_inc(s_ib_tasklet_call);

	memset(&ack_state, 0, sizeof(ack_state));

	ic->i_rx_poll_cq = 0;
	poll_rcq(ic, ic->i_rcq, ic->i_recv_wc, &ack_state);
	ib_req_notify_cq(ic->i_rcq, IB_CQ_SOLICITED);
	poll_rcq(ic, ic->i_rcq, ic->i_recv_wc, &ack_state);

	if (ack_state.ack_next_valid)
		rds_ib_set_ack(ic, ack_state.ack_next, ack_state.ack_required);
	if (ack_state.ack_recv_valid && ack_state.ack_recv > ic->i_ack_recv) {
		rds_send_drop_acked(conn, ack_state.ack_recv, NULL);
		ic->i_ack_recv = ack_state.ack_recv;
	}
	if (rds_conn_up(conn))
		rds_ib_attempt_ack(ic);

	if (rds_ib_srq_enabled) {
		struct rds_ib_device *rds_ibdev = ic->rds_ibdev;
		if (rds_ibdev &&
		    (atomic_read(&rds_ibdev->srq->s_num_posted) < rds_ib_srq_hwm_refill) &&
		    !test_and_set_bit(0, &rds_ibdev->srq->s_refill_gate))
			rds_queue_delayed_work_on(&conn->c_path[0],
						  ic->i_preferred_recv_cpu,
						  conn->c_path[0].cp_wq,
						  &rds_ibdev->srq->s_refill_w,
						  0,
						  "srq refill");
	}

	if (ic->i_rx_poll_cq >= RDS_IB_RX_LIMIT) {
		ic->i_rx_w.ic = ic;
		/* Delay 10 msecs until the RX worker starts reaping again */
		rds_queue_delayed_work_on(&conn->c_path[0],
					  ic->i_preferred_recv_cpu,
					  rds_aux_wq,
					  &ic->i_rx_w.work,
					  msecs_to_jiffies(10),
					  "delay for RX worker");
		ic->i_rx_wait_for_handler = 1;
	}
}

static void rds_ib_recv_cb(struct rds_ib_connection *ic)
{
	spin_lock_bh(&ic->i_rx_lock);
	if (ic->i_rx_wait_for_handler)
		goto out;
	rds_ib_rx(ic);
out:
	spin_unlock_bh(&ic->i_rx_lock);
}

void rds_ib_tasklet_fn_recv(unsigned long data)
{
	struct rds_ib_connection *ic = (struct rds_ib_connection *) data;

	rds_ib_recv_cb(ic);
}

static void rds_ib_recv_w(struct work_struct *work)
{
	struct rds_ib_connection *ic = container_of(work,
						    struct rds_ib_connection,
						    i_recv_w);

	rds_ib_recv_cb(ic);
}

static void rds_ib_rx_handler(struct work_struct *_work)
{
        struct rds_ib_rx_work *work =
                container_of(_work, struct rds_ib_rx_work, work.work);
	struct rds_ib_connection *ic = work->ic;

	spin_lock_bh(&ic->i_rx_lock);
	ic->i_rx_wait_for_handler = 0;
	rds_ib_rx(ic);
	spin_unlock_bh(&ic->i_rx_lock);
}

static void rds_ib_arm_cm_watchdog(struct rds_ib_connection *ic)
{
	unsigned cm_watchdog_ms = rds_ib_sysctl_cm_watchdog_ms;

	if (!cm_watchdog_ms)
		return;

	trace_rds_ib_queue_work(ic->rds_ibdev, rds_aux_wq,
				&ic->i_cm_watchdog_w.work,
				msecs_to_jiffies(cm_watchdog_ms),
				"arm cm watchdog");

	queue_delayed_work(rds_aux_wq, &ic->i_cm_watchdog_w,
			   msecs_to_jiffies(cm_watchdog_ms));
}

static void rds_ib_cancel_cm_watchdog(struct rds_ib_connection *ic, char *reason)
{
	trace_rds_ib_queue_cancel_work(ic->rds_ibdev, rds_aux_wq,
				       &ic->i_cm_watchdog_w.work, 0, reason);

	cancel_delayed_work(&ic->i_cm_watchdog_w);
}

static void rds_ib_cm_watchdog_handler(struct work_struct *work)
{
	struct rds_ib_connection *ic = container_of(work,
						    struct rds_ib_connection,
						    i_cm_watchdog_w.work);
	struct rds_connection *conn = ic->conn;

	if (!rds_conn_connecting(conn))
		return;

	pr_info("RDS/IB: CM watchdog triggered on connection <%pI6c,%pI6c,%d>\n",
		&conn->c_laddr, &conn->c_faddr, conn->c_tos);

	rds_conn_drop(conn, DR_IB_CONN_DROP_CM_WATCHDOG, 0);
	rds_ib_stats_inc(s_ib_cm_watchdog_triggered);
}

static void rds_ib_qp_event_handler(struct ib_event *event, void *data)
{
	struct rds_connection *conn = data;
	struct rds_ib_connection *ic = conn->c_transport_data;

	rdsdebug("conn %p ic %p event %u (%s)\n", conn, ic, event->event,
		 rds_ib_event_str(event->event));

	switch (event->event) {
	case IB_EVENT_COMM_EST:
		rdma_notify(ic->i_cm_id, IB_EVENT_COMM_EST);
		break;
	case IB_EVENT_QP_LAST_WQE_REACHED:
		complete(&ic->i_last_wqe_complete);
		break;
	default:
		rds_conn_drop(conn, DR_IB_QP_EVENT, 0);
		break;
	}
}

static int rds_ib_get_load(int *tos_row, u8 tos)
{
	int load = 0;
	int i;

	for (i = 0; i < RDS_IB_NMBR_TOS_ROWS; ++i) {
		int scale = i == (tos % RDS_IB_NMBR_TOS_ROWS) ? RDS_IB_NMBR_TOS_ROWS : 1;

		load += tos_row[i] * scale;
	}

	return load;
}

static inline int ibdev_get_unused_vector(struct rds_ib_device *rds_ibdev, u8 tos,
					  int sibling_vector)
{
	struct cpumask *l3_cpu_mask_p = NULL;
	struct cpumask cpu_mask;
	struct cpu_cacheinfo *cache_p;
	int *tos_row, load;
	int irqn, cpu;
	int index, min, i;

	/* try to allocate a vector pointing to a CPU that belongs
	 * to the same L3 cache, if sibling_vector >= 0 with CQ-preference
	 */
	if (sibling_vector >= 0 &&
	    (rds_ib_preferred_cpu & RDS_IB_PREFER_CPU_CQ))
		irqn = ib_get_vector_irqn(rds_ibdev->dev, sibling_vector);
	else
		irqn = -1;

	if (irqn >= 0) {
		rds_ib_get_preferred_cpu_mask(&cpu_mask,
					      irqn, rdsibdev_to_node(rds_ibdev));
		if (cpumask_weight(&cpu_mask) == 1) {
			cpu = cpumask_first(&cpu_mask);

			cache_p = get_cpu_cacheinfo(cpu);
			if (cache_p && cache_p->num_leaves > 3)
				l3_cpu_mask_p = &cache_p->info_list[3].shared_cpu_map;
		}
	}
 
        mutex_lock(&rds_ibdev->vector_load_lock);

	index = 0;
	min = -1;

	/* try to find a sibling with lowest load first */
	if (l3_cpu_mask_p) {
		for (i = rds_ibdev->dev->num_comp_vectors - 1; i >= 0; i--) {
			irqn = ib_get_vector_irqn(rds_ibdev->dev, i);
			rds_ib_get_preferred_cpu_mask(&cpu_mask,
						      irqn, rdsibdev_to_node(rds_ibdev));

			if (!cpumask_intersects(&cpu_mask, l3_cpu_mask_p))
				continue;

			tos_row = rds_ibdev->vector_load + i * RDS_IB_NMBR_TOS_ROWS;
			load = rds_ib_get_load(tos_row, tos);
			if (min >= 0 && load >= min)
				continue;

			index = i;
			min = load;
		}
	}

	if (min < 0) {
		/* no sibling found; pick up any vector with lowest load */
		for (i = rds_ibdev->dev->num_comp_vectors - 1; i >= 0; i--) {
			tos_row = rds_ibdev->vector_load + i * RDS_IB_NMBR_TOS_ROWS;
			load = rds_ib_get_load(tos_row, tos);
			if (min >= 0 && load >= min)
				continue;

			index = i;
			min = load;
		}
	}

	tos_row = rds_ibdev->vector_load + index * RDS_IB_NMBR_TOS_ROWS;
	tos_row[tos % RDS_IB_NMBR_TOS_ROWS]++;

	mutex_unlock(&rds_ibdev->vector_load_lock);

	return index;
}

static inline void ibdev_get_vector(struct rds_ib_device *rds_ibdev, int index, u8 tos)
{
	int *tos_row = rds_ibdev->vector_load + index * RDS_IB_NMBR_TOS_ROWS;

	mutex_lock(&rds_ibdev->vector_load_lock);
	tos_row[tos % RDS_IB_NMBR_TOS_ROWS]++;
	mutex_unlock(&rds_ibdev->vector_load_lock);
}

static inline void ibdev_put_vector(struct rds_ib_device *rds_ibdev, int index, u8 tos)
{
	int *tos_row = rds_ibdev->vector_load + index * RDS_IB_NMBR_TOS_ROWS;

	mutex_lock(&rds_ibdev->vector_load_lock);
	tos_row[tos % RDS_IB_NMBR_TOS_ROWS]--;
	mutex_unlock(&rds_ibdev->vector_load_lock);
}

static void rds_ib_check_cq(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
			    int *vector, int sibling_vector,
			    struct ib_cq **cqp, unsigned int *cq_entriesp,
			    ib_comp_handler comp_handler,
			    void (*event_handler)(struct ib_event *, void *),
			    void *ctx, int n, const char str[5], u8 tos)
{
	struct ib_cq_init_attr cq_attr = {};

	if (*cqp) {
		if (n == *cq_entriesp) {
			int spurious_completions = 0;
			struct ib_wc wc;

			while (ib_poll_cq(*cqp, 1, &wc) > 0)
				++spurious_completions;

			if (spurious_completions)
				pr_err("RDS/IB: %d spurious completions in %s cq for conn %p. Memory leak detected!\n",
				       spurious_completions, str, ctx);
			return;
		}

		rdsdebug("RDS/IB:conn %p  %s cq_entries %d != n %d recreate cq\n", ctx, str, *cq_entriesp, n);
		ib_destroy_cq(*cqp);
	}


	cq_attr.cqe = n;
	if (*vector < 0)
		*vector = ibdev_get_unused_vector(rds_ibdev, tos, sibling_vector);
	else
		ibdev_get_vector(rds_ibdev, *vector, tos);
	cq_attr.comp_vector = *vector;
	*cqp = ib_create_cq(dev, comp_handler, event_handler, ctx, &cq_attr);
	if (IS_ERR(*cqp)) {
		ibdev_put_vector(rds_ibdev, *vector, tos);
		rdsdebug("ib_create_cq %s failed: %ld\n", str, PTR_ERR(*cqp));
	}
	*cq_entriesp = n;
}

/* Helper function to deallocate the completion queues of an rds_ib_connection.
 *
 * @ic: pointer to the rds_ib_connection of the queues to be freed
 * @rds_ibdev: the underlying RDMA device of the completion queues
 */
static void __rds_rdma_free_cq(struct rds_ib_connection *ic,
			       struct rds_ib_device *rds_ibdev)
{
	struct ib_cq *rcq, *scq;

	rcq = ic->i_rcq;
	ic->i_rcq = NULL;
	if (rcq) {
		ibdev_put_vector(rds_ibdev, ic->i_rcq_vector, ic->conn->c_tos);
		ib_destroy_cq(rcq);
	}

	scq = ic->i_scq;
	ic->i_scq = NULL;
	if (scq) {
		ibdev_put_vector(rds_ibdev, ic->i_scq_vector, ic->conn->c_tos);
		ib_destroy_cq(scq);
	}
}

/* Delayed worker function for i_delayed_free_work of an rds_ib_connection.
 * It deallocates all the connection resource associated with an RDMA device.
 */
static void rds_rdma_conn_delayed_free_worker(struct work_struct *work)
{
	struct rds_ib_device *rds_ibdev;
	struct rds_ib_connection *ic;

	ic = container_of(work, struct rds_ib_connection,
			  i_delayed_free_work.work);
	mutex_lock(&ic->i_delayed_free_lock);
	rds_ibdev = ic->i_saved_rds_ibdev;
	ic->i_saved_rds_ibdev = NULL;
	if (!rds_ibdev) {
		mutex_unlock(&ic->i_delayed_free_lock);
		return;
	}

	__rds_rdma_free_cq(ic, rds_ibdev);
	mutex_unlock(&ic->i_delayed_free_lock);

	rds_ib_dev_put(rds_ibdev);
}

static void rds_ib_free_unmap_hdrs(struct ib_device *dev,
				   struct rds_header ***_hdrs,
				   dma_addr_t **_dma,
				   struct scatterlist **_sg,
				   const int nmbr_hdr_pages,
				   enum dma_data_direction direction)
{
	struct rds_header **hdrs = *_hdrs;
	struct scatterlist *sg = *_sg;
	dma_addr_t *dma = *_dma;
	int i;

	if (sg)
		for (i = 0; i < nmbr_hdr_pages; ++i) {
			ib_dma_unmap_sg(dev, sg + i, 1, direction);
			rds_page_free(sg_page(sg + i));
		}

	vfree(sg);
	vfree(dma);
	vfree(hdrs);
	*_sg = NULL;
	*_dma = NULL;
	*_hdrs = NULL;
}

static int rds_ib_alloc_map_hdrs(struct ib_device *dev,
				 struct rds_header ***_hdrs,
				 dma_addr_t **_dma,
				 struct scatterlist **_sg,
				 char **reason,
				 const int n,
				 const int nmbr_hdr_pages,
				 enum dma_data_direction direction)
{
	struct rds_header **hdrs;
	struct scatterlist *sg;
	dma_addr_t *dma;
	int i, j, k;
	int ret;

	hdrs = *_hdrs = vzalloc_node(sizeof(struct rds_header *) * n,
				     ibdev_to_node(dev));
	if (!hdrs) {
		*reason = "vzalloc_node for hdrs";
		return -ENOMEM;
	}

	dma = *_dma = vzalloc_node(sizeof(dma_addr_t *) * n,
				   ibdev_to_node(dev));
	if (!dma) {
		ret = -ENOMEM;
		*reason = "vzalloc_node for dma failed";
		goto hdrs_out;
	}

	sg = *_sg = vmalloc_node(sizeof(*sg) * nmbr_hdr_pages,
				 ibdev_to_node(dev));
	if (!sg) {
		ret = -ENOMEM;
		*reason = "vzalloc_node for sg failed";
		goto dma_out;
	}

	sg_init_table(sg, nmbr_hdr_pages);

	for (i = 0; i < nmbr_hdr_pages; i++) {
		ret = rds_page_remainder_alloc(sg + i, PAGE_SIZE, GFP_KERNEL,
					       ibdev_to_node(dev));
		if (ret) {
			*reason = "rds_page_remainder_alloc failed";
			for (j = 0; j < i; ++j)
				__free_page(sg_page(sg + j));
			goto sg_out;
		}
	}

	for (i = 0; i < nmbr_hdr_pages; i++) {
		ret = ib_dma_map_sg(dev, sg + i, 1, direction);
		if (ret != 1) {
			ret = -EIO;
			*reason = "ib_dma_map_sg failed";
			for (j = 0; j < i; ++j)
				ib_dma_unmap_sg(dev, sg + j, 1, direction);
			goto page_remainder;
		}
	}

	for (i = 0, j = 0; i < nmbr_hdr_pages; i++, j += HDRS_PER_PAGE)
		for (k = 0; k < HDRS_PER_PAGE; k++) {
			if (j + k >= n)
				break;
			hdrs[j + k] = (struct rds_header *)(sg_virt(sg + i) + k * ROUNDED_HDR_SIZE);
			dma[j + k] = sg_dma_address(sg + i) + k * ROUNDED_HDR_SIZE;
		}

	return 0;

page_remainder:
	for (i = 0; i < nmbr_hdr_pages; ++i)
		__free_page(sg_page(sg + i));

sg_out:
	vfree(sg);
	*_sg = NULL;

dma_out:
	vfree(dma);
	*_dma = NULL;

hdrs_out:
	vfree(hdrs);
	*_hdrs = NULL;

	return ret;
}

/* When an rds_ib_connection is shutdown, it is dissociated with the underlying
 * RDMA device.  All the resource tied to the device should be freed.  For
 * fail over optimization, the resource is not freed immediately.  After the
 * fail over and the connection is re-started, the new device is most likely
 * to be the original device.  So all the resource could be re-used.  This
 * function is called to handle this delayed deallocation.
 *
 * @ic: pointer to the rds_ib_connection for deallocation
 */
static void __rds_rdma_conn_dev_rele(struct rds_ib_connection *ic)
{
	struct rds_ib_device *rds_ibdev;
	struct ib_device *dev;

	rds_ibdev = ic->rds_ibdev;
	dev = rds_ibdev->dev;

	WARN_ON(ic->i_saved_rds_ibdev);

	rds_ib_free_unmap_hdrs(dev,
			       &ic->i_send_hdrs,
			       &ic->i_send_hdrs_dma,
			       &ic->i_send_hdrs_sg,
			       NMBR_SEND_HDR_PAGES,
			       DMA_TO_DEVICE);

	rds_ib_free_unmap_hdrs(dev,
			       &ic->i_recv_hdrs,
			       &ic->i_recv_hdrs_dma,
			       &ic->i_recv_hdrs_sg,
			       NMBR_RECV_HDR_PAGES,
			       DMA_FROM_DEVICE);

	if (ic->i_ack) {
		ib_dma_unmap_single(dev, ic->i_ack_dma, sizeof(struct rds_header),
				    DMA_BIDIRECTIONAL);
		kfree(ic->i_ack);
		ic->i_ack = NULL;
	}

	rds_ib_send_clear_ring(ic);
	rds_ib_recv_clear_ring(ic);

	/* If the module is going away, free all resource immediately. */
	if (rds_ibdev->rid_dev_rem) {
		mutex_lock(&ic->i_delayed_free_lock);
		__rds_rdma_free_cq(ic, rds_ibdev);
		mutex_unlock(&ic->i_delayed_free_lock);
	} else {
		/* Save the device and queue the delayed work. */
		mutex_lock(&ic->i_delayed_free_lock);
		ic->i_saved_rds_ibdev = rds_ibdev;
		mutex_unlock(&ic->i_delayed_free_lock);

		queue_delayed_work(rds_ibdev->rid_dev_wq,
				   &ic->i_delayed_free_work,
				   msecs_to_jiffies(rds_dev_free_wait_ms));
		atomic_inc(&rds_ibdev->rid_refcount);
	}

	ic->i_pd = NULL;
	ic->i_mr = NULL;

	/* Move connection back to the nodev list. */
	rds_ib_remove_conn(rds_ibdev, ic->conn);
}

/*
 * This needs to be very careful to not leave IS_ERR pointers around for
 * cleanup to trip over.
 */
static int rds_ib_setup_qp(struct rds_connection *conn)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rds_ib_device *rds_ibdev, *saved_ibdev;
	struct ib_device *dev = ic->i_cm_id->device;
	struct ib_qp_init_attr qp_attr;
	unsigned long max_wrs;
	char *reason = NULL;
	int ret;
	int mr_reg;

	WARN_ON(ic->rds_ibdev);

	/*
	 * It's normal to see a null device if an incoming connection races
	 * with device removal, so we don't print a warning.
	 */
	rds_ibdev = rds_ib_get_client_data(dev);
	if (!rds_ibdev) {
		ret = -EOPNOTSUPP;
		trace_rds_ib_setup_qp_err(NULL, NULL, conn, ic,
					  "no rds_ibdev during qp setup", ret);
		return ret;
	}

	set_bit_mb(RDS_IB_NEED_SHUTDOWN, &ic->i_flags);

	/* In the case of FRWR, mr registration wrs use the
	 * same work queue as the send wrs. To make sure that we are not
	 * overflowing the workqueue, we allocate separately for each operation.
	 * mr_reg is the wr numbers allocated for reg.
	 */
	if (rds_ibdev->use_fastreg)
		mr_reg = RDS_IB_DEFAULT_FREG_WR;
	else
		mr_reg = 0;

	max_wrs = rds_ibdev->max_wrs < rds_ib_sysctl_max_send_wr + 1  + mr_reg ?
		rds_ibdev->max_wrs - 1 - mr_reg : rds_ib_sysctl_max_send_wr;
	if (ic->i_send_ring.w_nr != max_wrs)
		rds_ib_ring_resize(&ic->i_send_ring, max_wrs);

	max_wrs = rds_ibdev->max_wrs < rds_ib_sysctl_max_recv_wr + 1 + mr_reg ?
		rds_ibdev->max_wrs - 1 - mr_reg : rds_ib_sysctl_max_recv_wr;
	if (ic->i_recv_ring.w_nr != max_wrs)
		rds_ib_ring_resize(&ic->i_recv_ring, max_wrs);

	/* Protection domain and memory range */
	ic->i_pd = rds_ibdev->pd;
	ic->i_mr = rds_ibdev->mr;

	cancel_delayed_work_sync(&ic->i_delayed_free_work);

	/* Check if the DMA headers, i_scq and i_rcq can be reused.  If not,
	 * free them.
	 */
	mutex_lock(&ic->i_delayed_free_lock);
	saved_ibdev = ic->i_saved_rds_ibdev;
	ic->i_saved_rds_ibdev = NULL;
	if (saved_ibdev) {
		/* If the underlying device does not match the saved one,
		 * finish the delayed work.
		 */
		if (saved_ibdev != rds_ibdev) {
			reason = "underlying device does not match saved";
			/* Note that this deletes both send and receive cqs.
			 * Both i_scq and i_rcq will be set to NULL.
			 */
			__rds_rdma_free_cq(ic, saved_ibdev);
		}
		mutex_unlock(&ic->i_delayed_free_lock);

		/* Need to remove the reference added when the delayed free
		 * work was scheduled.
		 */
		rds_ib_dev_put(saved_ibdev);
	} else {
		mutex_unlock(&ic->i_delayed_free_lock);
		WARN_ON(ic->i_send_hdrs);
		WARN_ON(ic->i_ack);
		WARN_ON(ic->i_rcq);
		WARN_ON(ic->i_scq);
	}

	rds_ib_check_cq(dev, rds_ibdev,
			&ic->i_scq_vector, -1,
			&ic->i_scq, &ic->i_scq_entries,
			rds_ib_cq_comp_handler_send,
			rds_ib_cq_event_handler, conn,
			ic->i_send_ring.w_nr + 1 + mr_reg,
			"send", conn->c_tos);
	if (IS_ERR(ic->i_scq)) {
		reason = "rds_ib_check_cq for send failed";
		ret = PTR_ERR(ic->i_scq);
		ic->i_scq = NULL;
		goto out;
	}

	rds_ib_check_cq(dev, rds_ibdev,
			&ic->i_rcq_vector, ic->i_scq_vector,
			&ic->i_rcq, &ic->i_rcq_entries,
			rds_ib_cq_comp_handler_recv,
			rds_ib_cq_event_handler, conn,
			rds_ib_srq_enabled ? rds_ib_srq_max_wr - 1 : ic->i_recv_ring.w_nr,
			"recv", conn->c_tos);
	if (IS_ERR(ic->i_rcq)) {
		reason = "rds_ib_check_cq for recv failed";
		ret = PTR_ERR(ic->i_rcq);
		ic->i_rcq = NULL;
		goto out;
	}

	ret = ib_req_notify_cq(ic->i_scq, IB_CQ_NEXT_COMP);
	if (ret) {
		reason = "ib_req_notify_cq send failed";
		goto out;
	}

	ret = ib_req_notify_cq(ic->i_rcq, IB_CQ_SOLICITED);
	if (ret) {
		reason = "ib_req_notify_cq recv failed";
		goto out;
	}

	/* XXX negotiate max send/recv with remote? */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.event_handler = rds_ib_qp_event_handler;
	qp_attr.qp_context = conn;
	/* + 1 to allow for the single ack message */
	qp_attr.cap.max_send_wr = ic->i_send_ring.w_nr + 1 + mr_reg;
	qp_attr.cap.max_recv_wr = ic->i_recv_ring.w_nr + 1;
	qp_attr.cap.max_send_sge = rds_ibdev->max_sge;
	qp_attr.cap.max_recv_sge = rds_ibdev->max_sge;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_attr.qp_type = IB_QPT_RC;
	qp_attr.send_cq = ic->i_scq;
	qp_attr.recv_cq = ic->i_rcq;

	if (rds_ib_srq_enabled) {
		qp_attr.cap.max_recv_wr = 0;
		qp_attr.srq = rds_ibdev->srq->s_srq;
	}

	ic->i_hca_sge = rds_ibdev->max_sge;
	/*
	 * XXX this can fail if max_*_wr is too large?  Are we supposed
	 * to back off until we get a value that the hardware can support?
	 */
	ret = rdma_create_qp(ic->i_cm_id, ic->i_pd, &qp_attr);
	if (ret) {
		reason = "rdma_create_qp failed";
		goto out;
	}

	ic->i_ack = kzalloc_node(sizeof(struct rds_header), GFP_KERNEL, ibdev_to_node(dev));
	if (!ic->i_ack) {
		ret = -ENOMEM;
		reason = "kzalloc_node ack failed";
		goto qp_out;
	}

	ic->i_ack_dma = ib_dma_map_single(dev, ic->i_ack, sizeof(struct rds_header),
					  DMA_BIDIRECTIONAL);
	ret = ib_dma_mapping_error(dev, ic->i_ack_dma);
	if (ret) {
		kfree(ic->i_ack);
		ic->i_ack = NULL;
		reason = "ib_dma_map_single ack failed";
		goto qp_out;
	}

	ic->i_sends = vzalloc_node(sizeof(struct rds_ib_send_work) * ic->i_send_ring.w_nr,
				   ibdev_to_node(dev));
	if (!ic->i_sends) {
		ret = -ENOMEM;
		reason = "vzalloc_node for i_sends failed";
		goto ack_out;
	}

	ic->i_recvs = vzalloc_node(sizeof(struct rds_ib_recv_work) * ic->i_recv_ring.w_nr,
				   ibdev_to_node(dev));
	if (!ic->i_recvs) {
		ret = -ENOMEM;
		reason = "vzalloc_node for i_recvs failed";
		goto sends_out;
	}

	rds_ib_recv_init_ack(ic);

	ret = rds_ib_alloc_map_hdrs(dev,
				    &ic->i_send_hdrs,
				    &ic->i_send_hdrs_dma,
				    &ic->i_send_hdrs_sg,
				    &reason,
				    ic->i_send_ring.w_nr,
				    NMBR_SEND_HDR_PAGES,
				    DMA_TO_DEVICE);
	if (ret) {
		reason = "alloc and map send hdrs failed";
		goto recvs_out;
	}

	ret = rds_ib_alloc_map_hdrs(dev,
				    &ic->i_recv_hdrs,
				    &ic->i_recv_hdrs_dma,
				    &ic->i_recv_hdrs_sg,
				    &reason,
				    ic->i_recv_ring.w_nr,
				    NMBR_RECV_HDR_PAGES,
				    DMA_FROM_DEVICE);
	if (ret) {
		reason = "alloc and map recv hdrs failed";
		goto send_hdrs_out;
	}

	/* Everything is set up, add the conn now so that connection
	 * establishment has the dev.
	 */
	ret = rds_ib_add_conn(rds_ibdev, conn);
	if (ret) {
		reason = "ib_add_conn failed";
		goto recv_hdrs_out;
	}

	rdsdebug("conn %p pd %p mr %p cq %p\n", conn, ic->i_pd, ic->i_mr, ic->i_rcq);

	goto out;

recv_hdrs_out:
	rds_ib_free_unmap_hdrs(dev,
			       &ic->i_recv_hdrs,
			       &ic->i_recv_hdrs_dma,
			       &ic->i_recv_hdrs_sg,
			       NMBR_RECV_HDR_PAGES,
			       DMA_FROM_DEVICE);

send_hdrs_out:
	rds_ib_free_unmap_hdrs(dev,
			       &ic->i_send_hdrs,
			       &ic->i_send_hdrs_dma,
			       &ic->i_send_hdrs_sg,
			       NMBR_SEND_HDR_PAGES,
			       DMA_TO_DEVICE);

recvs_out:
	vfree(ic->i_recvs);
	ic->i_recvs = NULL;
sends_out:
	vfree(ic->i_sends);
	ic->i_sends = NULL;
ack_out:
	ib_dma_unmap_single(dev, ic->i_ack_dma, sizeof(struct rds_header),
			    DMA_BIDIRECTIONAL);
	kfree(ic->i_ack);
qp_out:
	rdma_destroy_qp(ic->i_cm_id);
out:
	if (reason)
		trace_rds_ib_setup_qp_err(rds_ibdev ? rds_ibdev->dev : NULL,
					  rds_ibdev, conn, ic, reason, ret);
	else
		trace_rds_ib_setup_qp(rds_ibdev ? rds_ibdev->dev : NULL,
				      rds_ibdev, conn, ic, reason, ret);

	/* As this conn is already partially associated with the rds_ibdev
	 * if an error happens, we need to clean up this partial association
	 * here to avoid confusion in the RDS clean up path.  This RDMA
	 * connection request will be rejected when an error is returned and
	 * the conn will be dropped.
	 */
	if (ret) {
		if (ic->i_sends) {
			vfree(ic->i_sends);
			ic->i_sends = NULL;
		}
		if (ic->i_recvs) {
			vfree(ic->i_recvs);
			ic->i_recvs = NULL;
		}
		ic->i_mr = NULL;
		ic->i_pd = NULL;
		__rds_rdma_free_cq(ic, rds_ibdev);
	}

	conn->c_reconnect_err = ret;
	/* rds_ib_get_client_data() has a hold on the device. */
	rds_ib_dev_put(rds_ibdev);

	return ret;
}

static u32 rds_ib_protocol_compatible(struct rdma_cm_event *event, bool isv6)
{
	const union rds_ib_conn_priv *dp = event->param.conn.private_data;
	u8 data_len, major, minor;
	u32 version = 0;
	__be16 mask;
	u16 common;

	/*
	 * rdma_cm private data is odd - when there is any private data in the
	 * request, we will be given a pretty large buffer without telling us the
	 * original size. The only way to tell the difference is by looking at
	 * the contents, which are initialized to zero.
	 * If the protocol version fields aren't set, this is a connection attempt
	 * from an older version. This could could be 3.0 or 2.0 - we can't tell.
	 * We really should have changed this for OFED 1.3 :-(
	 */

	/* Be paranoid. RDS always has privdata */
	if (!event->param.conn.private_data_len) {
		printk(KERN_NOTICE "RDS incoming connection has no private data, "
			"rejecting\n");
		return 0;
	}

	if (isv6) {
		data_len = sizeof(struct rds6_ib_connect_private);
		major = dp->ricp_v6.dp_protocol_major;
		minor = dp->ricp_v6.dp_protocol_minor;
		mask = dp->ricp_v6.dp_protocol_minor_mask;
	} else {
		data_len = sizeof(struct rds_ib_connect_private);
		major = dp->ricp_v4.dp_protocol_major;
		minor = dp->ricp_v4.dp_protocol_minor;
		mask = dp->ricp_v4.dp_protocol_minor_mask;
	}
	/* Even if len is crap *now* I still want to check it. -ASG */
	if (event->param.conn.private_data_len < data_len || major == 0)
		return RDS_PROTOCOL_4_0;

	common = be16_to_cpu(mask) & RDS_IB_SUPPORTED_PROTOCOLS;
	if (major == 4 && common) {
		version = RDS_PROTOCOL_4_0;
		while ((common >>= 1) != 0)
			version++;
	} else if (RDS_PROTOCOL_COMPAT_VERSION == RDS_PROTOCOL(major, minor)) {
		version = RDS_PROTOCOL_COMPAT_VERSION;
	} else {
		if (isv6) {
			printk_ratelimited(KERN_NOTICE "RDS: Connection from %pI6c using incompatible protocol version %u.%u\n",
					   &dp->ricp_v6.dp_saddr, major, minor);
		} else {
			printk_ratelimited(KERN_NOTICE "RDS: Connection from %pI4 using incompatible protocol version %u.%u\n",
					   &dp->ricp_v4.dp_saddr, major, minor);
		}
	}
	return version;
}

#if IS_ENABLED(CONFIG_IPV6)
/* Given an IPv6 address, find the net_device which hosts that address and
 * return its index.  This is used by the rds_ib_cm_handle_connect() code to
 * find the interface index of where an incoming request comes from when
 * the request is using a link local address.
 *
 * Note one problem in this search.  It is possible that two interfaces have
 * the same link local address.  Unfortunately, this cannot be solved unless
 * the underlying layer gives us the interface which an incoming RDMA connect
 * request comes from.
 */
u32 __rds_find_ifindex_v6(struct net *net, const struct in6_addr *addr)
{
	struct net_device *dev;
	int idx = 0;

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		if (ipv6_chk_addr(net, addr, dev, 1)) {
			idx = dev->ifindex;
			break;
		}
	}
	rcu_read_unlock();

	return idx;
}
#endif

u32 __rds_find_ifindex_v4(struct net *net, __be32 addr)
{
	struct net_device *dev;
	int idx;

	dev = ip_dev_find(net, addr);
	if (!dev)
		return 0;
	idx = dev->ifindex;
	dev_put(dev);

	return idx;
}

static void rds_destroy_cm_id_worker(struct work_struct *_work)
{
	struct rds_ib_destroy_cm_id_work *work = container_of(_work,
							      struct rds_ib_destroy_cm_id_work,
							      work);

	rdma_destroy_id(work->cm_id);
	kfree(work);
}

static void rds_spawn_destroy_cm_id(struct rdma_cm_id *cm_id)
{
	struct rds_ib_destroy_cm_id_work *work;

	work = kmalloc(sizeof(*work), GFP_KERNEL);
	if (work) {
		INIT_WORK(&work->work, rds_destroy_cm_id_worker);
		work->cm_id = cm_id;
		trace_rds_ib_queue_work(NULL, rds_aux_wq,
					&work->work, 0,
					"destroy cm_id");
		queue_work(rds_aux_wq, &work->work);
	} else
		rdma_destroy_id(cm_id);
}

static int rds_ib_cm_accept(struct rds_connection *conn,
			    struct rdma_cm_id *cm_id,
			    bool isv6,
			    const union rds_ib_conn_priv *dp,
			    u32 version,
			    u8 responder_resources,
			    u8 initiator_depth)
{
	const struct rds_ib_conn_priv_cmn *dp_cmn;
	struct rdma_conn_param conn_param;
	union rds_ib_conn_priv dp_rep;
	struct rds_ib_connection *ic;
	u16 frag;
	int err;

	ic = conn->c_transport_data;

	BUG_ON(cm_id->context);
	BUG_ON(ic->i_cm_id);

	ic->i_cm_id = cm_id;
	cm_id->context = conn;

	if (isv6) {
#if IS_ENABLED(CONFIG_IPV6)
		dp_cmn = &dp->ricp_v6.dp_cmn;
#else
		return -EOPNOTSUPP;
#endif
	} else
		dp_cmn = &dp->ricp_v4.dp_cmn;

	rds_ib_set_flow_control(conn, be32_to_cpu(dp_cmn->ricpc_credit));
	/* Use ic->i_flowctl as the first post credit to enable
	 * IB transport flow control. This first post credit is
	 * deducted after advertise the credit to the remote
	 * connection.
	 */
	atomic_set(&ic->i_credits, IB_SET_POST_CREDITS(ic->i_flowctl));

	/* If the peer gave us the last packet it saw, process this as if
	 * we had received a regular ACK. */
	if (dp_cmn->ricpc_ack_seq)
		rds_send_drop_acked(conn, be64_to_cpu(dp_cmn->ricpc_ack_seq),
				    NULL);

	err = rds_ib_setup_qp(conn);
	if (err) {
		rds_conn_drop(conn, DR_IB_PAS_SETUP_QP_FAIL, err);
                trace_rds_ib_cm_accept_err(NULL, ic->rds_ibdev,
					   conn, ic, "rds_ib_setup_qp error", err);
		return err;
	}

	frag = rds_ib_set_frag_size(conn, be16_to_cpu(dp_cmn->ricpc_frag_sz));

	rds_ib_cm_fill_conn_param(conn, &conn_param, &dp_rep, version,
				  responder_resources,
				  initiator_depth,
				  frag, isv6);

	/* rdma_accept() calls rdma_reject() internally if it fails */
	if (rds_ib_sysctl_local_ack_timeout &&
	    rdma_port_get_link_layer(cm_id->device, cm_id->port_num) == IB_LINK_LAYER_ETHERNET)
		rdma_set_ack_timeout(cm_id, rds_ib_sysctl_local_ack_timeout);

	rdma_set_min_rnr_timer(cm_id, IB_RNR_TIMER_000_32);

	/* Post receive buffers - as a side effect, this will update
	 * the posted credit count.
	 */
	if (!rds_ib_srq_enabled) {
		rds_ib_recv_init_ring(ic);
		RDS_IB_RECV_REFILL(conn, 1, GFP_KERNEL, s_ib_rx_refill_from_cm);
	}

	err = rdma_accept(cm_id, &conn_param);
	if (err) {
		rds_conn_drop(conn, DR_IB_RDMA_ACCEPT_FAIL, err);
                trace_rds_ib_cm_accept_err(NULL, ic->rds_ibdev,
					   conn, ic, "rdma accept failure", err);
	}

	return err;
}

int rds_ib_cm_handle_connect(struct rdma_cm_id *cm_id,
			     struct rdma_cm_event *event,
			     bool isv6)
{
	const struct rds_ib_conn_priv_cmn *dp_cmn;
	struct rds_ib_connection *ic = NULL;
	struct rds_connection *conn = NULL;
	struct rds_ib_device *rds_ibdev;
	struct rds_conn_path *cp;
	const union rds_ib_conn_priv *dp;
	struct in6_addr s_mapped_addr;
	struct in6_addr d_mapped_addr;
	const struct in6_addr *saddr6;
	const struct in6_addr *daddr6;
	char *reason = NULL;
	int destroy = 1;
	int acl_ret = 0;
	u32 ifindex = 0;
	u32 version;
	int err = 1;

	/* Check whether the remote protocol version matches ours. */
	version = rds_ib_protocol_compatible(event, isv6);
	if (!version) {
		reason = "protocol incompatible";
		goto out;
	}

	dp = event->param.conn.private_data;
	if (isv6) {
#if IS_ENABLED(CONFIG_IPV6)
		dp_cmn = &dp->ricp_v6.dp_cmn;
		saddr6 = &dp->ricp_v6.dp_saddr;
		daddr6 = &dp->ricp_v6.dp_daddr;
		/* If either address is link local, need to find the
		 * interface index in order to create a proper RDS
		 * connection.
		 */
		if (ipv6_addr_type(daddr6) & IPV6_ADDR_LINKLOCAL ||
		    ipv6_addr_type(saddr6) & IPV6_ADDR_LINKLOCAL) {
			/* Using init_net for now ..  If peer address is
			 * link local, we also use our address to find the
			 * correct index.
			 */
			ifindex = __rds_find_ifindex_v6(&init_net, daddr6);
			/* No index found...  Need to bail out. */
			if (ifindex == 0) {
				reason = "no ifindex found";
				err = -EOPNOTSUPP;
				goto out;
			}
		}
#else
		reason = "IPv6 not supported";
		err = -EOPNOTSUPP;
		goto out;
#endif
	} else {
		dp_cmn = &dp->ricp_v4.dp_cmn;
		ipv6_addr_set_v4mapped(dp->ricp_v4.dp_saddr, &s_mapped_addr);
		ipv6_addr_set_v4mapped(dp->ricp_v4.dp_daddr, &d_mapped_addr);
		saddr6 = &s_mapped_addr;
		daddr6 = &d_mapped_addr;
	}

#ifdef CONFIG_RDS_ACL

	acl_ret = rds_ib_match_acl(cm_id, saddr6);
	if (acl_ret < 0) {
		err = RDS_ACL_FAILURE;
		reason = "passive: rds_ib_match_acl failed";
		goto out;
	}

#else /* !CONFIG_RDS_ACL */

	acl_ret = 0;

#endif /* !CONFIG_RDS_ACL */

	/* RDS/IB is not currently netns aware, thus init_net */
	conn = rds_conn_create(&init_net, daddr6, saddr6,
			       &rds_ib_transport, dp_cmn->ricpc_tos,
			       GFP_KERNEL, ifindex);

	if (IS_ERR(conn)) {
		reason = "rds_conn_create_failed";
		err = PTR_ERR(conn);
		conn = NULL;
		goto out;
	}

	cp = &conn->c_path[0];

	rds_ib_set_protocol(conn, version);

	conn->c_acl_en = acl_ret;
	conn->c_acl_init = 1;

	/*
	 * The connection request may occur while the
	 * previous connection exist, e.g. in case of failover.
	 */
	mutex_lock(&conn->c_cm_lock);

	ic = conn->c_transport_data;
	if (!ic) {
		err = -ENOLINK;
		reason = "no ic";
		goto out;
	}

	/* prevent the cm_id from being pulled right under our feet */
	down_read(&ic->i_cm_id_free_lock);

	/* There can only be a single alternative:
	 * A new connection request can arrive
	 * prior to this node having worked its way
	 * through the entire shutdown path
	 * plus the subsequent attempt to use
	 * "i_alt.cm_id" in "rds_ib_conn_path_connect".
	 * So we simply disregard the now stale cm_id
	 * and work with the latest incoming request.
	 */
	if (ic->i_alt.cm_id) {
		rds_ib_stats_inc(s_ib_yield_stale);
		trace_rds_ib_conn_yield_stale(NULL, ic->rds_ibdev,
					      conn, ic, "stale", 0);
		rds_spawn_destroy_cm_id(ic->i_alt.cm_id);
		ic->i_alt.cm_id = NULL;
	}

	if (!rds_conn_transition(conn, RDS_CONN_DOWN, RDS_CONN_CONNECTING,
				 DR_DEFAULT)) {
		bool yield;
		ktime_t conn_ts;
		s64 conn_age;

		/* Passive connections (loopback, same IP-address)
		 * always yield, since the "c_passive conn"
		 * never initiates.
		 *
		 * Also yield if the peer is what has been considered
		 * 'active side' (i.e. lower IP-address)
		 * for compatibility reasons during unsynchronized
		 * initial connection establishment races.
		 *
		 * Also yield to this incoming connection request
		 * if previous connection establishment took too long
		 * or the existing connection is just older:
		 *
		 * If we've been in state RDS_CONN_UP this long
		 * and there's a inbound connection requests
		 * the peer apparently doesn't agree the connection
		 * is UP. So we're better of accepting the call
		 * than hanging on to a connection that no longer works.
		 *
		 * If we're the 'active side' but haven't even come
		 * as far as trying to connect, we yield as well.
		 */
		yield = rds_addr_cmp(&conn->c_faddr, &conn->c_laddr) <= 0;
		if (!yield) {
			conn_ts = atomic64_read(&ic->i_connecting_ts);
			if (conn_ts) {
				conn_age = ktime_to_ms(ktime_sub(ktime_get(), conn_ts));
				yield = conn_age >= rds_ib_sysctl_yield_after_ms;
				if (yield && rds_conn_path_state(cp) != RDS_CONN_UP) {
					rds_ib_stats_inc(s_ib_yield_expired);
					trace_rds_ib_conn_yield_expired(NULL, ic->rds_ibdev,
									conn, ic, "expired", 0);
				}
			}
		}
		if (yield) {
			ic->i_alt.cm_id = cm_id;
			ic->i_alt.is_stale = false;
			ic->i_alt.isv6 = isv6;
			memcpy(&ic->i_alt.private_data, dp,
			       sizeof(ic->i_alt.private_data));
			ic->i_alt.version = version;
			ic->i_alt.responder_resources = event->param.conn.responder_resources;
			ic->i_alt.initiator_depth = event->param.conn.initiator_depth;
			atomic64_set(&ic->i_connecting_ts, 0);
			cp->cp_reconnect_jiffies = 0;
			/* We need to take the long route
			 * through the shutdown code-path here
			 * as the resources allocated and configured
			 * by "rds_ib_setup_qp" are only properly
			 * de-allocated in that path:
			 * e.g. "rds_ib_conn_path_shutdown"
			 */
			rds_conn_drop(conn, DR_IB_CONN_DROP_YIELD, 0);
			err = 0;
			destroy = 0;
			rds_ib_stats_inc(s_ib_yield_yielding);
			trace_rds_ib_conn_yield_yielding(NULL, ic->rds_ibdev,
							 conn, ic, "yielding", 0);
		} else {
			rds_ib_stats_inc(s_ib_yield_right_of_way);
			trace_rds_ib_conn_yield_right_of_way(NULL, ic->rds_ibdev,
							     conn, ic, "right of way", 0);
		}
	} else {
		destroy = 0;
		atomic64_set(&ic->i_connecting_ts, ktime_get());
		rds_ib_arm_cm_watchdog(ic);
		err = rds_ib_cm_accept(conn, cm_id,
				       isv6, dp, version,
				       event->param.conn.responder_resources,
				       event->param.conn.initiator_depth);
		if (err)
			reason = "rds_ib_cm_accept failed";
		else if (event->param.conn.qp_num)
			ic->i_dst_qp_num = event->param.conn.qp_num;
	}

out:
	rds_ibdev = ic ? ic->rds_ibdev : NULL;
	if (reason)
		trace_rds_ib_cm_handle_connect_err(rds_ibdev ?
						   rds_ibdev->dev : NULL,
						   rds_ibdev,
						   conn, ic, reason, err);
	else
		trace_rds_ib_cm_handle_connect(rds_ibdev ?
					       rds_ibdev->dev : NULL,
					       rds_ibdev,
					       conn, ic, reason, err);

	if (conn)
		mutex_unlock(&conn->c_cm_lock);
	if (err)
		rdma_reject(cm_id, &err, sizeof(int),
			    IB_CM_REJ_CONSUMER_DEFINED);
	if (ic)
		up_read(&ic->i_cm_id_free_lock);

	return destroy;
}

void rds_ib_conn_destroy_worker(struct work_struct *_work)
{
	struct rds_ib_conn_destroy_work    *work =
		container_of(_work, struct rds_ib_conn_destroy_work, work.work);
	struct rds_connection   *conn = work->conn;

	rds_conn_destroy(conn, 0);

	kfree(work);
}

void rds_ib_conn_destroy_init(struct rds_connection *conn)
{
	struct rds_ib_conn_destroy_work *work;

	work = kzalloc(sizeof *work, GFP_ATOMIC);
	if (!work) {
		pr_err("RDS/IB: failed to allocate connection destroy work\n");
		return;
	}

	work->conn = conn;
	INIT_DELAYED_WORK(&work->work, rds_ib_conn_destroy_worker);
	rds_queue_delayed_work(&conn->c_path[0], rds_aux_wq, &work->work, 0,
			       "conn destroy");
}

int rds_ib_cm_initiate_connect(struct rdma_cm_id *cm_id, bool isv6)
{
	struct rds_connection *conn = cm_id->context;
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rdma_conn_param conn_param;
	union rds_ib_conn_priv dp;
	u16 frag;
	int ret;

#ifdef CONFIG_RDS_ACL

	ret = rds_ib_match_acl(ic->i_cm_id, &conn->c_faddr);
	if (ret < 0) {
		pr_err("RDS: IB: active conn %p <%pI6c,%pI6c,%d> destroyed due ACL violation\n",
		       conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos);
		trace_rds_ib_cm_initiate_connect_err(ic->rds_ibdev ?
		    ic->rds_ibdev->dev : NULL, ic->rds_ibdev, conn, ic,
		    "active conn destroyed due to ACL violation", -EPERM);
		rds_ib_conn_destroy_init(conn);
		return 0;
	}

#else /* !CONFIG_RDS_ACL */

	ret = 0;

#endif /* !CONFIG_RDS_ACL */

	conn->c_acl_en = ret;
	conn->c_acl_init = 1;

	ic->i_flowctl = rds_ib_sysctl_flow_control;	/* advertise flow control */
	/* Use ic->i_flowctl as the first post credit to enable
	 * IB transport flow control. This first post credit is
	 * deducted after advertise the credit to the remote
	 * connection.
	 */
	atomic_set(&ic->i_credits, IB_SET_POST_CREDITS(ic->i_flowctl));

	trace_rds_ib_cm_initiate_connect(ic->rds_ibdev ?
	    ic->rds_ibdev->dev : NULL, ic->rds_ibdev, conn, ic,
	    "initiate conn", 0);

	ret = rds_ib_setup_qp(conn);
	if (ret) {
		rds_conn_drop(conn, DR_IB_ACT_SETUP_QP_FAIL, ret);
		goto out;
	}
	frag = rds_ib_set_frag_size(conn, ib_init_frag_size);
	rds_ib_cm_fill_conn_param(conn, &conn_param, &dp,
				  conn->c_proposed_version, UINT_MAX, UINT_MAX,
				  frag, isv6);
	rdma_set_min_rnr_timer(cm_id, IB_RNR_TIMER_000_32);

	/* Post receive buffers - as a side effect, this will update
	 * the posted credit count.
	 */
	if (!rds_ib_srq_enabled) {
		rds_ib_recv_init_ring(ic);
		RDS_IB_RECV_REFILL(conn, 1, GFP_KERNEL, s_ib_rx_refill_from_cm);
	}
	ret = rdma_connect(cm_id, &conn_param);
	if (ret) {
		rds_conn_drop(conn, DR_IB_RDMA_CONNECT_FAIL, ret);
	}

out:
	ic->i_active_side = 1;

	return ret;
}

void rds_ib_conn_path_reset(struct rds_conn_path *cp, unsigned flags)
{
	struct rds_connection *conn = cp->cp_conn;
	struct rds_ib_connection *ic = conn->c_transport_data;

	if (ic) {
		/* A reset of the connection-timestamp is implicit */
		atomic64_set(&ic->i_connecting_ts, 0);

		if (flags & RDS_CONN_PATH_RESET_ALT_CONN) {
			/* delaying destruction of "ic->i_alt.cm_id"
			 * until "rds_ib_conn_path_connect" so that
			 * we don't end up in a dead-lock acquiring
			 * "conn->c_cm_lock".
			 */
			ic->i_alt.is_stale = true;
			cp->cp_reconnect_jiffies = 0;
		}

		if (flags & RDS_CONN_PATH_RESET_WATCHDOG)
			rds_ib_cancel_cm_watchdog(ic, "conn path reset");
	}
}

int rds_ib_conn_preferred_cpu(struct rds_connection *conn, bool in_send_path)
{
	struct rds_ib_connection *ic = conn->c_transport_data;

	if (!ic)
		return WORK_CPU_UNBOUND;

	return in_send_path ? ic->i_preferred_send_cpu : ic->i_preferred_recv_cpu;
}

bool rds_ib_conn_has_alt_conn(struct rds_connection *conn)
{
	struct rds_ib_connection *ic = conn->c_transport_data;

	return ic && ic->i_alt.cm_id && !ic->i_alt.is_stale;
}

int rds_ib_conn_path_connect(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;
	struct sockaddr_storage src, dest;
	rdma_cm_event_handler handler;
	struct rds_ib_connection *ic;
	struct rdma_cm_id *cm_id, *alt_cm_id;
	char *reason = NULL;
	int ret;

	ic = conn->c_transport_data;

	trace_rds_ib_conn_path_connect(ic && ic->rds_ibdev ?
				       ic->rds_ibdev->dev : NULL,
				       ic ? ic->rds_ibdev : NULL,
				       conn, ic, "start connect", 0);
	conn->c_path->cp_conn_start_jf = jiffies;

	mutex_lock(&conn->c_cm_lock);

	atomic64_set(&ic->i_connecting_ts, ktime_get());
	rds_ib_arm_cm_watchdog(ic);

	if (ic->i_alt.cm_id && !ic->i_alt.is_stale) {
		rds_ib_stats_inc(s_ib_yield_accepting);
		trace_rds_ib_conn_yield_accepting(NULL, ic->rds_ibdev,
						  conn, ic, "accepting", 0);

		ret = rds_ib_cm_accept(conn, ic->i_alt.cm_id,
				       ic->i_alt.isv6,
				       &ic->i_alt.private_data,
				       ic->i_alt.version,
				       ic->i_alt.responder_resources,
				       ic->i_alt.initiator_depth);

		ic->i_alt.cm_id = NULL;
		mutex_unlock(&conn->c_cm_lock);

		if (ret) {
			/* Take the long route here,
			 * since "rds_ib_setup_qp" allocates a number of
			 * resources that are only released
			 * in the shutdown-path:
			 * e.g. "ic->i_send_hdrs", "ic->i_sends",
			 *      or even "rds_ib_remove_conn".
			 *
			 * But we want to reconnect as quickly as possible.
			 */

			trace_rds_ib_conn_yield_accept_err(NULL, ic->rds_ibdev,
							   conn, ic, "accept failed", ret);

			cp->cp_reconnect_jiffies = 0;

			return ret;
		}

		rds_ib_stats_inc(s_ib_yield_success);
		trace_rds_ib_conn_yield_success(NULL, ic->rds_ibdev,
						conn, ic, "success", 0);

		return 0;
	} else {
		alt_cm_id = ic->i_alt.cm_id;
		if (alt_cm_id) {
			rds_ib_stats_inc(s_ib_yield_stale);
			trace_rds_ib_conn_yield_stale(NULL, ic->rds_ibdev,
						      conn, ic, "stale", 0);
			ic->i_alt.cm_id = NULL;
		}

		if (test_bit(RDS_IB_NEED_SHUTDOWN, &ic->i_flags)) {
			/* The shutdown-path hasn't completed yet,
			 * so we can't make any progress quite yet.
			 * Try again in a jiff.
			 */
			cp->cp_reconnect_jiffies = 1;
			ret = -EAGAIN;
		} else
			ret = 0;

		mutex_unlock(&conn->c_cm_lock);

		if (alt_cm_id)
			rds_spawn_destroy_cm_id(alt_cm_id);

		if (ret)
			return ret;
	}

	/* XXX I wonder what affect the port space has */
	/* delegate cm event handler to rdma_transport */
#if IS_ENABLED(CONFIG_IPV6)
	if (conn->c_isv6)
		handler = rds6_rdma_cm_event_handler;
	else
#endif
		handler = rds_rdma_cm_event_handler;

	WARN_ON(ic->i_cm_id);
	ic->i_cm_id = rdma_create_id(rds_conn_net(conn),
				     handler, conn, RDMA_PS_TCP, IB_QPT_RC);

	if (IS_ERR(ic->i_cm_id)) {
		ret = PTR_ERR(ic->i_cm_id);
		ic->i_cm_id = NULL;
		reason = "rdma_create_id failed";
		goto out;
	}

	if (ipv6_addr_v4mapped(&conn->c_faddr)) {
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *)&src;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = conn->c_laddr.s6_addr32[3];
		sin->sin_port = 0;

		sin = (struct sockaddr_in *)&dest;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = conn->c_faddr.s6_addr32[3];
		sin->sin_port = htons(RDS_PORT);
	} else {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)&src;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = conn->c_laddr;
		sin6->sin6_port = 0;
		sin6->sin6_scope_id = conn->c_dev_if;

		sin6 = (struct sockaddr_in6 *)&dest;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = conn->c_faddr;
		sin6->sin6_port = htons(RDS_CM_PORT);
		sin6->sin6_scope_id = conn->c_dev_if;
	}

	ret = rdma_resolve_addr(ic->i_cm_id, (struct sockaddr *)&src,
				(struct sockaddr *)&dest,
				RDS_RDMA_RESOLVE_ADDR_TIMEOUT_MS(conn));
	if (ret) {
		reason = "addr resolve failed";

		down_write(&ic->i_cm_id_free_lock);
		cm_id = ic->i_cm_id;
		ic->i_cm_id = NULL;
		up_write(&ic->i_cm_id_free_lock);

		rdma_destroy_id(cm_id);
	}

out:
	if (reason)
		trace_rds_ib_conn_path_connect_err(ic && ic->rds_ibdev ?
						   ic->rds_ibdev->dev : NULL,
						   ic ? ic->rds_ibdev : NULL,
						   conn, ic, reason, ret);
	return ret;
}

void rds_ib_conn_path_shutdown_prepare(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;
	struct rds_ib_connection *ic = conn->c_transport_data;

	trace_rds_ib_conn_path_shutdown_prepare(ic && ic->rds_ibdev ?
						ic->rds_ibdev->dev : NULL,
						ic ? ic->rds_ibdev : NULL, conn, ic,
						"conn path shutdown prepare", 0);

	rds_ib_cancel_cm_watchdog(ic, "conn path shutdown prepare");

	if (ic->i_cm_id) {
		int err;
		err = rdma_disconnect(ic->i_cm_id);
		if (err) {
			/* Actually this may happen quite frequently, when
			 * an outgoing connect raced with an incoming connect.
			 */
			trace_rds_ib_conn_path_shutdown_prepare_err(ic->rds_ibdev ?
				ic->rds_ibdev->dev : NULL, ic->rds_ibdev,
				conn, ic, "failed to disconnect", err);

		} else if (rds_ib_srq_enabled && ic->rds_ibdev) {
			/*
			   wait for the last wqe to complete, then schedule
			   the recv work to drain the RX CQ.
			*/
			wait_for_completion(&ic->i_last_wqe_complete);
			if (rds_ib_preferred_cpu & RDS_IB_PREFER_CPU_TASKLET)
				tasklet_schedule(&ic->i_rtasklet);
			else
				queue_work_on(smp_processor_id(),
					      rds_evt_wq, &ic->i_recv_w);
		}
	}
}

unsigned long rds_ib_conn_path_shutdown_check_wait(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;
	struct rds_ib_connection *ic = conn->c_transport_data;

	return (!ic->i_cm_id ||
		test_bit(RDS_IB_CQ_ERR, &ic->i_flags) ||
		(rds_ib_ring_empty(&ic->i_recv_ring) &&
		 (atomic_read(&ic->i_signaled_sends) == 0) &&
		 (atomic_read(&ic->i_fastreg_wrs) ==
		  RDS_IB_DEFAULT_FREG_WR))) ? 0
		: msecs_to_jiffies(1000);
}

void rds_ib_conn_path_shutdown_tidy_up(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;
	struct rds_ib_connection *ic = conn->c_transport_data;

	if (!rds_ib_ring_empty(&ic->i_send_ring) ||
	    test_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags))
		rds_ib_tx(ic);

	if (!rds_ib_ring_empty(&ic->i_recv_ring)) {
		spin_lock_bh(&ic->i_rx_lock);
		rds_ib_rx(ic);
		spin_unlock_bh(&ic->i_rx_lock);
	}
}

void rds_ib_conn_path_shutdown_final(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rdma_cm_id *cm_id;

	if (test_and_clear_bit(RDS_USER_RESET, &cp->cp_flags))
		set_ib_conn_flag(RDS_IB_CQ_DESTROY, ic);

	if (ic->i_cm_id) {
		cancel_delayed_work_sync(&ic->i_cq_follow_send_affinity_w);
		cancel_delayed_work_sync(&ic->i_cq_follow_recv_affinity_w);

		cancel_delayed_work_sync(&ic->i_rx_w.work);

		cancel_work_sync(&ic->i_send_w);
		cancel_work_sync(&ic->i_recv_w);
		tasklet_kill(&ic->i_stasklet);
		tasklet_kill(&ic->i_rtasklet);

		clear_bit_mb(RDS_IB_CQ_ERR, &ic->i_flags);

		/* first destroy the ib state that generates callbacks */
		if (ic->i_cm_id->qp)
			rdma_destroy_qp(ic->i_cm_id);

		if (test_bit(RDS_IB_CQ_ERR, &ic->i_flags) || test_bit(RDS_IB_CQ_DESTROY, &ic->i_flags)) {
			pr_info("RDS/IB: Destroy CQ: conn %p <%pI6c,%pI6c,%d> ic %p cm_id %p\n",
				conn, &conn->c_laddr, &conn->c_faddr,
				conn->c_tos, ic, ic->i_cm_id);
			if (ic->rds_ibdev) {
				mutex_lock(&ic->i_delayed_free_lock);
				__rds_rdma_free_cq(ic, ic->rds_ibdev);
				mutex_unlock(&ic->i_delayed_free_lock);
			}
			clear_bit(RDS_IB_CQ_ERR, &ic->i_flags);
			clear_bit(RDS_IB_CQ_DESTROY, &ic->i_flags);
		}

		if (ic->rds_ibdev)
			__rds_rdma_conn_dev_rele(ic);

		/* Finally, destroy the cm_id.  Note that i_cm_id may be
		 * set even if rds_ibdev is NULL.  This is the error case
		 * when the conn cannot be associated with the underlying
		 * device.
		 */

		down_write(&ic->i_cm_id_free_lock);
		cm_id = ic->i_cm_id;
		cm_id->context = NULL;
		ic->i_cm_id = NULL;
		up_write(&ic->i_cm_id_free_lock);

		rds_spawn_destroy_cm_id(cm_id);

		ic->i_pd = NULL;
		ic->i_mr = NULL;
		ic->i_send_hdrs = NULL;
		ic->i_recv_hdrs = NULL;
		ic->i_ack = NULL;
		clear_bit_mb(RDS_IB_NEED_SHUTDOWN, &ic->i_flags);
	}

	BUG_ON(ic->rds_ibdev);

	/* Clear pending transmit */
	if (ic->i_data_op) {
		struct rds_message *rm;

		rm = container_of(ic->i_data_op, struct rds_message, data);
		rds_message_put(rm);
		ic->i_data_op = NULL;
	}

	/* Clear the ACK state */
	clear_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags);
#ifdef KERNEL_HAS_ATOMIC64
	atomic64_set(&ic->i_ack_next, 0);
#else
	ic->i_ack_next = 0;
#endif
	ic->i_ack_recv = 0;

	/* Clear flow control state */
	ic->i_flowctl = 0;
	atomic_set(&ic->i_credits, 0);

	/* Re-init rings, but retain sizes. */
	rds_ib_ring_init(&ic->i_send_ring, ic->i_send_ring.w_nr);
	rds_ib_ring_init(&ic->i_recv_ring, ic->i_recv_ring.w_nr);
	rds_ib_init_ic_frag(ic);

	if (ic->i_ibinc) {
		rds_inc_put(&ic->i_ibinc->ii_inc);
		ic->i_ibinc = NULL;
	}

	vfree(ic->i_sends);
	ic->i_sends = NULL;
	if (!rds_ib_srq_enabled)
		vfree(ic->i_recvs);

	ic->i_recvs = NULL;

	reinit_completion(&ic->i_last_wqe_complete);

	ic->i_active_side = 0;
}

/*
 * This is so careful about only cleaning up resources that were built up
 * so that it can be called at any point during startup.  In fact it
 * can be called multiple times for a given connection.
 */
void rds_ib_conn_path_shutdown(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;
	struct rds_ib_connection *ic = conn->c_transport_data;

	if (ic->i_cm_id) {
		rds_ib_conn_path_shutdown_prepare(cp);

		/* quiesce tx and rx completion before tearing down */
		while (!wait_event_timeout(rds_ib_ring_empty_wait,
					   rds_ib_conn_path_shutdown_check_wait(cp) == 0,
					   msecs_to_jiffies(1000))) {
			/* Try to reap pending RX and TX completions every second */
			rds_ib_conn_path_shutdown_tidy_up(cp);
		}
	}

	rds_ib_conn_path_shutdown_final(cp);
}

int rds_ib_conn_alloc(struct rds_connection *conn, gfp_t gfp)
{
	struct rds_ib_connection *ic;
	unsigned long flags;

	/* XXX too lazy? */
	ic = kzalloc(sizeof(struct rds_ib_connection), gfp);
	if (!ic)
		return -ENOMEM;

	INIT_LIST_HEAD(&ic->ib_node);
	init_rwsem(&ic->i_cm_id_free_lock);

	tasklet_init(&ic->i_stasklet, rds_ib_tasklet_fn_send, (unsigned long) ic);
	tasklet_init(&ic->i_rtasklet, rds_ib_tasklet_fn_recv, (unsigned long) ic);
	INIT_WORK(&ic->i_send_w, rds_ib_send_w);
	INIT_WORK(&ic->i_recv_w, rds_ib_recv_w);
	mutex_init(&ic->i_recv_mutex);
#ifndef KERNEL_HAS_ATOMIC64
	spin_lock_init(&ic->i_ack_lock);
#endif
	atomic_set(&ic->i_signaled_sends, 0);
	spin_lock_init(&ic->i_rx_lock);
	spin_lock_init(&ic->i_tx_lock);

	/*
	 * rds_ib_conn_path_shutdown() waits for these to be emptied so they
	 * must be initialized before it can be called.
	 */
	rds_ib_ring_init(&ic->i_send_ring, 0);
	rds_ib_ring_init(&ic->i_recv_ring, 0);

	/* Might want to change this hard-coded value to a variable in future.
	 * Updating this atomic counter will need an update to qp/cq size too.
	 */
	atomic_set(&ic->i_fastreg_wrs, RDS_IB_DEFAULT_FREG_WR);

	rds_ib_init_ic_frag(ic);

	ic->conn = conn;
	conn->c_transport_data = ic;

	init_completion(&ic->i_last_wqe_complete);

	INIT_DELAYED_WORK(&ic->i_rx_w.work, rds_ib_rx_handler);

	spin_lock_irqsave(&ib_nodev_conns_lock, flags);
	list_add_tail(&ic->ib_node, &ib_nodev_conns);
	spin_unlock_irqrestore(&ib_nodev_conns_lock, flags);

	ic->i_scq_vector = -1;
	ic->i_rcq_vector = -1;
	ic->i_scq_isolate_warned = false;
	ic->i_rcq_isolate_warned = false;
	ic->i_preferred_send_cpu = WORK_CPU_UNBOUND;
	ic->i_preferred_recv_cpu = WORK_CPU_UNBOUND;

	INIT_DELAYED_WORK(&ic->i_cm_watchdog_w, rds_ib_cm_watchdog_handler);
	INIT_DELAYED_WORK(&ic->i_cq_follow_send_affinity_w, rds_ib_cq_follow_send_affinity);
	INIT_DELAYED_WORK(&ic->i_cq_follow_recv_affinity_w, rds_ib_cq_follow_recv_affinity);

	INIT_DELAYED_WORK(&ic->i_delayed_free_work,
			  rds_rdma_conn_delayed_free_worker);
	mutex_init(&ic->i_delayed_free_lock);

	INIT_LIST_HEAD(&ic->i_delayed_free_work_node);

	rdsdebug("conn %p conn ic %p\n", conn, conn->c_transport_data);
	return 0;
}

/*
 * Free a connection. Connection must be shut down and not set for reconnect.
 */
void rds_ib_conn_free(void *arg)
{
	struct rds_ib_connection *ic = arg;
	unsigned long flags;

	rdsdebug("ic %p\n", ic);

	flush_delayed_work(&ic->i_delayed_free_work);

	spin_lock_irqsave(&ib_nodev_conns_lock, flags);
	/* Conn is either on a rds_ibdev's list or on the ib_nodev_conns list.
	 * If it is on a device's list, its rds_ibdev should be set.
	 */
	if (ic->rds_ibdev)
		spin_lock(&ic->rds_ibdev->spinlock);
	if (!list_empty(&ic->ib_node))
		list_del(&ic->ib_node);
	if (ic->rds_ibdev)
		spin_unlock(&ic->rds_ibdev->spinlock);
	spin_unlock_irqrestore(&ib_nodev_conns_lock, flags);

	if (ic->i_alt.cm_id)
		rdma_destroy_id(ic->i_alt.cm_id);

	kfree(ic);
}

void rds_ib_destroy_fastreg(struct rds_ib_device *rds_ibdev)
{
	/* Because we are using rw_lock, by this point we should have
	 * received completions for all the wrs posted
	 */
	WARN_ON(atomic_read(&rds_ibdev->fastreg_wrs) != RDS_IB_DEFAULT_FREG_WR);

	if (rds_ibdev->rid_tasklet_work_initialized) {
		cancel_work_sync(&rds_ibdev->fastreg_w);
		tasklet_kill(&rds_ibdev->fastreg_tasklet);
	}

	if (rds_ibdev->fastreg_qp) {
		/* Destroy qp */
		if (ib_destroy_qp(rds_ibdev->fastreg_qp))
			pr_err("Error destroying fastreg qp for rds_ibdev: %p\n",
			       rds_ibdev);
		rds_ibdev->fastreg_qp = NULL;
	}

	if (rds_ibdev->fastreg_cq) {
		/* Destroy cq and cq_vector */
		ib_destroy_cq(rds_ibdev->fastreg_cq);
		rds_ibdev->fastreg_cq = NULL;
		ibdev_put_vector(rds_ibdev, rds_ibdev->fastreg_cq_vector, RDS_IB_FASTREG_TOS);
	}
}

int rds_ib_setup_fastreg(struct rds_ib_device *rds_ibdev)
{
	int ret = 0;
	struct ib_cq_init_attr cq_attr;
	struct ib_qp_init_attr qp_init_attr;
	struct ib_qp_attr qp_attr;
	struct ib_port_attr port_attr;
	char *reason = NULL;
	int gid_index = 0;
	union ib_gid dgid;

	rds_ibdev->fastreg_cq_vector = ibdev_get_unused_vector(rds_ibdev, RDS_IB_FASTREG_TOS, -1);
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = RDS_IB_DEFAULT_FREG_WR + 1;
	cq_attr.comp_vector = rds_ibdev->fastreg_cq_vector;
	rds_ibdev->fastreg_cq = ib_create_cq(rds_ibdev->dev,
					     rds_ib_cq_comp_handler_fastreg,
					     rds_ib_cq_event_handler_fastreg,
					     rds_ibdev,
					     &cq_attr);
	if (IS_ERR(rds_ibdev->fastreg_cq)) {
		ret = PTR_ERR(rds_ibdev->fastreg_cq);
		rds_ibdev->fastreg_cq = NULL;
		ibdev_put_vector(rds_ibdev, rds_ibdev->fastreg_cq_vector, RDS_IB_FASTREG_TOS);
		reason = "ib_create_cq failed";
		goto clean_up;
	}

	ret = ib_req_notify_cq(rds_ibdev->fastreg_cq, IB_CQ_NEXT_COMP);
	if (ret) {
		reason = "ib_req_notify_cq failed";
		goto clean_up;
	}

	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.send_cq		= rds_ibdev->fastreg_cq;
	qp_init_attr.recv_cq		= rds_ibdev->fastreg_cq;
	qp_init_attr.qp_type		= IB_QPT_RC;
	/* 1 WR is used for invalidaton */
	qp_init_attr.cap.max_send_wr	= RDS_IB_DEFAULT_FREG_WR + 1;
	qp_init_attr.cap.max_recv_wr	= 0;
	qp_init_attr.cap.max_send_sge	= 0;
	qp_init_attr.cap.max_recv_sge	= 0;
	qp_init_attr.sq_sig_type	= IB_SIGNAL_REQ_WR;

	rds_ibdev->fastreg_qp = ib_create_qp(rds_ibdev->pd, &qp_init_attr);
	if (IS_ERR(rds_ibdev->fastreg_qp)) {
		ret = PTR_ERR(rds_ibdev->fastreg_qp);
		rds_ibdev->fastreg_qp = NULL;
		reason = "ib_create_qp failed";
		goto clean_up;
	}

	/* Use modify_qp verb to change the state from RESET to INIT */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state	= IB_QPS_INIT;
	qp_attr.pkey_index	= 0;
	qp_attr.qp_access_flags	= 0; /* Local Read is default */
	qp_attr.port_num	= RDS_IB_DEFAULT_FREG_PORT_NUM;

	ret = ib_modify_qp(rds_ibdev->fastreg_qp, &qp_attr, IB_QP_STATE	|
						IB_QP_PKEY_INDEX	|
						IB_QP_ACCESS_FLAGS	|
						IB_QP_PORT);
	if (ret) {
		reason = "ib_modify_qp to IB_QPS_INIT failed";
		goto clean_up;
	}

	/* query port to get the lid */
	ret = ib_query_port(rds_ibdev->dev, RDS_IB_DEFAULT_FREG_PORT_NUM,
			    &port_attr);
	if (ret) {
		reason = "ib_query_port failed";
		goto clean_up;
	}

	ret = rdma_query_gid(rds_ibdev->dev, RDS_IB_DEFAULT_FREG_PORT_NUM,
			     gid_index, &dgid);
	if (ret) {
		reason = "rdma_query_gid failed";
		goto clean_up;
	}

	/* Use modify_qp verb to change the state from INIT to RTR */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state	= IB_QPS_RTR;
	qp_attr.path_mtu	= IB_MTU_256;
	qp_attr.dest_qp_num	= rds_ibdev->fastreg_qp->qp_num;
	qp_attr.rq_psn		= 1;
	qp_attr.ah_attr.sl		= 0;
	qp_attr.ah_attr.port_num	= RDS_IB_DEFAULT_FREG_PORT_NUM;
	if (rdma_protocol_roce(rds_ibdev->dev, RDS_IB_DEFAULT_FREG_PORT_NUM)) {
		qp_attr.ah_attr.type		= RDMA_AH_ATTR_TYPE_ROCE;
		qp_attr.ah_attr.ah_flags        = IB_AH_GRH;
		qp_attr.ah_attr.grh.dgid	= dgid;
		qp_attr.ah_attr.grh.sgid_index	= gid_index;
	} else if (rdma_protocol_ib(rds_ibdev->dev, RDS_IB_DEFAULT_FREG_PORT_NUM)) {
		qp_attr.ah_attr.type		= RDMA_AH_ATTR_TYPE_IB;
		qp_attr.ah_attr.ib.dlid		= port_attr.lid;
	} else {
		reason = "unexpected port type";
		goto clean_up;
	}

	ret = ib_modify_qp(rds_ibdev->fastreg_qp, &qp_attr, IB_QP_STATE	|
						IB_QP_AV		|
						IB_QP_PATH_MTU		|
						IB_QP_DEST_QPN		|
						IB_QP_RQ_PSN		|
						IB_QP_MAX_DEST_RD_ATOMIC |
						IB_QP_MIN_RNR_TIMER);
	if (ret) {
		reason = "ib_modify_qp to IB_QPS_RTR failed";
		goto clean_up;
	}

	/* Use modify_qp verb to change the state from RTR to RTS */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state	= IB_QPS_RTS;
	qp_attr.sq_psn		= 1;
	qp_attr.timeout		= 14;
	qp_attr.retry_cnt	= 6;
	qp_attr.rnr_retry	= 6;
	qp_attr.max_rd_atomic	= 0;

	ret = ib_modify_qp(rds_ibdev->fastreg_qp, &qp_attr, IB_QP_STATE	|
						IB_QP_TIMEOUT		|
						IB_QP_RETRY_CNT		|
						IB_QP_RNR_RETRY		|
						IB_QP_SQ_PSN		|
						IB_QP_MAX_QP_RD_ATOMIC);
	if (ret) {
		reason = "ib_modify_qp to IB_QPS_RTS failed";
		goto clean_up;
	} else
		trace_rds_ib_setup_fastreg(rds_ibdev ? rds_ibdev->dev : NULL,
					   rds_ibdev, NULL, NULL,
					   "moved qp to RTS state for device",
					   0);

	tasklet_init(&rds_ibdev->fastreg_tasklet, rds_ib_tasklet_fn_fastreg,
		     (unsigned long)rds_ibdev);

	INIT_WORK(&rds_ibdev->fastreg_w, rds_ib_cq_comp_handler_fastreg_w);
	atomic_set(&rds_ibdev->fastreg_wrs, RDS_IB_DEFAULT_FREG_WR);
	rds_ibdev->rid_tasklet_work_initialized = true;

clean_up:
	if (reason)
		trace_rds_ib_setup_fastreg_err(rds_ibdev ?
		    rds_ibdev->dev : NULL, rds_ibdev, NULL, NULL, reason, ret);
	if (ret)
		rds_ib_destroy_fastreg(rds_ibdev);
	return ret;
}

void rds_ib_reset_fastreg(struct work_struct *work)
{
	struct rds_ib_device *rds_ibdev = container_of(work,
						       struct rds_ib_device,
						       fastreg_reset_w);

	pr_warn("RDS: IB: Resetting fastreg qp\n");
	/* Acquire write lock to stop posting on fastreg qp before resetting */
	down_write(&rds_ibdev->fastreg_lock);

	rds_ib_destroy_fastreg(rds_ibdev);
	if (rds_ib_setup_fastreg(rds_ibdev)) {
		up_write(&rds_ibdev->fastreg_lock);

		/* Failing to setup fastreg qp at this stage is unexpected.
		 * If it happens, throw a warning, and return immediately,
		 * without up_writing the fastreg_lock.
		 */
		pr_err("RDS: IB: Failed to setup fastreg resources in %s\n",
		       __func__);
		WARN_ON(1);
		return;
	}

	up_write(&rds_ibdev->fastreg_lock);
	pr_warn("RDS: IB: Finished resetting fastreg qp\n");
}
