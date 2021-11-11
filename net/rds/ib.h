#ifndef _RDS_IB_H
#define _RDS_IB_H

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include "rds.h"
#include "rdma_transport.h"
#include "rds_single_path.h"
#include "lfstack.h"

/* 1M MR pool size is doubled from 6144[=8192*3/4]. This is done to address the
 * scaling challenges seen with 6144 value. However we have to revisit this to
 * undrestand what needs to be done as a permanent fix.
 */
#define RDS_FMR_1M_POOL_SIZE		12288
#define RDS_FMR_1M_MSG_SIZE		256  /* 1M */
#define RDS_FMR_8K_MSG_SIZE             2
#define RDS_FMR_8K_POOL_SIZE		((256 / (RDS_FMR_8K_MSG_SIZE + 1)) * (8192 / 4))

#define RDS_IB_MAX_SGE			8
#define RDS_IB_RECV_SGE			2

#define RDS_IB_DEFAULT_RECV_WR		1024
#define RDS_IB_DEFAULT_SEND_WR		256
#define RDS_IB_DEFAULT_FREG_WR		256
#define RDS_IB_DEFAULT_SRQ_MAX_WR       4096
#define RDS_IB_DEFAULT_SRQ_HWM_REFILL	(RDS_IB_DEFAULT_SRQ_MAX_WR/2)
#define RDS_IB_DEFAULT_SRQ_LWM_REFILL	(RDS_IB_DEFAULT_SRQ_MAX_WR/10)

#define RDS_IB_DEFAULT_RETRY_COUNT	1

#define RDS_IB_DEFAULT_RNR_RETRY_COUNT  7

#define RDS_IB_DEFAULT_CACHE_GC_INTERVAL  20

#define RDS_IB_DEFAULT_NUM_ARPS		100

#define RDS_IB_RX_LIMIT			10000

#define RDS_IB_DEFAULT_TIMEOUT          16 /* 4.096 * 2 ^ 16 = 260 msec */

#define RDS_IB_SUPPORTED_PROTOCOLS	0x00000003	/* minor versions supported */

#define RDS_IB_SRQ_POST_BATCH_COUNT     64

#define RDS_IB_GID_FMT             "%2.2x%2.2x:%2.2x%2.2x"

#define RDS_IB_GID_RAW_ARG(gid) ((u8 *)(gid))[12],\
				((u8 *)(gid))[13],\
				((u8 *)(gid))[14],\
				((u8 *)(gid))[15]

#define RDS_IB_GID_ARG(gid)        RDS_IB_GID_RAW_ARG((gid).raw)

#define RDS_WC_MAX 32

#define NUM_RDS_RECV_SG	(PAGE_ALIGN(RDS_MAX_FRAG_SIZE) / PAGE_SIZE)

#define	RDS_IB_CQ_ERR		2
#define	RDS_IB_NEED_SHUTDOWN	4

#define RDS_IB_DEFAULT_FREG_PORT_NUM	1

#define RDS_RDMA_RESOLVE_ADDR_TIMEOUT_MS(c) ((c)->c_loopback ? 1000 : 4000)

#define RDS_IB_CQ_FOLLOW_AFFINITY_THROTTLE	100 /* msec */

enum rds_ib_preferred_cpu_options {
	RDS_IB_PREFER_CPU_CQ		= 1 << 0,
	RDS_IB_PREFER_CPU_NUMA		= 1 << 1,
	RDS_IB_PREFER_CPU_DEFAULT	= RDS_IB_PREFER_CPU_CQ
};

extern enum rds_ib_preferred_cpu_options rds_ib_preferred_cpu;

extern int rds_ib_preferred_cpu_load[];
extern spinlock_t rds_ib_preferred_cpu_load_lock;

extern struct rw_semaphore rds_ib_devices_lock;
extern struct list_head rds_ib_devices;

/*
 * IB posts i_frag_sz fragments of pages to the receive queues to
 * try and minimize the amount of memory tied up both the device and
 * socket receive queues.
 */
struct rds_page_frag {
	struct list_head	f_item;
	struct lfstack_el	f_cache_entry;
	struct scatterlist	f_sg[NUM_RDS_RECV_SG];
	struct rds_ib_device	*rds_ibdev;
};

struct rds_ib_incoming {
	struct list_head	ii_frags;
	struct lfstack_el	ii_cache_entry;
	struct rds_incoming	ii_inc;
	struct rds_ib_device	*rds_ibdev;
};

struct rds_ib_cache_head {
	struct lfstack		stack;
	atomic_t		count;
	atomic64_t		hit_count;
	atomic64_t		miss_count;
	atomic64_t		gc_count;
};

struct rds_ib_refill_cache {
	struct rds_ib_cache_head __percpu	*percpu;
	struct lfstack				ready;
	atomic64_t				hit_count;
	atomic64_t				miss_count;

};

struct rds_ib_conn_priv_cmn {
	u8			ricpc_protocol_major;
	u8			ricpc_protocol_minor;
	__be16			ricpc_protocol_minor_mask;	/* bitmask */
	u8			ricpc_tos;
	u8			ricpc_reserved1;
	__be16			ricpc_frag_sz;
	__be64			ricpc_ack_seq;
	__be32			ricpc_credit;	/* non-zero enables flow ctl */
};

struct rds_ib_connect_private {
	/* Add new fields at the end, and don't permute existing fields. */
	__be32				dp_saddr;
	__be32				dp_daddr;
	struct rds_ib_conn_priv_cmn	dp_cmn;
};

struct rds6_ib_connect_private {
	/* Add new fields at the end, and don't permute existing fields. */
	struct in6_addr			dp_saddr;
	struct in6_addr			dp_daddr;
	struct rds_ib_conn_priv_cmn	dp_cmn;
};

#define dp_protocol_major	dp_cmn.ricpc_protocol_major
#define dp_protocol_minor	dp_cmn.ricpc_protocol_minor
#define dp_protocol_minor_mask	dp_cmn.ricpc_protocol_minor_mask
#define dp_tos			dp_cmn.ricpc_tos
#define dp_reserved1		dp_cmn.ricpc_reserved1
#define dp_frag_sz		dp_cmn.ricpc_frag_sz
#define dp_ack_seq		dp_cmn.ricpc_ack_seq
#define dp_credit		dp_cmn.ricpc_credit

union rds_ib_conn_priv {
	struct rds_ib_connect_private	ricp_v4;
	struct rds6_ib_connect_private	ricp_v6;
};

struct rds_ib_send_work {
	void			*s_op;
	union {
		struct ib_send_wr	s_wr;
		struct ib_rdma_wr	s_rdma_wr;
		struct ib_atomic_wr	s_atomic_wr;
	};
	struct ib_sge		s_sge[RDS_IB_MAX_SGE];
	unsigned long		s_queued;
};

struct rds_ib_recv_work {
	struct rds_ib_incoming	*r_ibinc;
	struct rds_page_frag	*r_frag;
	struct ib_recv_wr	r_wr;
	struct ib_sge		r_sge[RDS_IB_MAX_SGE];
	struct rds_ib_connection	*r_ic;
	int				r_posted;
};

struct rds_ib_work_ring {
	u32		w_nr;
	u32		w_alloc_ptr;
	u32		w_alloc_ctr;
	u32		w_free_ptr;
	atomic_t	w_free_ctr;
};

/*
 * Rings are posted with all the allocations they'll need to queue the
 * incoming message to the receiving socket so this can't fail.
 * All fragments start with a header, so we can make sure we're not receiving
 * garbage, and we can tell a small 8 byte fragment from an ACK frame.
 */
struct rds_ib_ack_state {
	u64		ack_next;
	u64		ack_recv;
	unsigned int	ack_required:1;
	unsigned int	ack_next_valid:1;
	unsigned int	ack_recv_valid:1;
};

struct rds_ib_device;

struct rds_ib_path {
	union ib_gid    p_sgid;
	union ib_gid    p_dgid;
};

struct rds_ib_rx_work {
	struct delayed_work             work;
	struct rds_ib_connection        *ic;
};

/* Time (in millisec) to wait before deallocating connection resources tied
 * to a device
 */
extern u32 rds_dev_free_wait_ms;

struct rds_ib_connection {

	struct list_head	ib_node;
	struct rds_ib_device	*rds_ibdev;
	struct rds_connection	*conn;

	/* alphabet soup, IBTA style */
	struct rw_semaphore	i_cm_id_free_lock;
	struct rdma_cm_id	*i_cm_id;
	struct ib_pd		*i_pd;
	struct ib_mr		*i_mr;
	struct ib_cq		*i_scq;
	struct ib_cq		*i_rcq;
	struct ib_wc		i_send_wc[RDS_WC_MAX];
	struct ib_wc		i_recv_wc[RDS_WC_MAX];

	/* There are cases when we have the right_of_way
	 * and are sitting on an outbound connection-attempt
	 * that appears to be slow or stuck.
	 * At the same time, conection-request from the peer
	 * we're tryingt o reach comes in.
	 * In order to not stubbornly insist that our slow
	 * or frozen connection ought to succeed,
	 * we simply keep track of the last transition
	 * timestamp as:
	 *   max(time_of(rds_ib_conn_path_connect),
	 *       time_of(rds_ib_cm_accept),
	 *       time_of(rds_ib_cm_connect_complete))
	 *
	 * If this value exceeds sysctl 'net.rds.yield_after_ms'
	 * we accept the incoming call.
	 *
	 * Atomic value type: ktime_t
	 */
	atomic64_t              i_connecting_ts;

	/* Alternative connection to be accepted for resolving
	 * concurrent connect request.
	 * Refer to comments in rds_ib_cm_handle_connect().
	 */
	struct {
		struct rdma_cm_id	*cm_id;
		bool			 is_stale;
		bool			 isv6;
		union rds_ib_conn_priv	 private_data;
		u32			 version;
		u8			 responder_resources;
		u8			 initiator_depth;
	} i_alt;

	/* Number of wrs available for MR registration(frwr) */
	atomic_t		i_fastreg_wrs;

	/* interrupt handling */
	struct work_struct	i_recv_w;
	struct work_struct	i_send_w;

	/* tx */
	struct rds_ib_work_ring	i_send_ring;
	struct rm_data_op	*i_data_op;
	struct rds_header	**i_send_hdrs;
	dma_addr_t		*i_send_hdrs_dma;
	struct scatterlist	*i_send_hdrs_sg;

	struct rds_ib_send_work *i_sends;
	atomic_t		i_signaled_sends;

	/* rx */
	struct mutex		i_recv_mutex;
	struct rds_ib_work_ring	i_recv_ring;
	struct rds_ib_incoming	*i_ibinc;
	u32			i_recv_data_rem;
	struct rds_header	**i_recv_hdrs;
	dma_addr_t		*i_recv_hdrs_dma;
	struct scatterlist	*i_recv_hdrs_sg;
	struct rds_ib_recv_work *i_recvs;
	u64			i_ack_recv;	/* last ACK received */

	/* sending acks */
	unsigned long		i_ack_flags;
#ifdef KERNEL_HAS_ATOMIC64
	atomic64_t		i_ack_next;	/* next ACK to send */
#else
	spinlock_t		i_ack_lock;	/* protect i_ack_next */
	u64			i_ack_next;	/* next ACK to send */
#endif
	struct rds_header	*i_ack;
	struct ib_send_wr	i_ack_wr;
	struct ib_sge		i_ack_sge;
	u64			i_ack_dma;
	unsigned long		i_ack_queued;

	/* Flow control related information
	 *
	 * Our algorithm uses a pair variables that we need to access
	 * atomically - one for the send credits, and one posted
	 * recv credits we need to transfer to remote.
	 * Rather than protect them using a slow spinlock, we put both into
	 * a single atomic_t and update it using cmpxchg
	 */
	atomic_t		i_credits;

	/* Protocol version specific information */
	unsigned int		i_flowctl:1;	/* enable/disable flow ctl */
	u16			i_frag_sz;	/* IB fragment size */
	u16			i_frag_cache_sz;
	u8			i_frag_pages;
	u8			i_flags;
	u16			i_frag_cache_inx;
	u16			i_hca_sge;

	/* Batched completions */
	unsigned int		i_unsignaled_wrs;

	/* Wake up receiver once in a while */
	unsigned int		i_unsolicited_wrs;
	u8                      i_sl;

	atomic_t                i_cache_allocs;

	struct completion       i_last_wqe_complete;

	/* Active Bonding */
	unsigned int		i_active_side;

	int			i_cq_vector;
	int			i_irqn;
	bool			i_cq_isolate_warned;

	unsigned int            i_rx_poll_cq;
	struct rds_ib_rx_work   i_rx_w;
	spinlock_t              i_rx_lock;
	unsigned int            i_rx_wait_for_handler;
	atomic_t                i_worker_has_rx;
	int			i_preferred_cpu;

	/* For handling delayed release of device related resource. */
	struct mutex		i_delayed_free_lock;
	struct delayed_work	i_delayed_free_work;
	struct list_head	i_delayed_free_work_node;
	struct rds_ib_device	*i_saved_rds_ibdev;

	/* qp number info */
	s32			i_qp_num;
	s32			i_dst_qp_num;

	/* track irq miss */
	unsigned long		i_irq_miss_ts;
	struct delayed_work	i_cm_watchdog_w;
	struct delayed_work	i_cq_follow_affinity_w;
};

/* This assumes that atomic_t is at least 32 bits */
#define IB_GET_SEND_CREDITS(v)	((v) & 0xffff)
#define IB_GET_POST_CREDITS(v)	((v) >> 16)
#define IB_SET_SEND_CREDITS(v)	((v) & 0xffff)
#define IB_SET_POST_CREDITS(v)	((v) << 16)

struct rds_ib_ipaddr {
	struct list_head	list;
	struct in6_addr		ipaddr;
	struct rcu_head		rcu_head;
};

struct rds_ib_srq {
	struct rds_ib_device       *rds_ibdev;
	struct ib_srq              *s_srq;
	struct ib_event_handler    s_event_handler;
	struct rds_ib_recv_work    *s_recvs;
	u32                        s_n_wr;
	struct rds_header          *s_recv_hdrs;
	u64                        s_recv_hdrs_dma;
	atomic_t                   s_num_posted;
	unsigned long              s_refill_gate;
	struct delayed_work        s_refill_w;
	struct delayed_work        s_rearm_w;
};


struct rds_ib_conn_drop_work {
	struct delayed_work             work;
	struct rds_connection          *conn;
};

struct rds_ib_conn_destroy_work {
	struct delayed_work             work;
	struct rds_connection          *conn;
};


struct rds_ib_destroy_cm_id_work {
	struct work_struct		work;
	struct rdma_cm_id	       *cm_id;
};

enum {
	RDS_IB_MR_8K_POOL,
	RDS_IB_MR_1M_POOL,
};

#define RDS_FRAG_CACHE_ENTRIES (ilog2(RDS_MAX_FRAG_SIZE / PAGE_SIZE) + 1)

/* Each RDMA device maintains a list of RDS sockets associated with it.  The
 * following struct is used to represent this association.  This struct is
 * used as the synchronization point for device and socket removal.
 */
struct rds_rdma_dev_sock {
	struct rds_sock		*rrds_rs;
	struct rds_ib_device	*rrds_rds_ibdev;
	struct list_head	rrds_list;	/* List node for dev rs list */

	struct completion	rrds_work_done;
	struct work_struct	rrds_free_work;

	struct kref		rrds_kref;

	bool			rrds_rs_released;
	bool			rrds_dev_released;
};

struct rds_ib_device {
	struct list_head	list;
	struct list_head	ipaddr_list;
	struct list_head	conn_list;
	struct ib_device	*dev;
	struct ib_pd		*pd;
	struct workqueue_struct	*rid_dev_wq; /* Device work queue */

	bool			use_fastreg;
	int			fastreg_cq_vector;
	struct ib_cq		*fastreg_cq;
	struct ib_wc            fastreg_wc[RDS_WC_MAX];
	struct ib_qp		*fastreg_qp;
	atomic_t		fastreg_wrs;
	struct rw_semaphore	fastreg_lock;
	struct work_struct	fastreg_w;
	struct work_struct	fastreg_reset_w;

	struct ib_mr		*mr;
	struct rds_ib_mr_pool	*mr_1m_pool;
	struct rds_ib_mr_pool   *mr_8k_pool;
	unsigned int		fmr_max_remaps;
	unsigned int		max_8k_fmrs;
	unsigned int		max_1m_fmrs;
	int			max_sge;
	unsigned int		max_wrs;
	unsigned int		max_initiator_depth;
	unsigned int		max_responder_resources;
	spinlock_t		spinlock;	/* protect the above */
	struct rds_ib_srq       *srq;
	struct rds_ib_port      *ports;
	struct ib_event_handler event_handler;
	int			*vector_load;
	/* Several TOS connections may invoke ibdev_get_unused_vector()
	 * concurrently, hence we need protection for vector_load
	 */
	struct mutex		vector_load_lock;

	/* flag indicating ib_device is under freeing up or is freed up to make
	 * the race between rds_ib_remove_one() and rds_release() safe.
	 */
	atomic_t		free_dev;
	/* wait until freeing work is done */
	struct mutex		free_dev_lock;
	struct rds_ib_refill_cache i_cache_incs;
	struct rds_ib_refill_cache i_cache_frags[RDS_FRAG_CACHE_ENTRIES];
	struct delayed_work        i_cache_gc_work;
	int			   i_cache_gc_cpu;
	struct dentry *debugfs_dir;

	atomic_t		rid_refcount;
	struct work_struct	rid_free_work;

	struct list_head	rid_rs_list;	/* Device socket list */
	spinlock_t		rid_rs_list_lock;

	bool			rid_mod_unload;
	bool			rid_dev_rem;

	struct work_struct	rid_dev_rem_work;
	struct completion	*rid_dev_rem_complete;
};

static inline int ibdev_to_node(struct ib_device *ibdev)
{
	struct device *parent;

	parent = ibdev->dev.parent;
	return parent ? dev_to_node(parent) : NUMA_NO_NODE;
}
#define rdsibdev_to_node(rdsibdev) ibdev_to_node(rdsibdev->dev)

/* bits for i_ack_flags */
#define IB_ACK_IN_FLIGHT	0
#define IB_ACK_REQUESTED	1

/* Magic WR_ID for ACKs */
#define RDS_IB_ACK_WR_ID	(~(u64) 0)

struct rds_ib_statistics {
	uint64_t	s_ib_connect_raced;
	uint64_t	s_ib_listen_closed_stale;
	uint64_t	s_ib_evt_handler_call;
	uint64_t	s_ib_tasklet_call;
	uint64_t	s_ib_tx_cq_event;
	uint64_t	s_ib_tx_ring_full;
	uint64_t	s_ib_tx_throttle;
	uint64_t	s_ib_tx_sg_mapping_failure;
	uint64_t	s_ib_tx_stalled;
	uint64_t	s_ib_tx_credit_updates;
	uint64_t	s_ib_rx_cq_event;
	uint64_t	s_ib_rx_ring_empty;
	uint64_t	s_ib_rx_refill_from_cm;
	uint64_t	s_ib_rx_refill_from_cq;
	uint64_t	s_ib_rx_refill_from_thread;
	uint64_t	s_ib_rx_refill_lock_taken;
	uint64_t        s_ib_rx_alloc_limit;
	uint64_t        s_ib_rx_total_frags;
	uint64_t        s_ib_rx_total_incs;
	uint64_t	s_ib_rx_credit_updates;
	uint64_t	s_ib_rx_cache_get;
	uint64_t	s_ib_rx_cache_put;
	uint64_t	s_ib_rx_cache_put_alloc;
	uint64_t	s_ib_rx_cache_put_free;
	uint64_t	s_ib_rx_cache_alloc;
	uint64_t	s_ib_rx_cache_free;
	uint64_t	s_ib_rx_cache_get_percpu;
	uint64_t	s_ib_rx_cache_get_ready;
	uint64_t	s_ib_rx_cache_get_miss;
	uint64_t	s_ib_rx_cache_put_percpu;
	uint64_t	s_ib_ack_sent;
	uint64_t	s_ib_ack_send_failure;
	uint64_t	s_ib_ack_send_delayed;
	uint64_t	s_ib_ack_send_piggybacked;
	uint64_t	s_ib_ack_received;
	uint64_t	s_ib_rdma_mr_8k_alloc;
	uint64_t	s_ib_rdma_mr_8k_free;
	uint64_t	s_ib_rdma_mr_8k_used;
	uint64_t	s_ib_rdma_mr_8k_pool_flush;
	uint64_t	s_ib_rdma_mr_8k_pool_wait;
	uint64_t	s_ib_rdma_mr_8k_pool_depleted;
	uint64_t        s_ib_rdma_mr_1m_alloc;
	uint64_t        s_ib_rdma_mr_1m_free;
	uint64_t        s_ib_rdma_mr_1m_used;
	uint64_t        s_ib_rdma_mr_1m_pool_flush;
	uint64_t        s_ib_rdma_mr_1m_pool_wait;
	uint64_t        s_ib_rdma_mr_1m_pool_depleted;
	uint64_t	s_ib_atomic_cswp;
	uint64_t	s_ib_atomic_fadd;
	uint64_t        s_ib_srq_lows;
	uint64_t        s_ib_srq_refills;
	uint64_t        s_ib_srq_empty_refills;
	uint64_t	s_ib_recv_added_to_cache;
	uint64_t	s_ib_recv_removed_from_cache;
	uint64_t	s_ib_recv_nmb_added_to_cache;
	uint64_t	s_ib_recv_nmb_removed_from_cache;
	uint64_t	s_ib_yield_yielding;
	uint64_t	s_ib_yield_right_of_way;
	uint64_t	s_ib_yield_stale;
	uint64_t	s_ib_yield_expired;
	uint64_t	s_ib_yield_accepting;
	uint64_t	s_ib_yield_success;
	uint64_t	s_ib_cm_watchdog_triggered;
};

extern struct workqueue_struct *rds_ib_wq;

/*
 * Fake ib_dma_sync_sg_for_{cpu,device} as long as ib_verbs.h
 * doesn't define it.
 */
static inline void rds_ib_dma_sync_sg_for_cpu(struct ib_device *dev,
		struct scatterlist *sg, unsigned int sg_dma_len, int direction)
{
	unsigned int i;

	for (i = 0; i < sg_dma_len; ++i) {
		ib_dma_sync_single_for_cpu(dev,
				sg_dma_address(&sg[i]),
				sg_dma_len(&sg[i]),
				direction);
	}
}
#define ib_dma_sync_sg_for_cpu	rds_ib_dma_sync_sg_for_cpu

static inline void rds_ib_dma_sync_sg_for_device(struct ib_device *dev,
		struct scatterlist *sg, unsigned int sg_dma_len, int direction)
{
	unsigned int i;

	for (i = 0; i < sg_dma_len; ++i) {
		ib_dma_sync_single_for_device(dev,
				sg_dma_address(&sg[i]),
				sg_dma_len(&sg[i]),
				direction);
	}
}
#define ib_dma_sync_sg_for_device	rds_ib_dma_sync_sg_for_device

static inline __s32 rds_qp_num(struct rds_connection *conn, int dst)
{
	struct rds_ib_connection *ic;

	if (conn && conn->c_trans->t_type == RDS_TRANS_IB &&
	    conn->c_npaths > 0) {
		ic = conn->c_transport_data;

		return dst ? ic->i_dst_qp_num : ic->i_qp_num;
	}

	return 0;
}

/* ib.c */
extern struct workqueue_struct *rds_aux_wq;
extern struct workqueue_struct *rds_evt_wq;
extern struct rds_transport rds_ib_transport;
extern void rds_ib_add_one(struct ib_device *device);
extern void rds_ib_remove_one(struct ib_device *device, void *client_data);
void rds_ib_srq_exit(struct rds_ib_device *rds_ibdev);
int rds_ib_srq_init(struct rds_ib_device *rds_ibdev);

struct rds_ib_device *rds_ib_get_client_data(struct ib_device *device);
void rds_ib_dev_put(struct rds_ib_device *rds_ibdev);
void rds_ib_nodev_connect(void);
extern struct ib_client rds_ib_client;

extern unsigned int rds_ib_fmr_1m_pool_size;
extern unsigned int rds_ib_fmr_8k_pool_size;
extern bool prefer_frwr;
extern unsigned int rds_ib_retry_count;
extern unsigned int rds_ib_rnr_retry_count;

extern spinlock_t ib_nodev_conns_lock;
extern struct list_head ib_nodev_conns;

extern struct socket *rds_ib_inet_socket;

/* ib_cm.c */
int rds_ib_conn_alloc(struct rds_connection *conn, gfp_t gfp);
void rds_ib_conn_free(void *arg);
int rds_ib_conn_preferred_cpu(struct rds_connection *conn);
bool rds_ib_conn_has_alt_conn(struct rds_connection *conn);
void rds_ib_conn_path_reset(struct rds_conn_path *cp, unsigned flags);
int rds_ib_conn_path_connect(struct rds_conn_path *cp);
void rds_ib_conn_path_shutdown_prepare(struct rds_conn_path *cp);
unsigned long rds_ib_conn_path_shutdown_check_wait(struct rds_conn_path *cp);
void rds_ib_conn_path_shutdown_tidy_up(struct rds_conn_path *cp);
void rds_ib_conn_path_shutdown_final(struct rds_conn_path *cp);
void rds_ib_conn_path_shutdown(struct rds_conn_path *cp);
void rds_ib_state_change(struct sock *sk);
int rds_ib_listen_init(void);
void rds_ib_listen_stop(void);
int rds_ib_cm_handle_connect(struct rdma_cm_id *cm_id,
			     struct rdma_cm_event *event,
			     bool isv6);
int rds_ib_cm_initiate_connect(struct rdma_cm_id *cm_id, bool isv6);
void rds_ib_cm_connect_complete(struct rds_connection *conn,
				struct rdma_cm_event *event);
void rds_ib_conn_ha_changed(struct rds_connection *conn,
			    const unsigned char *ha,
			    unsigned ha_len);
void rds_ib_init_frag(unsigned int version);
void rds_ib_conn_destroy_init(struct rds_connection *conn);
void rds_ib_destroy_fastreg(struct rds_ib_device *rds_ibdev);
int rds_ib_setup_fastreg(struct rds_ib_device *rds_ibdev);
void rds_ib_reset_fastreg(struct work_struct *work);
void rds_ib_tasklet_fn_send(unsigned long data);
void rds_ib_tasklet_fn_recv(unsigned long data);
void rds_ib_conn_destroy_worker(struct work_struct *_work);
u32 __rds_find_ifindex_v4(struct net *net, __be32 addr);
#if IS_ENABLED(CONFIG_IPV6)
u32 __rds_find_ifindex_v6(struct net *net, const struct in6_addr *addr);
#endif

/* ib_rdma.c */
void rds_ib_get_preferred_cpu_mask(struct cpumask *preferred_cpu_mask_p,
				   int irq, int nid);
struct rds_ib_device *rds_ib_get_device(const struct in6_addr *ipaddr);
int rds_ib_update_ipaddr(struct rds_ib_device *rds_ibdev,
			 struct in6_addr *ipaddr);
int rds_ib_add_conn(struct rds_ib_device *rds_ibdev,
		    struct rds_connection *conn);
void rds_ib_remove_conn(struct rds_ib_device *rds_ibdev, struct rds_connection *conn);
void rds_ib_destroy_nodev_conns(void);
struct rds_ib_mr_pool *rds_ib_create_mr_pool(struct rds_ib_device *rds_dev, int npages);
void rds_ib_get_mr_info(struct rds_ib_device *rds_ibdev, struct rds_info_rdma_connection *iinfo);
void rds6_ib_get_mr_info(struct rds_ib_device *rds_ibdev,
			 struct rds6_info_rdma_connection *iinfo6);
void rds_ib_destroy_mr_pool(struct rds_ib_mr_pool *);
void *rds_ib_get_mr(struct scatterlist *sg, unsigned long nents,
		    struct rds_sock *rs, u32 *key_ret, u32 *iova_ret,
		    struct rds_connection *conn);
void rds_ib_sync_mr(void *trans_private, int dir);
void rds_ib_free_mr(void *trans_private, int invalidate);
void rds_ib_flush_mrs(void);
int rds_ib_fmr_init(void);
void rds_ib_fmr_exit(void);
void rds_ib_fcq_handler(struct rds_ib_device *rds_ibdev, struct ib_wc *wc);
void rds_ib_mr_cqe_handler(struct rds_ib_connection *ic, struct ib_wc *wc);
void rds_rrds_free(struct kref *kref);
struct rds_ib_device *rds_rdma_rs_get_device(const struct in6_addr *addr,
					     struct rds_sock *rs);

/* ib_recv.c */
extern struct kmem_cache *rds_ib_incoming_slab;
extern struct kmem_cache *rds_ib_frag_slab;
extern atomic_t rds_ib_allocation;
int rds_ib_recv_init(void);
void rds_ib_recv_exit(void);
int rds_ib_recv_path(struct rds_conn_path *cp);
int rds_ib_recv_alloc_caches(struct rds_ib_connection *ic, gfp_t gfp);
void rds_ib_recv_free_caches(struct rds_ib_connection *ic);
void rds_ib_recv_rebuild_caches(struct rds_ib_connection *ic);
void rds_ib_recv_free_frag(struct rds_page_frag *frag, int nent);
void __rds_ib_recv_refill(struct rds_connection *conn, int prefill, gfp_t gfp);
void rds_ib_inc_free(struct rds_incoming *inc);
int rds_ib_inc_copy_to_user(struct rds_incoming *inc, struct iov_iter *to);
void rds_ib_recv_cqe_handler(struct rds_ib_connection *ic,
			    struct ib_wc *wc,
			    struct rds_ib_ack_state *state);
void rds_ib_recv_init_ring(struct rds_ib_connection *ic);
void rds_ib_recv_clear_ring(struct rds_ib_connection *ic);
void rds_ib_recv_init_ack(struct rds_ib_connection *ic);
void rds_ib_attempt_ack(struct rds_ib_connection *ic);
void rds_ib_ack_send_complete(struct rds_ib_connection *ic);
u64 rds_ib_piggyb_ack(struct rds_ib_connection *ic);
void rds_ib_srq_refill(struct work_struct *work);
int rds_ib_srq_prefill_ring(struct rds_ib_device *rds_ibdev);
void rds_ib_srq_rearm(struct work_struct *work);
void rds_ib_set_ack(struct rds_ib_connection *ic, u64 seq, int ack_required);
void rds_ib_srq_process_recv(struct rds_connection *conn,
			     struct rds_ib_recv_work *recv, u32 data_len,
			     struct rds_ib_ack_state *state);
static inline int rds_ib_recv_acquire_refill(struct rds_connection *conn)
{
	return test_and_set_bit(RDS_RECV_REFILL, &conn->c_flags) == 0;
}

/* The goal here is to just make sure that someone, somewhere
 * is posting buffers.  If we can't get the refill lock,
 * let them do their thing
 */
#define RDS_IB_RECV_REFILL(conn, prefill, gfp, where) do {	\
	struct rds_connection *c = (conn);			\
	if (rds_ib_recv_acquire_refill(c)) {			\
		rds_ib_stats_inc(where);			\
		__rds_ib_recv_refill(c, prefill, gfp);		\
	} else {						\
		rds_ib_stats_inc(s_ib_rx_refill_lock_taken);	\
	}							\
} while (false)

/* ib_ring.c */
void rds_ib_ring_init(struct rds_ib_work_ring *ring, u32 nr);
void rds_ib_ring_resize(struct rds_ib_work_ring *ring, u32 nr);
u32 rds_ib_ring_alloc(struct rds_ib_work_ring *ring, u32 val, u32 *pos);
void rds_ib_ring_free(struct rds_ib_work_ring *ring, u32 val);
void rds_ib_ring_unalloc(struct rds_ib_work_ring *ring, u32 val);
int rds_ib_ring_empty(struct rds_ib_work_ring *ring);
int rds_ib_ring_low(struct rds_ib_work_ring *ring);
u32 rds_ib_ring_oldest(struct rds_ib_work_ring *ring);
u32 rds_ib_ring_completed(struct rds_ib_work_ring *ring, u32 wr_id, u32 oldest);
extern wait_queue_head_t rds_ib_ring_empty_wait;

/* ib_send.c */
char *rds_ib_wc_status_str(enum ib_wc_status status);
void rds_ib_xmit_path_complete(struct rds_conn_path *cp);
int rds_ib_xmit(struct rds_connection *conn, struct rds_message *rm,
		unsigned int hdr_off, unsigned int sg, unsigned int off);
void rds_ib_send_cqe_handler(struct rds_ib_connection *ic,
			    struct ib_wc *wc);
void rds_ib_send_init_ring(struct rds_ib_connection *ic);
void rds_ib_send_clear_ring(struct rds_ib_connection *ic);
int rds_ib_xmit_rdma(struct rds_connection *conn, struct rm_rdma_op *op);
void rds_ib_send_add_credits(struct rds_connection *conn, unsigned int credits);
void rds_ib_advertise_credits(struct rds_connection *conn, unsigned int posted);
int rds_ib_send_grab_credits(struct rds_ib_connection *ic, u32 wanted,
			     u32 *adv_credits, int need_posted);
int rds_ib_xmit_atomic(struct rds_connection *conn, struct rm_atomic_op *op);

/* ib_stats.c */
DECLARE_PER_CPU(struct rds_ib_statistics, rds_ib_stats);
#define rds_ib_stats_inc(member) rds_stats_inc_which(rds_ib_stats, member)
#define rds_ib_stats_add(member, count) \
		rds_stats_add_which(rds_ib_stats, member, count)
unsigned int rds_ib_stats_info_copy(struct rds_info_iterator *iter,
				    unsigned int avail);
void rds_ib_stats_print(const char *where);

/* ib_recv.c */
extern unsigned int rds_ib_srq_max_wr;
extern unsigned int rds_ib_srq_hwm_refill;
extern unsigned int rds_ib_srq_lwm_refill;
extern unsigned int rds_ib_srq_enabled;

/* ib_sysctl.c */
int rds_ib_sysctl_init(void);
void rds_ib_sysctl_exit(void);

extern unsigned long rds_ib_sysctl_max_send_wr;
extern unsigned long rds_ib_sysctl_max_recv_wr;
extern unsigned long rds_ib_sysctl_max_unsig_wrs;
extern unsigned long rds_ib_sysctl_max_unsolicited_wrs;
extern unsigned long rds_ib_sysctl_max_unsig_bytes;
extern unsigned long rds_ib_sysctl_max_recv_allocation;
extern unsigned int rds_ib_sysctl_flow_control;
extern unsigned int rds_ib_sysctl_disable_unmap_fmr_cpu;
extern int rds_ib_sysctl_local_ack_timeout;
extern u32 rds_frwr_wake_intrvl;
extern u32 rds_frwr_ibmr_gc_time;
extern u32 rds_frwr_ibmr_qrtn_time;
extern unsigned rds_ib_sysctl_yield_after_ms;
extern unsigned rds_ib_sysctl_cm_watchdog_ms;

#endif
