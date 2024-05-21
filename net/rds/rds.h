#ifndef _RDS_RDS_H
#define _RDS_RDS_H

#include <net/sock.h>
#include <linux/interrupt.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <rdma/rdma_cm.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <uapi/linux/rds.h>
#include <linux/in6.h>
#include <linux/iov_iter.h>
#include <linux/skbuff.h>
#include <linux/sizes.h>
#include <linux/rhashtable.h>
#include <linux/trace_events.h>
#include <linux/tracepoint-defs.h>
#include <linux/uaccess.h>
#include <net/checksum.h>

#include "info.h"

/*
 * RDS Network protocol version
 */
#define RDS_PROTOCOL_3_0	0x0300
#define RDS_PROTOCOL_3_1	0x0301
#define RDS_PROTOCOL_4_0	0x0400
#define RDS_PROTOCOL_4_1	0x0401
#define RDS_PROTOCOL_COMPAT_VERSION	RDS_PROTOCOL_3_1
#define RDS_PROTOCOL_VERSION    RDS_PROTOCOL_4_1
#define RDS_PROTOCOL_MAJOR(v)	((v) >> 8)
#define RDS_PROTOCOL_MINOR(v)	((v) & 255)
#define RDS_PROTOCOL(maj, min)	(((maj) << 8) | min)

/* Reject reason codes.
 * 0401 below indicates 4.1 version.
 * 0020 indicates type of reject.
 * Reserving earlier ones for version mismatch or other reasons.
 */
#define RDS_ACL_FAILURE		0x04010020

/* The following ports, 16385, 18634, 18635, are registered with IANA as
 * the ports to be used for RDS over TCP and UDP.  18634 is the historical
 * value used for the RDMA_CM listener port.  RDS/TCP uses port 16385.  After
 * IPv6 work, RDMA_CM also uses 16385 as the listener port.  18634 is kept
 * to ensure compatibility with older RDS modules.
 */
#define RDS_PORT	18634
#define RDS_CM_PORT	16385
#define RDS_TCP_PORT	RDS_CM_PORT

#ifdef ATOMIC64_INIT
#define KERNEL_HAS_ATOMIC64
#endif

#ifdef RDS_DEBUG
#define rdsdebug(fmt, args...) pr_debug("%s(): " fmt, __func__ , ##args)
#else
/* sigh, pr_debug() causes unused variable warnings */
static inline void __attribute__ ((format (printf, 1, 2)))
rdsdebug(char *fmt, ...)
{
}
#endif

/* Keep previous debugging bitmap values as these will be mapped
 * to relevant tracepoints such that logging behaviour is
 * backwards-compatible.  It is simply realized via tracepoints
 * rather than via direct use of trace_printk() now.
 */
extern u32 kernel_rds_rt_debug_bitmap;
enum {
	/* bit 0 ~ 19 are feature related bits */
	RDS_RTD_ERR			= 1 << 0,	/* 0x1    */
	RDS_RTD_ERR_EXT			= 1 << 1,	/* 0x2    */

	RDS_RTD_CM			= 1 << 3,	/* 0x8    */
	RDS_RTD_CM_EXT			= 1 << 4,	/* 0x10   */
	RDS_RTD_CM_EXT_P		= 1 << 5,	/* 0x20   */

	RDS_RTD_ACT_BND			= 1 << 7,	/* 0x80   */
	RDS_RTD_ACT_BND_EXT		= 1 << 8,	/* 0x100  */

	RDS_RTD_RCV			= 1 << 11,	/* 0x800  */
	RDS_RTD_RCV_EXT			= 1 << 12,	/* 0x1000 */

	RDS_RTD_SND			= 1 << 14,	/* 0x4000 */
	RDS_RTD_SND_EXT			= 1 << 15,	/* 0x8000 */
	RDS_RTD_FLOW_CNTRL		= 1 << 16,	/* 0x10000 */

	/* bit 20 ~ 31 are module specific bits */
	RDS_RTD_RDMA_IB			= 1 << 23,	/* 0x800000   */
	RDS_RTD_ALL			= 1 << 31,	/* Enable All */
};

/* XXX is there one of these somewhere? */
#define ceil(x, y) \
	({ unsigned long __x = (x), __y = (y); (__x + __y - 1) / __y; })

#define RDS_FRAG_SHIFT	12
#define RDS_FRAG_SIZE	((unsigned int)(1 << RDS_FRAG_SHIFT))
#define RDS_MAX_FRAG_SIZE	SZ_16K

/* Used to limit both RDMA and non-RDMA RDS message to 1MB */
#define RDS_MAX_MSG_SIZE	((unsigned int)(1 << 20))

#define RDS_CONG_MAP_BYTES	(65536 / 8)
#define RDS_CONG_PAGE_SIZE	(1UL << 12)
#define RDS_CONG_MAP_LONGS	(RDS_CONG_MAP_BYTES / sizeof(unsigned long))
#define RDS_CONG_MAP_PAGES	(PAGE_ALIGN(RDS_CONG_MAP_BYTES) / RDS_CONG_PAGE_SIZE)
#define RDS_CONG_MAP_PAGE_BITS	(RDS_CONG_PAGE_SIZE * 8)

#define RDS_CP_WQ_MAX_ACTIVE	4

struct rds_cong_monitor {
	/* global list of monitoring sockets */
	struct list_head	rc_monitor;
	rwlock_t		rc_monitor_lock;

	/* kworker related */
	spinlock_t		rc_notify_lock;
	u64			rc_notify_portmask;
	struct work_struct	rc_notify_work;
	bool			rc_notify_work_scheduled;
	struct rds_net		*rc_rns;
};

struct rds_cong_map {
	struct rb_node		m_rb_node;
	struct in6_addr		m_addr;
	wait_queue_head_t	m_waitq;
	struct list_head	m_conn_list;
	struct wait_queue_head *m_wait_queue_ptr;
	unsigned long		m_page_addrs[RDS_CONG_MAP_PAGES];
	struct rds_net		*m_rns;
};

/*
 * This is how we will track the connection state:
 * A connection is always in one of the following
 * states. Updates to the state are atomic and imply
 * a memory barrier.
 */
enum {
	RDS_CONN_DOWN = 0,
	RDS_CONN_CONNECTING,
	RDS_CONN_DISCONNECTING,
	RDS_CONN_UP,
	RDS_CONN_RESETTING,
	RDS_CONN_ERROR,
};

static inline const char *conn_state_mnem(int state)
{
#define CASE_RET(s) case (s): return #s
	switch (state) {
		CASE_RET(RDS_CONN_DOWN);
		CASE_RET(RDS_CONN_CONNECTING);
		CASE_RET(RDS_CONN_DISCONNECTING);
		CASE_RET(RDS_CONN_UP);
		CASE_RET(RDS_CONN_RESETTING);
		CASE_RET(RDS_CONN_ERROR);
	default:
		return "RDS_CONN_UNKNOWN";
	}
#undef CASE_RET
}

/* Bits for c_flags */
#define RDS_LL_SEND_FULL	0
#define RDS_RECONNECT_PENDING	1
#define RDS_IN_XMIT		2
#define RDS_RECV_REFILL		3
#define RDS_DESTROY_PENDING	4
#define RDS_SEND_WORK_QUEUED	5
#define RDS_RECV_WORK_QUEUED	6
#define RDS_SHUTDOWN_WORK_QUEUED 7
#define RDS_SHUTDOWN_WAITING	8
#define RDS_SHUTDOWN_WAIT1_DONE	9
#define RDS_SHUTDOWN_PREPARE_DONE 10
#define RDS_USER_RESET		11

#define RDS_RDMA_RESOLVE_TO_MAX_INDEX   5
#define RDS_ADDR_RES_TM_INDEX_MAX 5

/* Max number of multipaths per RDS connection. Must be a power of 2 */
#define RDS_MPATH_WORKERS       8
#define RDS_MPATH_HASH(rs, n) (jhash_1word((__force u32)(rs)->rs_bound_port, \
					   (rs)->rs_hash_initval) & ((n) - 1))
enum rds_conn_drop_src {
	/* rds-core */
	DR_DEFAULT,
	DR_USER_RESET,
	DR_INV_CONN_STATE,
	DR_DOWN_TRANSITION_FAIL,
	DR_CONN_DESTROY,
	DR_CONN_CONNECT_FAIL,
	DR_HB_TIMEOUT,
	DR_RECONNECT_TIMEOUT,
	DR_SOCK_CANCEL,

	/* ib_cm  */
	DR_IB_CONN_DROP_RACE,
	DR_IB_NOT_CONNECTING_STATE,
	DR_IB_QP_EVENT,
	DR_IB_REQ_WHILE_CONN_UP,
	DR_IB_REQ_WHILE_CONNECTING_MULTI,
	DR_IB_REQ_WHILE_CONNECTING_TIME,
	DR_IB_PAS_SETUP_QP_FAIL,
	DR_IB_RDMA_ACCEPT_FAIL,
	DR_IB_ACT_SETUP_QP_FAIL,
	DR_IB_RDMA_CONNECT_FAIL,
	DR_IB_CONN_DROP_YIELD,
	DR_IB_CONN_DROP_CM_WATCHDOG,

	/* event handling */
	DR_IB_RESOLVE_ROUTE_FAIL,
	DR_IB_RDMA_CM_ID_MISMATCH,
	DR_IB_ROUTE_ERR,
	DR_IB_ADDR_ERR,
	DR_IB_CONNECT_ERR,
	DR_IB_CONSUMER_DEFINED_REJ,
	DR_IB_REJECTED_EVENT,
	DR_IB_ADDR_CHANGE,
	DR_IB_PEER_ADDR_CHANGE,
	DR_IB_DISCONNECTED_EVENT,
	DR_IB_TIMEWAIT_EXIT,
	DR_IB_SHUTDOWN_NEEDED,

	/* data path */
	DR_IB_POST_RECV_FAIL,
	DR_IB_SEND_ACK_FAIL,
	DR_IB_HEADER_MISSING,
	DR_IB_HEADER_CORRUPTED,
	DR_IB_FRAG_HEADER_MISMATCH,
	DR_IB_RECV_COMP_ERR,
	DR_IB_SEND_COMP_ERR,
	DR_IB_POST_SEND_FAIL,

	/* special features like active bonding */
	DR_RDMA_DEV_REM,
	DR_IB_ACTIVE_BOND_FAILOVER,
	DR_IB_LOOPBACK_CONN_DROP,
	DR_IB_ACTIVE_BOND_FAILBACK,
	DR_IB_FRWR_INV_COMP_ERR,
	DR_IB_FRWR_REG_COMP_ERR,
	DR_IB_FRWR_WC_TMOUT,

	/* TCP */
	DR_TCP_STATE_CLOSE,
	DR_TCP_STATE_CLOSE_KA_TIMEOUT,
	DR_TCP_SEND_FAIL,
	DR_TCP_STATE_ACCEPT_CLOSED,
	DR_TCP_INVALID_SLOT0,
	DR_TCP_STATE_DISCONNECT_ADDR_CMP,
};

enum rds_hb_state {
	HB_PING_SENT,
	HB_PONG_RCVD,
};

struct bind_bucket;

/* Structure to store an RDS module's statistics counters
 *
 * rs_stats: per_cpu uint64_t array of counters
 * rs_names: array of names corresponding to the rs_stats counters
 * rs_num_stats: number of elements in the rs_stats array
 */
struct rds_stats_struct {
	void __percpu	*rs_stats;
	char		**rs_names;
	int		rs_num_stats;
};

struct rds_net {
	/* The following socket info is used for stats gathering */
	struct mutex		rns_sock_lock;
	u32			rns_sock_count;
	struct list_head	rns_sock_list;

	struct bind_bucket	*rns_bind_hash_table;

	spinlock_t		rns_conn_lock;		/* protect connection */
	struct hlist_head	*rns_conn_hash;

	atomic_t		rns_cong_generation;
	struct rds_cong_monitor *rns_cong_monitor;
	spinlock_t		rns_cong_lock;	/* protect congestion maps */
	struct rb_root		rns_cong_tree;

	spinlock_t		rns_loop_conns_lock;	/* protect loopback conns */
	struct list_head	rns_loop_conns;

	struct mutex		rns_mod_mutex;	/* protect rns_mod_stats */

	/* Array for RDS modules' stats information */
	struct rds_stats_struct	*rns_mod_stats[RDS_MOD_MAX];
};

#define IS_CANONICAL(laddr, faddr) (htonl(laddr) < htonl(faddr))

/* Per mpath connection state */
struct rds_conn_path {
	struct rds_connection	*cp_conn;
	struct rds_message	*cp_xmit_rm;
	unsigned long		cp_xmit_sg;
	unsigned int		cp_xmit_hdr_off;
	unsigned int		cp_xmit_data_off;
	unsigned int		cp_xmit_atomic_sent;
	unsigned int		cp_xmit_rdma_sent;
	unsigned int		cp_xmit_data_sent;

	spinlock_t		cp_lock;		/* protect msg queues */
	u64			cp_next_tx_seq;
	struct list_head	cp_send_queue;
	struct list_head	cp_retrans;

	u64			cp_next_rx_seq;

	void			*cp_transport_data;

	struct workqueue_struct	*cp_wq;
	atomic_t		cp_state;
	unsigned long		cp_send_gen;
	unsigned long		cp_flags;
	atomic_t		cp_rdma_map_pending;
	unsigned long		cp_reconnect_jiffies;
	struct delayed_work	cp_send_w;
	struct delayed_work	cp_recv_w;
	struct delayed_work     cp_hb_w;
	struct delayed_work	cp_up_or_down_w;
	struct delayed_work	cp_down_wait_w;
	struct mutex		cp_cm_lock;	/* protect cp_state & cm */
	wait_queue_head_t	cp_waitq;

	unsigned int		cp_unacked_packets;
	unsigned int		cp_unacked_bytes;
	unsigned int		cp_index;

	/* when was this connection started */
	uint64_t		cp_conn_start_jf;
	uint64_t		cp_conn_ts_jf;

	/* Re-connect stall diagnostics */
	unsigned long		cp_reconn_flags;
	unsigned long		cp_reconnect_retry;
	unsigned int		cp_reconnect_retry_count;
	time64_t                cp_reconnect_start;
	int                     cp_reconnect_warn;
	int                     cp_reconnect_err;
	int			cp_to_index;

	unsigned int		cp_reconnect;

	unsigned int		cp_pending_flush;

	time64_t                cp_hb_start;
	enum rds_hb_state	cp_hb_state;

	enum rds_conn_drop_src	cp_drop_source;

	unsigned char		cp_acl_init;
	unsigned char		cp_acl_en;

	wait_queue_head_t	cp_up_waitq;	/* start up waitq */
	u64			cp_rcvd;
	u64			cp_xmit;
	u64			cp_rexmit;
	u64			cp_unacked;
	u64			cp_send_queued;
	time64_t		cp_connection_reset;
	time64_t		cp_connection_initiated;
	time64_t		cp_connection_established;
	u32			cp_connection_attempts;
	time64_t		cp_connection_backoff_start;

	struct completion	*cp_shutdown_final;
};

struct rds_conn_ha_changed_work {
	struct work_struct	work;

	unsigned char		ha[MAX_ADDR_LEN];
	unsigned		ha_len;
};

struct rds_connection {
	struct hlist_node	c_hash_node;
	struct in6_addr		c_laddr;
	struct in6_addr		c_faddr;
	int			c_dev_if; /* ifindex uses for this conn */
	int			c_bound_if; /* ifindex of c_laddr */
	unsigned int		c_loopback:1,
				c_isv6:1,
				c_ping_triggered:1,
				c_destroy_in_prog:1,
				c_is_hb_enabled:1,
				c_is_first_hb_ping:1,

				c_pad_to_32:26;
	int			c_npaths;
	bool			c_with_sport_idx;
	struct rds_connection	*c_passive;
	struct rds_transport	*c_trans;

	struct rds_cong_map	*c_lcong;
	struct rds_cong_map	*c_fcong;

	struct list_head	c_map_item;

	/* c_map_queued: bit map field */
	unsigned long		c_map_queued;

	/**	bit 0: set indicates congestion update
	 *		pending to send to peer.
	 *	bit 1: set indicates last alloc attempt(GFP_NOWAIT)
	 *		for congestion update message failed
	 *		and update was deferred
	 */
#define	RCMQ_BITOFF_CONGU_PENDING	0
#define RCMQ_BITOFF_CONGU_ALLOC_DEFER	1

	/* Protocol version */
	unsigned int		c_proposed_version;
	unsigned int		c_version;
	possible_net_t		c_net;
	struct rds_net		*c_rns;

	/* Re-connect stall diagnostics */
	unsigned long           c_reconnect_start;
	int                     c_reconnect_warn;
	int                     c_reconnect_err;
	int			c_to_index;

	unsigned int		c_reconnect;

	/* Qos support */
	u8                      c_tos;

	struct rds_conn_path	*c_path;
	wait_queue_head_t	c_hs_waitq; /* handshake waitq */


	struct list_head	c_laddr_node;
	struct hlist_node	c_faddr_node;

	/* for rds_conn_ha_changed_task */
	struct rds_conn_ha_changed_work c_ha_changed;

	atomic64_t		c_send_bytes;
	atomic64_t		c_recv_bytes;

	atomic_t		c_dr_sock_cancel_refs;
	struct delayed_work	c_dr_sock_cancel_w;

	u64			c_cp0_mprds_catchup_tx_seq;

	struct rds_statistics __percpu	*c_stats;
};

struct rds_info_iterator {
	struct page **pages;
	void *addr;
	unsigned long offset;
	struct net *net;
};

#define RDS_FLAG_CONG_BITMAP		0x01
#define RDS_FLAG_ACK_REQUIRED		0x02
#define RDS_FLAG_RETRANSMITTED		0x04
#define RDS_FLAG_HB_PING		0x08
#define RDS_FLAG_HB_PONG		0x10
#define RDS_FLAG_ANY_HB			(RDS_FLAG_HB_PING | RDS_FLAG_HB_PONG)
#define RDS_FLAG_EXTHDR_EXTENSION	0x20
#define RDS_FLAG_EXTHDR_CAP_BITS_HB	BIT(0)
#define RDS_MAX_ADV_CREDIT		255

/* RDS_FLAG_PROBE_PORT is the reserved sport used for sending a ping
 * probe to exchange control information before establishing a connection.
 * Currently the control information that is exchanged is the number of
 * supported paths. If the peer is a legacy (older kernel revision) peer,
 * it would return a pong message without additional control information
 * that would then alert the sender that the peer was an older rev.
 */
#define RDS_FLAG_PROBE_PORT	1
#define	RDS_HS_PROBE(sport, dport) \
		((sport == RDS_FLAG_PROBE_PORT && dport == 0) || \
		 (sport == 0 && dport == RDS_FLAG_PROBE_PORT))

/*
 * Maximum space available for extension headers.
 */
#define RDS_HEADER_EXT_SPACE	16

struct rds_header {
	__be64	h_sequence;
	__be64	h_ack;
	__be32	h_len;
	__be16	h_sport;
	__be16	h_dport;
	u8	h_flags;
	u8	h_credit;
	u8	h_padding[4];
	__sum16	h_csum;

	u8	h_exthdr[RDS_HEADER_EXT_SPACE];
};

/*
 * Reserved - indicates end of extensions
 */
#define RDS_EXTHDR_NONE		0

/*
 * This extension header is included in the very
 * first message that is sent on a new connection,
 * and identifies the protocol level. This will help
 * rolling updates if a future change requires breaking
 * the protocol.
 * NB: This is no longer true for IB, where we do a version
 * negotiation during the connection setup phase (protocol
 * version information is included in the RDMA CM private data).
 */
#define RDS_EXTHDR_VERSION	1
struct rds_ext_header_version {
	__be32			h_version;
};

/*
 * This extension header is included in the RDS message
 * chasing an RDMA operation.
 */
#define RDS_EXTHDR_RDMA		2
struct rds_ext_header_rdma {
	__be32			h_rdma_rkey;
};

/*
 * This extension header tells the peer about the
 * destination <R_Key,offset> of the requested RDMA
 * operation.
 */
#define RDS_EXTHDR_RDMA_DEST	3
struct rds_ext_header_rdma_dest {
	__be32			h_rdma_rkey;
	__be32			h_rdma_offset;
};

/*
 * This extension header tells the peer about delivered RDMA byte count.
 */
#define RDS_EXTHDR_RDMA_BYTES	4

#define RDS_FLAG_RDMA_WR_BYTES	0x01
#define RDS_FLAG_RDMA_RD_BYTES	0x02

struct rds_ext_header_rdma_bytes {
	__be32		h_rdma_bytes;	/* byte count */
	u8		h_rflags;	/* direction of RDMA, write or read */
};

#define RDS_EXTHDR_NPATHS	5
#define RDS_EXTHDR_GEN_NUM	6
#define RDS_EXTHDR_CAP_BITS	7
struct rds_ext_header_cap_bits {
	__be32			h_cap_bits;
};

#define RDS_EXTHDR_SPORT_IDX	8
#define RDS_EXTHDR_CSUM		9
struct rds_ext_header_rdma_csum {
	__be32  h_rdma_csum_val;
	bool    h_rdma_csum_enabled;
};

struct rds_csum {
	union {
		__wsum	csum;
		u32	raw;
	} csum_val;
	bool csum_enabled;
};

/* Remember to update __RDS_EXTHDR_MAX when new extension headers are added */
#define __RDS_EXTHDR_MAX	RDS_EXTHDR_CSUM
#define RDS_RX_MAX_TRACES	(RDS_MSG_RX_DGRAM_TRACE_MAX + 1)
#define	RDS_MSG_RX_HDR		0
#define	RDS_MSG_RX_START	1
#define	RDS_MSG_RX_END		2
#define	RDS_MSG_RX_CMSG		3

/* The following values are whitelisted for usercopy */
struct rds_inc_usercopy {
	rds_rdma_cookie_t	rdma_cookie;
	struct __kernel_old_timeval rx_tstamp;
};

struct rds_incoming {
	atomic_t		i_refcount;
	struct list_head	i_item;
	struct rds_connection	*i_conn;
	struct rds_conn_path	*i_conn_path;
	struct rds_header	i_hdr;
	unsigned long		i_rx_jiffies;
	struct in6_addr		i_saddr;

	struct rds_inc_usercopy i_usercopy;
	u64			i_rx_lat_trace[RDS_RX_MAX_TRACES];
/* use same field for tx and rx as we need only one at a time */
#define i_tx_lat		i_rx_lat_trace[RDS_MSG_RX_END]
	struct rds_csum		i_payload_csum;
};

struct rds_mr {
	struct rb_node		r_rb_node;
	struct kref		r_kref;
	u32			r_key;
	u32                     r_iova;

	/* A copy of the creation flags */
	u32			r_use_once:1;
	u32			r_invalidate:1;
	u32			r_write:1;

	struct rds_sock		*r_sock; /* back pointer to the socket that owns us */
	struct rds_transport	*r_trans;
	void			*r_trans_private;
};

static inline rds_rdma_cookie_t rds_rdma_make_cookie(u32 r_key, u32 offset)
{
	return r_key | (((u64) offset) << 32);
}

static inline u32 rds_rdma_cookie_key(rds_rdma_cookie_t cookie)
{
	return cookie;
}

static inline u32 rds_rdma_cookie_offset(rds_rdma_cookie_t cookie)
{
	return cookie >> 32;
}

/* atomic operation types */
#define RDS_ATOMIC_TYPE_CSWP		0
#define RDS_ATOMIC_TYPE_FADD		1

/*
 * m_sock_item and m_conn_item are on lists that are serialized under
 * conn->c_lock.  m_sock_item has additional meaning in that once it is empty
 * the message will not be put back on the retransmit list after being sent.
 * messages that are canceled while being sent rely on this.
 *
 * m_inc is used by loopback so that it can pass an incoming message straight
 * back up into the rx path.  It embeds a wire header which is also used by
 * the send path, which is kind of awkward.
 *
 * m_sock_item indicates the message's presence on a socket's send or receive
 * queue.  m_rs will point to that socket.
 *
 * m_daddr is used by cancellation to prune messages to a given destination.
 *
 * The RDS_MSG_ON_SOCK and RDS_MSG_ON_CONN flags are used to avoid lock
 * nesting.  As paths iterate over messages on a sock, or conn, they must
 * also lock the conn, or sock, to remove the message from those lists too.
 * Testing the flag to determine if the message is still on the lists lets
 * us avoid testing the list_head directly.  That means each path can use
 * the message's list_head to keep it on a local list while juggling locks
 * without confusing the other path.
 *
 * m_ack_seq is an optional field set by transports who need a different
 * sequence number range to invalidate.  They can use this in a callback
 * that they pass to rds_send_drop_acked() to see if each message has been
 * acked.  The HAS_ACK_SEQ flag can be used to detect messages which haven't
 * had ack_seq set yet.
 */
#define RDS_MSG_ON_SOCK		1
#define RDS_MSG_ON_CONN		2
#define RDS_MSG_HAS_ACK_SEQ	3
#define RDS_MSG_ACK_REQUIRED	4
#define RDS_MSG_RETRANSMITTED	5
#define RDS_MSG_MAPPED		6
#define RDS_MSG_PAGEVEC		7
#define RDS_MSG_FLUSH           8
#define RDS_MSG_CANCELED	9

struct rds_iov_vector {
	struct rds_iovec *iv_vec;
	int		 *iv_nr_pages;
	int              iv_entries;
	int              iv_tot_pages;
};

struct rds_iov_vector_arr {
	struct rds_iov_vector *iva_iov;
	int                    iva_entries_allocated;
	int                    iva_entries_used;
	int                    iva_incr;
};

struct rds_message {
	atomic_t		m_refcount;
	struct list_head	m_sock_item;
	struct list_head	m_conn_item;
	struct rds_incoming	m_inc;
	u64			m_ack_seq;
	struct in6_addr		m_daddr;
	unsigned long		m_flags;

	/* Never access m_rs without holding m_rs_lock.
	 * Lock nesting is
	 *  rm->m_rs_lock
	 *   -> rs->rs_lock
	 */
	spinlock_t		m_rs_lock;
	wait_queue_head_t	m_flush_wait;

	struct rds_sock		*m_rs;

	/* cookie to send to remote, in rds header */
	rds_rdma_cookie_t	m_rdma_cookie;

	unsigned int		m_used_sgs;
	unsigned int		m_total_sgs;

	void			*m_final_op;

	struct {
		struct rm_atomic_op {
			int			op_type;
			uint64_t		op_swap_add;
			uint64_t		op_compare;

			u32			op_rkey;
			u64			op_remote_addr;
			unsigned int		op_notify:1;
			unsigned int		op_recverr:1;
			unsigned int		op_mapped:1;
			unsigned int		op_silent:1;
			unsigned int		op_active:1;
			struct scatterlist	*op_sg;
			struct rds_notifier	*op_notifier;

			struct rds_mr		*op_rdma_mr;
		} atomic;
		struct rm_rdma_op {
			u32			op_rkey;
			u64			op_remote_addr;
			unsigned int		op_write:1;
			unsigned int		op_fence:1;
			unsigned int		op_notify:1;
			unsigned int		op_recverr:1;
			unsigned int		op_mapped:1;
			unsigned int		op_silent:1;
			unsigned int		op_active:1;
			unsigned int            op_implicit_mr:1;
			unsigned int            op_remote_complete:1;
			unsigned int		op_bytes;
			unsigned int		op_nents;
			unsigned int		op_count;
			struct scatterlist	*op_sg;
			struct rds_notifier	*op_notifier;
			struct rds_mr		*op_rdma_mr;
		} rdma;
		struct rm_data_op {
			unsigned int		op_active:1;
			unsigned int            op_notify:1;
			unsigned int            op_async:1;
			struct rds_notifier     *op_notifier;
			unsigned int		op_nents;
			unsigned int		op_count;
			unsigned int		op_dmasg;
			unsigned int		op_dmaoff;
			struct scatterlist	*op_sg;
		} data;
	};

	struct rds_conn_path *m_conn_path;
	struct rds_csum m_payload_csum;
	int m_alloc_cpu;
};

/*
 * The RDS notifier is used (optionally) to tell the application about
 * completed RDMA operations. Rather than keeping the whole rds message
 * around on the queue, we allocate a small notifier that is put on the
 * socket's notifier_list. Notifications are delivered to the application
 * through control messages.
 */
struct rds_notifier {
	struct list_head	n_list;
	uint64_t		n_user_token;
	int			n_status;
	struct rds_connection   *n_conn;
};

enum {
	RDS_CONN_PATH_RESET_ALT_CONN	= 1 << 0,
	RDS_CONN_PATH_RESET_WATCHDOG	= 1 << 1,
};

/**
 * struct rds_transport -  transport specific behavioural hooks
 *
 * @xmit: .xmit is called by rds_send_xmit() to tell the transport to send
 *        part of a message.  The caller serializes on the send_sem so this
 *        doesn't need to be reentrant for a given conn.  The header must be
 *        sent before the data payload.  .xmit must be prepared to send a
 *        message with no data payload.  .xmit should return the number of
 *        bytes that were sent down the connection, including header bytes.
 *        Returning 0 tells the caller that it doesn't need to perform any
 *        additional work now.  This is usually the case when the transport has
 *        filled the sending queue for its connection and will handle
 *        triggering the rds thread to continue the send when space becomes
 *        available.  Returning -EAGAIN tells the caller to retry the send
 *        immediately.  Returning -ENOMEM tells the caller to retry the send at
 *        some point in the future.
 *
 * @conn_shutdown: conn_shutdown stops traffic on the given connection.  Once
 *                 it returns the connection can not call rds_recv_incoming().
 *                 This will only be called once after conn_connect returns
 *                 non-zero success and will The caller serializes this with
 *                 the send and connecting paths (xmit_* and conn_*).  The
 *                 transport is responsible for other serialization, including
 *                 rds_recv_incoming().  This is called in process context but
 *                 should try hard not to block.
 */

struct rds_transport {
	char			t_name[TRANSNAMSIZ];
	struct list_head	t_item;
	struct module		*t_owner;
	unsigned int		t_prefer_loopback:1,
				t_mp_capable:1;
	unsigned int		t_type;

	atomic_t		t_conn_count;

	int (*laddr_check)(struct net *net, const struct in6_addr *addr,
			   __u32 scope_id);
	int (*conn_alloc)(struct rds_connection *conn, gfp_t gfp);
	void (*conn_free)(void *data);
	int (*conn_preferred_cpu)(struct rds_connection *conn, bool in_send_path);
	bool (*conn_has_alt_conn)(struct rds_connection *conn);
	void (*conn_slots_available)(struct rds_connection *conn, bool fan_out);
	void (*conn_path_reset)(struct rds_conn_path *cp, unsigned flags);
	int (*conn_path_connect)(struct rds_conn_path *cp);
	void (*conn_path_shutdown_prepare)(struct rds_conn_path *cp);
	unsigned long (*conn_path_shutdown_check_wait)(struct rds_conn_path *cp);
	void (*conn_path_shutdown_tidy_up)(struct rds_conn_path *cp);
	void (*conn_path_shutdown_final)(struct rds_conn_path *cp);
	void (*conn_path_shutdown)(struct rds_conn_path *cp);
	void (*xmit_path_prepare)(struct rds_conn_path *cp);
	void (*xmit_path_complete)(struct rds_conn_path *cp);
	int (*xmit)(struct rds_connection *conn, struct rds_message *rm,
		    unsigned int hdr_off, unsigned int sg, unsigned int off);
	int (*xmit_rdma)(struct rds_connection *conn, struct rm_rdma_op *op);
	int (*xmit_atomic)(struct rds_connection *conn, struct rm_atomic_op *op);
	int (*recv_path)(struct rds_conn_path *cp);
	int (*inc_copy_to_user)(struct rds_sock *rs, struct rds_incoming *inc,
				struct iov_iter *to);
	bool (*recv_need_bufs)(struct rds_conn_path *cp);
	void (*inc_free)(struct rds_incoming *inc);

	int (*cm_handle_connect)(struct rdma_cm_id *cm_id,
				 struct rdma_cm_event *event,
				 bool isv6);
	int (*cm_initiate_connect)(struct rdma_cm_id *cm_id, bool isv6);
	void (*cm_connect_complete)(struct rds_connection *conn,
				    struct rdma_cm_event *event);
	void (*conn_ha_changed)(struct rds_connection *conn,
				const unsigned char *ha,
				unsigned ha_len);

	unsigned int (*stats_info_copy)(struct rds_info_iterator *iter,
					unsigned int avail);
	void *(*get_mr)(struct scatterlist *sg, unsigned long nr_sg,
			struct rds_sock *rs, u32 *key_ret, u32 *iova_ret,
			struct rds_connection *conn);
	void (*sync_mr)(void *trans_private, int direction);
	void (*free_mr)(void *trans_private, int invalidate);
	void (*flush_mrs)(void);
	void (*check_migration)(struct rds_connection *conn,
				struct rdma_cm_event *event);
	void (*sock_release)(struct rds_sock *rs);
	int (*process_send_cmsg)(struct rds_sock *rs, struct rds_message *rm,
				 struct cmsghdr *cmsg, int *indp,
				 struct rds_iov_vector_arr *vct);

	atomic64_t rds_avg_conn_jf;
};

/* Used to store per peer socket buffer info. */
struct rs_buf_info {
	struct in6_addr		rsbi_key;
	struct rhash_head	rsbi_link;
	u32			rsbi_snd_bytes;
};

struct rds_sock {
	struct sock		rs_sk;

	u64			rs_user_addr;
	u64			rs_user_bytes;

	/*
	 * bound_addr used for both incoming and outgoing, no INADDR_ANY
	 * support.
	 */
	struct hlist_node	rs_bound_node;
	struct sockaddr_in6	rs_bound_sin6;
#define rs_bound_addr		rs_bound_sin6.sin6_addr
#define rs_bound_addr_v4	rs_bound_sin6.sin6_addr.s6_addr32[3]
#define rs_bound_port		rs_bound_sin6.sin6_port
#define rs_bound_scope_id	rs_bound_sin6.sin6_scope_id
	struct in6_addr		rs_conn_addr;
#define rs_conn_addr_v4		rs_conn_addr.s6_addr32[3]
	__be16			rs_conn_port;
	struct rds_transport    *rs_transport;

	/*
	 * rds_sendmsg caches the conn and conn_path it used the last time
	 * around. This helps avoid costly lookups.
	 */
	struct rds_connection	*rs_conn;
	struct rds_conn_path	*rs_conn_path;

	/* flag indicating we were congested or not */
	int			rs_congested;
	/* seen congestion (ENOBUFS) when sending? */
	int			rs_seen_congestion;

	/* rs_lock protects all these adjacent members before the newline.
	 *
	 * Congestion wake_up. If rs_cong_monitor is set, we use cong_mask
	 * to decide whether the application should be woken up.
	 * If not set, we use rs_cong_track to find out whether a cong map
	 * update arrived.
	 */
	spinlock_t		rs_lock;
	atomic64_t		rs_cong_mask;
	atomic64_t		rs_cong_notify;
	struct list_head	rs_cong_list;
	unsigned long		rs_cong_track;
	/* currently used for failed RDMAs */
	struct list_head	rs_notify_queue;

	/* rs_snd_lock protects all these adjacent members before the
	 * newline
	 */
	spinlock_t		rs_snd_lock;
	struct list_head	rs_send_queue;
	u32			rs_snd_bytes; /* Total bytes to all peers */
	u32			rs_buf_info_dest_cnt;
	struct rhashtable	rs_buf_info_tbl;

	/*
	 * rs_recv_lock protects the receive queue, and is
	 * used to serialize with rds_release.
	 */
	rwlock_t		rs_recv_lock;
	int			rs_rcv_bytes;
	struct list_head	rs_recv_queue;
	/*
	 * rs_recv_pending actively counts the yet-to-be-processed
	 * entried in the rs_recv_queue queue
	 */
	int			rs_recv_pending;

	/* just for stats reporting */
	struct list_head	rs_item;

	/* these have their own lock */
	spinlock_t		rs_rdma_lock;
	struct rb_root		rs_rdma_keys;

	/* Socket options - in case there will be more */
	unsigned char		rs_recverr,
				rs_cong_monitor;
	int			poison;

	u8                      rs_tos;

	/* Socket receive path trace points*/
	u8			rs_rx_traces;
	u8			rs_rx_trace[RDS_MSG_RX_DGRAM_TRACE_MAX];

	u32			rs_hash_initval;

	/* Transport private info */
	struct mutex		rs_trans_lock;
	void			*rs_trans_private;
	pid_t                   rs_pid;
	unsigned char		rs_inq;
	struct rds_net		*rs_rns;
	struct rds_statistics __percpu	*rs_stats;
};

static inline struct rds_sock *rds_sk_to_rs(const struct sock *sk)
{
	return container_of(sk, struct rds_sock, rs_sk);
}
static inline struct sock *rds_rs_to_sk(struct rds_sock *rs)
{
	return &rs->rs_sk;
}

/* Used by tracepoints to retrieve cgroup info */
static inline struct cgroup *rds_rs_to_cgroup(struct rds_sock *rs)
{
	struct cgroup *cgrp = NULL;
	struct sock *sk;

	if (rs) {
		sk = rds_rs_to_sk(rs);
		if (sk)
			cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
	}
	return cgrp;
}

/* Used by tracepoints to retrieve netns inode number associated with sock */
static inline u64 rds_rs_to_ns_inum(struct rds_sock *rs)
{
	struct sock *sk;

	if (rs) {
		sk = rds_rs_to_sk(rs);
		if (sk)
			return sk->sk_net.net->ns.inum;
	}
	return 0;
}

/*
 * The stack assigns sk_sndbuf and sk_rcvbuf to twice the specified value
 * to account for overhead.  We don't account for overhead, we just apply
 * the number of payload bytes to the specified value.
 */
static inline int rds_sk_sndbuf(struct rds_sock *rs)
{
	return rds_rs_to_sk(rs)->sk_sndbuf / 2;
}
static inline int rds_sk_rcvbuf(struct rds_sock *rs)
{
	return rds_rs_to_sk(rs)->sk_rcvbuf / 2;
}

struct rds_statistics {
	uint64_t	s_conn_reset;
	uint64_t	s_recv_drop_bad_checksum;
	uint64_t	s_recv_drop_old_seq;
	uint64_t	s_recv_drop_no_sock;
	uint64_t	s_recv_drop_dead_sock;
	uint64_t	s_recv_deliver_raced;
	uint64_t	s_recv_delivered;
	uint64_t	s_recv_queued;
	uint64_t	s_recv_immediate_retry;
	uint64_t	s_recv_delayed_retry;
	uint64_t	s_recv_ack_required;
	uint64_t	s_recv_rdma_bytes;
	uint64_t	s_recv_payload_bad_checksum;
	uint64_t	s_recv_payload_csum_ib;
	uint64_t	s_recv_payload_csum_loopback;
	uint64_t	s_recv_payload_csum_tcp;
	uint64_t	s_recv_payload_csum_ignored;
	uint64_t	s_recv_ping;
	uint64_t	s_recv_pong;
	uint64_t	s_recv_hb_ping;
	uint64_t	s_recv_hb_pong;
	uint64_t	s_recv_mprds_ping;
	uint64_t	s_recv_mprds_pong;
	uint64_t	s_send_queue_empty;
	uint64_t	s_send_queue_full;
	uint64_t	s_send_lock_contention;
	uint64_t	s_send_lock_queue_raced;
	uint64_t	s_send_immediate_retry;
	uint64_t	s_send_delayed_retry;
	uint64_t	s_send_drop_acked;
	uint64_t	s_send_ack_required;
	uint64_t	s_send_queued;
	uint64_t	s_send_rdma;
	uint64_t	s_send_rdma_bytes;
	uint64_t	s_send_ping;
	uint64_t	s_send_pong;
	uint64_t	s_send_hb_ping;
	uint64_t	s_send_hb_pong;
	uint64_t	s_send_mprds_ping;
	uint64_t	s_send_mprds_pong;
	uint64_t	s_send_payload_csum_added;
	uint64_t	s_page_remainder_hit;
	uint64_t	s_page_remainder_miss;
	uint64_t	s_copy_to_user;
	uint64_t	s_copy_from_user;
	uint64_t	s_copy_from_user_cache_get;
	uint64_t	s_copy_from_user_cache_put;
	uint64_t	s_cong_update_queued;
	uint64_t	s_cong_update_received;
	uint64_t	s_cong_send_error;
	uint64_t	s_cong_send_blocked;
	uint64_t	s_qos_threshold_exceeded;
	uint64_t	s_recv_bytes_added_to_socket;
	uint64_t	s_recv_bytes_removed_from_socket;
	uint64_t	s_send_stuck_rm;
	uint64_t	s_page_allocs;
	uint64_t	s_page_frees;
	uint64_t	s_page_gets;
	uint64_t	s_mprds_catchup_tx0_retries;
};

/* af_rds.c */
#define	RDS_SOCK_BUF_INFO_HTBL_SIZE	512
static const struct rhashtable_params rs_buf_info_params = {
	.nelem_hint = RDS_SOCK_BUF_INFO_HTBL_SIZE,
	.key_len = sizeof(struct in6_addr),
	.key_offset = offsetof(struct rs_buf_info, rsbi_key),
	.head_offset = offsetof(struct rs_buf_info, rsbi_link),
};

/* Maximum number of peers a socket can communicate with */
extern unsigned int rds_sock_max_peers;

struct rs_buf_info *rds_add_buf_info(struct rds_sock *rs, struct in6_addr *addr,
				     int *ret, gfp_t gfp);
static inline struct rs_buf_info *rds_get_buf_info(struct rds_sock *rs,
						   struct in6_addr *addr)
{
	return rhashtable_lookup_fast(&rs->rs_buf_info_tbl, addr,
				      rs_buf_info_params);
}
char *rds_str_array(char **array, size_t elements, size_t index);
void rds_sock_addref(struct rds_sock *rs);
void rds_sock_put(struct rds_sock *rs);
void rds_wake_sk_sleep(struct rds_sock *rs);
static inline void __rds_wake_sk_sleep(struct sock *sk)
{
	wait_queue_head_t *waitq = sk_sleep(sk);

	if (!sock_flag(sk, SOCK_DEAD) && waitq)
		wake_up(waitq);
}

int rds_check_qos_threshold(struct rds_statistics __percpu *stats, u8 tos,
			    size_t pauload_len);
#define RDS_NMBR_WAITQ BIT(6)
extern struct wait_queue_head rds_poll_waitq[RDS_NMBR_WAITQ];

void debug_sock_hold(struct sock *sock);
void debug_sock_put(struct sock *sock);

/* bind.c */
int rds_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);
void rds_remove_bound(struct rds_net *rds_ns, struct rds_sock *rs);
struct rds_sock *rds_find_bound(struct rds_net *rds_ns,
				struct in6_addr *addr, __be16 port,
				__u32 scope_id);
int rds_bind_tbl_net_init(struct rds_net *rds_ns);
void rds_bind_tbl_net_exit(struct rds_net *rds_ns);

/* cong.c */
int  rds_cong_net_init(struct rds_net *rds_ns);
void  rds_cong_net_exit(struct rds_net *rds_ns);
int rds_cong_get_maps(struct rds_connection *conn);
void rds_cong_add_conn(struct rds_connection *conn);
void rds_cong_remove_conn(struct rds_connection *conn);
void rds_cong_set_bit(struct rds_cong_map *map, __be16 port);
void rds_cong_clear_bit(struct rds_cong_map *map, __be16 port);
int rds_cong_wait(struct rds_cong_map *map, __be16 port, int nonblock, struct rds_sock *rs);
void rds_cong_queue_updates(struct rds_cong_map *map);
void rds_cong_map_updated(struct rds_connection *conn,
			  struct rds_cong_map *map, uint64_t portmask);
int rds_cong_updated_since(struct rds_sock *rs);
void rds_cong_add_socket(struct rds_sock *);
void rds_cong_remove_socket(struct rds_sock *);
struct rds_message *rds_cong_update_alloc(struct rds_connection *conn);

/* conn.c */
int rds_conn_init(void);
void rds_conn_exit(void);
int rds_conn_tbl_net_init(struct rds_net *rns);
void rds_conn_tbl_net_exit(struct rds_net *rns);
struct rds_connection *rds_conn_create(struct net *net,
				       const struct in6_addr *laddr,
				       const struct in6_addr *faddr,
				       struct rds_transport *trans,
				       u8 tos, gfp_t gfp, int dev_if);
struct rds_connection *rds_conn_create_outgoing(struct net *net,
						struct in6_addr *laddr,
						struct in6_addr *faddr,
						struct rds_transport *trans,
						u8 tos, gfp_t gfp, int dev_if);
struct rds_connection *rds_conn_find(struct rds_net *rns,
				     struct in6_addr *laddr,
				     struct in6_addr *faddr,
				     struct rds_transport *trans, u8 tos,
				     int dev_if);
void rds_conn_init_shutdown(struct rds_conn_path *cp);
void rds_conn_destroy(struct rds_connection *conn, int shutdown);
void rds_conn_reset(struct rds_connection *conn);
void rds_conn_drop(struct rds_connection *conn, int reason, int err);
void rds_conn_path_drop(struct rds_conn_path *cp, int reason, int err);
void rds_conn_faddr_ha_changed(const struct in6_addr *faddr,
			       const unsigned char *ha,
			       unsigned ha_len);
void rds_conn_laddr_list(struct rds_net *rns, struct in6_addr *laddr,
			 struct list_head *laddr_conns);
void rds_conn_connect_if_down(struct rds_connection *conn);
void rds_conn_path_connect_if_down(struct rds_conn_path *conn);
void rds_check_all_paths(struct rds_connection *conn);
void rds_for_each_conn_info(struct socket *sock, unsigned int len,
			    struct rds_info_iterator *iter,
			    struct rds_info_lengths *lens,
			    int (*visitor)(struct rds_connection *, void *),
			    u64 *buffer,
			    size_t item_len);
char *conn_drop_reason_str(enum rds_conn_drop_src reason);
void rds_conn_path_trace_state_change(int changed, struct rds_conn_path *cp,
				      int old, int new, int reason, int err);
void rds_queue_work(struct rds_conn_path *cp,
		    struct workqueue_struct *wq,
		    struct work_struct *work,
		    char *reason);
void rds_queue_delayed_work(struct rds_conn_path *cp,
			    struct workqueue_struct *wq,
			    struct delayed_work *dwork,
			    unsigned long delay, char *reason);
void rds_queue_delayed_work_on(struct rds_conn_path *cp, int cpu,
			       struct workqueue_struct *wq,
			       struct delayed_work *dwork,
			       unsigned long delay, char *reason);
void rds_mod_delayed_work(struct rds_conn_path *cp,
			  struct workqueue_struct *wq,
			  struct delayed_work *dwork,
			  unsigned long delay, char *reason);

static inline void rds_conn_path_state_change(struct rds_conn_path *cp,
					      int new, int reason, int err)
{
	int old = atomic_read(&cp->cp_state);

	atomic_set(&cp->cp_state, new);
	rds_conn_path_trace_state_change(1, cp, old, new, reason, err);
}

static inline void rds_cond_queue_shutdown_work(struct rds_conn_path *cp)
{
	if (!test_and_set_bit(RDS_SHUTDOWN_WORK_QUEUED, &cp->cp_flags))
		rds_mod_delayed_work(cp, cp->cp_wq, &cp->cp_up_or_down_w,
				     0, "queue shutdown work");
}

static inline void rds_clear_shutdown_pending_work_bit(struct rds_conn_path *cp)
{
	/* clear_bit() does not imply a memory barrier */
	smp_mb__before_atomic();
	clear_bit(RDS_SHUTDOWN_WORK_QUEUED, &cp->cp_flags);
	/* clear_bit() does not imply a memory barrier */
	smp_mb__after_atomic();
}

/* sysctl.c */
extern unsigned long rds_sysctl_reconnect_max_jiffies;

static inline bool rds_cond_queue_reconnect_work(struct rds_conn_path *cp, unsigned long delay)
{
	unsigned long mod_delay = max(delay,
				      msecs_to_jiffies(rds_sysctl_reconnect_max_jiffies));

	if (!test_and_set_bit(RDS_RECONNECT_PENDING, &cp->cp_flags)) {
		rds_queue_delayed_work(cp, cp->cp_wq, &cp->cp_up_or_down_w,
				       delay, "reconnect work");
		return true;
	} else if (!test_bit(RDS_SHUTDOWN_WORK_QUEUED, &cp->cp_flags) &&
		   (cp->cp_up_or_down_w.timer.expires > 0) &&
		   (cp->cp_up_or_down_w.timer.expires < KTIME_MAX) &&
		   time_after(cp->cp_up_or_down_w.timer.expires,
			      jiffies + mod_delay)) {
		/* mod_delayed_work due to an immediate sendmsg()
		 * by always allowing shortening the delay,
		 * if the existing reconnect timer expires later
		 * than reconnect_max_delay_ms (1s).
		 */
		rds_mod_delayed_work(cp, cp->cp_wq, &cp->cp_up_or_down_w,
				     mod_delay, "reconnect work");
		return true;
	} else {
		return false;
	}
}

static inline void
rds_clear_reconnect_pending_work_bit(struct rds_conn_path *cp)
{
	/* clear_bit() does not imply a memory barrier */
	smp_mb__before_atomic();
	clear_bit(RDS_RECONNECT_PENDING, &cp->cp_flags);
	/* clear_bit() does not imply a memory barrier */
	smp_mb__after_atomic();
}

static inline void rds_cond_queue_send_work(struct rds_conn_path *cp, unsigned long delay)
{
	int cpu;

	if (test_and_set_bit(RDS_SEND_WORK_QUEUED, &cp->cp_flags))
		return;

	if (cp->cp_conn->c_trans->conn_preferred_cpu) {
		cpu = cp->cp_conn->c_trans->conn_preferred_cpu(cp->cp_conn, true);
		rds_queue_delayed_work_on(cp, cpu, cp->cp_wq, &cp->cp_send_w, delay,
					  "send work");
	} else
		rds_queue_delayed_work(cp, cp->cp_wq, &cp->cp_send_w, delay,
				       "send work");
}

static inline void rds_clear_queued_send_work_bit(struct rds_conn_path *cp)
{
	/* clear_bit() does not imply a memory barrier */
	smp_mb__before_atomic();
	clear_bit(RDS_SEND_WORK_QUEUED, &cp->cp_flags);
	/* clear_bit() does not imply a memory barrier */
	smp_mb__after_atomic();
}

static inline void rds_cond_queue_recv_work(struct rds_conn_path *cp, unsigned long delay)
{
	if (!test_and_set_bit(RDS_RECV_WORK_QUEUED, &cp->cp_flags))
		rds_queue_delayed_work(cp, cp->cp_wq, &cp->cp_recv_w, delay,
				       "recv work");
}

static inline void rds_clear_queued_recv_work_bit(struct rds_conn_path *cp)
{
	/* clear_bit() does not imply a memory barrier */
	smp_mb__before_atomic();
	clear_bit(RDS_RECV_WORK_QUEUED, &cp->cp_flags);
	/* clear_bit() does not imply a memory barrier */
	smp_mb__after_atomic();
}

static inline void rds_set_rm_flag_bit(struct rds_message *rm, int n)
{
	/* set_bit() does not imply a memory barrier */
	smp_mb__before_atomic();
	set_bit(n, &rm->m_flags);
	/* set_bit() does not imply a memory barrier */
	smp_mb__after_atomic();
}

static inline void rds_clear_rm_flag_bit(struct rds_message *rm, int n)
{
	/* clear_bit() does not imply a memory barrier */
	smp_mb__before_atomic();
	clear_bit(n, &rm->m_flags);
	/* clear_bit() does not imply a memory barrier */
	smp_mb__after_atomic();
}

static inline int
rds_conn_path_transition(struct rds_conn_path *cp, int old, int new, int reason)
{
	int ret = atomic_cmpxchg(&cp->cp_state, old, new) == old;

	rds_conn_path_trace_state_change(ret, cp, old, new, reason, 0);

	return ret;
}

static inline int
rds_conn_transition(struct rds_connection *conn, int old, int new, int reason)
{
	WARN_ON(conn->c_trans->t_mp_capable);
	return rds_conn_path_transition(&conn->c_path[0], old, new, reason);
}

static inline int
rds_conn_path_state(struct rds_conn_path *cp)
{
	return atomic_read(&cp->cp_state);
}

static inline int
rds_conn_state(struct rds_connection *conn)
{
	WARN_ON(conn->c_trans->t_mp_capable);
	return rds_conn_path_state(&conn->c_path[0]);
}

static inline int
rds_conn_path_up(struct rds_conn_path *cp)
{
	return atomic_read(&cp->cp_state) == RDS_CONN_UP;
}

static inline int
rds_conn_path_down(struct rds_conn_path *cp)
{
	return atomic_read(&cp->cp_state) == RDS_CONN_DOWN;
}

static inline int
rds_conn_up(struct rds_connection *conn)
{
	WARN_ON(conn->c_trans->t_mp_capable);
	return rds_conn_path_up(&conn->c_path[0]);
}

static inline int
rds_conn_path_connecting(struct rds_conn_path *cp)
{
	return atomic_read(&cp->cp_state) == RDS_CONN_CONNECTING;
}

static inline int
rds_conn_connecting(struct rds_connection *conn)
{
	WARN_ON(conn->c_trans->t_mp_capable);
	return rds_conn_path_connecting(&conn->c_path[0]);
}

static inline bool
rds_conn_self_loopback_passive(struct rds_connection *conn)
{
	if (ipv6_addr_equal(&conn->c_laddr, &conn->c_faddr) && !conn->c_passive)
		return true;
	else
		return false;
}

/* message.c */
struct rds_message *rds_message_alloc(unsigned int nents, gfp_t gfp);
struct scatterlist *rds_message_alloc_sgs(struct rds_message *rm, int nents);
int rds_message_copy_from_user(struct rds_sock *rs, struct rds_message *rm, struct iov_iter *from);
void rds_message_populate_header(struct rds_header *hdr, __be16 sport,
				 __be16 dport, u64 seq);
int rds_message_add_extension(struct rds_header *hdr,
			      unsigned int type, const void *data);
int rds_message_next_extension(struct rds_header *hdr,
			       unsigned int *pos, void *buf, unsigned int *buflen);
int rds_message_add_version_extension(struct rds_header *hdr, unsigned int version);
int rds_message_get_version_extension(struct rds_header *hdr, unsigned int *version);
int rds_message_add_rdma_dest_extension(struct rds_header *hdr, u32 r_key, u32 offset);
int rds_message_inc_copy_to_user(struct rds_sock *rs, struct rds_incoming *inc,
				 struct iov_iter *to);
void rds_message_inc_free(struct rds_incoming *inc);
void rds_message_addref(struct rds_message *rm);
void rds_message_put(struct rds_message *rm);
void rds_message_wait(struct rds_message *rm);
void rds_message_unmapped(struct rds_message *rm);
void rds_cfu_init_cache(void);
void rds_cfu_fini_cache(void);

static inline void rds_message_make_checksum(struct rds_header *hdr)
{
	hdr->h_csum = 0;
	hdr->h_csum = ip_fast_csum((void *) hdr, sizeof(*hdr) >> 2);
}

static inline int rds_message_verify_checksum(const struct rds_header *hdr)
{
	return !hdr->h_csum || ip_fast_csum((void *) hdr, sizeof(*hdr) >> 2) == 0;
}

/* used by __init functions in rds, rds_rdma and rds_tcp to enable tracepoints
 * associated with the legacy rds_rt_debug_bitmap values specified.
 */
void rds_rt_debug_tp_enable(void);

/* page.c */
int rds_page_remainder_alloc(struct scatterlist *scat, unsigned long bytes,
			     gfp_t gfp, int nid);
void rds_page_exit(void);

/* recv.c */
void rds_inc_init(struct rds_incoming *inc, struct rds_connection *conn,
		  struct in6_addr *saddr);
void rds_inc_path_init(struct rds_incoming *inc, struct rds_conn_path *conn,
		       struct in6_addr *saddr);
void rds_inc_addref(struct rds_incoming *inc);
void rds_inc_put(struct rds_incoming *inc);
void rds_recv_incoming(struct rds_connection *conn, struct in6_addr *saddr,
		       struct in6_addr *daddr,
		       struct rds_incoming *inc, gfp_t gfp);
int rds_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
		int msg_flags);
void rds_clear_recv_queue(struct rds_sock *rs);
void do_rds_receive_csum_err(struct rds_incoming *inc, u32 csum_calc);
int rds_notify_queue_get(struct rds_sock *rs, struct msghdr *msg);
void rds_inc_info_copy(struct rds_incoming *inc,
		       struct rds_info_iterator *iter,
		       __be32 saddr, __be32 daddr, int flip);
void rds6_inc_info_copy(struct rds_incoming *inc,
			struct rds_info_iterator *iter,
			struct in6_addr *saddr, struct in6_addr *daddr,
			int flip);

/* send.c */
int rds_sendmsg(struct socket *sock, struct msghdr *msg, size_t payload_len);
void rds_send_path_reset(struct rds_conn_path *cp);
int rds_send_xmit(struct rds_conn_path *cp);
void rds_conn_drop_sock_cancel_worker(struct work_struct *work);
void rds_send_drop_to(struct rds_sock *rs, struct sockaddr_in6 *dest);
typedef int (*is_acked_func)(struct rds_message *rm, uint64_t ack);
void rds_send_drop_acked(struct rds_connection *conn, u64 ack,
			 is_acked_func is_acked);
void rds_send_path_drop_acked(struct rds_conn_path *cp, u64 ack,
			      is_acked_func is_acked);
void rds_send_remove_from_sock(struct list_head *messages, int status);
void rds_send_hs_ping(struct rds_connection *conn, int cp_index);
int rds_send_pong(struct rds_conn_path *cp, __be16 dport);
void rds_send_hb(struct rds_connection *conn, int response);
struct rds_message *rds_send_get_message(struct rds_connection *,
					 struct rm_rdma_op *);
int rds_get_pending_sends(struct rds_sock *rs);
extern unsigned int rds_async_send_enabled;

/* rdma.c */
void rds_rdma_unuse(struct rds_sock *rs, u32 r_key, int force);

int rds_get_mr(struct rds_sock *rs, sockptr_t optval, int optlen);
int rds_get_mr_for_dest(struct rds_sock *rs, sockptr_t optval, int optlen);
int rds_free_mr(struct rds_sock *rs, sockptr_t optval, int optlen);

void rds_rdma_drop_keys(struct rds_sock *rs);
int rds_rdma_extra_size(struct rds_rdma_args *args,
			struct rds_iov_vector *iov);

int rds_rdma_process_send_cmsg(struct rds_sock *rs, struct rds_message *rm,
			       struct cmsghdr *cmsg, int *indp,
			       struct rds_iov_vector_arr *vct);
void rds_rdma_free_op(struct rm_rdma_op *ro);
void rds_atomic_free_op(struct rm_atomic_op *ao);
void rds_rdma_send_complete(struct rds_message *rm, int wc_status);
void rds_atomic_send_complete(struct rds_message *rm, int wc_status);
void rds_asend_complete(struct rds_message *rm, int wc_status);

void __rds_put_mr_final(struct kref *kref);

/* stats.c */
DECLARE_PER_CPU_SHARED_ALIGNED(struct rds_statistics, rds_stats);
#define rds_stats_inc_which(which, member) do {		\
	per_cpu_ptr(which, get_cpu())->member++;	\
	put_cpu();					\
} while (0)
#define rds_stats_inc(stats, member)\
	rds_stats_inc_which(stats, member)
#define rds_stats_dec_which(which, member) do {		\
	per_cpu(which, get_cpu()).member--;	\
	put_cpu();				\
} while (0)
#define rds_stats_add_which(which, member, count) do {		\
	per_cpu_ptr(which, get_cpu())->member += count;	\
	put_cpu();						\
} while (0)
#define rds_stats_add(stats, member, count)		\
	rds_stats_add_which(stats, member, count)

#define rds_stats_sub_which(which, member, count) do {	\
	per_cpu_ptr(which, get_cpu())->member -= count;	\
	put_cpu();					\
} while (0)
#define rds_stats_sub(stats, member, count)		\
	rds_stats_sub_which(stats, member, count)
int rds_stats_net_init(struct net *net);
void rds_stats_net_exit(struct net *net);
int rds_mod_stats_register(struct net *net, int module,
			   struct rds_stats_struct *stats);
struct rds_stats_struct *rds_mod_stats_unregister(struct net *net,
						  int module);
void rds_stats_info_copy(struct rds_info_iterator *iter,
			 uint64_t *values, char **names, size_t nr);
void rds_stats_print(const char *where);

/* sysctl.c */
int rds_sysctl_init(void);
void rds_sysctl_exit(void);
extern unsigned long rds_sysctl_sndbuf_min;
extern unsigned long rds_sysctl_sndbuf_default;
extern unsigned long rds_sysctl_sndbuf_max;
extern unsigned long rds_sysctl_reconnect_min_jiffies;
extern unsigned long rds_sysctl_reconnect_passive_min_jiffies;
extern unsigned int  rds_sysctl_reconnect_backoff_after_secs;
extern unsigned int  rds_sysctl_reconnect_backoff_max_interval_secs;
extern unsigned int  rds_sysctl_max_unacked_packets;
extern unsigned int  rds_sysctl_max_unacked_bytes;
extern unsigned int  rds_sysctl_ping_enable;
extern unsigned long rds_sysctl_trace_flags;
extern unsigned int  rds_sysctl_trace_level;
extern unsigned int  rds_sysctl_shutdown_trace_start_time;
extern unsigned int  rds_sysctl_shutdown_trace_end_time;
extern unsigned int  rds_sysctl_conn_hb_timeout;
extern unsigned int  rds_sysctl_conn_hb_interval;
extern unsigned long rds_sysctl_dr_sock_cancel_jiffies;
extern unsigned int  rds_sysctl_enable_payload_csum;
extern unsigned int  rds_sysctl_cfu_cache_cap;
extern unsigned int  rds_cfu_cache_gc_interval;

/* threads.c */
int rds_threads_init(void);
void rds_threads_exit(void);
extern struct workqueue_struct *rds_wq;
void rds_queue_reconnect(struct rds_conn_path *cp, bool immediate);
void rds_up_or_down_worker(struct work_struct *);
void rds_send_worker(struct work_struct *);
void rds_recv_worker(struct work_struct *);
void rds_hb_worker(struct work_struct *);
void rds_connect_path_complete(struct rds_conn_path *cp, int curr);
void rds_connect_complete(struct rds_connection *conn);
int rds_addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2);
void rds_queue_cancel_work(struct rds_conn_path *cp,
			   struct delayed_work *dwork,
			   char *reason);
void rds_queue_flush_work(struct rds_conn_path *cp,
			  struct work_struct *dwork,
			  char *reason);

/* transport.c */
int rds_trans_register(struct rds_transport *trans);
void rds_trans_unregister(struct rds_transport *trans);
struct rds_transport *rds_trans_get_preferred(struct net *net,
					      const struct in6_addr *addr,
					      __u32 scope_id);
void rds_trans_put(struct rds_transport *trans);
unsigned int rds_trans_stats_info_copy(struct rds_info_iterator *iter,
				       unsigned int avail);
struct rds_transport *rds_trans_get(int t_type);
int rds_trans_init(void);
void rds_trans_exit(void);

/* rds_ns.c */
struct rds_net *rds_ns(struct net *net);
int rds_reg_pernet(void);
void rds_unreg_pernet(void);

/* ib.c */

static inline void rds_page_free(struct page *page)
{
	__free_page(page);
	rds_stats_inc(&rds_stats, s_page_frees);
}

static inline void rds_pages_free(struct page *page, int order)
{
	__free_pages(page, order);
	rds_stats_inc(&rds_stats, s_page_frees);

}

static inline
struct rds_conn_path *rds_conn_to_path(struct rds_connection *conn, struct rds_incoming *inc)
{
	return conn->c_trans->t_mp_capable ? inc->i_conn_path : conn->c_path + 0;
}

/* RDS checksum structures and code */

struct rds_csum_state {
	__wsum csum;
	size_t off;
};

/* RDS checksum version of copy_page_from_iter()
 *
 * This code is largely a functional copy of copy_page_from_iter() as found in
 * lib/iov_iter.c, as that code does not have a provision for calculating a
 * checksum but otherwise has the functionality needed.
 */
static inline size_t
rds_csum_and_copy_page_from_iter(struct page *page, size_t offset, size_t bytes,
				 struct rds_csum *csum, struct iov_iter *i)
{
	size_t res = 0;
	__wsum *wsump = &csum->csum_val.csum;

	page += offset / PAGE_SIZE; // first subpage
	offset %= PAGE_SIZE;

	while (1) {
		void *kaddr = kmap_local_page(page);
		size_t n = min(bytes, (size_t)PAGE_SIZE - offset);
		bool status = csum_and_copy_from_iter_full(kaddr + offset, n, wsump, i);

		kunmap_local(kaddr);

		/* If the returned status is false, the full copy did not occur so return
		 * a count less than (bytes) to signify an error.
		 */
		if (!status)
			break;

		res += n;
		bytes -= n;

		if (!bytes)
			break;

		offset += n;

		if (offset == PAGE_SIZE) {
			page++;
			offset = 0;
		}
	}

	return res;
}

/* Below are local versions of csum_and_copy_to_iter() and ancillary routines
 * from net/core/datagram.c as they are no longer callable outside of core
 * networking due to changes in the upstream kernel.
 *
 * The upstream kernel also no longer exports arch-specific versions of
 * csum_and_copy_to_user(), so the code must use an architecture-agnostic version.
 *
 * As payload checksums are a diagnostic tool ONLY that must specifically be enabled, a
 * slight performance impact isn't of concern.
 */
static __always_inline
__wsum rds_csum_and_copy_to_user(const void *src, void __user *dst, int len)
{
	__wsum sum = csum_partial(src, len, ~0U);

	if (copy_to_user(dst, src, len) == 0)
		return sum;
	return 0;
}

/* Copy to destination address mapped into user space:
 * iovec ITER_UBUF || ITER_IOVEC
 */
static __always_inline
size_t rds_copy_to_user_iter_csum(void __user *iter_to, size_t progress,
				  size_t len, void *from, void *priv2)
{
	__wsum next, *csum = priv2;

	next = rds_csum_and_copy_to_user(from + progress, iter_to, len);
	*csum = csum_block_add(*csum, next, progress);
	return next ? 0 : len;
}

/* Copy to destination address mapped into kernel space:
 * iovec ITER_BVEC || ITER_KVEC || ITER_XARRAY
 */
static __always_inline
size_t rds_memcpy_to_iter_csum(void *iter_to, size_t progress,
			       size_t len, void *from, void *priv2)
{
	__wsum *csum = priv2;
	__wsum next = csum_partial_copy_nocheck(from + progress, iter_to, len);

	*csum = csum_block_add(*csum, next, progress);
	return 0;
}

/* Local version of csum_and_copy_to_iter() as it is now declared as a static in
 * upstream code.
 */
static __always_inline
size_t rds_csum_and_copy_to_iter(const void *addr, size_t bytes, void *_csstate,
				 struct iov_iter *i)
{
	struct rds_csum_state *csstate = _csstate;
	__wsum sum;

	if (unlikely(iov_iter_is_discard(i))) {
		// can't use csum_memcpy() for that one - data is not copied
		csstate->csum = csum_block_add(csstate->csum,
					       csum_partial(addr, bytes, 0),
					       csstate->off);
		csstate->off += bytes;
		return bytes;
	}

	sum = csum_shift(csstate->csum, csstate->off);

	/* iterate_and_advance2:
	 *	iter = i				[destination iov]
	 *	len = bytes				[copy length]
	 *	priv = (void *)addr			[source address]
	 *	priv2 = &sum				[loop checksum value]
	 *	ustep = rds_copy_to_user_iter_csum	[userspace dest copy routine]
	 *	step = rds_memcpy_to_iter_csum		[kernel dest copy routine]
	 */
	bytes = iterate_and_advance2(i, bytes, (void *)addr, &sum,
				     rds_copy_to_user_iter_csum,
				     rds_memcpy_to_iter_csum);

	csstate->csum = csum_shift(sum, csstate->off);
	csstate->off += bytes;
	return bytes;
}

/* Local version of copy_page_to_iter() from lib/iov_iter.c modified to accommodate
 * checksums.
 */
static __always_inline
size_t rds_csum_and_copy_page_to_iter(struct page *page, size_t offset,
				      size_t bytes, struct rds_csum *csum,
				      struct iov_iter *i)
{
	size_t res = 0;
	struct rds_csum_state csdata = { .csum = csum->csum_val.csum };

	if (WARN_ON_ONCE(i->data_source))
		return 0;

	page += offset / PAGE_SIZE; // first subpage
	offset %= PAGE_SIZE;

	while (1) {
		void *kaddr = kmap_local_page(page);
		size_t n = min(bytes, (size_t)PAGE_SIZE - offset);

		n = rds_csum_and_copy_to_iter(kaddr + offset, n, &csdata, i);
		kunmap_local(kaddr);

		if (!n)
			break;

		res += n;
		bytes -= n;

		if (!bytes) {
			csum->csum_val.csum = csdata.csum;
			break;
		}

		offset += n;

		if (offset == PAGE_SIZE) {
			page++;
			offset = 0;
		}
	}

	return res;
}

/* end of routines based upon upstream generic code */

/* The tracepoint documentation states tracepoint-defs.h and a C routine to
 * execute the actual tracepoint must be used if a tracepoint is called from
 * within an inline function.
 */
DECLARE_TRACEPOINT(rds_receive_csum_err);

static __always_inline
void rds_check_csum(struct rds_incoming *inc, struct rds_csum *csum)
{
	if (unlikely(inc->i_payload_csum.csum_val.raw != csum->csum_val.raw)) {
		rds_stats_inc(inc->i_conn->c_stats, s_recv_payload_bad_checksum);

		if (unlikely(tracepoint_enabled(rds_receive_csum_err)))
			do_rds_receive_csum_err(inc, csum->csum_val.raw);
	}
}

/* Get a module's statistics memory of a given namespace.  The main purpose
 * is for caller to store the memory for fast update to the statistics.  It
 * is assumed that the module has already registered such that the returned
 * memory is valid.  It is also assumed that the caller will not access this
 * memory after the module unregisters.  Both are true if the caller is using
 * that module.
 */
static inline void __percpu *__rds_get_mod_stats(struct rds_net *rns,
						 int module)
{
	return rns->rns_mod_stats[module]->rs_stats;
}

static inline
struct net *rds_conn_net(struct rds_connection *conn)
{
	struct net *net = read_pnet(&conn->c_net);

	WARN_ON(!net);
	return net;
}

struct rds_net *rds_ns(struct net *);
static inline
void rds_conn_net_set(struct rds_connection *conn, struct net *net)
{
	/* Once set, never changed until connection destruction. */
	write_pnet(&conn->c_net, net);

	if (net) {
		conn->c_rns = rds_ns(net);
		conn->c_stats = __rds_get_mod_stats(conn->c_rns, RDS_MOD_RDS);
	} else {
		conn->c_rns = NULL;
		conn->c_stats = NULL;
	}
}

#endif
