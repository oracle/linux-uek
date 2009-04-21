#ifndef _SDP_H_
#define _SDP_H_

#include <linux/workqueue.h>
#include <linux/wait.h>
#include <net/inet_sock.h>
#include <net/tcp.h> /* For urgent data flags */
#include <rdma/ib_verbs.h>

#define SDPSTATS_ON

#define sdp_printk(level, sk, format, arg...)                \
	printk(level "%s:%d sdp_sock(%d %d:%d): " format,             \
	       __func__, __LINE__, \
	       current->pid, \
	       (sk) ? inet_sk(sk)->num : -1,                 \
	       (sk) ? ntohs(inet_sk(sk)->dport) : -1, ## arg)
#define sdp_warn(sk, format, arg...)                         \
	sdp_printk(KERN_WARNING, sk, format , ## arg)

#ifdef CONFIG_INFINIBAND_SDP_DEBUG
extern int sdp_debug_level;

#define sdp_dbg(sk, format, arg...)                          \
	do {                                                 \
		if (sdp_debug_level > 0)                     \
		sdp_printk(KERN_DEBUG, sk, format , ## arg); \
	} while (0)

#define sock_ref(sk, msg, sock_op) ({ \
	if (!atomic_read(&(sk)->sk_refcnt)) {\
		sdp_warn(sk, "%s:%d - %s (%s) ref = 0.\n", \
				 __func__, __LINE__, #sock_op, msg); \
		WARN_ON(1); \
	} else { \
		sdp_dbg(sk, "%s:%d - %s (%s) ref = %d.\n", __func__, __LINE__, \
			#sock_op, msg, atomic_read(&(sk)->sk_refcnt)); \
		sock_op(sk); \
	}\
})

#define sk_common_release(sk) do { \
		sdp_dbg(sk, "%s:%d - sock_put(" SOCK_REF_BORN ") - refcount = %d " \
			"from withing sk_common_release\n",\
			__FUNCTION__, __LINE__, atomic_read(&(sk)->sk_refcnt)); \
		sk_common_release(sk); \
} while (0)

#else /* CONFIG_INFINIBAND_SDP_DEBUG */
#define sdp_dbg(priv, format, arg...)                        \
	do { (void) (priv); } while (0)
#define sock_ref(sk, msg, sock_op) sock_op(sk)
#endif /* CONFIG_INFINIBAND_SDP_DEBUG */

#ifdef CONFIG_INFINIBAND_SDP_DEBUG_DATA

extern int sdp_data_debug_level;
#define sdp_dbg_data(sk, format, arg...)                     \
	do {                                                 \
		if (sdp_data_debug_level & 0x2)                \
		sdp_printk(KERN_DEBUG, sk, format , ## arg); \
	} while (0)
#define SDP_DUMP_PACKET(sk, str, skb, h)                     \
	do {                                                 \
		if (sdp_data_debug_level & 0x1)                \
			dump_packet(sk, str, skb, h); \
	} while (0)
#else
#define sdp_dbg_data(priv, format, arg...)
//	do { (void) (priv); } while (0)
#define SDP_DUMP_PACKET(sk, str, skb, h)
#endif

#ifdef SDPSTATS_ON

struct sdpstats {
	u32 post_send[256];
	u32 sendmsg_bcopy_segment;
	u32 sendmsg_bzcopy_segment;
	u32 sendmsg;
	u32 post_send_credits;
	u32 sendmsg_nagle_skip;
	u32 sendmsg_seglen[25];
	u32 send_size[25];
	u32 post_recv;
	u32 int_count;
	u32 bzcopy_poll_miss;
	u32 send_wait_for_mem;
	u32 send_miss_no_credits;
	u32 rx_poll_miss;
	u32 tx_poll_miss;
	u32 memcpy_count;
	u32 credits_before_update[64];
	u32 send_interval[25];
};
extern struct sdpstats sdpstats;

static inline void sdpstats_hist(u32 *h, u32 val, u32 maxidx, int is_log)
{
	int idx = is_log ? ilog2(val) : val;
	if (idx > maxidx)
		idx = maxidx;

	h[idx]++;
}

#define SDPSTATS_COUNTER_INC(stat) do {sdpstats.stat++;} while (0)
#define SDPSTATS_COUNTER_ADD(stat, val) do {sdpstats.stat+=val;} while (0)
#define SDPSTATS_COUNTER_MID_INC(stat, mid) do {sdpstats.stat[mid]++;} while (0)
#define SDPSTATS_HIST(stat, size) \
	sdpstats_hist(sdpstats.stat, size, ARRAY_SIZE(sdpstats.stat) - 1, 1)

#define SDPSTATS_HIST_LINEAR(stat, size) \
	sdpstats_hist(sdpstats.stat, size, ARRAY_SIZE(sdpstats.stat) - 1, 0)

#else
#define SDPSTATS_COUNTER_INC(stat)
#define SDPSTATS_COUNTER_ADD(stat, val)
#define SDPSTATS_COUNTER_MID_INC(stat, mid)
#define SDPSTATS_HIST_LINEAR(stat, size)
#define SDPSTATS_HIST(stat, size)
#endif

#define SOCK_REF_RESET "RESET"
#define SOCK_REF_BORN "BORN" /* sock_alloc -> destruct_sock */
#define SOCK_REF_CLONE "CLONE"
#define SOCK_REF_CM_TW "CM_TW" /* TIMEWAIT_ENTER -> TIMEWAIT_EXIT */
#define SOCK_REF_SEQ "SEQ" /* during proc read */
#define SOCK_REF_DREQ_TO "DREQ_TO" /* dreq timeout is pending */

#define sock_hold(sk, msg)  sock_ref(sk, msg, sock_hold)
#define sock_put(sk, msg)  sock_ref(sk, msg, sock_put)
#define __sock_put(sk, msg)  sock_ref(sk, msg, __sock_put)

#define SDP_RESOLVE_TIMEOUT 1000
#define SDP_ROUTE_TIMEOUT 1000
#define SDP_RETRY_COUNT 5
#define SDP_KEEPALIVE_TIME (120 * 60 * HZ)
#define SDP_FIN_WAIT_TIMEOUT (60 * HZ)

#define SDP_TX_SIZE 0x40
#define SDP_RX_SIZE 0x40

#define SDP_MAX_SEND_SKB_FRAGS (PAGE_SIZE > 0x8000 ? 1 : 0x8000 / PAGE_SIZE)
#define SDP_HEAD_SIZE (PAGE_SIZE / 2 + sizeof(struct sdp_bsdh))
#define SDP_NUM_WC 4
#define SDP_MAX_PAYLOAD ((1 << 16) - SDP_HEAD_SIZE)

#define SDP_MIN_ZCOPY_THRESH    1024
#define SDP_MAX_ZCOPY_THRESH 1048576

#define SDP_OP_RECV 0x800000000LL
#define SDP_OP_SEND 0x400000000LL

#define BZCOPY_STATE(skb) (*(struct bzcopy_state **)(skb->cb))
#ifndef MIN
#define MIN(a, b) (a < b ? a : b)
#endif

extern struct list_head sock_list;
extern spinlock_t sock_list_lock;

enum sdp_mid {
	SDP_MID_HELLO = 0x0,
	SDP_MID_HELLO_ACK = 0x1,
	SDP_MID_DISCONN = 0x2,
	SDP_MID_CHRCVBUF = 0xB,
	SDP_MID_CHRCVBUF_ACK = 0xC,
	SDP_MID_DATA = 0xFF,
};

enum sdp_flags {
        SDP_OOB_PRES = 1 << 0,
        SDP_OOB_PEND = 1 << 1,
};

enum {
	SDP_MIN_TX_CREDITS = 2
};

enum {
	SDP_ERR_ERROR   = -4,
	SDP_ERR_FAULT   = -3,
	SDP_NEW_SEG     = -2,
	SDP_DO_WAIT_MEM = -1
};

struct rdma_cm_id;
struct rdma_cm_event;

struct sdp_bsdh {
	u8 mid;
	u8 flags;
	__u16 bufs;
	__u32 len;
	__u32 mseq;
	__u32 mseq_ack;
};

union cma_ip_addr {
        struct in6_addr ip6;
        struct {
                __u32 pad[3];
                __u32 addr;
        } ip4;
};

/* TODO: too much? Can I avoid having the src/dst and port here? */
struct sdp_hh {
	struct sdp_bsdh bsdh;
	u8 majv_minv;
	u8 ipv_cap;
	u8 rsvd1;
	u8 max_adverts;
	__u32 desremrcvsz;
	__u32 localrcvsz;
	__u16 port;
	__u16 rsvd2;
	union cma_ip_addr src_addr;
	union cma_ip_addr dst_addr;
};

struct sdp_hah {
	struct sdp_bsdh bsdh;
	u8 majv_minv;
	u8 ipv_cap;
	u8 rsvd1;
	u8 ext_max_adverts;
	__u32 actrcvsz;
};

struct sdp_buf {
        struct sk_buff *skb;
        u64             mapping[SDP_MAX_SEND_SKB_FRAGS + 1];
};

struct sdp_sock {
	/* sk has to be the first member of inet_sock */
	struct inet_sock isk;
	struct list_head sock_list;
	struct list_head accept_queue;
	struct list_head backlog_queue;
	struct sock *parent;

	struct work_struct work;
	wait_queue_head_t wq;

	struct delayed_work dreq_wait_work;
	struct work_struct destroy_work;

	/* Like tcp_sock */
	u16 urg_data;
	u32 urg_seq;
	u32 copied_seq;
	u32 rcv_nxt;

	int write_seq;
	int snd_una;
	int pushed_seq;
	int xmit_size_goal;
	int nonagle;

	int dreq_wait_timeout;

	unsigned keepalive_time;

	spinlock_t lock;

	/* tx_head/rx_head when keepalive timer started */
	unsigned keepalive_tx_head;
	unsigned keepalive_rx_head;

	int destructed_already;
	int sdp_disconnect;
	int destruct_in_process;

	struct sdp_buf *rx_ring;
	struct sdp_buf   *tx_ring;

	/* rdma specific */
	struct ib_qp *qp;
	struct ib_cq *cq;
	struct ib_mr *mr;
	/* Data below will be reset on error */
	struct rdma_cm_id *id;
	struct ib_device *ib_device;

	/* SDP specific */
	struct ib_recv_wr rx_wr;
	unsigned rx_head;
	unsigned rx_tail;
	unsigned mseq_ack;
	unsigned tx_credits;
	unsigned max_bufs;	/* Initial buffers offered by other side */
	unsigned min_bufs;	/* Low water mark to wake senders */

	int               remote_credits;
	int 		  poll_cq;

	unsigned          tx_head;
	unsigned          tx_tail;
	struct ib_send_wr tx_wr;

	/* SDP slow start */
	int rcvbuf_scale; 	/* local recv buf scale for each socket */
	int sent_request_head; 	/* mark the tx_head of the last send resize
				   request */
	int sent_request; 	/* 0 - not sent yet, 1 - request pending
				   -1 - resize done succesfully */
	int recv_request_head; 	/* mark the rx_head when the resize request
				   was recieved */
	int recv_request; 	/* flag if request to resize was recieved */
	int recv_frags; 	/* max skb frags in recv packets */
	int send_frags; 	/* max skb frags in send packets */

	/* BZCOPY data */
	int   zcopy_thresh;

	struct ib_sge ibsge[SDP_MAX_SEND_SKB_FRAGS + 1];
	struct ib_wc  ibwc[SDP_NUM_WC];
};

/* Context used for synchronous zero copy bcopy (BZCOY) */
struct bzcopy_state {
	unsigned char __user  *u_base;
	int                    u_len;
	int                    left;
	int                    page_cnt;
	int                    cur_page;
	int                    cur_offset;
	int                    busy;
	struct sdp_sock      *ssk;
	struct page         **pages;
};

extern int rcvbuf_initial_size;

extern struct proto sdp_proto;
extern struct workqueue_struct *sdp_workqueue;

extern atomic_t sdp_current_mem_usage;
extern spinlock_t sdp_large_sockets_lock;

/* just like TCP fs */
struct sdp_seq_afinfo {
	struct module           *owner;
	char                    *name;
	sa_family_t             family;
	int                     (*seq_show) (struct seq_file *m, void *v);
	struct file_operations  *seq_fops;
};

struct sdp_iter_state {
	sa_family_t             family;
	int                     num;
	struct seq_operations   seq_ops;
};

static inline struct sdp_sock *sdp_sk(const struct sock *sk)
{
	        return (struct sdp_sock *)sk;
}

static inline char *sdp_state_str(int state)
{
	static char *state_str[] = {
		[TCP_ESTABLISHED] = "TCP_ESTABLISHED",
		[TCP_SYN_SENT] = "TCP_SYN_SENT",
		[TCP_SYN_RECV] = "TCP_SYN_RECV",
		[TCP_FIN_WAIT1] = "TCP_FIN_WAIT1",
		[TCP_FIN_WAIT2] = "TCP_FIN_WAIT2",
		[TCP_TIME_WAIT] = "TCP_TIME_WAIT",
		[TCP_CLOSE] = "TCP_CLOSE",
		[TCP_CLOSE_WAIT] = "TCP_CLOSE_WAIT",
		[TCP_LAST_ACK] = "TCP_LAST_ACK",
		[TCP_LISTEN] = "TCP_LISTEN",
		[TCP_CLOSING] = "TCP_CLOSING",
	};

	if (state < 0 || state >= TCP_MAX_STATES)
		return "unknown";

	return state_str[state];
}

static inline int _sdp_exch_state(const char *func, int line, struct sock *sk,
				 int from_states, int state)
{
	unsigned long flags;
	int old;

	spin_lock_irqsave(&sdp_sk(sk)->lock, flags);
	
	sdp_dbg(sk, "%s:%d - set state: %s -> %s 0x%x\n", func, line,
		sdp_state_str(sk->sk_state), sdp_state_str(state), from_states);

	if ((1 << sk->sk_state) & ~from_states) {
		sdp_warn(sk, "trying to exchange state from unexpected state "
			"%s to state %s. expected states: 0x%x\n",
			sdp_state_str(sk->sk_state), sdp_state_str(state),
			from_states);
	}

	old = sk->sk_state;
	sk->sk_state = state;

	spin_unlock_irqrestore(&sdp_sk(sk)->lock, flags);

	return old;
}
#define sdp_exch_state(sk, from_states, state) \
	_sdp_exch_state(__func__, __LINE__, sk, from_states, state)

static inline void sdp_set_error(struct sock *sk, int err)
{
	int ib_teardown_states = TCPF_FIN_WAIT1 | TCPF_CLOSE_WAIT
		| TCPF_LAST_ACK;
	sk->sk_err = -err;
	if (sk->sk_socket)
		sk->sk_socket->state = SS_DISCONNECTING;

	if ((1 << sk->sk_state) & ib_teardown_states)
		sdp_exch_state(sk, ib_teardown_states, TCP_TIME_WAIT);
	else
		sdp_exch_state(sk, ~0, TCP_CLOSE);

	sk->sk_error_report(sk);
}

extern struct workqueue_struct *sdp_workqueue;

#ifdef CONFIG_INFINIBAND_SDP_DEBUG_DATA
void dump_packet(struct sock *sk, char *str, struct sk_buff *skb, const struct sdp_bsdh *h);
#endif
int sdp_cma_handler(struct rdma_cm_id *, struct rdma_cm_event *);
void sdp_reset(struct sock *sk);
void sdp_reset_sk(struct sock *sk, int rc);
void sdp_completion_handler(struct ib_cq *cq, void *cq_context);
void sdp_work(struct work_struct *work);
int sdp_post_credits(struct sdp_sock *ssk);
void sdp_post_send(struct sdp_sock *ssk, struct sk_buff *skb, u8 mid);
void sdp_post_recvs(struct sdp_sock *ssk);
int sdp_poll_cq(struct sdp_sock *ssk, struct ib_cq *cq);
void sdp_post_sends(struct sdp_sock *ssk, int nonagle);
void sdp_destroy_work(struct work_struct *work);
void sdp_cancel_dreq_wait_timeout(struct sdp_sock *ssk);
void sdp_dreq_wait_timeout_work(struct work_struct *work);
struct sk_buff *sdp_recv_completion(struct sdp_sock *ssk, int id);
struct sk_buff *sdp_send_completion(struct sdp_sock *ssk, int mseq);
void sdp_urg(struct sdp_sock *ssk, struct sk_buff *skb);
void sdp_add_sock(struct sdp_sock *ssk);
void sdp_remove_sock(struct sdp_sock *ssk);
void sdp_remove_large_sock(struct sdp_sock *ssk);
int sdp_resize_buffers(struct sdp_sock *ssk, u32 new_size);
int sdp_init_buffers(struct sdp_sock *ssk, u32 new_size);
void sdp_post_keepalive(struct sdp_sock *ssk);
void sdp_start_keepalive_timer(struct sock *sk);
void sdp_bzcopy_write_space(struct sdp_sock *ssk);
int sdp_init_sock(struct sock *sk);
int __init sdp_proc_init(void);
void sdp_proc_unregister(void);

static inline struct sk_buff *sdp_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp)
{
	struct sk_buff *skb;

	/* The TCP header must be at least 32-bit aligned.  */
	size = ALIGN(size, 4);

	skb = alloc_skb_fclone(size + sk->sk_prot->max_header, gfp);
	if (skb) {
		if (sk_wmem_schedule(sk, skb->truesize)) {
			/*
			 * Make sure that we have exactly size bytes
			 * available to the caller, no more, no less.
			 */
			skb_reserve(skb, skb_tailroom(skb) - size);
			return skb;
		}
		__kfree_skb(skb);
	} else {
		sk->sk_prot->enter_memory_pressure(sk);
		sk_stream_moderate_sndbuf(sk);
	}
	return NULL;
}


#endif
