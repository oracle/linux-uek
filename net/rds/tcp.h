#ifndef _RDS_TCP_H
#define _RDS_TCP_H

/* Per-network namespace private data for rds_tcp module */
struct rds_tcp_net {
	/* serialize "rds_tcp_accept_one" with "rds_tcp_accept_lock"
	 * to protect "rds_tcp_accepted_sock"
	 */
	struct mutex		rds_tcp_accept_lock;
	struct socket		*rds_tcp_listen_sock;
	struct socket		*rds_tcp_accepted_sock;

	struct workqueue_struct	*rds_tcp_accept_wq;
	struct work_struct	rds_tcp_accept_w;

	struct ctl_table_header	*rds_tcp_sysctl;
	struct ctl_table	*ctl_table;

	int			sndbuf_size;
	int			rcvbuf_size;

	/* only for info exporting */
	spinlock_t		rds_tcp_tc_list_lock;
	struct list_head	rds_tcp_tc_list;

	/* rds_tcp_tc_count counts only IPv4 connections.
	 * rds6_tcp_tc_count counts both IPv4 and IPv6 connections.
	 */
	unsigned int		rds_tcp_tc_count;
#if IS_ENABLED(CONFIG_IPV6)
	unsigned int		rds6_tcp_tc_count;
#endif

	/* Track rds_tcp_connection structs so they can be cleaned up */
	spinlock_t		rds_tcp_conn_lock;
	struct list_head	rds_tcp_conn_list;
};

struct rds_tcp_incoming {
	struct rds_incoming	ti_inc;
	struct sk_buff_head	ti_skb_list;
};

struct rds_tcp_statistics {
	u64	s_tcp_data_ready_calls;
	u64	s_tcp_write_space_calls;
	u64	s_tcp_sndbuf_full;
	u64	s_tcp_connect_raced;
	u64	s_tcp_listen_closed_stale;
	u64	s_tcp_ka_timeout;
};

struct rds_tcp_connection {

	struct list_head	t_tcp_node;
	struct rds_conn_path    *t_cpath;
	/* t_conn_path_lock synchronizes the connection establishment between
	 * rds_tcp_accept_one and rds_tcp_conn_path_connect
	 */
	struct mutex		t_conn_path_lock;
	struct socket		*t_sock;
	u32			t_client_port_group;
	struct rds_tcp_net	*t_rtn;
	void			*t_orig_write_space;
	void			*t_orig_data_ready;
	void			*t_orig_state_change;

	struct rds_tcp_incoming	*t_tinc;
	size_t			t_tinc_hdr_rem;
	size_t			t_tinc_data_rem;

	struct work_struct	t_fan_out_w;

	/* for info exporting only */
	struct list_head	t_list_item;
	u32			t_last_sent_nxt;
	u32			t_last_expected_una;
	u32			t_last_seen_una;

	/* for rds_tcp_conn_path_shutdown */
	wait_queue_head_t	t_recv_done_waitq;

	struct rds_tcp_statistics __percpu	*t_stats;
};

/* tcp.c */
extern int rds_tcp_netid;
bool rds_tcp_tune(struct socket *sock);
void rds_tcp_set_callbacks(struct socket *sock, struct rds_conn_path *cp,
			   struct rds_tcp_net *rtn);
void rds_tcp_reset_callbacks(struct socket *sock, struct rds_conn_path *cp,
			     struct rds_tcp_net *rtn);
void rds_tcp_restore_callbacks(struct socket *sock,
			       struct rds_tcp_connection *tc,
			       struct rds_tcp_net *rtn);
u32 rds_tcp_write_seq(struct rds_tcp_connection *tc);
u32 rds_tcp_snd_una(struct rds_tcp_connection *tc);
u64 rds_tcp_map_seq(struct rds_tcp_connection *tc, u32 seq);
extern struct rds_transport rds_tcp_transport;
void rds_tcp_accept_work(struct rds_tcp_net *rtn);
int rds_tcp_laddr_check(struct net *net, const struct in6_addr *addr,
			__u32 scope_id);
/* tcp_connect.c */
int rds_tcp_conn_path_connect(struct rds_conn_path *cp);
void rds_tcp_conn_path_shutdown(struct rds_conn_path *cp);
void rds_tcp_state_change(struct sock *sk);

/* tcp_listen.c */
struct socket *rds_tcp_listen_init(struct net *net, bool isv6);
void rds_tcp_listen_stop(struct socket *sock, struct work_struct *acceptor);
void rds_tcp_listen_data_ready(struct sock *sk);
void rds_tcp_fan_out_w(struct work_struct *work);
void rds_tcp_conn_slots_available(struct rds_connection *conn, bool fan_out);
int rds_tcp_accept_one(struct rds_tcp_net *rtn);
int rds_tcp_keepalive(struct socket *sock);
void *rds_tcp_listen_sock_def_readable(struct net *net);
void rds_tcp_set_linger(struct socket *sock);

/* tcp_recv.c */
int rds_tcp_recv_init(void);
void rds_tcp_recv_exit(void);
void rds_tcp_data_ready(struct sock *sk);
int rds_tcp_recv_path(struct rds_conn_path *cp);
int rds_tcp_recv_path_lock(struct rds_conn_path *cp);
void rds_tcp_inc_free(struct rds_incoming *inc);
int rds_tcp_inc_copy_to_user(struct rds_sock *rs, struct rds_incoming *inc,
			     struct iov_iter *to);


/* tcp_send.c */
void rds_tcp_xmit_path_prepare(struct rds_conn_path *cp);
void rds_tcp_xmit_path_complete(struct rds_conn_path *cp);
int rds_tcp_xmit(struct rds_connection *conn, struct rds_message *rm,
	         unsigned int hdr_off, unsigned int sg, unsigned int off);
int rds_tcp_is_acked(struct rds_message *rm, uint64_t ack);
void rds_tcp_write_space(struct sock *sk);

/* tcp_stats.c */
DECLARE_PER_CPU(struct rds_tcp_statistics, rds_tcp_stats);
#define rds_tcp_stats_inc(stats, member) rds_stats_inc_which(stats, member)
unsigned int rds_tcp_stats_info_copy(struct rds_info_iterator *iter,
				     unsigned int avail);
int rds_tcp_stats_net_init(struct net *net);
void rds_tcp_stats_net_exit(struct net *net);


#endif
