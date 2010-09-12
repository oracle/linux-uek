#ifndef _SDP_DBG_H_
#define _SDP_DBG_H_

#define SDPSTATS_ON

#ifdef CONFIG_INFINIBAND_SDP_DEBUG_DATA
#define SDP_PROFILING
#endif
//#define GETNSTIMEODAY_SUPPORTED

#define SDP_WARN_ON(x) WARN_ON(x)

#define _sdp_printk(func, line, level, sk, format, arg...) do {               \
	preempt_disable(); \
	printk(level "%s:%d sdp_sock(%5d:%d %d:%d): " format,             \
	       func, line, \
	       current->pid, smp_processor_id(), \
	       (sk) ? inet_sk(sk)->num : -1,                 \
	       (sk) ? ntohs(inet_sk(sk)->dport) : -1, ## arg); \
	preempt_enable(); \
} while (0)
#define sdp_printk(level, sk, format, arg...)                \
	_sdp_printk(__func__, __LINE__, level, sk, format, ## arg)
#define sdp_warn(sk, format, arg...)					\
	do {								\
		sdp_printk(KERN_WARNING, sk, format, ## arg); \
		sdp_prf(sk, NULL, format , ## arg);			\
	} while (0)

#define SDP_MODPARAM_SINT(var, def_val, msg) \
	static int var = def_val; \
	module_param_named(var, var, int, 0644); \
	MODULE_PARM_DESC(var, msg " [" #def_val "]"); \

#define SDP_MODPARAM_INT(var, def_val, msg) \
	int var = def_val; \
	module_param_named(var, var, int, 0644); \
	MODULE_PARM_DESC(var, msg " [" #def_val "]"); \

#ifdef SDP_PROFILING
struct sk_buff;
struct sdpprf_log {
	int 		idx;
	int 		pid;
	int 		cpu;
	int 		sk_num;
	int 		sk_dport;
	struct sk_buff 	*skb;
	char		msg[256];

	unsigned long long time;

	const char 	*func;
	int 		line;
};

#define SDPPRF_LOG_SIZE 0x20000 /* must be a power of 2 */

extern struct sdpprf_log sdpprf_log[SDPPRF_LOG_SIZE];
extern int sdpprf_log_count;

#ifdef GETNSTIMEODAY_SUPPORTED
static inline unsigned long long current_nsec(void)
{
	struct timespec tv;
	getnstimeofday(&tv);
	return tv.tv_sec * NSEC_PER_SEC + tv.tv_nsec;
}
#else
#define current_nsec() jiffies_to_usecs(jiffies)
#endif

#define _sdp_prf(sk, s, _func, _line, format, arg...) ({ \
	struct sdpprf_log *l = \
		&sdpprf_log[sdpprf_log_count++ & (SDPPRF_LOG_SIZE - 1)]; \
	preempt_disable(); \
	l->idx = sdpprf_log_count - 1; \
	l->pid = current->pid; \
	l->sk_num = (sk) ? inet_sk(sk)->num : -1;                 \
	l->sk_dport = (sk) ? ntohs(inet_sk(sk)->dport) : -1; \
	l->cpu = smp_processor_id(); \
	l->skb = s; \
	snprintf(l->msg, sizeof(l->msg) - 1, format, ## arg); \
	l->time = current_nsec(); \
	l->func = _func; \
	l->line = _line; \
	preempt_enable(); \
	1; \
})
#define sdp_prf1(sk, s, format, arg...)	\
	_sdp_prf(sk, s, __func__, __LINE__, format, ## arg)
#define sdp_prf(sk, s, format, arg...) sdp_prf1(sk, s, format, ## arg)

#else
#define _sdp_prf(sk, s, _func, _line, format, arg...)
#define sdp_prf1(sk, s, format, arg...)
#define sdp_prf(sk, s, format, arg...)
#endif

#ifdef CONFIG_INFINIBAND_SDP_DEBUG
extern int sdp_debug_level;

#define sdp_dbg(sk, format, arg...)					\
	do {								\
		if (sdp_debug_level > 0)				\
			sdp_printk(KERN_WARNING, sk, format , ## arg);	\
		sdp_prf(sk, NULL, format , ## arg);			\
	} while (0)

#define sock_ref(sk, msg, sock_op) ({ \
	if (!atomic_read(&(sk)->sk_refcnt)) {\
		sdp_warn(sk, "%s:%d - %s (%s) ref = 0.\n", \
				 __func__, __LINE__, #sock_op, msg); \
		SDP_WARN_ON(1); \
	} else { \
		sdp_dbg(sk, "%s:%d - %s (%s) ref = %d.\n", __func__, __LINE__, \
			#sock_op, msg, atomic_read(&(sk)->sk_refcnt)); \
		sock_op(sk); \
	}\
})

#else /* CONFIG_INFINIBAND_SDP_DEBUG */
#define sdp_dbg(priv, format, arg...)                        \
	do { (void) (priv); } while (0)
#define sock_ref(sk, msg, sock_op) sock_op(sk)
#endif /* CONFIG_INFINIBAND_SDP_DEBUG */

#ifdef CONFIG_INFINIBAND_SDP_DEBUG_DATA

extern int sdp_data_debug_level;
#define sdp_dbg_data(sk, format, arg...)				\
	do {								\
		if (sdp_data_debug_level & 0x2)				\
			sdp_printk(KERN_WARNING, sk, format , ## arg);	\
		sdp_prf(sk, NULL, format , ## arg);			\
	} while (0)
#define SDP_DUMP_PACKET(sk, str, skb, h)                     		\
	do {                                                 		\
		if (sdp_data_debug_level & 0x1)				\
			dump_packet(sk, str, skb, h);			\
	} while (0)
#else
#define sdp_dbg_data(priv, format, arg...)
#define SDP_DUMP_PACKET(sk, str, skb, h)
#endif

#define SOCK_REF_RESET "RESET"
#define SOCK_REF_ALIVE "ALIVE" /* sock_alloc -> destruct_sock */
#define SOCK_REF_CLONE "CLONE"
#define SOCK_REF_CMA "CMA" /* sdp_cma_handler() is expected to be invoked */
#define SOCK_REF_SEQ "SEQ" /* during proc read */
#define SOCK_REF_DREQ_TO "DREQ_TO" /* dreq timeout is pending */
#define SOCK_REF_ZCOPY "ZCOPY" /* zcopy send in process */
#define SOCK_REF_RDMA_RD "RDMA_RD" /* RDMA read in process */
#define SOCK_REF_KEEPALIVE "KEEPALIVE" /* socket is held by sk_reset_timer */

#define sock_hold(sk, msg)  sock_ref(sk, msg, sock_hold)
#define sock_put(sk, msg)  sock_ref(sk, msg, sock_put)
#define __sock_put(sk, msg)  sock_ref(sk, msg, __sock_put)

#define ENUM2STR(e) [e] = #e

static inline char *sdp_state_str(int state)
{
	static char *state2str[] = {
		ENUM2STR(TCP_ESTABLISHED),
		ENUM2STR(TCP_SYN_SENT),
		ENUM2STR(TCP_SYN_RECV),
		ENUM2STR(TCP_FIN_WAIT1),
		ENUM2STR(TCP_FIN_WAIT2),
		ENUM2STR(TCP_TIME_WAIT),
		ENUM2STR(TCP_CLOSE),
		ENUM2STR(TCP_CLOSE_WAIT),
		ENUM2STR(TCP_LAST_ACK),
		ENUM2STR(TCP_LISTEN),
		ENUM2STR(TCP_CLOSING),
	};

	if (state < 0 || state >= ARRAY_SIZE(state2str))
		return "unknown";

	return state2str[state];
}

static inline const char* rdma_cm_event_str(int event)
{
	static const char* state2str[] = {
		ENUM2STR(RDMA_CM_EVENT_ADDR_RESOLVED),
		ENUM2STR(RDMA_CM_EVENT_ADDR_ERROR),
		ENUM2STR(RDMA_CM_EVENT_ROUTE_RESOLVED),
		ENUM2STR(RDMA_CM_EVENT_ROUTE_ERROR),
		ENUM2STR(RDMA_CM_EVENT_CONNECT_REQUEST),
		ENUM2STR(RDMA_CM_EVENT_CONNECT_RESPONSE),
		ENUM2STR(RDMA_CM_EVENT_CONNECT_ERROR),
		ENUM2STR(RDMA_CM_EVENT_UNREACHABLE),
		ENUM2STR(RDMA_CM_EVENT_REJECTED),
		ENUM2STR(RDMA_CM_EVENT_ESTABLISHED),
		ENUM2STR(RDMA_CM_EVENT_DISCONNECTED),
		ENUM2STR(RDMA_CM_EVENT_DEVICE_REMOVAL),
		ENUM2STR(RDMA_CM_EVENT_MULTICAST_JOIN),
		ENUM2STR(RDMA_CM_EVENT_MULTICAST_ERROR),
		ENUM2STR(RDMA_CM_EVENT_ADDR_CHANGE),
		ENUM2STR(RDMA_CM_EVENT_TIMEWAIT_EXIT)
	};
	if (event < 0 || event >= ARRAY_SIZE(state2str))
		return "unknown";

	return state2str[event];

}

struct sdp_bsdh;
#ifdef CONFIG_INFINIBAND_SDP_DEBUG_DATA
void _dump_packet(const char *func, int line, struct sock *sk, char *str,
		struct sk_buff *skb, const struct sdp_bsdh *h);
#define dump_packet(sk, str, skb, h) \
	_dump_packet(__func__, __LINE__, sk, str, skb, h)
#endif

#endif
