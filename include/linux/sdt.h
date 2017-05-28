/* Copyright (C) 2011 -- 2016 Oracle, Inc. */

#ifndef _LINUX_SDT_H_
#define	_LINUX_SDT_H_

#include <linux/sdt_internal.h>

#ifdef CONFIG_DTRACE

#include <asm/dtrace_sdt_arch.h>
#include <linux/stringify.h>

#define	DTRACE_PROBE(name, ...)	{				\
	extern void __dtrace_probe_##name(__DTRACE_TYPE_APPLY_DEFAULT(__DTRACE_UINTPTR_EACH, void, ## __VA_ARGS__)); \
	__dtrace_probe_##name(__DTRACE_ARG_APPLY(__DTRACE_UINTCAST_EACH, ## __VA_ARGS__)); \
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n" \
		     ".ascii \"" __stringify(name) "\"\n"		\
		     ".byte 0\n"					\
		     ".popsection\n"					\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n" \
		     __DTRACE_TYPE_APPLY_NOCOMMA(__DTRACE_TYPE_EACH, ## __VA_ARGS__) \
		     ".byte 0\n"					\
		     ".popsection\n");					\
}

#define	DTRACE_PROBE_ENABLED(name)	unlikely(({			\
	extern int __dtrace_isenabled_##name(__DTRACE_SDT_ISENABLED_PROTO); \
	__dtrace_isenabled_##name(__DTRACE_SDT_ISENABLED_ARGS);		\
}))

#ifdef CONFIG_DT_SDT_PERF

#define __DTRACE_UINTPTR_CAST_EACH(x) ({				\
  union {								\
    typeof((x)) __val;							\
    unsigned char __c;							\
    unsigned short __s;							\
    unsigned int __i;							\
    unsigned long __l;							\
    unsigned long long __ll; } __u = { .__val = (x) };			\
  __builtin_choose_expr(sizeof(__u.__val) == sizeof(__u.__c), __u.__c,	\
  __builtin_choose_expr(sizeof(__u.__val) == sizeof(__u.__s), __u.__s, 	\
  __builtin_choose_expr(sizeof(__u.__val) == sizeof(__u.__i), __u.__i, 	\
  __builtin_choose_expr(sizeof(__u.__val) == sizeof(__u.__l), __u.__l, 	\
  __builtin_choose_expr(sizeof(__u.__val) == sizeof(__u.__ll), __u.__ll,\
  (uintptr_t)&(__u.__val))))));})

#define DTRACE_PROBE_TRACEPOINT(name, ...) {				\
	extern void __dtrace_probe___perf_##name(__DTRACE_APPLY(__DTRACE_UINTPTR_EACH, ## __VA_ARGS__)); \
	__dtrace_probe___perf_##name(__DTRACE_APPLY(__DTRACE_UINTPTR_CAST_EACH, ## __VA_ARGS__));	\
}

#define DTRACE_PROTO_TRACEPOINT(name, ...) {				\
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n"\
		     ".ascii \"" __stringify(__perf_##name) "\"\n"	\
		     ".byte 0\n"					\
		     ".popsection\n"					\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n" \
		     ".ascii \"" __stringify(__VA_ARGS__) "\"\n"	\
		     ".byte 0\n"					\
		     ".popsection\n");					\
}
#else

#define DTRACE_PROBE_TRACEPOINT(name, ...)
#define DTRACE_PROTO_TRACEPOINT(name, ...)

#endif

typedef struct sdt_probedesc {
	char			*sdpd_name;	/* probe name */
	char			*sdpd_func;	/* probe function */
#ifndef __GENKSYMS__
	const char		*sdpd_args;	/* arg string */
#endif
	unsigned long		sdpd_offset;	/* offset of call in text */
	struct sdt_probedesc	*sdpd_next;	/* next static probe */
} sdt_probedesc_t;

#else /* ! CONFIG_DTRACE */

/*
 * This apparently redundant call serves to validate the DTRACE_PROBE has the
 * right number of args even when dtrace is turned off.
 */
#define	DTRACE_PROBE(name, ...)						\
	__DTRACE_DOUBLE_APPLY_NOCOMMA(__DTRACE_NONE, __DTRACE_NONE, ## __VA_ARGS__)	\
	do { } while (0)
#define	DTRACE_PROBE_ENABLED(name) 0
#define DTRACE_PROBE_TRACEPOINT(name, ...)
#define DTRACE_PROTO_TRACEPOINT(name, ...)

#endif /* CONFIG_DTRACE */

#define	DTRACE_SCHED(name, ...)						\
	DTRACE_PROBE(__sched_##name, ## __VA_ARGS__);

#define	DTRACE_PROC(name, ...)						\
	DTRACE_PROBE(__proc_##name, ## __VA_ARGS__);

#define	DTRACE_IO(name, ...)						\
	DTRACE_PROBE(__io_##name, ## __VA_ARGS__);

#define	DTRACE_ISCSI(name, ...)						\
	DTRACE_PROBE(__iscsi_##name, ## __VA_ARGS__);

#define	DTRACE_NFSV3(name, ...)						\
	DTRACE_PROBE(__nfsv3_##name, ## __VA_ARGS__);

#define	DTRACE_NFSV4(name, ...)						\
	DTRACE_PROBE(__nfsv4_##name, ## __VA_ARGS__);

#define	DTRACE_SMB(name, ...)						\
	DTRACE_PROBE(__smb_##name, ## __VA_ARGS__);

/*
 * These definitions are used at probe points to specify the traffic direction;
 * this helps simplify argument translation.
 */
#define	DTRACE_NET_PROBE_OUTBOUND	0x0
#define	DTRACE_NET_PROBE_INBOUND	0x1

#define	DTRACE_IP(name, ...)						\
	DTRACE_PROBE(__ip_##name, ## __VA_ARGS__);

/*
 * Default DTRACE_TCP() and DTRACE_UDP() provider definitions specify the
 * probe point within an is-enabled predicate.  This is to avoid the overhead
 * incurred during argument dereferencing (e.g. calls to ip_hdr(skb)), along
 * with any conditional evaluation (which would require branching) when the
 * probe is disabled.
 *
 * Because some TCP probe points require additional argument preparation,
 * we also define the is-enabled predicate directly as
 * DTRACE_TCP_ENABLED(probename) along with a probe point which does not
 * the probe in an is-enabled predicate; this allows us to handle cases such
 * as this:
 *
 * if (DTRACE_TCP_ENABLED(state__change)) {
 *      ...argument preparation...
 *      DTRACE_TCP_NOCHECK(state__change, ...);
 * }
 */

#define	DTRACE_TCP(name, ...)						\
	if (DTRACE_PROBE_ENABLED(__tcp_##name))				\
		DTRACE_PROBE(__tcp_##name, ## __VA_ARGS__)
#define	DTRACE_TCP_ENABLED(name)					\
	DTRACE_PROBE_ENABLED(__tcp_##name)
#define	DTRACE_TCP_NOCHECK(name, ...)					\
	DTRACE_PROBE(__tcp_##name, ## __VA_ARGS__);

#define	DTRACE_UDP(name, ...)						\
	if (DTRACE_PROBE_ENABLED(__udp_##name))				\
		DTRACE_PROBE(__udp_##name, ## __VA_ARGS__);

#define	DTRACE_SYSEVENT(name, ...)					\
	DTRACE_PROBE(__sysevent_##name, ## __VA_ARGS__);

#define	DTRACE_XPV(name, ...)						\
	DTRACE_PROBE(__xpv_##name, ## __VA_ARGS__);

#define	DTRACE_FC(name, ...)						\
	DTRACE_PROBE(__fc_##name, ## __VA_ARGS__);

#define	DTRACE_SRP(name, ...)						\
	DTRACE_PROBE(__srp_##name, ## __VA_ARGS__);

#endif	/* _LINUX_SDT_H_ */
