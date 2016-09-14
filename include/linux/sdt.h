/* Copyright (C) 2011-2014 Oracle, Inc. */

#ifndef _LINUX_SDT_H_
#define	_LINUX_SDT_H_

#ifdef CONFIG_DTRACE

#ifndef __KERNEL__

#ifdef __cplusplus
extern "C" {
#endif

#define	DTRACE_PROBE(provider, name) {					\
	extern void __dtrace_##provider##___##name(void);		\
	__dtrace_##provider##___##name();				\
}

#define	DTRACE_PROBE1(provider, name, arg1) {				\
	extern void __dtrace_##provider##___##name(unsigned long);	\
	__dtrace_##provider##___##name((unsigned long)arg1);		\
}

#define	DTRACE_PROBE2(provider, name, arg1, arg2) {			\
	extern void __dtrace_##provider##___##name(unsigned long,	\
	    unsigned long);						\
	__dtrace_##provider##___##name((unsigned long)arg1,		\
	    (unsigned long)arg2);					\
}

#define	DTRACE_PROBE3(provider, name, arg1, arg2, arg3) {		\
	extern void __dtrace_##provider##___##name(unsigned long,	\
	    unsigned long, unsigned long);				\
	__dtrace_##provider##___##name((unsigned long)arg1,		\
	    (unsigned long)arg2, (unsigned long)arg3);			\
}

#define	DTRACE_PROBE4(provider, name, arg1, arg2, arg3, arg4) {		\
	extern void __dtrace_##provider##___##name(unsigned long,	\
	    unsigned long, unsigned long, unsigned long);		\
	__dtrace_##provider##___##name((unsigned long)arg1,		\
	    (unsigned long)arg2, (unsigned long)arg3,			\
	    (unsigned long)arg4);					\
}

#define	DTRACE_PROBE5(provider, name, arg1, arg2, arg3, arg4, arg5) {	\
	extern void __dtrace_##provider##___##name(unsigned long,	\
	    unsigned long, unsigned long, unsigned long, unsigned long);\
	__dtrace_##provider##___##name((unsigned long)arg1,		\
	    (unsigned long)arg2, (unsigned long)arg3,			\
	    (unsigned long)arg4, (unsigned long)arg5);			\
}

#ifdef	__cplusplus
}
#endif

#else /* __KERNEL__ */

#include <linux/stringify.h>

#define PROBENAME_STR(str) ".ascii \"" __stringify(str) "\"\n"
#define ARG_STR(str) ".ascii \"" __stringify(str) ",\"\n"

#define	DTRACE_PROBE(name)	{					\
	extern void __dtrace_probe_##name(void);			\
	__dtrace_probe_##name();					\
}

#define	DTRACE_PROBE1(name, type1, arg1)	{			\
	extern void __dtrace_probe_##name(uintptr_t);			\
	__dtrace_probe_##name((uintptr_t)(arg1));			\
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n" \
		     PROBENAME_STR(name)				\
		     ".byte 0\n"					\
		     ".popsection\n"					\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n" \
		     ARG_STR(type1)					\
		     ".byte 0\n"					\
		     ".popsection\n"); 					\
}

#define	DTRACE_PROBE2(name, type1, arg1, type2, arg2)	{		\
	extern void __dtrace_probe_##name(uintptr_t, uintptr_t);	\
	__dtrace_probe_##name((uintptr_t)(arg1), (uintptr_t)(arg2));	\
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n" \
		     PROBENAME_STR(name)				\
		     ".byte 0\n"					\
		     ".popsection\n"					\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n" \
		     ARG_STR(type1)					\
		     ARG_STR(type2)					\
		     ".byte 0\n"					\
		     ".popsection\n"); 					\
}

#define	DTRACE_PROBE3(name, type1, arg1, type2, arg2, type3, arg3) {	\
	extern void __dtrace_probe_##name(uintptr_t, uintptr_t, uintptr_t); \
	__dtrace_probe_##name((uintptr_t)(arg1), (uintptr_t)(arg2),	\
	    (uintptr_t)(arg3));						\
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n" \
		     PROBENAME_STR(name)				\
		     ".byte 0\n"					\
		     ".popsection\n"					\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n" \
		     ARG_STR(type1)					\
		     ARG_STR(type2)					\
		     ARG_STR(type3)					\
		     ".byte 0\n"					\
		     ".popsection\n"); 					\
}

#define	DTRACE_PROBE4(name, type1, arg1, type2, arg2, 			\
	type3, arg3, type4, arg4) {					\
	extern void __dtrace_probe_##name(uintptr_t, uintptr_t,		\
	    uintptr_t, uintptr_t);					\
	__dtrace_probe_##name((uintptr_t)(arg1), (uintptr_t)(arg2),	\
	    (uintptr_t)(arg3), (uintptr_t)(arg4));			\
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n" \
		     PROBENAME_STR(name)				\
		     ".byte 0\n"					\
		     ".popsection\n"					\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n" \
		     ARG_STR(type1)					\
		     ARG_STR(type2)					\
		     ARG_STR(type3)					\
		     ARG_STR(type4)					\
		     ".byte 0\n"					\
		     ".popsection\n"); 					\
}

#define	DTRACE_PROBE5(name, type1, arg1, type2, arg2, 			\
	type3, arg3, type4, arg4, type5, arg5) {			\
	extern void __dtrace_probe_##name(uintptr_t, uintptr_t,		\
	    uintptr_t, uintptr_t, uintptr_t);				\
	__dtrace_probe_##name((uintptr_t)(arg1), (uintptr_t)(arg2),	\
	    (uintptr_t)(arg3), (uintptr_t)(arg4), (uintptr_t)(arg5));	\
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n" \
		     PROBENAME_STR(name)				\
		     ".byte 0\n"					\
		     ".popsection\n"					\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n" \
		     ARG_STR(type1)					\
		     ARG_STR(type2)					\
		     ARG_STR(type3)					\
		     ARG_STR(type4)					\
		     ARG_STR(type5)					\
		     ".byte 0\n"					\
		     ".popsection\n"); 					\
}

#define	DTRACE_PROBE6(name, type1, arg1, type2, arg2, 			\
	type3, arg3, type4, arg4, type5, arg5, type6, arg6) {		\
	extern void __dtrace_probe_##name(uintptr_t, uintptr_t,		\
	    uintptr_t, uintptr_t, uintptr_t, uintptr_t);		\
	__dtrace_probe_##name((uintptr_t)(arg1), (uintptr_t)(arg2),	\
	    (uintptr_t)(arg3), (uintptr_t)(arg4), (uintptr_t)(arg5),	\
	    (uintptr_t)(arg6));						\
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n" \
		     PROBENAME_STR(name)				\
		     ".byte 0\n"					\
		     ".popsection\n"					\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n" \
		     ARG_STR(type1)					\
		     ARG_STR(type2)					\
		     ARG_STR(type3)					\
		     ARG_STR(type4)					\
		     ARG_STR(type5)					\
		     ARG_STR(type6)					\
		     ".byte 0\n"					\
		     ".popsection\n"); 					\
}

#define	DTRACE_PROBE7(name, type1, arg1, type2, arg2, type3, arg3,	\
	type4, arg4, type5, arg5, type6, arg6, type7, arg7) {		\
	extern void __dtrace_probe_##name(uintptr_t, uintptr_t,		\
	    uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);	\
	__dtrace_probe_##name((uintptr_t)(arg1), (uintptr_t)(arg2),	\
	    (uintptr_t)(arg3), (uintptr_t)(arg4), (uintptr_t)(arg5),	\
	    (uintptr_t)(arg6), (uintptr_t)(arg7));			\
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n" \
		     PROBENAME_STR(name)				\
		     ".byte 0\n"					\
		     ".popsection\n"					\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n" \
		     ARG_STR(type1)					\
		     ARG_STR(type2)					\
		     ARG_STR(type3)					\
		     ARG_STR(type4)					\
		     ARG_STR(type5)					\
		     ARG_STR(type6)					\
		     ARG_STR(type7)					\
		     ".byte 0\n"					\
		     ".popsection\n"); 					\
}

#define	DTRACE_PROBE8(name, type1, arg1, type2, arg2, type3, arg3,	\
	type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8) { \
	extern void __dtrace_probe_##name(uintptr_t, uintptr_t,		\
	    uintptr_t, uintptr_t, uintptr_t, uintptr_t,			\
	    uintptr_t, uintptr_t);					\
	__dtrace_probe_##name((uintptr_t)(arg1), (uintptr_t)(arg2),	\
	    (uintptr_t)(arg3), (uintptr_t)(arg4), (uintptr_t)(arg5),	\
	    (uintptr_t)(arg6), (uintptr_t)(arg7), (uintptr_t)(arg8));	\
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n" \
		     PROBENAME_STR(name)				\
		     ".byte 0\n"					\
		     ".popsection\n"					\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n" \
		     ARG_STR(type1)					\
		     ARG_STR(type2)					\
		     ARG_STR(type3)					\
		     ARG_STR(type4)					\
		     ARG_STR(type5)					\
		     ARG_STR(type6)					\
		     ARG_STR(type7)					\
		     ARG_STR(type8)					\
		     ".byte 0\n"					\
		     ".popsection\n"); 					\
}

#ifdef CONFIG_DT_SDT_PERF

/*
 * This counts the number of args.
 */
#define DTRACE_NARGS_SEQ(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,N,...) N
#define DTRACE_NARGS(...) DTRACE_NARGS_SEQ(__VA_ARGS__, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)

/*
 * This will let macros expand before concatting them.
 */
#define DTRACE_PRIMITIVE_CAT(x, y) x ## y
#define DTRACE_CAT(x, y) DTRACE_PRIMITIVE_CAT(x, y)

/*
 * This will call a macro on each argument passed in.
 */
#define DTRACE_APPLY(macro, ...) DTRACE_CAT(DTRACE_APPLY_, DTRACE_NARGS(__VA_ARGS__))(macro, __VA_ARGS__)
#define DTRACE_APPLY_1(m, x1) m(x1)
#define DTRACE_APPLY_2(m, x1, x2) m(x1), m(x2)
#define DTRACE_APPLY_3(m, x1, x2, x3) m(x1), m(x2), m(x3)
#define DTRACE_APPLY_4(m, x1, x2, x3, x4) m(x1), m(x2), m(x3), m(x4)
#define DTRACE_APPLY_5(m, x1, x2, x3, x4, x5) m(x1), m(x2), m(x3), m(x4), m(x5)
#define DTRACE_APPLY_6(m, x1, x2, x3, x4, x5, x6) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6)
#define DTRACE_APPLY_7(m, x1, x2, x3, x4, x5, x6, x7) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7)
#define DTRACE_APPLY_8(m, x1, x2, x3, x4, x5, x6, x7, x8) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)

/*
 * Without investigation I went ahead and assumed the most arguments that could
 * be passed would be 8, but this is purely arbitrary. However, inexplicably
 * there are existing tracepoints that pass as many as 18 arguments!
 */

#define DTRACE_APPLY_9(m, x1, x2, x3, x4, x5, x6, x7, x8, ...) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)
#define DTRACE_APPLY_10(m, x1, x2, x3, x4, x5, x6, x7, x8, ...) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)
#define DTRACE_APPLY_11(m, x1, x2, x3, x4, x5, x6, x7, x8, ...) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)
#define DTRACE_APPLY_12(m, x1, x2, x3, x4, x5, x6, x7, x8, ...) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)
#define DTRACE_APPLY_13(m, x1, x2, x3, x4, x5, x6, x7, x8, ...) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)
#define DTRACE_APPLY_14(m, x1, x2, x3, x4, x5, x6, x7, x8, ...) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)
#define DTRACE_APPLY_15(m, x1, x2, x3, x4, x5, x6, x7, x8, ...) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)
#define DTRACE_APPLY_16(m, x1, x2, x3, x4, x5, x6, x7, x8, ...) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)
#define DTRACE_APPLY_17(m, x1, x2, x3, x4, x5, x6, x7, x8, ...) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)
#define DTRACE_APPLY_18(m, x1, x2, x3, x4, x5, x6, x7, x8, ...) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)

/*
 * Convert everything to the appropriate integral type, unless too large to fit
 * into any of them, in which case its address is taken instead.
 */

#define DTRACE_UINTPTR_CAST_EACH(x) ({					\
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
#define DTRACE_UINTPTR_EACH(x) uintptr_t

#define DTRACE_PROBE_TRACEPOINT(name, args...) {			\
	extern void __dtrace_probe___perf_##name(DTRACE_APPLY(DTRACE_UINTPTR_EACH, args)); \
	__dtrace_probe___perf_##name(DTRACE_APPLY(DTRACE_UINTPTR_CAST_EACH, args));	\
}

#define DTRACE_PROTO_TRACEPOINT(name, proto...) {				\
	asm volatile(".pushsection _dtrace_sdt_names, \"a\", @progbits\n"	\
		     ".ascii \"" __stringify(__perf_##name) "\"\n"		\
		     ".byte 0\n"						\
		     ".popsection\n"						\
		     ".pushsection _dtrace_sdt_args, \"a\", @progbits\n"	\
		     ".asciz \"" __stringify(proto) "\"\n"			\
		     ".popsection\n");						\
}
#else

#define DTRACE_PROBE_TRACEPOINT(name, args...)
#define DTRACE_PROTO_TRACEPOINT(name, proto...)

#endif

typedef struct sdt_probedesc {
	char			*sdpd_name;	/* probe name */
	char			*sdpd_func;	/* probe function */
	unsigned long		sdpd_offset;	/* offset of call in text */
	struct sdt_probedesc	*sdpd_next;	/* next static probe */
} sdt_probedesc_t;

#endif /* __KERNEL__ */

#else /* ! CONFIG_DTRACE */

#define	DTRACE_PROBE(name)				do { } while (0)
#define	DTRACE_PROBE1(name, type1, arg1)		DTRACE_PROBE(name)
#define	DTRACE_PROBE2(name, type1, arg1, type2, arg2)	DTRACE_PROBE(name)
#define	DTRACE_PROBE3(name, type1, arg1, type2, arg2, type3, arg3)	\
							DTRACE_PROBE(name)
#define	DTRACE_PROBE4(name, type1, arg1, type2, arg2, type3, arg3,	\
			type4, arg4)			DTRACE_PROBE(name)
#define	DTRACE_PROBE5(name, type1, arg1, type2, arg2, type3, arg3,	\
			type4, arg4, type5, arg5)	DTRACE_PROBE(name)
#define	DTRACE_PROBE6(name, type1, arg1, type2, arg2, type3, arg3,	\
	type4, arg4, type5, arg5, type6, arg6)		DTRACE_PROBE(name)
#define	DTRACE_PROBE7(name, type1, arg1, type2, arg2, type3, arg3,	\
	type4, arg4, type5, arg5, type6, arg6, type7, arg7)		\
							DTRACE_PROBE(name)
#define	DTRACE_PROBE8(name, type1, arg1, type2, arg2, type3, arg3,	\
	type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8) \
							DTRACE_PROBE(name)
#define DTRACE_PROBE_TRACEPOINT(name, args...)
#define DTRACE_PROTO_TRACEPOINT(name, proto)

#endif /* CONFIG_DTRACE */

#define	DTRACE_SCHED(name)						\
	DTRACE_PROBE(__sched_##name);

#define	DTRACE_SCHED1(name, type1, arg1)				\
	DTRACE_PROBE1(__sched_##name, type1, arg1);

#define	DTRACE_SCHED2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(__sched_##name, type1, arg1, type2, arg2);

#define	DTRACE_SCHED3(name, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE3(__sched_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_SCHED4(name, type1, arg1, type2, arg2, 			\
    type3, arg3, type4, arg4)						\
	DTRACE_PROBE4(__sched_##name, type1, arg1, type2, arg2, 	\
	    type3, arg3, type4, arg4);

#define	DTRACE_PROC(name)						\
	DTRACE_PROBE(__proc_##name);

#define	DTRACE_PROC1(name, type1, arg1)					\
	DTRACE_PROBE1(__proc_##name, type1, arg1);

#define	DTRACE_PROC2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(__proc_##name, type1, arg1, type2, arg2);

#define	DTRACE_PROC3(name, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE3(__proc_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_PROC4(name, type1, arg1, type2, arg2, 			\
    type3, arg3, type4, arg4)						\
	DTRACE_PROBE4(__proc_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4);

#define	DTRACE_IO(name)							\
	DTRACE_PROBE(__io_##name);

#define	DTRACE_IO1(name, type1, arg1)					\
	DTRACE_PROBE1(__io_##name, type1, arg1);

#define	DTRACE_IO2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(__io_##name, type1, arg1, type2, arg2);

#define	DTRACE_IO3(name, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE3(__io_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_IO4(name, type1, arg1, type2, arg2, 			\
    type3, arg3, type4, arg4)						\
	DTRACE_PROBE4(__io_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4);

#define	DTRACE_ISCSI_2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(__iscsi_##name, type1, arg1, type2, arg2);

#define	DTRACE_ISCSI_3(name, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE3(__iscsi_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_ISCSI_4(name, type1, arg1, type2, arg2,			\
    type3, arg3, type4, arg4)						\
	DTRACE_PROBE4(__iscsi_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4);

#define	DTRACE_ISCSI_5(name, type1, arg1, type2, arg2,			\
    type3, arg3, type4, arg4, type5, arg5)				\
	DTRACE_PROBE5(__iscsi_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4, type5, arg5);

#define	DTRACE_ISCSI_6(name, type1, arg1, type2, arg2,			\
    type3, arg3, type4, arg4, type5, arg5, type6, arg6)			\
	DTRACE_PROBE6(__iscsi_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6);

#define	DTRACE_ISCSI_7(name, type1, arg1, type2, arg2,			\
    type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7)	\
	DTRACE_PROBE7(__iscsi_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6,		\
	    type7, arg7);

#define	DTRACE_ISCSI_8(name, type1, arg1, type2, arg2,			\
    type3, arg3, type4, arg4, type5, arg5, type6, arg6,			\
    type7, arg7, type8, arg8)						\
	DTRACE_PROBE8(__iscsi_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6,		\
	    type7, arg7, type8, arg8);

#define	DTRACE_NFSV3_3(name, type1, arg1, type2, arg2, 			\
    type3, arg3)							\
	DTRACE_PROBE3(__nfsv3_##name, type1, arg1, type2, arg2,		\
	    type3, arg3);
#define	DTRACE_NFSV3_4(name, type1, arg1, type2, arg2, 			\
    type3, arg3, type4, arg4)						\
	DTRACE_PROBE4(__nfsv3_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4);

#define	DTRACE_NFSV4_1(name, type1, arg1) \
	DTRACE_PROBE1(__nfsv4_##name, type1, arg1);

#define	DTRACE_NFSV4_2(name, type1, arg1, type2, arg2) \
	DTRACE_PROBE2(__nfsv4_##name, type1, arg1, type2, arg2);

#define	DTRACE_NFSV4_3(name, type1, arg1, type2, arg2, type3, arg3) \
	DTRACE_PROBE3(__nfsv4_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_SMB_1(name, type1, arg1) \
	DTRACE_PROBE1(__smb_##name, type1, arg1);

#define	DTRACE_SMB_2(name, type1, arg1, type2, arg2) \
	DTRACE_PROBE2(__smb_##name, type1, arg1, type2, arg2);

#define	DTRACE_IP(name)						\
	DTRACE_PROBE(__ip_##name);

#define	DTRACE_IP1(name, type1, arg1)					\
	DTRACE_PROBE1(__ip_##name, type1, arg1);

#define	DTRACE_IP2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(__ip_##name, type1, arg1, type2, arg2);

#define	DTRACE_IP3(name, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE3(__ip_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_IP4(name, type1, arg1, type2, arg2, 			\
    type3, arg3, type4, arg4)						\
	DTRACE_PROBE4(__ip_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4);

#define	DTRACE_IP5(name, type1, arg1, type2, arg2, 			\
    type3, arg3, type4, arg4, type5, arg5)				\
	DTRACE_PROBE5(__ip_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5);

#define	DTRACE_IP6(name, type1, arg1, type2, arg2, 			\
    type3, arg3, type4, arg4, type5, arg5, type6, arg6)			\
	DTRACE_PROBE6(__ip_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6);

#define	DTRACE_IP7(name, type1, arg1, type2, arg2, type3, arg3,		\
    type4, arg4, type5, arg5, type6, arg6, type7, arg7)			\
	DTRACE_PROBE7(__ip_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6,		\
	    type7, arg7);

#define	DTRACE_TCP(name)						\
	DTRACE_PROBE(__tcp_##name);

#define	DTRACE_TCP1(name, type1, arg1)					\
	DTRACE_PROBE1(__tcp_##name, type1, arg1);

#define	DTRACE_TCP2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(__tcp_##name, type1, arg1, type2, arg2);

#define	DTRACE_TCP3(name, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE3(__tcp_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_TCP4(name, type1, arg1, type2, arg2,			\
    type3, arg3, type4, arg4)						\
	DTRACE_PROBE4(__tcp_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4);

#define	DTRACE_TCP5(name, type1, arg1, type2, arg2,			\
    type3, arg3, type4, arg4, type5, arg5)				\
	DTRACE_PROBE5(__tcp_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4, type5, arg5);

#define	DTRACE_TCP6(name, type1, arg1, type2, arg2,			\
    type3, arg3, type4, arg4, type5, arg5, type6, arg6)			\
	DTRACE_PROBE6(__tcp_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6);

#define	DTRACE_UDP(name)						\
	DTRACE_PROBE(__udp_##name);

#define	DTRACE_UDP1(name, type1, arg1)					\
	DTRACE_PROBE1(__udp_##name, type1, arg1);

#define	DTRACE_UDP2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(__udp_##name, type1, arg1, type2, arg2);

#define	DTRACE_UDP3(name, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE3(__udp_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_UDP4(name, type1, arg1, type2, arg2,			\
    type3, arg3, type4, arg4)						\
	DTRACE_PROBE4(__udp_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4);

#define	DTRACE_UDP5(name, type1, arg1, type2, arg2,			\
    type3, arg3, type4, arg4, type5, arg5)				\
	DTRACE_PROBE5(__udp_##name, type1, arg1, type2, arg2,		\
	    type3, arg3, type4, arg4, type5, arg5);


#define	DTRACE_SYSEVENT2(name, type1, arg1, type2, arg2)		\
	DTRACE_PROBE2(__sysevent_##name, type1, arg1, type2, arg2);

#define	DTRACE_XPV(name)						\
	DTRACE_PROBE(__xpv_##name);

#define	DTRACE_XPV1(name, type1, arg1)					\
	DTRACE_PROBE1(__xpv_##name, type1, arg1);

#define	DTRACE_XPV2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(__xpv_##name, type1, arg1, type2, arg2);

#define	DTRACE_XPV3(name, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE3(__xpv_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_XPV4(name, type1, arg1, type2, arg2, type3, arg3,	\
	    type4, arg4)						\
	DTRACE_PROBE4(__xpv_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4);

#define	DTRACE_FC_1(name, type1, arg1) \
	DTRACE_PROBE1(__fc_##name, type1, arg1);

#define	DTRACE_FC_2(name, type1, arg1, type2, arg2) \
	DTRACE_PROBE2(__fc_##name, type1, arg1, type2, arg2);

#define	DTRACE_FC_3(name, type1, arg1, type2, arg2, type3, arg3) \
	DTRACE_PROBE3(__fc_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_FC_4(name, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
	DTRACE_PROBE4(__fc_##name, type1, arg1, type2, arg2, type3, arg3, \
	    type4, arg4);

#define	DTRACE_FC_5(name, type1, arg1, type2, arg2, type3, arg3, 	\
	    type4, arg4, type5, arg5)					\
	DTRACE_PROBE5(__fc_##name, type1, arg1, type2, arg2, type3, arg3, \
	    type4, arg4, type5, arg5);

#define	DTRACE_SRP_1(name, type1, arg1)					\
	DTRACE_PROBE1(__srp_##name, type1, arg1);

#define	DTRACE_SRP_2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(__srp_##name, type1, arg1, type2, arg2);

#define	DTRACE_SRP_3(name, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE3(__srp_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_SRP_4(name, type1, arg1, type2, arg2, type3, arg3,	\
	    type4, arg4)						\
	DTRACE_PROBE4(__srp_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4);

#define	DTRACE_SRP_5(name, type1, arg1, type2, arg2, type3, arg3,	\
	    type4, arg4, type5, arg5)					\
	DTRACE_PROBE5(__srp_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5);

#define	DTRACE_SRP_6(name, type1, arg1, type2, arg2, type3, arg3,	\
	    type4, arg4, type5, arg5, type6, arg6)			\
	DTRACE_PROBE6(__srp_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6);

#define	DTRACE_SRP_7(name, type1, arg1, type2, arg2, type3, arg3,	\
	    type4, arg4, type5, arg5, type6, arg6, type7, arg7)		\
	DTRACE_PROBE7(__srp_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7);

#define	DTRACE_SRP_8(name, type1, arg1, type2, arg2, type3, arg3,	\
	    type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8) \
	DTRACE_PROBE8(__srp_##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6,		\
	    type7, arg7, type8, arg8);

#endif	/* _LINUX_SDT_H_ */
