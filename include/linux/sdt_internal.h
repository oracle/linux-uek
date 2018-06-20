/*
 * Hide away all the terrible macro magic.
 *
 * Copyright (C) 2016 Oracle, Inc.
 */

#ifndef _LINUX_SDT_INTERNAL_H_
#define _LINUX_SDT_INTERNAL_H_

#include <linux/types.h>

/*
 * This counts the number of args.
 */
#define __DTRACE_NARGS_SEQ(dummy,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,_21,_22,_23,_24,_25,_26,_27,_28,_29,_30,_31,_32,_33,_34,_35,_36,N,...) N
#define __DTRACE_NARGS(...)						\
	__DTRACE_NARGS_SEQ(dummy, ##__VA_ARGS__, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

/*
 * This will let macros expand before concatting them.
 */
#define __DTRACE_PRIMITIVE_CAT(x, y) x ## y
#define __DTRACE_CAT(x, y) __DTRACE_PRIMITIVE_CAT(x, y)

#define __DTRACE_COMMA ,
#define __DTRACE_NO_COMMA
#define __DTRACE_NONE(x)

/*
 * This will call two macros on each argument-pair passed in (the first two args
 * are the names of the macros to call).  Its TYPE and NAME variants will throw
 * away the name and type arguments, respectively. __DTRACE_*_APPLY_NOCOMMA
 * are like DTRACE_*_APPLY, but also omit the comma between arguments in the
 * expansion of the macro.  DTRACE_TYPE_APPLY_DEFAULT lets you specify a default
 * if no variadic args are provided.
 */
#define __DTRACE_DOUBLE_APPLY(type_macro, arg_macro, ...)		\
	__DTRACE_CAT(__DTRACE_DOUBLE_APPLY_,				\
		     __DTRACE_NARGS(__VA_ARGS__))(type_macro,		\
						  arg_macro, __DTRACE_COMMA, \
						  __DTRACE_COMMA, , ## __VA_ARGS__)
#define __DTRACE_DOUBLE_APPLY_NOCOMMA(type_macro, arg_macro, ...)		\
	__DTRACE_CAT(__DTRACE_DOUBLE_APPLY_,				\
		     __DTRACE_NARGS(__VA_ARGS__))(type_macro,		\
						  arg_macro, __DTRACE_NO_COMMA, \
						  __DTRACE_NO_COMMA, , ## __VA_ARGS__)
#define __DTRACE_TYPE_APPLY(type_macro, ...)				\
	__DTRACE_CAT(__DTRACE_DOUBLE_APPLY_,				\
		     __DTRACE_NARGS(__VA_ARGS__))(type_macro,		\
						  __DTRACE_NONE, __DTRACE_NO_COMMA, \
						  __DTRACE_COMMA, , ## __VA_ARGS__)
#define __DTRACE_TYPE_APPLY_NOCOMMA(type_macro, ...)			\
	__DTRACE_CAT(__DTRACE_DOUBLE_APPLY_,				\
		     __DTRACE_NARGS(__VA_ARGS__))(type_macro,		\
						  __DTRACE_NONE, __DTRACE_NO_COMMA, \
						  __DTRACE_NO_COMMA, , ## __VA_ARGS__)
#define __DTRACE_TYPE_APPLY_DEFAULT(type_macro, def, ...)		\
	__DTRACE_CAT(__DTRACE_DOUBLE_APPLY_,				\
		     __DTRACE_NARGS(__VA_ARGS__))(type_macro,		\
						  __DTRACE_NONE, __DTRACE_NO_COMMA, \
						  __DTRACE_COMMA, def, ## __VA_ARGS__)
#define __DTRACE_ARG_APPLY(arg_macro, ...)				\
	__DTRACE_CAT(__DTRACE_DOUBLE_APPLY_,				\
		     __DTRACE_NARGS(__VA_ARGS__))(__DTRACE_NONE,	\
						  arg_macro, __DTRACE_NO_COMMA,	\
						  __DTRACE_COMMA, , ## __VA_ARGS__)
#define __DTRACE_DOUBLE_APPLY_0(t, a, comma_t, comma_a, def) def
#define __DTRACE_DOUBLE_APPLY_2(t, a, comma_t, comma_a, def, type1, arg1) \
	t(type1) comma_t a(arg1)
#define __DTRACE_DOUBLE_APPLY_4(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2)
#define __DTRACE_DOUBLE_APPLY_6(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3)
#define __DTRACE_DOUBLE_APPLY_8(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4)
#define __DTRACE_DOUBLE_APPLY_10(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5)
#define __DTRACE_DOUBLE_APPLY_12(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6)
#define __DTRACE_DOUBLE_APPLY_14(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7)
#define __DTRACE_DOUBLE_APPLY_16(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8)
#define __DTRACE_DOUBLE_APPLY_18(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8, type9, arg9) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8) comma_a \
	t(type9) comma_t a(arg9)
#define __DTRACE_DOUBLE_APPLY_20(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8, type9, arg9, typea, arga) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8) comma_a \
	t(type9) comma_t a(arg9) comma_a t(typea) comma_t a(arga)
#define __DTRACE_DOUBLE_APPLY_22(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8, type9, arg9, typea, arga, typeb, argb) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8) comma_a \
	t(type9) comma_t a(arg9) comma_a t(typea) comma_t a(arga) comma_a \
	t(typeb) comma_t a(argb)
#define __DTRACE_DOUBLE_APPLY_24(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8, type9, arg9, typea, arga, typeb, argb, typec, argc) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8) comma_a \
	t(type9) comma_t a(arg9) comma_a t(typea) comma_t a(arga) comma_a \
	t(typeb) comma_t a(argb) comma_a t(typec) comma_t a(argc)
#define __DTRACE_DOUBLE_APPLY_26(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8, type9, arg9, typea, arga, typeb, argb, typec, argc, typed, argd) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8) comma_a \
	t(type9) comma_t a(arg9) comma_a t(typea) comma_t a(arga) comma_a \
	t(typeb) comma_t a(argb) comma_a t(typec) comma_t a(argc) comma_a \
	t(typed) comma_t a(argd)
#define __DTRACE_DOUBLE_APPLY_28(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8, type9, arg9, typea, arga, typeb, argb, typec, argc, typed, argd, typee, arge) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8) comma_a \
	t(type9) comma_t a(arg9) comma_a t(typea) comma_t a(arga) comma_a \
	t(typeb) comma_t a(argb) comma_a t(typec) comma_t a(argc) comma_a \
	t(typed) comma_t a(argd) comma_a t(typee) comma_t a(arge)
#define __DTRACE_DOUBLE_APPLY_30(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8, type9, arg9, typea, arga, typeb, argb, typec, argc, typed, argd, typee, arge, typef, argf) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8) comma_a \
	t(type9) comma_t a(arg9) comma_a t(typea) comma_t a(arga) comma_a \
	t(typeb) comma_t a(argb) comma_a t(typec) comma_t a(argc) comma_a \
	t(typed) comma_t a(argd) comma_a t(typee) comma_t a(arge) comma_a \
	t(typef) comma_t a(argf)
#define __DTRACE_DOUBLE_APPLY_32(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8, type9, arg9, typea, arga, typeb, argb, typec, argc, typed, argd, typee, arge, typef, argf, typeg, argg) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8) comma_a \
	t(type9) comma_t a(arg9) comma_a t(typea) comma_t a(arga) comma_a \
	t(typeb) comma_t a(argb) comma_a t(typec) comma_t a(argc) comma_a \
	t(typed) comma_t a(argd) comma_a t(typee) comma_t a(arge) comma_a \
	t(typef) comma_t a(argf) comma_a t(typeg) comma_t a(argg)
#define __DTRACE_DOUBLE_APPLY_34(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8, type9, arg9, typea, arga, typeb, argb, typec, argc, typed, argd, typee, arge, typef, argf, typeg, argg, typeh, argh) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8) comma_a \
	t(type9) comma_t a(arg9) comma_a t(typea) comma_t a(arga) comma_a \
	t(typeb) comma_t a(argb) comma_a t(typec) comma_t a(argc) comma_a \
	t(typed) comma_t a(argd) comma_a t(typee) comma_t a(arge) comma_a \
	t(typef) comma_t a(argf) comma_a t(typeg) comma_t a(argg) comma_a \
	t(typeh) comma_t a(argh)
#define __DTRACE_DOUBLE_APPLY_36(t, a, comma_t, comma_a, def, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6, type7, arg7, type8, arg8, type9, arg9, typea, arga, typeb, argb, typec, argc, typed, argd, typee, arge, typef, argf, typeg, argg, typeh, argh, typei, argi) \
	t(type1) comma_t a(arg1) comma_a t(type2) comma_t a(arg2) comma_a \
	t(type3) comma_t a(arg3) comma_a t(type4) comma_t a(arg4) comma_a \
	t(type5) comma_t a(arg5) comma_a t(type6) comma_t a(arg6) comma_a \
	t(type7) comma_t a(arg7) comma_a t(type8) comma_t a(arg8) comma_a \
	t(type9) comma_t a(arg9) comma_a t(typea) comma_t a(arga) comma_a \
	t(typeb) comma_t a(argb) comma_a t(typec) comma_t a(argc) comma_a \
	t(typed) comma_t a(argd) comma_a t(typee) comma_t a(arge) comma_a \
	t(typef) comma_t a(argf) comma_a t(typeg) comma_t a(argg) comma_a \
	t(typeh) comma_t a(argh) comma_a t(typei) comma_t a(argi)

#define __DTRACE_DOUBLE_APPLY_ERROR Error: type specified without arg.
#define __DTRACE_DOUBLE_APPLY_1 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_3 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_5 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_7 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_9 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_11 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_13 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_15 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_17 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_19 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_21 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_23 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_25 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_27 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_29 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_31 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_33 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_35 __DTRACE_DOUBLE_APPLY_ERROR
#define __DTRACE_DOUBLE_APPLY_37 __DTRACE_DOUBLE_APPLY_ERROR

#define __DTRACE_UINTPTR_EACH(x) uintptr_t

#define __DTRACE_UINTCAST_EACH(x) (uintptr_t)(x)
#define __DTRACE_TYPE_EACH(x) ".ascii \"" __stringify(x) ",\"\n"

/*
 * Convert everything to the appropriate integral type, unless too large to fit
 * into any of them, in which case its address is taken instead.
 */

/*
 * This will call a macro on each argument passed in, with optional default for
 * zero args.
 */
#define __DTRACE_APPLY(macro, ...) __DTRACE_CAT(__DTRACE_APPLY_, __DTRACE_NARGS(__VA_ARGS__))(macro, , ## __VA_ARGS__)
#define __DTRACE_APPLY_DEFAULT(macro, def, ...) __DTRACE_CAT(__DTRACE_APPLY_, __DTRACE_NARGS(__VA_ARGS__))(macro, def, ## __VA_ARGS__)
#define __DTRACE_APPLY_0(m, def) def
#define __DTRACE_APPLY_1(m, def, x1) m(x1)
#define __DTRACE_APPLY_2(m, def, x1, x2) m(x1), m(x2)
#define __DTRACE_APPLY_3(m, def, x1, x2, x3) m(x1), m(x2), m(x3)
#define __DTRACE_APPLY_4(m, def, x1, x2, x3, x4) m(x1), m(x2), m(x3), m(x4)
#define __DTRACE_APPLY_5(m, def, x1, x2, x3, x4, x5) m(x1), m(x2), m(x3), m(x4), m(x5)
#define __DTRACE_APPLY_6(m, def, x1, x2, x3, x4, x5, x6) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6)
#define __DTRACE_APPLY_7(m, def, x1, x2, x3, x4, x5, x6, x7) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7)
#define __DTRACE_APPLY_8(m, def, x1, x2, x3, x4, x5, x6, x7, x8) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8)
#define __DTRACE_APPLY_9(m, def, x1, x2, x3, x4, x5, x6, x7, x8, x9) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8), m(x9)
#define __DTRACE_APPLY_10(m, def, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8), m(x9), m(xa)
#define __DTRACE_APPLY_11(m, def, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8), m(x9), m(xa), m(xb)
#define __DTRACE_APPLY_12(m, def, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8), m(x9), m(xa), m(xb), m(xc)
#define __DTRACE_APPLY_13(m, def, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8), m(x9), m(xa), m(xb), m(xc), m(xd)
#define __DTRACE_APPLY_14(m, def, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8), m(x9), m(xa), m(xb), m(xc), m(xd), m(xe)
#define __DTRACE_APPLY_15(m, def, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8), m(x9), m(xa), m(xb), m(xc), m(xd), m(xe), m(xf)
#define __DTRACE_APPLY_16(m, def, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf, xg) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8), m(x9), m(xa), m(xb), m(xc), m(xd), m(xe), m(xf), m(xg)
#define __DTRACE_APPLY_17(m, def, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf, xg, xh) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8), m(x9), m(xa), m(xb), m(xc), m(xd), m(xe), m(xf), m(xg), m(xh)
#define __DTRACE_APPLY_18(m, def, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf, xg, xh, xi) m(x1), m(x2), m(x3), m(x4), m(x5), m(x6), m(x7), m(x8), m(x9), m(xa), m(xb), m(xc), m(xd), m(xe), m(xf), m(xg), m(xh), m(xi)

/* Needed for lockstat probes where we cannot include ktime.h */
extern u64 dtrace_gethrtime_ns(void);

#endif	/* _LINUX_SDT_INTERNAL_H */
