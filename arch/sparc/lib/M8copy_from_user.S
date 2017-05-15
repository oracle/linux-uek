/*
 * M8copy_from_user.S: SPARC M8 optimized copy from userspace.
 *
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 */


#define EX_LD(x)			\
98:	x;				\
	.section __ex_table,"a";	\
	.align 4;			\
	.word 98b, __retl_one_asi;	\
	.text;				\
	.align 4;

#define EX_LD_FP(x)			\
98:	x;				\
	.section __ex_table,"a";	\
	.align 4;			\
	.word 98b, __retl_one_asi_fp;	\
	.text;				\
	.align 4;


#ifndef ASI_AIUS
#define ASI_AIUS	0x11
#endif

#define FUNC_NAME		M8copy_from_user
#define LOAD(type,addr,dest)	type##a [addr] %asi, dest

#define EX_RETVAL(x)		0

#ifdef __KERNEL__
#define PREAMBLE					\
	rd		%asi, %g1;			\
	cmp		%g1, ASI_AIUS;			\
	bne,pn		%icc, ___copy_in_user;		\
	nop;						\
	set		M7memop_enable, %g1;		\
	ld		[%g1], %g1;			\
	andcc		%g1, 8, %g0;			\
	bz,pn		%xcc, NG4copy_from_user;	\
	nop
#endif

#include "M8memcpy.S"
