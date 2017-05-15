/*
 * M8copy_to_user.S: SPARC M8 optimized copy to userspace.
 *
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 */


#define EX_ST(x)			\
98:	x;				\
	.section __ex_table,"a";	\
	.align 4;			\
	.word 98b, __retl_one_asi;	\
	.text;				\
	.align 4;

#define EX_ST_FP(x)			\
98:	x;				\
	.section __ex_table,"a";	\
	.align 4;			\
	.word 98b, __retl_one_asi_fp;	\
	.text;				\
	.align 4;


#ifndef ASI_AIUS
#define ASI_AIUS	0x11
#endif

#ifndef ASI_BLK_INIT_QUAD_LDD_AIUS
#define ASI_BLK_INIT_QUAD_LDD_AIUS 0x23
#endif

#define FUNC_NAME		M8copy_to_user
#define STORE(type,src,addr)	type##a src, [addr] %asi
#define STORE_ASI		ASI_BLK_INIT_QUAD_LDD_AIUS
#define	STORE_MRU_ASI		ASI_ST_BLKINIT_MRU_S
#define EX_RETVAL(x)		0

#ifdef __KERNEL__
	/* Writing to %asi is _expensive_ so we hardcode it.
	 * Reading %asi to check for KERNEL_DS is comparatively
	 * cheap.
	 */
#define PREAMBLE					\
	rd		%asi, %g1;			\
	cmp		%g1, ASI_AIUS;			\
	bne,pn		%icc, ___copy_in_user;		\
	nop;						\
	set		M7memop_enable, %g1;		\
	ld		[%g1], %g1;			\
	andcc		%g1, 4, %g0;			\
	bz,pn		%xcc, NG4copy_to_user;		\
	nop
#endif

#include "M8memcpy.S"
