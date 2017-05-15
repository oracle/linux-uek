/*
 * M8patch.S: Patch generic routines with M8 variant.
 *
 * Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
 */

#define BRANCH_ALWAYS	0x10680000
#define NOP		0x01000000
#define NG_DO_PATCH(OLD, NEW)	\
	sethi	%hi(NEW), %g1; \
	or	%g1, %lo(NEW), %g1; \
	sethi	%hi(OLD), %g2; \
	or	%g2, %lo(OLD), %g2; \
	sub	%g1, %g2, %g1; \
	sethi	%hi(BRANCH_ALWAYS), %g3; \
	sll	%g1, 11, %g1; \
	srl	%g1, 11 + 2, %g1; \
	or	%g3, %lo(BRANCH_ALWAYS), %g3; \
	or	%g3, %g1, %g3; \
	stw	%g3, [%g2]; \
	sethi	%hi(NOP), %g3; \
	or	%g3, %lo(NOP), %g3; \
	stw	%g3, [%g2 + 0x4]; \
	flush	%g2;

	.globl	m8_patch_copyops
	.type	m8_patch_copyops,#function
m8_patch_copyops:
	NG_DO_PATCH(memcpy, M8memcpy)
	NG_DO_PATCH(___copy_from_user, M8copy_from_user)
	NG_DO_PATCH(___copy_to_user, M8copy_to_user)
	retl
	 nop
	.size	m8_patch_copyops,.-m8_patch_copyops

	.globl	m8_patch_bzero
	.type	m8_patch_bzero,#function
m8_patch_bzero:
	NG_DO_PATCH(memset, M7memset)
	NG_DO_PATCH(__bzero, M7bzero)
	NG_DO_PATCH(__clear_user, NGclear_user)
	NG_DO_PATCH(tsb_init, NGtsb_init)
	retl
	 nop
	.size	m8_patch_bzero,.-m8_patch_bzero

	.globl	m8_patch_pageops
	.type	m8_patch_pageops,#function
m8_patch_pageops:
	NG_DO_PATCH(copy_user_page, NG4copy_user_page)
	NG_DO_PATCH(_clear_page, M7clear_page)
	NG_DO_PATCH(clear_user_page, M7clear_user_page)
	retl
	 nop
	.size	m8_patch_pageops,.-m8_patch_pageops
