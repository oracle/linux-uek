/*
 * M7clear_page.S: SPARC M7 optimized clear_page and clear_user_page.
 *
 * Copyright (c) 2016, Oracle and/or its affiliates.  All rights reserved.
 */

#include <asm/asi.h>
#include <asm/page.h>

#define ASI_STBI_P      ASI_BLK_INIT_QUAD_LDD_P

	.text
	.register       %g3, #scratch
	.align		32
	.globl		M7clear_page
	.globl		M7clear_user_page
M7clear_page:	/* %o0=dest */
M7clear_user_page:	/* %o0=dest */
	set	PAGE_SIZE, %o2

.wrzero_loop:

	mov     64, %g3
	stxa    %g0, [%o0]ASI_STBI_P
	subcc   %o2, 256, %o2
	stxa    %g0, [%o0+%g3]ASI_STBI_P
	add     %o0, 256, %o0
	sub     %g3, 192, %g3
	stxa    %g0, [%o0+%g3]ASI_STBI_P
	add	%g3, 64, %g3
	bg,pt	%ncc, .wrzero_loop
	stxa    %g0, [%o0+%g3]ASI_STBI_P
	retl
	membar  #StoreStore	! required by use of Block Store Init
	.size		M7clear_page,.-M7clear_page
	.size		M7clear_user_page,.-M7clear_user_page
