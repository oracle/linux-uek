	.text
	.align 32
mem_corrupt_detect_precise:
	ldxa    [%g0] ASI_SCRATCHPAD, %g2;
	ba,a	sun4v_mcd_detect_precise
	nop; nop; nop; nop; nop; nop;
sun4v_mcd_detect_precise:
	ldx     [%g2 + HV_FAULT_D_ADDR_OFFSET], %g4
	ldx     [%g2 + HV_FAULT_D_CTX_OFFSET], %g5
	ba,pt	%xcc, etrap
	rd	%pc, %g7
	or	%l4, %g0, %o1
	or 	%l5, %g0, %o2
	call	sun4v_mem_corrupt_detect_precise
	add	%sp, PTREGS_OFF, %o0
	ba,a,pt	%xcc, rtrap
/*
 * We replace the trap handler and compute the branch displacement.
 * We might want to do this in C.
 */
#define	SUN4V_PATCH_MCD(OLDTRAP, NEWTRAP, BTARGET)		\
	sethi	%hi(NEWTRAP), %g1;				\
	or	%g1, %lo(NEWTRAP), %g1;				\
	sethi	%hi(OLDTRAP), %g2;				\
	or	%g2, %lo(OLDTRAP), %g2;				\
	ldx	[%g1 + 0], %g3;					\
	stx	%g3, [%g2 + 0];					\
	ldx	[%g1 + 8], %g3;					\
	stx	%g3, [%g2 + 8];					\
	ldx	[%g1 + 16], %g3;				\
	stx	%g3, [%g2 + 16];				\
	ldx	[%g1 + 24], %g3;				\
	stx	%g3, [%g2 + 24];				\
	add	%g2, 4, %g2;					\
	sethi	%hi(BTARGET), %g1;				\
	or	%g1, %lo(BTARGET), %g1;				\
	sub	%g1, %g2, %g1;					\
	srax	%g1, 2, %g1;					\
	sethi	%hi(0x3ffc00), %g3;				\
	or	%g3, 0x3ff, %g3;				\
	and	%g3, %g1, %g1;					\
	lduw	[%g2 + 0], %g7;					\
	andn	%g7, %g3, %g7;					\
	or	%g1, %g7, %g1;					\
	stw	%g1, [%g2 + 0];					\
	sub	%g2, 4, %g2;					\
	flush	%g2;
	.global sun4v_patch_mcd_handlers
	.type	sun4v_patch_mcd_handlers,#function
sun4v_patch_mcd_handlers:
	SUN4V_PATCH_MCD(tl0_mem_corrupt_detect_precise,		\
		mem_corrupt_detect_precise, sun4v_mcd_detect_precise)
	retl
	nop
	.size	sun4v_patch_mcd_handlers,.-sun4v_patch_mcd_handler1
