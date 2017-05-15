/*
 * M8memcpy: Optimized SPARC M8 memcpy
 *
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 */

	.file	"M8memcpy.S"

/*
 * memcpy(s1, s2, len)
 *
 * Copy s2 to s1, always copy n bytes.
 * Note: this C code does not work for overlapped copies.
 *
 * Fast assembler language version of the following C-program for memcpy
 * which represents the `standard' for the C-library.
 *
 *	void *
 *	memcpy(void *s, const void *s0, size_t n)
 *	{
 *		if (n != 0) {
 *		    char *s1 = s;
 *		    const char *s2 = s0;
 *		    do {
 *			*s1++ = *s2++;
 *		    } while (--n != 0);
 *		}
 *		return (s);
 *	}
 *
 *
 * SPARC T8/M8 Flow :
 *
 * if (count < SMALL_MAX) {
 *   if count < SHORTCOPY              (SHORTCOPY=3)
 *	copy bytes; exit with dst addr
 *   if src & dst aligned on word boundary but not long word boundary,
 *     copy with ldw/stw; branch to finish_up
 *   if src & dst aligned on long word boundary
 *     copy with ldx/stx; branch to finish_up
 *   if src & dst not aligned and length <= SHORTCHECK   (SHORTCHECK=14)
 *     copy bytes; exit with dst addr
 *   move enough bytes to get src to word boundary
 *   if dst now on word boundary
 * move_words:
 *     copy words; branch to finish_up
 *   if dst now on half word boundary
 *     load words, shift half words, store words; branch to finish_up
 *   if dst on byte 1
 *     load words, shift 3 bytes, store words; branch to finish_up
 *   if dst on byte 3
 *     load words, shift 1 byte, store words; branch to finish_up
 * finish_up:
 *     copy bytes; exit with dst addr
 * } else {                                         More than SMALL_MAX bytes
 *   move bytes until dst is on long word boundary
 *   if( src is on long word boundary ) {
 *     if (count < MED_MAX) {
 * finish_long:					   src/dst aligned on 8 bytes
 *       copy with ldx/stx in 8-way unrolled loop;
 *       copy final 0-63 bytes; exit with dst addr
 *     } else {				     src/dst aligned; count > MED_MAX
 *       align dst on 64 byte boundary; for main data movement:
 *       prefetch src data to L2 cache; let HW prefetch move data to L1 cache
 *       Use BIS (block initializing store) to avoid copying store cache
 *       lines from memory. But pre-store first element of each cache line
 *       ST_CHUNK lines in advance of the rest of that cache line. That
 *       gives time for replacement cache lines to be written back without
 *       excess STQ and Miss Buffer filling. Repeat until near the end,
 *       then finish up storing before going to finish_long.
 *     }
 *   } else {                                   src/dst not aligned on 8 bytes
 *     if src is word aligned and count < MED_WMAX
 *       move words in 8-way unrolled loop
 *       move final 0-31 bytes; exit with dst addr
 *     if count < MED_UMAX
 *       use alignaddr/faligndata combined with ldd/std in 8-way
 *       unrolled loop to move data.
 *       go to unalign_done
 *     else
 *       setup alignaddr for faligndata instructions
 *       align dst on 64 byte boundary; prefetch src data to L1 cache
 *       loadx8, falign, block-store, prefetch loop
 *	 (only use block-init-store when src/dst on 8 byte boundaries.)
 * unalign_done:
 *       move remaining bytes for unaligned cases. exit with dst addr.
 * }
 *
 */

#include <asm/visasm.h>
#include <asm/asi.h>

#if !defined(EX_LD) && !defined(EX_ST)
#define NON_USER_COPY
#endif

#ifndef EX_LD
#define EX_LD(x)	x
#endif
#ifndef EX_LD_FP
#define EX_LD_FP(x)	x
#endif

#ifndef EX_ST
#define EX_ST(x)	x
#endif
#ifndef EX_ST_FP
#define EX_ST_FP(x)	x
#endif

#ifndef EX_RETVAL
#define EX_RETVAL(x)    x
#endif

#ifndef LOAD
#define LOAD(type,addr,dest)	type [addr], dest
#endif

#ifndef LOAD_MS
#define LOAD_MS(type,addr,offset,dest)  EX_LD(.word 0xd98a7400+offset)
#endif

#ifndef STORE
#define STORE(type,src,addr)	type src, [addr]
#endif

/*
 * ASI_BLK_INIT_QUAD_LDD_P/ASI_BLK_INIT_QUAD_LDD_S marks the cache
 * line as "least recently used" which means if many threads are
 * active, it has a high probability of being pushed out of the cache
 * between the first initializing store and the final stores.
 * Thus, we use ASI_ST_BLKINIT_MRU_P/ASI_ST_BLKINIT_MRU_S which
 * marks the cache line as "most recently used" for all
 * but the last cache line
 */
#ifndef STORE_ASI
#ifndef SIMULATE_NIAGARA_ON_NON_NIAGARA
#define STORE_ASI	ASI_BLK_INIT_QUAD_LDD_P
#else
#define STORE_ASI	0x80		/* ASI_P */
#endif
#endif

#ifndef STORE_MRU_ASI
#ifndef SIMULATE_NIAGARA_ON_NON_NIAGARA
#define STORE_MRU_ASI	ASI_ST_BLKINIT_MRU_P
#else
#define STORE_MRU_ASI	0x80		/* ASI_P */
#endif
#endif

#ifndef STORE_INIT
#define STORE_INIT(src,addr)	stxa src, [addr] STORE_ASI
#endif

#ifndef STORE_INIT_MRU
#define STORE_INIT_MRU(src,addr)	stxa src, [addr] STORE_MRU_ASI
#endif

#ifndef FUNC_NAME
#define FUNC_NAME	M8memcpy
#endif

#ifndef PREAMBLE
#define PREAMBLE				\
	set     M7memop_enable, %g1;		\
	ld      [%g1], %g1;			\
	andcc   %g1, 2, %g0;			\
	bz,pn   %xcc, NG4memcpy;		\
	nop
#endif

#define	BLOCK_SIZE	64
#define	SHORTCOPY	3
#define	SHORTCHECK	14
#define	SHORT_LONG	64	/* max copy for short longword-aligned case */
				/* must be at least 64 */
#define	SMALL_MAX	128
#define MED_MS_UMAX	4096	/* max copy for medium un-aligned case where */
				/* ldmx makes lot of difference */
#define	MED_UMAX	32960	/* max copy for medium un-aligned case */
#define	MED_WMAX	32960	/* max copy for medium word-aligned case */
#define	MED_MAX		32960	/* max copy for medium longword-aligned case */
#define ST_CHUNK	24	/* ST_CHUNK - block of values for BIS Store */
#define ALIGN_PRE	24	/* distance for aligned prefetch loop */

        .register      %g2,#scratch

       .section        ".text"
       .global FUNC_NAME
       .type   FUNC_NAME, #function
       .align  16
FUNC_NAME:
	srlx            %o2, 31, %g2
	cmp             %g2, 0
	tne             %xcc, 5
	PREAMBLE
	mov		%o0, %g1	! save %o0
	brz,pn          %o2, .Lsmallexit

	cmp	%o2, SMALL_MAX		! check for not small case
	bgeu,pn	%ncc, .Lmedium		! go to larger cases
	nop
.Lmv_short:
	cmp	%o2, SHORTCOPY		! check for really short case
	ble,pn	%ncc, .Lsmallfin
	or	%o0, %o1, %o4		! prepare alignment check
	andcc	%o4, 0x3, %o5		! test for alignment
	bnz,pn	%ncc, .Lsmallunalign	! branch to word aligned case
	nop
	subcc	%o2, 7, %o2		! adjust count
	ble,pn	%ncc, .Lsmallwordx
	andcc	%o4, 0x7, %o5		! test for long alignment
! 8 or more bytes, src and dest start on word boundary
! %o4 contains or %o0, %o1;
.Lsmalllong:
	bnz,pn	%ncc, .Lsmallwords	! branch to word aligned case
	cmp	%o2, SHORT_LONG-7
	bge,a	%ncc, .Lmedl64		! if we branch
	sub	%o2,56,%o2		! adjust %o2 to -63 off count

! slightly unroll the.Lsmall_long_loop to improve very short copies
	cmp   %o2, 32-7
	blt,a,pn  %ncc,.Lsmall_long_l
	sub	%o1, %o0, %o1		! %o1 gets the difference
	EX_LD(LOAD(ldx, %o1, %o3))
	EX_ST(STORE(stx, %o3, %o0))	! write word
	EX_LD(LOAD(ldx, %o1+8, %o3))
	EX_ST(STORE(stx, %o3, %o0+8))	! write word
	EX_LD(LOAD(ldx, %o1+16, %o3))
	subcc	%o2, 24, %o2
	sub	%o1, %o0, %o1		! %o1 gets the difference
	EX_ST(STORE(stx, %o3, %o0+16))	! write word
	add	%o0, 24, %o0

! end loop unroll

.Lsmall_long_l:
	add	%o1, %o0, %o3
	EX_LD(LOAD(ldx, %o3, %o3))
	subcc	%o2, 8, %o2
	add	%o0, 8, %o0
	bgu,pn	%ncc, .Lsmall_long_l	! loop until done
	EX_ST(STORE(stx, %o3, %o0-8))	! write word
	addcc	%o2, 7, %o2		! restore %o2 to correct count
	bnz,pn	%ncc, .Lsmall_long_x	! check for completion
	add	%o1, %o0, %o1		! restore %o1
	retl
	mov	EX_RETVAL(%g1), %o0
.Lsmall_long_x:
	cmp	%o2, 4			! check for 4 or more bytes left
	blt,pn	%ncc, .Lsmallleft3	! if not, go to finish up
	nop
	EX_LD(LOAD(lduw, %o1, %o3))
	add	%o1, 4, %o1
	subcc	%o2, 4, %o2
	EX_ST(STORE(stw, %o3, %o0))
	bnz,pn	%ncc, .Lsmallleft3
	add	%o0, 4, %o0
	retl
	mov	EX_RETVAL(%g1), %o0

	.align 32
! src and dest start on word boundary; 7 or fewer bytes
.Lsmallwordx:
	EX_LD(LOAD(lduw, %o1, %o3))	! read word
	addcc	%o2, 3, %o2		! restore count
	bz,pt	%ncc, .Lsmallexit
	EX_ST(STORE(stw, %o3, %o0))	! write word
	deccc	%o2			! reduce count for cc test
	EX_LD(LOAD(ldub, %o1+4, %o3))	! load one byte
	bz,pt	%ncc, .Lsmallexit
	EX_ST(STORE(stb, %o3, %o0+4))	! store one byte
	EX_LD(LOAD(ldub, %o1+5, %o3))	! load second byte
	deccc	%o2
	bz,pt	%ncc, .Lsmallexit
	EX_ST(STORE(stb, %o3, %o0+5))	! store second byte
	EX_LD(LOAD(ldub, %o1+6, %o3))	! load third byte
	EX_ST(STORE(stb, %o3, %o0+6))	! store third byte
.Lsmallexit:
	retl
	mov	EX_RETVAL(%g1), %o0


	.align 32
.Lsmallunalign:
	cmp	%o2, SHORTCHECK
	ble,pn	%ncc, .Lsmallrest
	andcc	%o1, 0x3, %o5		! is src word aligned
	bz,pn	%ncc, .Laldst
	cmp	%o5, 2			! is src half-word aligned
	be,pt	%ncc, .Ls2algn
	cmp	%o5, 3			! src is byte aligned
.Ls1algn:EX_LD(LOAD(ldub, %o1, %o3))	! move 1 or 3 bytes to align it
	inc	1, %o1
	EX_ST(STORE(stb, %o3, %o0))	! move a byte to align src
	inc	1, %o0
	bne,pt	%ncc, .Ls2algn
	dec	%o2
	b	.Lald			! now go align dest
	andcc	%o0, 0x3, %o5

.Ls2algn:EX_LD(LOAD(lduh, %o1, %o3))	! know src is 2 byte aligned
	inc	2, %o1
	srl	%o3, 8, %o4
	EX_ST(STORE(stb, %o4, %o0))	! have to do bytes,
	EX_ST(STORE(stb, %o3, %o0+1))	! do not know dst alignment
	inc	2, %o0
	dec	2, %o2

.Laldst:	andcc	%o0, 0x3, %o5	! align the destination address
.Lald:	bz,pn	%ncc, .Lw4cp
	cmp	%o5, 2
	be,pn	%ncc, .Lw2cp
	cmp	%o5, 3
.Lw3cp:	EX_LD(LOAD(lduw, %o1, %o4))
	inc	4, %o1
	srl	%o4, 24, %o5
	EX_ST(STORE(stb, %o5, %o0))
	bne,pt	%ncc, .Lw1cp
	inc	%o0
	dec	1, %o2
	andn	%o2, 3, %o3		! %o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %o0, %o1		! %o1 gets the difference

1:	sll	%o4, 8, %g7		! save residual bytes
	add	%o1, %o0, %o4
	EX_LD(LOAD(lduw, %o4, %o4))
	deccc	4, %o3
	srl	%o4, 24, %o5		! merge with residual
	or	%o5, %g7, %g7
	EX_ST(STORE(st, %g7, %o0))
	bnz,pt	%ncc, 1b
	inc	4, %o0
	sub	%o1, 3, %o1		! used one byte of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.Lw1cp:	srl	%o4, 8, %o5
	EX_ST(STORE(sth, %o5, %o0))
	inc	2, %o0
	dec	3, %o2
	andn	%o2, 3, %o3		! %o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %o0, %o1		! %o1 gets the difference

2:	sll	%o4, 24, %g7		! save residual bytes
	add	%o1, %o0, %o4
	EX_LD(LOAD(lduw, %o4, %o4))
	deccc	4, %o3
	srl	%o4, 8, %o5		! merge with residual
	or	%o5, %g7, %g7
	EX_ST(STORE(st, %g7, %o0))
	bnz,pt	%ncc, 2b
	inc	4, %o0
	sub	%o1, 1, %o1		! used three bytes of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.Lw2cp:	EX_LD(LOAD(lduw, %o1, %o4))
	inc	4, %o1
	srl	%o4, 16, %o5
	EX_ST(STORE(sth, %o5, %o0))
	inc	2, %o0
	dec	2, %o2
	andn	%o2, 3, %o3		! %o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %o0, %o1		! %o1 gets the difference

3:	sll	%o4, 16, %g7		! save residual bytes
	add	%o1, %o0, %o4
	EX_LD(LOAD(lduw, %o4, %o4))
	deccc	4, %o3
	srl	%o4, 16, %o5		! merge with residual
	or	%o5, %g7, %g7
	EX_ST(STORE(st, %g7, %o0))
	bnz,pt	%ncc, 3b
	inc	4, %o0
	sub	%o1, 2, %o1		! used two bytes of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.Lw4cp:	andn	%o2, 3, %o3		! %o3 is aligned word count
	sub	%o1, %o0, %o1		! %o1 gets the difference

1:	add	%o1, %o0, %o4
	EX_LD(LOAD(lduw, %o4, %o4))	! read from address
	deccc	4, %o3			! decrement count
	EX_ST(STORE(st, %o4, %o0))	! write at destination address
	bgu,pt	%ncc, 1b
	inc	4, %o0			! increment to address
	and	%o2, 3, %o2		! number of leftover bytes, if any

	! simple finish up byte copy, works with any alignment
7:
	add	%o1, %o0, %o1		! restore %o1
.Lsmallrest:
	tst	%o2
	bz,pt	%ncc, .Lsmallx
	cmp	%o2, 4
	blt,pn	%ncc, .Lsmallleft3
	nop
	sub	%o2, 3, %o2
.Lsmallnotalign4:
	EX_LD(LOAD(ldub, %o1, %o3))	! read byte
	subcc	%o2, 4, %o2		! reduce count by 4
	EX_ST(STORE(stb, %o3, %o0))	! write byte
	EX_LD(LOAD(ldub, %o1+1, %o3))	! repeat for total of 4 bytes
	add	%o1, 4, %o1		! advance SRC by 4
	EX_ST(STORE(stb, %o3, %o0+1))
	EX_LD(LOAD(ldub, %o1-2, %o3))
	add	%o0, 4, %o0		! advance DST by 4
	EX_ST(STORE(stb, %o3, %o0-2))
	EX_LD(LOAD(ldub, %o1-1, %o3))
	bgu,pt	%ncc, .Lsmallnotalign4	! loop til 3 or fewer bytes remain
	EX_ST(STORE(stb, %o3, %o0-1))
	addcc	%o2, 3, %o2		! restore count
	bz,pt	%ncc, .Lsmallx
.Lsmallleft3:				! 1, 2, or 3 bytes remain
	subcc	%o2, 1, %o2
	EX_LD(LOAD(ldub, %o1, %o3))	! load one byte
	bz,pt	%ncc, .Lsmallx
	EX_ST(STORE(stb, %o3, %o0))	! store one byte
	EX_LD(LOAD(ldub, %o1+1, %o3))	! load second byte
	subcc	%o2, 1, %o2
	bz,pt	%ncc, .Lsmallx
	EX_ST(STORE(stb, %o3, %o0+1))	! store second byte
	EX_LD(LOAD(ldub, %o1+2, %o3))	! load third byte
	EX_ST(STORE(stb, %o3, %o0+2))	! store third byte
.Lsmallx:
	retl
	mov	EX_RETVAL(%g1), %o0
.Lsmallfin:
	tst	%o2
	bnz,pn	%ncc, .Lsmallleft3
	nop
	retl
	mov	EX_RETVAL(%g1), %o0	! restore %o0

	.align 16
.Lsmallwords:
	EX_LD(LOAD(lduw, %o1, %o3))	! read word
	subcc	%o2, 8, %o2		! update count
	EX_ST(STORE(stw, %o3, %o0))	! write word
	add	%o1, 8, %o1		! update SRC
	EX_LD(LOAD(lduw, %o1-4, %o3))	! read word
	add	%o0, 8, %o0		! update DST
	bgu,pt	%ncc, .Lsmallwords	! loop until done
	EX_ST(STORE(stw, %o3, %o0-4))	! write word
	addcc	%o2, 7, %o2		! restore count
	bz,pt	%ncc, .Lsmallexit	! check for completion
	cmp	%o2, 4			! check for 4 or more bytes left
	blt	%ncc, .Lsmallleft3	! if not, go to finish up
	nop
	EX_LD(LOAD(lduw, %o1, %o3))
	add	%o1, 4, %o1
	subcc	%o2, 4, %o2
	add	%o0, 4, %o0
	bnz,pn	%ncc, .Lsmallleft3
	EX_ST(STORE(stw, %o3, %o0-4))
	retl
	mov	EX_RETVAL(%g1), %o0

	.align 16
.Lmedium:
	neg	%o0, %o5
	andcc	%o5, 7, %o5		! bytes till DST 8 byte aligned
	brz,pt	%o5, .Ldst_aligned_on_8

	! %o5 has the bytes to be written in partial store.
	sub	%o2, %o5, %o2
	sub	%o1, %o0, %o1		! %o1 gets the difference
7:					! dst aligning loop
	add	%o1, %o0, %o4
	EX_LD(LOAD(ldub, %o4, %o4))	! load one byte
	subcc	%o5, 1, %o5
	EX_ST(STORE(stb, %o4, %o0))
	bgu,pt	%ncc, 7b
	add	%o0, 1, %o0		! advance dst
	add	%o1, %o0, %o1		! restore %o1
.Ldst_aligned_on_8:
	andcc	%o1, 7, %o5
	brnz,pt	%o5, .Lsrc_dst_unaligned_on_8
	nop

.Lsrc_dst_aligned_on_8:
	! check if we are copying MED_MAX or more bytes
        set MED_MAX, %o3
        cmp %o2, %o3 			! limit to store buffer size
	bgu,pn	%ncc, .Llarge_align8_copy
	nop

/*
 * Special case for handling when src and dest are both long word aligned
 * and total data to move is less than MED_MAX bytes
 */
.Lmedlong:
	subcc	%o2, 63, %o2		! adjust length to allow cc test
	ble,pn	%ncc, .Lmedl63		! skip big loop if less than 64 bytes
	nop
.Lmedl64:
	EX_LD(LOAD(ldx, %o1, %o4))	! load
	subcc	%o2, 64, %o2		! decrement length count
	EX_ST(STORE(stx, %o4, %o0))	! and store
	EX_LD(LOAD(ldx, %o1+8, %o3))	! a block of 64 bytes
	EX_ST(STORE(stx, %o3, %o0+8))
	EX_LD(LOAD(ldx, %o1+16, %o4))
	EX_ST(STORE(stx, %o4, %o0+16))
	EX_LD(LOAD(ldx, %o1+24, %o3))
	EX_ST(STORE(stx, %o3, %o0+24))
	EX_LD(LOAD(ldx, %o1+32, %o4))	! load
	EX_ST(STORE(stx, %o4, %o0+32))	! and store
	EX_LD(LOAD(ldx, %o1+40, %o3))	! a block of 64 bytes
	add	%o1, 64, %o1		! increase src ptr by 64
	EX_ST(STORE(stx, %o3, %o0+40))
	EX_LD(LOAD(ldx, %o1-16, %o4))
	add	%o0, 64, %o0		! increase dst ptr by 64
	EX_ST(STORE(stx, %o4, %o0-16))
	EX_LD(LOAD(ldx, %o1-8, %o3))
	bgu,pt	%ncc, .Lmedl64		! repeat if at least 64 bytes left
	EX_ST(STORE(stx, %o3, %o0-8))
.Lmedl63:
	addcc	%o2, 32, %o2		! adjust remaining count
	ble,pt	%ncc, .Lmedl31		! to skip if 31 or fewer bytes left
	nop
	EX_LD(LOAD(ldx, %o1, %o4))	! load
	sub	%o2, 32, %o2		! decrement length count
	EX_ST(STORE(stx, %o4, %o0))	! and store
	EX_LD(LOAD(ldx, %o1+8, %o3))	! a block of 32 bytes
	add	%o1, 32, %o1		! increase src ptr by 32
	EX_ST(STORE(stx, %o3, %o0+8))
	EX_LD(LOAD(ldx, %o1-16, %o4))
	add	%o0, 32, %o0		! increase dst ptr by 32
	EX_ST(STORE(stx, %o4, %o0-16))
	EX_LD(LOAD(ldx, %o1-8, %o3))
	EX_ST(STORE(stx, %o3, %o0-8))
.Lmedl31:
	addcc	%o2, 16, %o2		! adjust remaining count
	ble,pt	%ncc, .Lmedl15		! skip if 15 or fewer bytes left
	nop				!
	EX_LD(LOAD(ldx, %o1, %o4))
	add	%o1, 16, %o1		! increase src ptr by 16
	EX_ST(STORE(stx, %o4, %o0))
	sub	%o2, 16, %o2		! decrease count by 16
	EX_LD(LOAD(ldx, %o1-8, %o3))
	add	%o0, 16, %o0		! increase dst ptr by 16
	EX_ST(STORE(stx, %o3, %o0-8))
.Lmedl15:
	addcc	%o2, 15, %o2		! restore count
	bz,pt	%ncc, .Lsmallexit	! exit if finished
	cmp	%o2, 8
	blt,pt	%ncc, .Lmedw7		! skip if 7 or fewer bytes left
	tst	%o2
	EX_LD(LOAD(ldx, %o1, %o4))	! load 8 bytes
	add	%o1, 8, %o1		! increase src ptr by 8
	add	%o0, 8, %o0		! increase dst ptr by 8
	subcc	%o2, 8, %o2		! decrease count by 8
	bnz,pn	%ncc, .Lmedw7
	EX_ST(STORE(stx, %o4, %o0-8))	! and store 8 bytes
	retl
	mov	EX_RETVAL(%g1), %o0	! restore %o0

	.align 16
.Lsrc_dst_unaligned_on_8:
	! DST is 8-byte aligned, src is not
2:
	andcc	%o1, 0x3, %o5		! test word alignment
	bnz,pt	%ncc, .Lunalignsetup	! branch to skip if not word aligned
	nop

/*
 * Handle all cases where src and dest are aligned on word
 * boundaries. Use unrolled loops for better performance.
 * This option wins over standard large data move when
 * source and destination is in cache for.Lmedium
 * to short data moves.
 */
        set MED_WMAX, %o3
        cmp %o2, %o3 			! limit to store buffer size
	bge,pt	%ncc, .Lunalignrejoin	! otherwise rejoin main loop
	nop

	subcc	%o2, 31, %o2		! adjust length to allow cc test
					! for end of loop
	ble,pt	%ncc, .Lmedw31		! skip big loop if less than 16
.Lmedw32:
	EX_LD(LOAD(ld, %o1, %o4))	! move a block of 32 bytes
	sllx	%o4, 32, %o5
	EX_LD(LOAD(ld, %o1+4, %o4))
	or	%o4, %o5, %o5
	EX_ST(STORE(stx, %o5, %o0))
	subcc	%o2, 32, %o2		! decrement length count
	EX_LD(LOAD(ld, %o1+8, %o4))
	sllx	%o4, 32, %o5
	EX_LD(LOAD(ld, %o1+12, %o4))
	or	%o4, %o5, %o5
	EX_ST(STORE(stx, %o5, %o0+8))
	add	%o1, 32, %o1		! increase src ptr by 32
	EX_LD(LOAD(ld, %o1-16, %o4))
	sllx	%o4, 32, %o5
	EX_LD(LOAD(ld, %o1-12, %o4))
	or	%o4, %o5, %o5
	EX_ST(STORE(stx, %o5, %o0+16))
	add	%o0, 32, %o0		! increase dst ptr by 32
	EX_LD(LOAD(ld, %o1-8, %o4))
	sllx	%o4, 32, %o5
	EX_LD(LOAD(ld, %o1-4, %o4))
	or	%o4, %o5, %o5
	bgu,pt	%ncc, .Lmedw32		! repeat if at least 32 bytes left
	EX_ST(STORE(stx, %o5, %o0-8))
.Lmedw31:
	addcc	%o2, 31, %o2		! restore count

	bz,pt	%ncc, .Lsmallexit	! exit if finished
	nop
	cmp	%o2, 16
	blt,pt	%ncc, .Lmedw15
	nop
	EX_LD(LOAD(ld, %o1, %o4))	! move a block of 16 bytes
	sllx	%o4, 32, %o5
	subcc	%o2, 16, %o2		! decrement length count
	EX_LD(LOAD(ld, %o1+4, %o4))
	or	%o4, %o5, %o5
	EX_ST(STORE(stx, %o5, %o0))
	add	%o1, 16, %o1		! increase src ptr by 16
	EX_LD(LOAD(ld, %o1-8, %o4))
	add	%o0, 16, %o0		! increase dst ptr by 16
	sllx	%o4, 32, %o5
	EX_LD(LOAD(ld, %o1-4, %o4))
	or	%o4, %o5, %o5
	EX_ST(STORE(stx, %o5, %o0-8))
.Lmedw15:
	bz,pt	%ncc, .Lsmallexit	! exit if finished
	cmp	%o2, 8
	blt,pn	%ncc, .Lmedw7		! skip if 7 or fewer bytes left
	tst	%o2
	EX_LD(LOAD(ld, %o1, %o4))	! load 4 bytes
	subcc	%o2, 8, %o2		! decrease count by 8
	EX_ST(STORE(stw, %o4, %o0))	! and store 4 bytes
	add	%o1, 8, %o1		! increase src ptr by 8
	EX_LD(LOAD(ld, %o1-4, %o3))	! load 4 bytes
	add	%o0, 8, %o0		! increase dst ptr by 8
	EX_ST(STORE(stw, %o3, %o0-4))	! and store 4 bytes
	bz,pt	%ncc, .Lsmallexit	! exit if finished
.Lmedw7:				! count is ge 1, less than 8
	cmp	%o2, 4			! check for 4 bytes left
	blt,pn	%ncc, .Lsmallleft3	! skip if 3 or fewer bytes left
	nop				!
	EX_LD(LOAD(ld, %o1, %o4))	! load 4 bytes
	add	%o1, 4, %o1		! increase src ptr by 4
	add	%o0, 4, %o0		! increase dst ptr by 4
	subcc	%o2, 4, %o2		! decrease count by 4
	bnz	.Lsmallleft3
	EX_ST(STORE(stw, %o4, %o0-4))	! and store 4 bytes
	retl
	mov	EX_RETVAL(%g1), %o0

	.align 16
.Llarge_align8_copy:			! Src and dst share 8 byte alignment
	! align dst to 64 byte boundary
	andcc	%o0, 0x3f, %o3		! %o3 == 0 means dst is 64 byte aligned
	brz,pn	%o3, .Laligned_to_64
	andcc	%o0, 8, %o3		! odd long words to move?
	brz,pt	%o3, .Laligned_to_16
	nop
	EX_LD(LOAD(ldx, %o1, %o4))
	sub	%o2, 8, %o2
	add	%o1, 8, %o1		! increment src ptr
	add	%o0, 8, %o0		! increment dst ptr
	EX_ST(STORE(stx, %o4, %o0-8))
.Laligned_to_16:
	andcc	%o0, 16, %o3		! pair of long words to move?
	brz,pt	%o3, .Laligned_to_32
	nop
	EX_LD(LOAD(ldx, %o1, %o4))
	sub	%o2, 16, %o2
	EX_ST(STORE(stx, %o4, %o0))
	add	%o1, 16, %o1		! increment src ptr
	EX_LD(LOAD(ldx, %o1-8, %o4))
	add	%o0, 16, %o0		! increment dst ptr
	EX_ST(STORE(stx, %o4, %o0-8))
.Laligned_to_32:
	andcc	%o0, 32, %o3		! four long words to move?
	brz,pt	%o3, .Laligned_to_64
	nop
	EX_LD(LOAD(ldx, %o1, %o4))
	sub	%o2, 32, %o2
	EX_ST(STORE(stx, %o4, %o0))
	EX_LD(LOAD(ldx, %o1+8, %o4))
	EX_ST(STORE(stx, %o4, %o0+8))
	EX_LD(LOAD(ldx, %o1+16, %o4))
	EX_ST(STORE(stx, %o4, %o0+16))
	add	%o1, 32, %o1		! increment src ptr
	EX_LD(LOAD(ldx, %o1-8, %o4))
	add	%o0, 32, %o0		! increment dst ptr
	EX_ST(STORE(stx, %o4, %o0-8))
.Laligned_to_64:
!
!	Using block init store (BIS) instructions to avoid fetching cache
!	lines from memory. Use ST_CHUNK stores to first element of each cache
!	line (similar to prefetching) to avoid overfilling STQ or miss buffers.
!	Gives existing cache lines time to be moved out of L1/L2/L3 cache.
!	Initial stores using MRU version of BIS to keep cache line in
!	cache until we are ready to store final element of cache line.
!	Then store last element using the LRU version of BIS.
!
	andn	%o2, 0x3f, %o5		! %o5 is multiple of block size
	and	%o2, 0x3f, %o2		! residue bytes in %o2
!
!	We use STORE_MRU_ASI for the first seven stores to each cache line
!	followed by STORE_ASI (mark as LRU) for the last store. That
!	mixed approach reduces the probability that the cache line is removed
!	before we finish setting it, while minimizing the effects on
!	other cached values during a large memcpy
!
!	ST_CHUNK batches up initial BIS operations for several cache lines
!	to allow multiple requests to not be blocked by overflowing the
!	the store miss buffer. Then the matching stores for all those
!	BIS operations are executed.
!

	sub	%o0, 8, %o0		! adjust %o0 for ASI alignment
.Lalign_loop:
	cmp	%o5, ST_CHUNK*64
	blu,pt	%ncc, .Lalign_loop_fin
	mov	ST_CHUNK,%o3
.Lalign_loop_start:
	prefetch [%o1 + (ALIGN_PRE * BLOCK_SIZE)], 21
	subcc	%o3, 1, %o3
	EX_LD(LOAD(ldx, %o1, %o4))
	add	%o1, 64, %o1
	add	%o0, 8, %o0
	EX_ST(STORE_INIT_MRU(%o4, %o0))
	bgu	%ncc,.Lalign_loop_start
	add	%o0, 56, %o0

	mov	ST_CHUNK,%o3
	sllx	%o3, 6, %o4		! ST_CHUNK*64
	sub	%o1, %o4, %o1		! reset %o1
	sub	%o0, %o4, %o0		! reset %o0

.Lalign_loop_rest:
	EX_LD(LOAD(ldx, %o1+8, %o4))
	add	%o0, 16, %o0
	EX_ST(STORE_INIT_MRU(%o4, %o0))
	EX_LD(LOAD(ldx, %o1+16, %o4))
	add	%o0, 8, %o0
	EX_ST(STORE_INIT_MRU(%o4, %o0))
	subcc	%o3, 1, %o3
	EX_LD(LOAD(ldx, %o1+24, %o4))
	add	%o0, 8, %o0
	EX_ST(STORE_INIT_MRU(%o4, %o0))
	EX_LD(LOAD(ldx, %o1+32, %o4))
	add	%o0, 8, %o0
	EX_ST(STORE_INIT_MRU(%o4, %o0))
	EX_LD(LOAD(ldx, %o1+40, %o4))
	add	%o0, 8, %o0
	EX_ST(STORE_INIT_MRU(%o4, %o0))
	EX_LD(LOAD(ldx, %o1+48, %o4))
	add	%o1, 64, %o1
	add	%o0, 8, %o0
	EX_ST(STORE_INIT_MRU(%o4, %o0))
	add	%o0, 8, %o0
	EX_LD(LOAD(ldx, %o1-8, %o4))
	sub	%o5, 64, %o5
	bgu	%ncc,.Lalign_loop_rest
	EX_ST(STORE_INIT(%o4, %o0))	! mark cache line as LRU

	cmp	%o5, ST_CHUNK*64
	bgu,pt	%ncc, .Lalign_loop_start
	mov	ST_CHUNK,%o3

	cmp	%o5, 0
	beq	.Lalign_done
	nop
.Lalign_loop_fin:
	EX_LD(LOAD(ldx, %o1, %o4))
	EX_ST(STORE(stx, %o4, %o0+8))
	EX_LD(LOAD(ldx, %o1+8, %o4))
	EX_ST(STORE(stx, %o4, %o0+8+8))
	EX_LD(LOAD(ldx, %o1+16, %o4))
	EX_ST(STORE(stx, %o4, %o0+8+16))
	subcc	%o5, 64, %o5
	EX_LD(LOAD(ldx, %o1+24, %o4))
	EX_ST(STORE(stx, %o4, %o0+8+24))
	EX_LD(LOAD(ldx, %o1+32, %o4))
	EX_ST(STORE(stx, %o4, %o0+8+32))
	EX_LD(LOAD(ldx, %o1+40, %o4))
	EX_ST(STORE(stx, %o4, %o0+8+40))
	EX_LD(LOAD(ldx, %o1+48, %o4))
	add	%o1, 64, %o1
	EX_ST(STORE(stx, %o4, %o0+8+48))
	add	%o0, 64, %o0
	EX_LD(LOAD(ldx, %o1-8, %o4))
	bgu	%ncc,.Lalign_loop_fin
	EX_ST(STORE(stx, %o4, %o0))

.Lalign_done:
	add	%o0, 8, %o0		! restore %o0 from ASI alignment
	membar	#StoreStore
	sub	%o2, 63, %o2		! adjust length to allow cc test
	ba	.Lmedl63		! in .Lmedl63
	nop

	.align 16
	! Dst is on 8 byte boundary; src is not; remaining count > SMALL_MAX
.Lunalignsetup:
.Lunalignrejoin:
	! At smaller lengths, new ldm instructions perform better than
	! FP logic. This is due to fixed overhead of FP save/restore. But
	! the overhead does not matter how big the memcpy length is. However,
	! the internal overhead due to the slower ldmx instruction grows with
	! memcpy size. With our experiments, we noticed that ldm performance
	! starts to converge with FP performance at about length 4096 and over.
	! We check the memcpy length length here. Jump to mis-aligned logic
	! if the length is 4096 or less. Else continue with FP logic.

	set MED_MS_UMAX, %o3
	cmp %o2, %o3
	ble,pt  %ncc, .Lunalign_ms_start
	nop

	/* Now let's start FP/alignaddr logic */

	mov	%g1, %o3		! save %g1 as VISEntryHalf clobbers it
#ifdef NON_USER_COPY
	VISEntryHalfFast(.Lunalign_ms_start)
#else
	VISEntryHalf
#endif
	VISEntryHalf
	mov	%o3, %g1		! restore %g1

	set MED_UMAX, %o3
	cmp %o2, %o3 			! check for.Lmedium unaligned limit
	bge,pt	%ncc,.Lunalign_large
	prefetch [%o1 + (4 * BLOCK_SIZE)], 20
	andn	%o2, 0x3f, %o5		! %o5 is multiple of block size
	and	%o2, 0x3f, %o2		! residue bytes in %o2
	cmp	%o2, 8			! Insure we do not load beyond
	bgt	.Lunalign_adjust	! end of source buffer
	andn	%o1, 0x7, %o4		! %o4 has long word aligned src address
	add	%o2, 64, %o2		! adjust to leave loop
	sub	%o5, 64, %o5		! early if necessary
.Lunalign_adjust:
	alignaddr %o1, %g0, %g0		! generate %gsr
	add	%o1, %o5, %o1		! advance %o1 to after blocks
	EX_LD_FP(LOAD(ldd, %o4, %f0))
.Lunalign_loop:
	EX_LD_FP(LOAD(ldd, %o4+8, %f2))
	faligndata %f0, %f2, %f16
	EX_LD_FP(LOAD(ldd, %o4+16, %f4))
	subcc	%o5, BLOCK_SIZE, %o5
	EX_ST_FP(STORE(std, %f16, %o0))
	faligndata %f2, %f4, %f18
	EX_LD_FP(LOAD(ldd, %o4+24, %f6))
	EX_ST_FP(STORE(std, %f18, %o0+8))
	faligndata %f4, %f6, %f20
	EX_LD_FP(LOAD(ldd, %o4+32, %f8))
	EX_ST_FP(STORE(std, %f20, %o0+16))
	faligndata %f6, %f8, %f22
	EX_LD_FP(LOAD(ldd, %o4+40, %f10))
	EX_ST_FP(STORE(std, %f22, %o0+24))
	faligndata %f8, %f10, %f24
	EX_LD_FP(LOAD(ldd, %o4+48, %f12))
	EX_ST_FP(STORE(std, %f24, %o0+32))
	faligndata %f10, %f12, %f26
	EX_LD_FP(LOAD(ldd, %o4+56, %f14))
	add	%o4, BLOCK_SIZE, %o4
	EX_ST_FP(STORE(std, %f26, %o0+40))
	faligndata %f12, %f14, %f28
	EX_LD_FP(LOAD(ldd, %o4, %f0))
	EX_ST_FP(STORE(std, %f28, %o0+48))
	faligndata %f14, %f0, %f30
	EX_ST_FP(STORE(std, %f30, %o0+56))
	add	%o0, BLOCK_SIZE, %o0
	bgu,pt	%ncc, .Lunalign_loop
	prefetch [%o4 + (5 * BLOCK_SIZE)], 20
	ba	.Lunalign_done
	nop

.Lunalign_large:
	andcc	%o0, 0x3f, %o3		! is dst 64-byte block aligned?
	bz	%ncc, .Lunalignsrc
	sub	%o3, 64, %o3		! %o3 will be multiple of 8
	neg	%o3			! bytes until dest is 64 byte aligned
	sub	%o2, %o3, %o2		! update cnt with bytes to be moved
	! Move bytes according to source alignment
	andcc	%o1, 0x1, %o5
	bnz	%ncc, .Lunalignbyte	! check for byte alignment
	nop
	andcc	%o1, 2, %o5		! check for half word alignment
	bnz	%ncc, .Lunalignhalf
	nop
	! Src is word aligned
.Lunalignword:
	EX_LD_FP(LOAD(ld, %o1, %o4))	! load 4 bytes
	add	%o1, 8, %o1		! increase src ptr by 8
	EX_ST_FP(STORE(stw, %o4, %o0))	! and store 4 bytes
	subcc	%o3, 8, %o3		! decrease count by 8
	EX_LD_FP(LOAD(ld, %o1-4, %o4))	! load 4 bytes
	add	%o0, 8, %o0		! increase dst ptr by 8
	bnz	%ncc, .Lunalignword
	EX_ST_FP(STORE(stw, %o4, %o0-4))! and store 4 bytes
	ba	.Lunalignsrc
	nop

	! Src is half-word aligned
.Lunalignhalf:
	EX_LD_FP(LOAD(lduh, %o1, %o4))	! load 2 bytes
	sllx	%o4, 32, %o5		! shift left
	EX_LD_FP(LOAD(lduw, %o1+2, %o4))
	or	%o4, %o5, %o5
	sllx	%o5, 16, %o5
	EX_LD_FP(LOAD(lduh, %o1+6, %o4))
	or	%o4, %o5, %o5
	EX_ST_FP(STORE(stx, %o5, %o0))
	add	%o1, 8, %o1
	subcc	%o3, 8, %o3
	bnz	%ncc, .Lunalignhalf
	add	%o0, 8, %o0
	ba	.Lunalignsrc
	nop

	! Src is Byte aligned
.Lunalignbyte:
	sub	%o0, %o1, %o0		! share pointer advance
.Lunalignbyte_loop:
	EX_LD_FP(LOAD(ldub, %o1, %o4))
	sllx	%o4, 56, %o5
	EX_LD_FP(LOAD(lduh, %o1+1, %o4))
	sllx	%o4, 40, %o4
	or	%o4, %o5, %o5
	EX_LD_FP(LOAD(lduh, %o1+3, %o4))
	sllx	%o4, 24, %o4
	or	%o4, %o5, %o5
	EX_LD_FP(LOAD(lduh, %o1+5, %o4))
	sllx	%o4,  8, %o4
	or	%o4, %o5, %o5
	EX_LD_FP(LOAD(ldub, %o1+7, %o4))
	or	%o4, %o5, %o5
	add	%o0, %o1, %o0
	EX_ST_FP(STORE(stx, %o5, %o0))
	sub	%o0, %o1, %o0
	subcc	%o3, 8, %o3
	bnz	%ncc, .Lunalignbyte_loop
	add	%o1, 8, %o1
	add	%o0,%o1, %o0 		! restore pointer

	! Destination is now block (64 byte aligned)
.Lunalignsrc:
	andn	%o2, 0x3f, %o5		! %o5 is multiple of block size
	and	%o2, 0x3f, %o2		! residue bytes in %o2
	add	%o2, 64, %o2		! Insure we do not load beyond
	sub	%o5, 64, %o5		! end of source buffer

	andn	%o1, 0x7, %o4		! %o4 has long word aligned src address
	alignaddr %o1, %g0, %g0		! generate %gsr
	add	%o1, %o5, %o1		! advance %o1 to after blocks

	EX_LD_FP(LOAD(ldd, %o4, %f14))
	add	%o4, 8, %o4
.Lunalign_sloop:
	EX_LD_FP(LOAD(ldd, %o4, %f16))
	faligndata %f14, %f16, %f0
	EX_LD_FP(LOAD(ldd, %o4+8, %f18))
	faligndata %f16, %f18, %f2
	EX_LD_FP(LOAD(ldd, %o4+16, %f20))
	faligndata %f18, %f20, %f4
	EX_ST_FP(STORE(std, %f0, %o0))
	subcc	%o5, 64, %o5
	EX_LD_FP(LOAD(ldd, %o4+24, %f22))
	faligndata %f20, %f22, %f6
	EX_ST_FP(STORE(std, %f2, %o0+8))
	EX_LD_FP(LOAD(ldd, %o4+32, %f24))
	faligndata %f22, %f24, %f8
	EX_ST_FP(STORE(std, %f4, %o0+16))
	EX_LD_FP(LOAD(ldd, %o4+40, %f26))
	faligndata %f24, %f26, %f10
	EX_ST_FP(STORE(std, %f6, %o0+24))
	EX_LD_FP(LOAD(ldd, %o4+48, %f28))
	faligndata %f26, %f28, %f12
	EX_ST_FP(STORE(std, %f8, %o0+32))
	add	%o4, 64, %o4
	EX_LD_FP(LOAD(ldd, %o4-8, %f30))
	faligndata %f28, %f30, %f14
	EX_ST_FP(STORE(std, %f10, %o0+40))
	EX_ST_FP(STORE(std, %f12, %o0+48))
	add	%o0, 64, %o0
	EX_ST_FP(STORE(std, %f14, %o0-8))
	fsrc2	%f30, %f14
	bgu,pt	%ncc, .Lunalign_sloop
	prefetch [%o4 + (6 * BLOCK_SIZE)], 20

.Lunalign_done:
	! Handle trailing bytes, 64 to 127
	! Dest long word aligned, Src not long word aligned
	cmp	%o2, 15
	bleu	%ncc, .Lunalign_short

	andn	%o2, 0x7, %o5		! %o5 is multiple of 8
	and	%o2, 0x7, %o2		! residue bytes in %o2
	add	%o2, 8, %o2
	sub	%o5, 8, %o5		! insure we do not load past end of src
	andn	%o1, 0x7, %o4		! %o4 has long word aligned src address
	add	%o1, %o5, %o1		! advance %o1 to after multiple of 8
	EX_LD_FP(LOAD(ldd, %o4, %f0))	! fetch partial word
.Lunalign_by8:
	EX_LD_FP(LOAD(ldd, %o4+8, %f2))
	add	%o4, 8, %o4
	faligndata %f0, %f2, %f16
	subcc	%o5, 8, %o5
	EX_ST_FP(STORE(std, %f16, %o0))
	fsrc2	%f2, %f0
	bgu,pt	%ncc, .Lunalign_by8
	add	%o0, 8, %o0

.Lunalign_short:
#ifdef NON_USER_COPY
	VISExitHalfFast
#else
	VISExitHalf
#endif
	ba	.Lsmallrest
	nop

	! Start using M8 mis-aligned instructions.
.Lunalign_ms_start:
	prefetch [%o1 + (4 * BLOCK_SIZE)], 20
	andn    %o2, 0x3f, %o5	! %o5 is multiple of block size
	and     %o2, 0x3f, %o2	! residue bytes in %o2

.Lunalign_ms_loop:
	LOAD_MS(ldmx, %o1, 0, %o4)
	subcc   %o5, BLOCK_SIZE, %o5
	EX_ST(STORE(stx, %o4, %o0))
	LOAD_MS(ldmx, %o1, 8, %o4)
	EX_ST(STORE(stx, %o4, %o0+8))
	LOAD_MS(ldmx, %o1, 16, %o4)
	EX_ST(STORE(stx, %o4, %o0+16))
	LOAD_MS(ldmx, %o1, 24, %o4)
	EX_ST(STORE(stx, %o4, %o0+24))
	LOAD_MS(ldmx, %o1, 32, %o4)
	EX_ST(STORE(stx, %o4, %o0+32))
	LOAD_MS(ldmx, %o1, 40, %o4)
	EX_ST(STORE(stx, %o4, %o0+40))
	LOAD_MS(ldmx, %o1, 48, %o4)
	EX_ST(STORE(stx, %o4, %o0+48))
	LOAD_MS(ldmx, %o1, 56, %o4)
	add     %o1, BLOCK_SIZE, %o1
	EX_ST(STORE(stx, %o4, %o0+56))
	add     %o0, BLOCK_SIZE, %o0
	bgu,pt  %ncc, .Lunalign_ms_loop
	prefetch [%o1 + (5 * BLOCK_SIZE)], 20

	! Handle trailing bytes, 64 to 127
	! Dest long word aligned, Src not long word aligned
	cmp     %o2, 15
	bleu    %ncc, .Lunalign_ms_short

	andn    %o2, 0x7, %o5           ! %o5 is multiple of 8
	and     %o2, 0x7, %o2           ! residue bytes in %o2

.Lunalign_ms_by8:
	subcc   %o5, 8, %o5
	LOAD_MS(ldmx, %o1, 0, %o4)
	EX_ST(STORE(stx, %o4, %o0))
	add     %o1, 8, %o1
	bgu,pt  %ncc, .Lunalign_ms_by8
	add     %o0, 8, %o0

.Lunalign_ms_short:
	ba      .Lsmallrest
	nop
	.size  FUNC_NAME, .-FUNC_NAME
