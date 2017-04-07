/*
 * FILE:	fbt_sparc64.c
 * DESCRIPTION:	Function Boundary Tracing: architecture-specific implementation
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/vmalloc.h>
#include <linux/dtrace_fbt.h>
#include <asm/cacheflush.h>
#include <asm/dtrace_util.h>
#include <dtrace/isa_arch.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fbt_impl.h"

/*
 * For entry probes, we generate the following trampoline (for id < 0xfff):
 *
 *	sethi	%hi(id), %o0
 *	or	%o0, %lo(id), %o0
 *	mov	%i0, %o1
 *	mov	%i1, %o2
 *	mov	%i2, %o3
 *	mov	%i3, %o4
 *	mov	%i4, %o5
 *	call	dtrace_probe
 *	 nop
 *	sethi	%hi(instr), %o7
 *	or	%o7, %lo(instr), %o7
 *	retl
 *	 nop
 *
 * otherwise we use:
 *
 *	or	%g0, id, %o0
 *	mov	%i0, %o1
 *	mov	%i1, %o2
 *	mov	%i2, %o3
 *	mov	%i3, %o4
 *	mov	%i4, %o5
 *	call	dtrace_probe
 *	 nop
 *	sethi	%hi(instr), %o7
 *	or	%o7, %lo(instr), %o7
 *	retl
 *	 nop
 */
#define	FBT_TRAMP_SIZE	19


static void add_entry_tramp(fbt_probe_t *fbp, int nargs)
{
	struct module	*mp = fbp->fbp_module;
	dtrace_id_t	id = fbp->fbp_id;
	size_t		idx = PDATA(mp)->fbt_probe_cnt;
	asm_instr_t	*trampoline = &(PDATA(mp)->fbt_tab[idx *
							   FBT_TRAMP_SIZE]);
	asm_instr_t	*instr = trampoline;

	if (id > (uint32_t)ASM_SIMM13_MAX) {
		*instr++ = ASM_SETHI(id, ASM_REG_O0);
		*instr++ = ASM_ORLO(ASM_REG_O0, id, ASM_REG_O0);
	} else
		*instr++ = ASM_ORSIMM13(ASM_REG_G0, id, ASM_REG_O0);

	if (nargs >= 1)
		*instr++ = ASM_MOV(ASM_REG_I0, ASM_REG_O1);
	if (nargs >= 2)
		*instr++ = ASM_MOV(ASM_REG_I1, ASM_REG_O2);
	if (nargs >= 3)
		*instr++ = ASM_MOV(ASM_REG_I2, ASM_REG_O3);
	if (nargs >= 4)
		*instr++ = ASM_MOV(ASM_REG_I3, ASM_REG_O4);
	if (nargs >= 5)
		*instr++ = ASM_MOV(ASM_REG_I4, ASM_REG_O5);

	*instr = ASM_CALL(instr, dtrace_probe);
        instr++;

	*instr++ = ASM_NOP;

	if ((uintptr_t)fbp->fbp_patchpoint > (uintptr_t)ASM_SIMM13_MAX) {
		*instr++ = ASM_SETHI(
				(uintptr_t)fbp->fbp_patchpoint, ASM_REG_O7
			   );
		*instr++ = ASM_ORLO(ASM_REG_O7, (uintptr_t)fbp->fbp_patchpoint,
				    ASM_REG_O7);
	} else
		*instr++ = ASM_ORSIMM13(ASM_REG_G0,
					(uintptr_t)fbp->fbp_patchpoint,
                                        ASM_REG_O7);

	*instr++ = ASM_RETL;
	*instr++ = ASM_NOP;

	fbp->fbp_patchval = ASM_CALL(fbp->fbp_patchpoint, trampoline);
	fbp->fbp_savedval = *fbp->fbp_patchpoint;
	fbp->fbp_isret = 0;
}

/*
 * This function should always succeed as we have removed all problematic cases
 * in advance.
 */
static void add_return_tramp(fbt_probe_t *fbp, int stype)
{
	struct module	*mp = fbp->fbp_module;
	dtrace_id_t	id = fbp->fbp_id;
	uint64_t	roffset = fbp->fbp_roffset;
	size_t		idx = PDATA(mp)->fbt_probe_cnt;
	asm_instr_t	*trampoline = &(PDATA(mp)->fbt_tab[idx *
							   FBT_TRAMP_SIZE]);
	asm_instr_t	*instr = trampoline;
	asm_instr_t	instr_ret = *fbp->fbp_patchpoint;
	asm_instr_t	instr_delay = *(fbp->fbp_patchpoint + 1);

	uint32_t	locals[ASM_REG_NLOCALS];
	uint32_t	local, tmpreg, saved_g1, saved_g2;

	/*
	 * The RETURN case is bit more complex compared to others. The RETURN
	 * performs ret and restore at the same time. Thus the instruction in
	 * delay slot operates on callers register window. In case there is
	 * something else than NOP in the delay slot we have to do following:
	 *
	 *     1) RESTORE
	 *     2) Execute Delay slot
	 *     3) SAVE
	 *     4) Handle probe
	 *     5) Simulate return by pair of ret/restore
	 */
	if (ASM_FMT3_OP(instr_ret) == ASM_OP_RETURN) {
		if (instr_delay != ASM_NOP) {
			*instr++ = ASM_RESTORE(ASM_REG_G0, ASM_REG_G0, ASM_REG_G0);
			*instr++ = instr_delay;
			*instr++ = ASM_SAVEIMM(ASM_REG_O6, -ASM_MINFRAME, ASM_REG_O6);
		}

		/* This is safe as we support only return %i7 + 8. */
		instr_ret = ASM_RET;
		instr_delay = ASM_RESTORE(ASM_REG_G0, ASM_REG_G0, ASM_REG_G0);
	}

	/*
	 * Now we need to remap arguments so we use safe location that is not
	 * destroyed during call to dtrace_probe(). This is done in multiple steps:
	 *
	 *     1) Mark currently used locals
	 *     2) Move non-locals to unused locals
	 *     3) Update instruction to use locals only
	 */
	ASM_REG_INITLOCALS(local, locals);

	/* Only JMPL needs extra care here. */
	if (ASM_FMT3_OP(instr_ret) == ASM_OP_JMPL) {
		ASM_REG_MARKLOCAL(locals, ASM_FMT3_RS1(instr_ret));
		if (!ASM_FMT3_ISIMM(instr_ret)) {
			ASM_REG_MARKLOCAL(locals, ASM_FMT3_RS2(instr_ret));
		}
	}

	/* At this point isntr_delay can hold RESTORE only. */
	ASM_REG_MARKLOCAL(locals, ASM_FMT3_RS1(instr_delay));
	if (!ASM_FMT3_ISIMM(instr_delay)) {
		ASM_REG_MARKLOCAL(locals, ASM_FMT3_RS2(instr_delay));
	}

	/* Remap */
	if (ASM_FMT3_OP(instr_ret) == ASM_OP_JMPL) {
		tmpreg = ASM_FMT3_RS1(instr_ret);

		if (ASM_REG_ISVOLATILE(tmpreg)) {
			ASM_REG_ALLOCLOCAL(local, locals);
			*instr++ = ASM_MOV(tmpreg, local);
			ASM_FMT3_RS1_SET(instr_ret, local);
		}

		if (!ASM_FMT3_ISIMM(instr_ret)) {
			tmpreg = ASM_FMT3_RS2(instr_ret);

			if (ASM_REG_ISVOLATILE(tmpreg)) {
				ASM_REG_ALLOCLOCAL(local, locals);
				*instr++ = ASM_MOV(tmpreg, local);
				ASM_FMT3_RS2_SET(instr_ret, local);
			}
		}
	}

	tmpreg = ASM_FMT3_RS1(instr_delay);
	if (ASM_REG_ISVOLATILE(tmpreg)) {
		ASM_REG_ALLOCLOCAL(local, locals);
		*instr++ = ASM_MOV(tmpreg, local);
		ASM_FMT3_RS1_SET(instr_delay, local);
	}

	if (!ASM_FMT3_ISIMM(instr_delay)) {
		tmpreg = ASM_FMT3_RS2(instr_delay);

		if (ASM_REG_ISVOLATILE(tmpreg)) {
			ASM_REG_ALLOCLOCAL(local, locals);
			*instr++ = ASM_MOV(tmpreg, local);
			ASM_FMT3_RS2_SET(instr_delay, local);
		}
	}

	/* backup globals */
	ASM_REG_ALLOCLOCAL(local, locals);
	saved_g1 = local;
	*instr++ = ASM_MOV(ASM_REG_G1, saved_g1);
	ASM_REG_ALLOCLOCAL(local, locals);
	saved_g2 = local;
	*instr++ = ASM_MOV(ASM_REG_G2, saved_g2);

	/* prepare arguments */
	if (id > (uint32_t)ASM_SIMM13_MAX) {
		*instr++ = ASM_SETHI(id, ASM_REG_O0);
		*instr++ = ASM_ORLO(ASM_REG_O0, id, ASM_REG_O0);
	} else {
		*instr++ = ASM_ORSIMM13(ASM_REG_G0, id, ASM_REG_O0);
	}

	if (roffset > (uint32_t)ASM_SIMM13_MAX) {
		*instr++ = ASM_SETHI(roffset, ASM_REG_O1);
		*instr++ = ASM_ORLO(ASM_REG_O1, roffset, ASM_REG_O1);
	} else {
		*instr++ = ASM_ORSIMM13(ASM_REG_G0, roffset, ASM_REG_O1);
	}

	/* fire probe */
	*instr = ASM_CALL(instr, dtrace_probe);
	instr++;

	/* recover return value */
	if (ASM_FMT3_RD(instr_delay) == ASM_REG_O0) {
		uint32_t instr_add = (instr_delay & ~ASM_FMT3_OP_MASK) |
				     ASM_OP_ADD;
		instr_add = (instr_add & ~ASM_FMT3_RD_MASK) |
			    (ASM_REG_O2 << ASM_FMT3_RD_SHIFT);
		*instr++ = instr_add;
	} else {
		*instr++ = ASM_MOV(ASM_REG_I0, ASM_REG_O2);
	}

	/* restore globals */
	*instr++ = ASM_MOV(saved_g1, ASM_REG_G1);
	*instr++ = ASM_MOV(saved_g2, ASM_REG_G2);

	/*
	 * Emit original instruction return pair. In case of call update it's
	 * label to correct value.
	 */
	if (ASM_FMT1_OP(instr_ret) == ASM_OP_CALL) {
		asm_instr_t *dest = fbp->fbp_patchpoint + ASM_FMT1_DISP30(instr_ret);
		*instr = ASM_CALL(instr, dest);
		instr++;
	} else {
		*instr++ = instr_ret;
	}
	*instr++ = instr_delay;

	fbp->fbp_patchval = ASM_TA(0x75);
	fbp->fbp_savedval = *fbp->fbp_patchpoint;
	fbp->fbp_isret = 1;
	fbp->fbp_trampdest = trampoline;
}

void fbt_provide_probe_arch(fbt_probe_t *fbp, int type, int stype)
{
	switch (type) {
	case FBT_ENTRY:
		add_entry_tramp(fbp, stype);
		break;
	case FBT_RETURN:
		add_return_tramp(fbp, stype);
		break;
	default:
		pr_info("%s: %s: Unknown FBT type %d\n",
			__func__, fbp->fbp_name, type);
		return;
	}
}

/*
 * We filetered out unsupported return probes (DCTIs, PC-relative instructions
 * in the delay slot) in kernel. Rest of the logic is in the module to give us
 * flexibility when we need to alter the logic later.
 *
 * At the moment we rely on the fact that every supported function has SAVE in
 * its prologue. Thus there is no need to support RETL stuff. A call to probe
 * may destroy globals and outs so they are not supported. It is in theory
 * possible to support RETL but current mechanism of FBT guarantees it is going
 * to destroy value in %o7 but that would need bigger changes to how we allocate
 * trampolines.
 *
 * Possible return cases:
 *
 *   1) ret/restore
 *   2) return/delay
 *   3) call/restore
 *
 * The function assumes that it is safe to touch instruction at (addr + 1) to
 * access delay slot.
 */
int fbt_can_patch_return_arch(asm_instr_t *addr)
{
	int	rd;

	/* RETURN %i7, 8*/
	if (ASM_FMT3_OP(*addr) == ASM_OP_RETURN &&
	    *addr == ASM_RETURN(ASM_REG_I7, 8)) {
		return 1;
	}

	/* RESTORE in delay */
	if (ASM_FMT3_OP(*(addr + 1)) != ASM_OP_RESTORE)
		return 0;

	/* CALL */
	if (ASM_FMT1_OP(*addr) == ASM_OP_CALL)
		return 1;

	/* JMPL %i7 + 8, %g0 */
	if (ASM_FMT3_OP(*addr) != ASM_OP_JMPL)
		return 0;

	rd = ASM_FMT3_RD(*addr);
	if (rd == ASM_REG_G0 || rd == ASM_REG_I7)
		return 1;

	/* unsupported */
	return 0;
}

static void *fbt_count_probe(struct module *mp, char *func, int type,
			     int stype, asm_instr_t *addr, uint64_t offset,
			     void *pfbt, void *arg)
{
	static int dummy;
	size_t *count = arg;

	switch (type) {
	case FBT_ENTRY:
		(*count)++;
		return NULL;
	case FBT_RETURN:
		if (!fbt_can_patch_return_arch(addr))
			return pfbt;

		(*count)++;
		if (pfbt == NULL)
			return &dummy;
		return pfbt;
	default:
		printk(KERN_INFO "FBT: Invalid probe type %d (%d) for %s\n",
		       type, stype, func);
		return NULL;
	}
}

int fbt_provide_module_arch(void *arg, struct module *mp)
{
	size_t probe_cnt = 0;

	/* First estimate the size of trampoline we need */
	dtrace_fbt_init((fbt_add_probe_fn)fbt_count_probe, mp, &probe_cnt);

	if (probe_cnt > 0 && PDATA(mp)->fbt_tab == NULL) {
		asm_instr_t *tramp = dtrace_alloc_text(mp, probe_cnt *
						       FBT_TRAMP_SIZE *
						       sizeof (asm_instr_t));

		if (tramp == NULL) {
			printk(KERN_INFO "FBT: can't allocate FBT trampoline"
			       " for %s\n", mp->name);
			return 0;
		}

		PDATA(mp)->fbt_tab = tramp;
		return 1;
	}

	return 0;
}

void fbt_destroy_module(void *arg, struct module *mp)
{
	if (PDATA(mp)->fbt_tab != NULL) {
		dtrace_free_text(PDATA(mp)->fbt_tab);
		PDATA(mp)->fbt_tab = NULL;
	}
}

void fbt_enable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	*fbp->fbp_patchpoint = fbp->fbp_patchval;
	flushi(fbp->fbp_patchpoint);
}

void fbt_disable_arch(fbt_probe_t *fbp, dtrace_id_t id, void *arg)
{
	*fbp->fbp_patchpoint = fbp->fbp_savedval;
	flushi(fbp->fbp_patchpoint);
}

static void fbt_handler(struct pt_regs *regs)
{
	fbt_probe_t	*fbp = fbt_probetab[FBT_ADDR2NDX(regs->tpc)];

	for(; fbp != NULL; fbp = fbp->fbp_hashnext) {
		if ((uintptr_t)fbp->fbp_patchpoint == regs->tpc) {
			regs->tpc = (uintptr_t)fbp->fbp_trampdest;
			regs->tnpc = regs->tpc + 4;

			return;
		}
	}

	/*
	 * The only way that ends here is that we hit our trap in kernel mode.
	 * The trap is not shared with anyone else so it means we have lost a
	 * tracpoint somehow. We must die as there is no safe way how we could
	 * restore original instruction stream.
	 */
	dtrace_panic(KERN_EMERG, "FBT trap without a probe at %p",
		     regs->tpc);
}

int fbt_dev_init_arch(void)
{
	fbt_probetab_mask = fbt_probetab_size - 1;
	fbt_probetab = dtrace_vzalloc_try(fbt_probetab_size *
					  sizeof (fbt_probe_t *));

	if (fbt_probetab == NULL)
		return -ENOMEM;

	return dtrace_fbt_set_handler(fbt_handler);
}

void fbt_dev_exit_arch(void)
{
	vfree(fbt_probetab);
	fbt_probetab_mask = 0;
	fbt_probetab_size = 0;

	(void) dtrace_fbt_set_handler(NULL);
}
