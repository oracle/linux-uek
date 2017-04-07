/*
 * FILE:        dtrace_fbt.c
 * DESCRIPTION: Dynamic Tracing: FBT registration code (arch-specific)
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/kdebug.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/context_tracking.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_fbt.h>
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <asm/bug.h>
#include <asm/dtrace_arch.h>
#include <asm/sections.h>

#define ASM_REG_G0		0
#define ASM_REG_G1		1
#define ASM_REG_O0		8
#define ASM_REG_O1		9
#define ASM_REG_O2		10
#define ASM_REG_O3		11
#define ASM_REG_O4		12
#define ASM_REG_O5		13
#define ASM_REG_O6		14
#define ASM_REG_O7		15
#define ASM_REG_I0		24
#define ASM_REG_I1		25
#define ASM_REG_I2		26
#define ASM_REG_I3		27
#define ASM_REG_I4		28
#define ASM_REG_I7		31
#define ASM_REG_L0		16
#define ASM_REG_L1		17
#define ASM_REG_L2		18
#define ASM_REG_L3		19
#define ASM_REG_PC		5

#define ASM_REG_ISOUTPUT(r)	((r) >= 8 && (r) < 16)
#define ASM_REG_ISINPUT(r)	((r) >= 24 && (r) < 32)

#define ASM_OP_MASK		0xc0000000
#define ASM_OP_SHIFT		30
#define ASM_OP(val)		((val) & ASM_OP_MASK)

#define ASM_SIMM13_MASK		0x1fff
#define ASM_SIMM13_MAX		((int32_t)0xfff)
#define ASM_IMM22_MASK		0x3fffff
#define ASM_IMM22_SHIFT		10

#define ASM_OP0			(((uint32_t)0) << ASM_OP_SHIFT)
#define ASM_OP1			(((uint32_t)1) << ASM_OP_SHIFT)
#define ASM_OP2			(((uint32_t)2) << ASM_OP_SHIFT)

#define ASM_FMT3_OP3_SHIFT	19
#define ASM_FMT3_OP_MASK	0xc1f80000
#define ASM_FMT3_OP(val)	((val) & ASM_FMT3_OP_MASK)

#define ASM_FMT3_RD_SHIFT	25
#define ASM_FMT3_RD_MASK	(0x1f << ASM_FMT3_RD_SHIFT)
#define ASM_FMT3_RD(val)						      \
	(((val) & ASM_FMT3_RD_MASK) >> ASM_FMT3_RD_SHIFT)

#define ASM_FMT3_RS1_SHIFT	14
#define ASM_FMT3_RS1_MASK	(0x1f << ASM_FMT3_RS1_SHIFT)
#define ASM_FMT3_RS1(val)						      \
	(((val) & ASM_FMT3_RS1_MASK) >> ASM_FMT3_RS1_SHIFT)
#define ASM_FMT3_RS1_SET(val, rs1)					      \
	(val) = ((val) & ~ASM_FMT3_RS1_MASK) | ((rs1) << ASM_FMT3_RS1_SHIFT)

#define ASM_FMT3_RS2_SHIFT	0
#define ASM_FMT3_RS2_MASK	(0x1f << ASM_FMT3_RS2_SHIFT)
#define ASM_FMT3_RS2(val)						      \
	(((val) & ASM_FMT3_RS2_MASK) >> ASM_FMT3_RS2_SHIFT)
#define ASM_FMT3_RS2_SET(val, rs2)					      \
	(val) = ((val) & ~ASM_FMT3_RS2_MASK) | ((rs2) << ASM_FMT3_RS2_SHIFT)

#define ASM_FMT3_IMM_SHIFT	13
#define ASM_FMT3_IMM		(1 << ASM_FMT3_IMM_SHIFT)
#define ASM_FMT3_SIMM13_MASK	ASM_SIMM13_MASK

#define ASM_FMT3_ISIMM(val)	((val) & ASM_FMT3_IMM)
#define ASM_FMT3_SIMM13(val)	((val) & ASM_FMT3_SIMM13_MASK)

#define ASM_FMT2_OP2_SHIFT	22
#define ASM_FMT2_OP2_MASK	(0x7 << ASM_FMT2_OP2_SHIFT)
#define ASM_FMT2_RD_SHIFT	25

#define ASM_FMT2_OP2_BPCC	(0x01 << ASM_FMT2_OP2_SHIFT)
#define ASM_FMT2_OP2_BCC	(0x02 << ASM_FMT2_OP2_SHIFT)
#define ASM_FMT2_OP2_BPR	(0x03 << ASM_FMT2_OP2_SHIFT)
#define ASM_FMT2_OP2_SETHI	(0x04 << ASM_FMT2_OP2_SHIFT)

#define ASM_FMT2_COND_SHIFT	25
#define ASM_FMT2_COND_BA	(0x8 << ASM_FMT2_COND_SHIFT)
#define ASM_FMT2_COND_BL	(0x3 << ASM_FMT2_COND_SHIFT)
#define ASM_FMT2_COND_BGE	(0xb << ASM_FMT2_COND_SHIFT)

#define ASM_OP_SAVE		(ASM_OP2 | (0x3c << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_JMPL		(ASM_OP2 | (0x38 << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_RETURN		(ASM_OP2 | (0x39 << ASM_FMT3_OP3_SHIFT))
#define ASM_OP_SETHI		(ASM_OP0 | ASM_FMT2_OP2_SETHI)
#define ASM_OP_RD		(ASM_OP2 | (0x28 << ASM_FMT3_OP3_SHIFT))

#define ASM_SETHI(val, reg)						      \
	(ASM_OP_SETHI | (reg << ASM_FMT2_RD_SHIFT) |			      \
	 ((val >> ASM_IMM22_SHIFT) & ASM_IMM22_MASK))

#define ASM_NOP			ASM_SETHI(0, 0)

/*
 * We're only going to treat a save as safe if
 *   (a) both rs1 and rd are %sp and
 *   (b) if the instruction has a simm, the value isn't 0.
 */
#define ASM_IS_SAVE(instr)						      \
	(ASM_FMT3_OP(instr) == ASM_OP_SAVE &&				      \
	 ASM_FMT3_RD(instr) == ASM_REG_O6 &&				      \
	 ASM_FMT3_RS1(instr) == ASM_REG_O6 &&				      \
	 !(ASM_FMT3_ISIMM(instr) && ASM_FMT3_SIMM13(instr) == 0))

#define ASM_IS_RDPC(instr)	((ASM_FMT3_OP(instr) == ASM_OP_RD) &&	      \
				 (ASM_FMT3_RD(instr) == ASM_REG_PC))

#define ASM_IS_PCRELATIVE(instr)					      \
        ((((instr) & ASM_OP_MASK) == ASM_OP0 &&				      \
	  ((instr) & ASM_FMT2_OP2_MASK) != ASM_FMT2_OP2_SETHI) ||	      \
	 ((instr) & ASM_OP_MASK) == ASM_OP1 ||				      \
	 ASM_IS_RDPC(instr))

#define ASM_IS_CTI(instr)						      \
	((((instr) & ASM_OP_MASK) == ASM_OP0 &&				      \
	  ((instr) & ASM_FMT2_OP2_MASK) != ASM_FMT2_OP2_SETHI) ||	      \
	 ((instr) & ASM_OP_MASK) == ASM_OP1 ||				      \
	 (ASM_FMT3_OP(instr) == ASM_OP_JMPL) ||				      \
	 (ASM_FMT3_OP(instr) == ASM_OP_RETURN))

#define ASM_IS_NOP(instr)	((instr) == ASM_NOP)

#define ASM_MOD_INPUTS(instr)	(ASM_OP(instr) == ASM_OP2 &&		      \
				 ASM_REG_ISINPUT(ASM_FMT3_RD(instr)))
#define ASM_MOD_OUTPUTS(instr)	(ASM_OP(instr) == ASM_OP2 &&		      \
				 ASM_REG_ISOUTPUT(ASM_FMT3_RD(instr)))

#define BL_SENTRY(tp, nm)	extern tp nm;
#define BL_DENTRY(tp, nm)
#include "fbt_blacklist.h"
#undef BL_DENTRY
#undef BL_SENTRY

static void
dtrace_fbt_populate_bl(void)
{
#define BL_SENTRY(tp, nm)	dtrace_fbt_bl_add((unsigned long)&nm, __stringify(nm));
#define BL_DENTRY(tp, nm)	dtrace_fbt_bl_add(0, __stringify(nm));
#include "fbt_blacklist.h"
#undef BL_DENTRY
#undef BL_SENTRY
};

void dtrace_fbt_init(fbt_add_probe_fn fbt_add_probe, struct module *mp,
		     void *arg)
{
	loff_t			pos;
	struct kallsym_iter	sym;
	asm_instr_t		*paddr = NULL;
	dt_fbt_bl_entry_t	*blent = NULL;

	/*
	 * Look up any unresolved symbols in the blacklist, and sort the list
	 * by ascending address.
	 */
	dtrace_fbt_populate_bl();
	blent = dtrace_fbt_bl_first();

	pos = 0;
	kallsyms_iter_reset(&sym, 0);
	while (kallsyms_iter_update(&sym, pos++)) {
		asm_instr_t	*addr, *end, *ins;
		void *fbtp = NULL;

		/*
		 * There is no point considering non-function symbols for FBT,
		 * or symbols that have a zero size.  We could consider weak
		 * symbols but that gets quite complicated and there is no
		 * demands for that (so far).
		 */
		if (sym.type != 'T' && sym.type != 't')
			continue;
		if (!sym.size)
			continue;

		/*
		 * The symbol must be at a properly aligned address.
		 */
		if (!IS_ALIGNED(sym.value, 4))
			continue;

		/*
		 * Handle only symbols that belong to the module we have been
		 * asked for.
		 */
		if (mp == dtrace_kmod && !core_kernel_text(sym.value))
			continue;

		/*
		 * Ensure we have not been given .init symbol from kallsyms
		 * interface. This could lead to memory corruption once DTrace
		 * tries to enable probe in already freed memory.
		 */
		if (mp != dtrace_kmod && !within_module_core(sym.value, mp))
			continue;

		/*
		 * See if the symbol is on the FBT's blacklist.  Since both
		 * iterators are workng in sort order by ascending address we
		 * can use concurrent traversal.
		 */
		while (blent != NULL &&
		       dtrace_fbt_bl_entry_addr(blent) < sym.value) {
			blent = dtrace_fbt_bl_next(blent);
		}
		if (dtrace_fbt_bl_entry_addr(blent) == sym.value)
			continue;

		/*
		 * No FBT tracing for DTrace functions.  Also weed out symbols
		 * that are not relevant here.
		 */
		if (strncmp(sym.name, "dtrace_", 7) == 0)
			continue;
		if (strncmp(sym.name, "_GLOBAL_", 8) == 0)
			continue;
		if (strncmp(sym.name, "do_", 3) == 0)
			continue;
		if (!sym.size)
			continue;

		addr = (asm_instr_t *)sym.value;
		end = (asm_instr_t *)(sym.value + sym.size);

		/*
		 * When there are multiple symbols for the same address we
		 * should link them together as probes that are associated with
		 * the same function.  When a probe for that function is
		 * triggered, all the associated probes should fire.
		 *
		 * For now, we're ignoring all but the first symbol...
		 */
		if (addr == paddr)
			continue;
		paddr = addr;

		if (ASM_IS_SAVE(*addr)) {
			/*
			 * If there are other saves, this function has multiple
			 * entry points or some other complex construct - we'll
			 * skip it.
			 */
			ins = addr;
			while (++ins < end) {
				if (ASM_IS_SAVE(*ins))
					break;
			}
			if (ins != end)
				continue;

			/*
			 * What we are really looking for is a sequence like:
			 *	save %sp, <num>, %sp
			 *	call _mcount
			 *	nop
			 * but due to ftrace patching in executable code, that
			 * call actually gets rewritten as a NOP before we even
			 * get to looking at it.  We depend on ftrace already
			 * to get a count of functions that are potential
			 * candidates for FBT.
			 */
			if (!ASM_IS_NOP(*(addr + 1)))
				continue;

			/*
			 * We should be OK as long as the instruction in the
			 * delay slot after the call to the trampoline does not
			 * modify input or output registers.
			 */
			if (!ASM_IS_NOP(*(addr + 2)) &&
			    (ASM_MOD_INPUTS(*(addr + 2)) ||
			     ASM_MOD_OUTPUTS(*(addr + 2))))
				continue;

			fbt_add_probe(mp, sym.name, FBT_ENTRY, 32,
				      addr + 1, 0, NULL, arg);
		} else
			continue;

		/* Scan function for possible return probes. */
		for (ins = addr; ins + 1 < end; ins++) {

			/* Only CTIs may become return probe. */
			if (!ASM_IS_CTI(*ins))
				continue;

			/*
			 * Check the delay slot for incompatible instructions:
			 *   - DCTI
			 *   - PC relative instruction
			 *
			 * More detailed analysis is performed in the fbt module.
			 */
			if (ASM_IS_CTI(*(ins + 1)))
				continue;

			if (ASM_IS_PCRELATIVE(*(ins + 1)))
				continue;

			/* Create or update the return probe. */
			fbtp = fbt_add_probe(mp, sym.name, FBT_RETURN, 32, ins,
					     (uintptr_t)ins - (uintptr_t)addr,
					     fbtp, arg);
		}
	}
}
EXPORT_SYMBOL(dtrace_fbt_init);

static void (*fbt_handler)(struct pt_regs *) = NULL;

int dtrace_fbt_set_handler(void (*func)(struct pt_regs *))
{
	fbt_handler = func;
	return 0;
}
EXPORT_SYMBOL(dtrace_fbt_set_handler);

asmlinkage void dtrace_fbt_trap(unsigned long traplevel, struct pt_regs *regs)
{
	enum ctx_state prev_state = exception_enter();

	if (user_mode(regs)) {
		local_irq_enable();
		bad_trap(regs, traplevel);
		goto out;
	}

        /*
	 * If we take this trap and fbt_handler is not set we are out of luck.
	 * Since we don't know why the trap fired (it should never happen in
	 * DTrace code unless fbt_handler is set), there is no way of knowing
	 * whether it is safe to just do nothing.
	 */
        BUG_ON(fbt_handler == NULL);

	fbt_handler(regs);

out:
	exception_exit(prev_state);
}
