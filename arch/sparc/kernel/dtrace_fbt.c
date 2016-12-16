/*
 * FILE:        dtrace_fbt.c
 * DESCRIPTION: Dynamic Tracing: FBT registration code (arch-specific)
 *
 * Copyright (C) 2010-2016 Oracle Corporation
 */

#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_fbt.h>
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
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
#define ASM_OP_SETHI		(ASM_OP0 | ASM_FMT2_OP2_SETHI)

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

typedef struct _bl_entry {
	void *addr;
	const char *name;
} bl_entry;

static bl_entry blacklist[] = {
#define BL_SENTRY(tp, nm)	{ (void *)&nm, __stringify(nm) },
#define BL_DENTRY(tp, nm)	{ NULL, __stringify(nm) },
#include "fbt_blacklist.h"
#undef BL_DENTRY
#undef BL_SENTRY
};
static int	blacklist_len = ARRAY_SIZE(blacklist);

static int bl_entry_cmp(const void *xx, const void *yy)
{
	bl_entry	*x = (bl_entry *)xx;
	bl_entry	*y = (bl_entry *)yy;

	return x->addr > y->addr ? 1
				 : x->addr < y->addr ? -1 : 0;
}

void dtrace_fbt_init(fbt_add_probe_fn fbt_add_probe)
{
	loff_t			pos;
	struct kallsym_iter	sym;
	size_t			blpos = 0;
	asm_instr_t		*paddr = NULL;

	/*
	 * Look up any unresolved symbols in the blacklist, and sort the list
	 * by ascending address.
	 */
	for (pos = 0; pos < blacklist_len; pos++) {
		bl_entry	*be = &blacklist[pos];

		if (!be->addr)
			be->addr = (void *)kallsyms_lookup_name(be->name);
	}
	sort(blacklist, blacklist_len, sizeof(bl_entry), bl_entry_cmp, NULL);

	pos = 0;
	kallsyms_iter_reset(&sym, 0);
	while (kallsyms_iter_update(&sym, pos++)) {
		asm_instr_t	*addr, *end;

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
		 * Only core kernel symbols are of interest here.
		 */
		if (!core_kernel_text(sym.value))
			continue;

		/*
		 * See if the symbol is on the blacklist.  Since both lists are
		 * sorted by ascending address we can use concurrent traversal
		 * of both lists.
		 */
		while (blpos < blacklist_len &&
		       blacklist[blpos].addr < (void *)sym.value)
			blpos++;

		if (blacklist[blpos].addr == (void *)sym.value)
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
			asm_instr_t	*ins = addr;

			/*
			 * If there are other saves, this function has multiple
			 * entry points or some other complex construct - we'll
			 * skip it.
			 */
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

			fbt_add_probe(dtrace_kmod, sym.name, FBT_ENTRY, 32,
				      addr + 1, NULL);
		} else
			continue;
	}
}
EXPORT_SYMBOL(dtrace_fbt_init);
