/*
 * FILE:	dtrace_util.c
 * DESCRIPTION:	Dynamic Tracing: Architecture utility functions
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/dtrace_cpu.h>
#include <linux/dtrace_os.h>
#include <linux/kdebug.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <asm/switch_to.h>

void dtrace_skip_instruction(struct pt_regs *regs)
{
	regs->tpc = regs->tnpc;
	regs->tnpc += 4;
}

void dtrace_handle_badaddr(struct pt_regs *regs) {
	unsigned long	addr = current_thread_info()->fault_address;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
	this_cpu_core->cpuc_dtrace_illval = addr;

	dtrace_skip_instruction(regs);
}

int dtrace_die_notifier(struct notifier_block *nb, unsigned long val,
			void *args)
{
	struct die_args		*dargs = args;

	switch (val) {
	case DIE_PAGE_FAULT: {
		if (!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))
			return NOTIFY_DONE;

		dtrace_handle_badaddr(dargs->regs);

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}
	case DIE_GPF: {
		if (!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))
			return NOTIFY_DONE;

		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);

		dtrace_skip_instruction(dargs->regs);

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}
	case DIE_TRAP: {
		if (dargs->trapnr != 0x34 && dargs->trapnr != 0x08)
			return NOTIFY_DONE;

		if (!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))
			return NOTIFY_DONE;

		dtrace_handle_badaddr(dargs->regs);

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}
	case DIE_OOPS: {
		printk("DTrace: probe ctx %d last probe %ld\n",
		       !!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_PROBE_CTX),
		       this_cpu_core->cpu_dtrace_caller);
		return NOTIFY_DONE;
	}
	default:
		return NOTIFY_DONE;
	}
}

int dtrace_user_addr_is_exec(uintptr_t addr)
{
	struct mm_struct	*mm = current->mm;
	pgd_t			pgd;
	pud_t			pud;
	pmd_t			pmd;
	unsigned long		flags;
	int			ret = 0;

	if (mm == NULL)
		return 0;

	addr &= PAGE_MASK;

	local_irq_save(flags);

	pgd = *pgd_offset(mm, addr);
	if (pgd_none(pgd))
		goto out;

	pud = *pud_offset(&pgd, addr);
	if (pud_none(pud))
		goto out;

	pmd = *pmd_offset(&pud, addr);
	if (pmd_none(pmd))
		goto out;
	if (unlikely(pmd_large(pmd))) {
		/* not sure how to do this */
		goto out;
	} else {
		pte_t	pte;

		pte = *pte_offset_kernel(&pmd, addr);

		ret = pte_exec(pte);
	}

out:
	local_irq_restore(flags);

	return ret;
}
EXPORT_SYMBOL(dtrace_user_addr_is_exec);

void dtrace_user_stacktrace(stacktrace_state_t *st)
{
	struct thread_info	*t = current_thread_info();
	struct pt_regs		*regs = current_pt_regs();
	uint64_t		*pcs = st->pcs;
	int			limit = st->limit;
	unsigned long		window;
	unsigned long		sp = user_stack_pointer(regs);
	int			ret;

	if (!user_mode(regs))
		goto out;

	flush_user_windows();

	st->depth = 1;
	if (pcs)
		*pcs++ = (uint64_t)instruction_pointer(regs);
	limit--;

	if (!limit)
		goto out;

	if (test_thread_flag(TIF_32BIT))
		sp = (uint32_t)sp;

	/*
	 * First we have to process all user windows that have not been flushed
	 * to the stack save area.
	 */
	window = get_thread_wsaved();
	while (window--) {
		unsigned long	addr;

		sp = t->rwbuf_stkptrs[window];

		if (test_thread_64bit_stack((unsigned long)sp)) {
			addr = t->reg_window[window].ins[7];
		} else {
			addr = ((struct reg_window32 *)(&t->reg_window[window]))->ins[7];
		}

		if (pcs)
			*pcs++ = addr;
		limit--;
		st->depth++;

		if (!limit)
			goto out;

		/* Grab %fp so we can continue iteration on stack. */
		if (window == 0) {
			if (test_thread_64bit_stack((unsigned long)sp)) {
				sp = t->reg_window[window].ins[6];
			} else {
				sp = ((struct reg_window32 *)(&t->reg_window[window]))->ins[6];
			}
		}
	}

	/* continue iteration on the stack */
	while ((sp != 0 || sp != STACK_BIAS) && limit > 0) {
		unsigned long addr;

		pagefault_disable();
		if (test_thread_64bit_stack(sp)) {
			ret = __copy_from_user_inatomic(&addr, (unsigned long *)(sp + STACK_BIAS + SF_V9_PC),
							sizeof(addr));
		} else {
			unsigned int addr32;

			ret = __copy_from_user_inatomic(&addr32, (unsigned int *)(sp + SF_PC), sizeof(addr32));
			addr = addr32;
		}
		pagefault_enable();

		if (ret)
			break;

		if (pcs)
			*pcs++ = addr;
		limit--;
		st->depth++;

		pagefault_disable();
		if (test_thread_64bit_stack(sp)) {
			ret = __copy_from_user_inatomic(&sp, (unsigned long *)(sp + STACK_BIAS + SF_V9_FP),
							sizeof (sp));
		} else {
			unsigned int sp_tmp;

			ret = __copy_from_user_inatomic(&sp_tmp, (unsigned int *)(sp + SF_FP), sizeof (sp_tmp));
			sp = sp_tmp;
		}
		pagefault_enable();

		if (ret)
			break;
	}

out:
	if (pcs) {
		while (limit--)
			*pcs++ = 0;
	}
}
