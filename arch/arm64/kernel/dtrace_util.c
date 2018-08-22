/*
 * FILE:	dtrace_util.c
 * DESCRIPTION:	Dynamic Tracing: Architecture utility functions
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/dtrace_cpu.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_task_impl.h>
#include <linux/kdebug.h>
#include <linux/notifier.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/uprobes.h>
#include <asm/debug-monitors.h>
#include <asm/insn.h>

void dtrace_skip_instruction(struct pt_regs *regs)
{
	instruction_pointer_set(regs, instruction_pointer(regs) + 4);
}

void dtrace_handle_badaddr(struct pt_regs *regs)
{
	unsigned long	addr = current->thread.fault_address;

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

		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		this_cpu_core->cpuc_dtrace_illval = dargs->err;

		dtrace_skip_instruction(dargs->regs);

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}
	case DIE_OOPS: {
		pr_info("DTrace: last probe %u\n",
		       this_cpu_core->cpuc_current_probe);
		return NOTIFY_DONE;
	}
	default:
		return NOTIFY_DONE;
	}
}

struct user_stackframe {
	struct user_stackframe	__user	*fp;
	unsigned long			lr;
} __packed;

static int dtrace_unwind_frame(struct user_stackframe *frame)
{
	struct user_stackframe	__user	*ofp = frame->fp;
	unsigned long			ret;

	/* Verify alignment. */
	if ((unsigned long)ofp & 0xf)
		return -EINVAL;

	/* Verify read access. */
	if (!access_ok(VERIFY_READ, ofp, sizeof(struct user_stackframe)))
		return -EINVAL;

	pagefault_disable();
	ret = __copy_from_user_inatomic(frame, ofp,
					sizeof(struct user_stackframe));
	pagefault_enable();

	/* Make sure the read worked. */
	if (ret) {
		frame->fp = ofp;
		return -EINVAL;
	}

	/* Verify strictly increasing consecutive values.  Since the stack
	 * grows downward, walking the call chain in reverse must yield ever
	 * increasing frame pointers.
	 */
	if (ofp >= frame->fp) {
		if (((uintptr_t)frame->fp & 0xf) &&
		    current->dt_task && current->dt_task->dt_ustack == ofp) {
			frame->fp = NULL;
			return 0;
		}

		return -EINVAL;
	}

	return 0;
}

void dtrace_user_stacktrace(stacktrace_state_t *st)
{
	struct pt_regs		*regs = current_pt_regs();
	uint64_t		*pcs = st->pcs;
	int			limit = st->limit;
	int			fixups, patches, skip;
	struct user_stackframe	frame0, frame;
	struct user_stackframe	*bos = current->dt_task
					? current->dt_task->dt_ustack
					: NULL;
	struct return_instance	*rilist = current->utask
					? current->utask->return_instances
					: NULL;
	struct return_instance	*ri;

	/*
	 * If we do not have user-mode registers, or if there is no known
	 * bottom of stack, we cannot collect a call chain.
	 */
	if (!user_mode(regs))
		goto out;
	if (!bos)
		goto out;
	if (!limit)
		goto out;

	frame0.fp = (struct user_stackframe __user *)regs->regs[29];
	frame0.lr = regs->regs[30];

	/*
	 * The first special situation we need to deal with here is the rare
	 * case of tracing the instruction after a call, when the current
	 * program counter just got loaded from the link register, i.e. they
	 * will be the same.  In that case, we don't want to record both pc
	 * and lr in the trace.
	 *
	 * Uretprobes are also tricky because if we are asked to provide a
	 * ustack() while processing a uretprobe firing, we are still in the
	 * middle of handling the probe.  Things are not back to normal yet.
	 */
	if (regs->pc != frame0.lr) {
		ri = rilist;
		if (pcs) {
			if (uprobe_return_addr_is_hijacked(frame0.lr) &&
			    ri && ri->orig_ret_vaddr == regs->pc)
				*pcs++ = ri->func;
			else
				*pcs++ = regs->pc;
		}

		limit--;
		st->depth++;

		if (!limit)
			goto out;
	}

	/*
	 * First pass: determine how many return addresses need to be fixed up,
	 * and how many return instances we have.
	 */
	frame = frame0;
	fixups = 0;
	do {
		if (uprobe_return_addr_is_hijacked(frame.lr))
			fixups++;

		if (dtrace_unwind_frame(&frame) < 0) {
			this_cpu_core->cpuc_dtrace_illval = (uintptr_t)frame.fp;
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADSTACK);
			break;
		}
	} while (frame.fp);

	patches = 0;
	for (ri = rilist; ri != NULL; ri = ri->next)
		patches++;

	/*
	 * It is possible that we think we need one more fixup than we can
	 * satisfy with the return instances.  This is because we cannot quite
	 * determine whether the first one is actually needed or not (due to
	 * lack of proper state when the uretprobe implementation interferes
	 * with frame chain walking).
	 */
	skip = fixups - patches;
	if (skip > 1) {
		this_cpu_core->cpuc_dtrace_illval = 0;
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADSTACK);
		goto out;
	}

	/*
	 * Second pass: fill in the actual stack trace.
	 */
	frame = frame0;
	ri = rilist;
	do {
		if (uprobe_return_addr_is_hijacked(frame.lr)) {
			if (skip) {
				skip = 0;
				goto skip_frame;
			}

			frame.lr = ri->orig_ret_vaddr;
			ri = ri->next;
		}

		if (pcs)
			*pcs++ = frame.lr;
		limit--;
		st->depth++;

skip_frame:
		if (dtrace_unwind_frame(&frame) < 0) {
			this_cpu_core->cpuc_dtrace_illval = (uintptr_t)frame.fp;
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADSTACK);
			break;
		}
	} while (limit && frame.fp);

out:
	if (pcs) {
		while (limit--)
			*pcs++ = 0;
	}
}

asm_instr_t dtrace_text_peek(asm_instr_t *addr)
{
	asm_instr_t	opcode;

	aarch64_insn_read(addr, &opcode);

	return opcode;
}
EXPORT_SYMBOL(dtrace_text_peek);

void dtrace_text_poke(asm_instr_t *addr, asm_instr_t opcode)
{
	aarch64_insn_patch_text_nosync(addr, opcode);
}
EXPORT_SYMBOL(dtrace_text_poke);

void dtrace_brk_start(void *arg)
{
	register_break_hook((struct break_hook *)arg);
}
EXPORT_SYMBOL(dtrace_brk_start);

void dtrace_brk_stop(void *arg)
{
	unregister_break_hook((struct break_hook *)arg);
}
EXPORT_SYMBOL(dtrace_brk_stop);

void dtrace_mod_pdata_init(dtrace_module_t *pdata)
{
}

void dtrace_mod_pdata_cleanup(dtrace_module_t *pdata)
{
}
