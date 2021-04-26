// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/mm.h>
#include <asm/current.h>
#include <asm/traps.h>
#include <asm/vdso.h>

struct vdso_exception_table_entry {
	int insn, fixup;
};

bool fixup_vdso_exception(struct pt_regs *regs, int trapnr,
			  unsigned long error_code, unsigned long fault_addr)
{
	const struct vdso_image *image = current->mm->context.vdso_image;
	const struct vdso_image_ext *image_ext;
	const struct vdso_exception_table_entry *extable;
	unsigned int nr_entries, i;
	unsigned long base;

	/*
	 * Do not attempt to fixup #DB or #BP.  It's impossible to identify
	 * whether or not a #DB/#BP originated from within an SGX enclave and
	 * SGX enclaves are currently the only use case for vDSO fixup.
	 */
	if (trapnr == X86_TRAP_DB || trapnr == X86_TRAP_BP)
		return false;

	if (!current->mm->context.vdso)
		return false;

	/* use vdso_image_ext structure to access the extended members */
#ifdef CONFIG_X86_64
	if (image == &vdso_image_64)
		image_ext = &vdso_image_64_ext;
#endif

#ifdef CONFIG_X86_X32
	if (image == &vdso_image_x32)
		image_ext = &vdso_image_x32_ext;
#endif

#if defined CONFIG_X86_32 || defined CONFIG_COMPAT
	if (image == &vdso_image_32)
		image_ext = &vdso_image_32_ext;
#endif

	if (!image_ext){
		WARN_ONCE(true, "Cannot find extended vdso image structure for image address %p\n",
			  image);
		return false;
	}

	base =  (unsigned long)current->mm->context.vdso + image_ext->extable_base;
	nr_entries = image_ext->extable_len / (sizeof(*extable));
	extable = image_ext->extable;

	for (i = 0; i < nr_entries; i++) {
		if (regs->ip == base + extable[i].insn) {
			regs->ip = base + extable[i].fixup;
			regs->di = trapnr;
			regs->si = error_code;
			regs->dx = fault_addr;
			return true;
		}
	}

	return false;
}
