/*
 * vmcoreinfo trace extern kexec setup
 *
 * Copyright (C) 2019 Isaac Chen <isaac.chen@oracle.com>
 */
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/crash_core.h>

void trace_extern_vmcoreinfo_setup(void)
{
	/*
	 * The following symbol and offsets are for reading symbols
	 * defined in dynamically loaded modules.
	 */
	VMCOREINFO_SYMBOL(vmcore_modules);
	VMCOREINFO_OFFSET(module, state);
	VMCOREINFO_OFFSET(module, list);
	VMCOREINFO_OFFSET(module, name);
	VMCOREINFO_OFFSET(module, num_syms);
	VMCOREINFO_OFFSET(module, kallsyms);
	VMCOREINFO_OFFSET(mod_kallsyms, symtab);
	VMCOREINFO_OFFSET(mod_kallsyms, num_symtab);
	VMCOREINFO_OFFSET(mod_kallsyms, strtab);
	VMCOREINFO_OFFSET(elf64_sym, st_name);
	VMCOREINFO_OFFSET(elf64_sym, st_info);
	VMCOREINFO_OFFSET(elf64_sym, st_value);
}
