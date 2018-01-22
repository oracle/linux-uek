// SPDX-License-Identifier: GPL-2.0
/* System call table for x86-64. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <asm/asm-offsets.h>
#include <asm/syscall.h>

#define __SYSCALL_64_QUAL_(sym) sym
#define __SYSCALL_64_QUAL_ptregs(sym) ptregs_##sym

#define __SYSCALL_64(nr, sym, qual) extern asmlinkage long __SYSCALL_64_QUAL_##qual(sym)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
#include <asm/syscalls_64.h>
#undef __SYSCALL_64

#define __SYSCALL_64(nr, sym, qual) [nr] = __SYSCALL_64_QUAL_##qual(sym),

extern long sys_ni_syscall(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);

#if defined(CONFIG_DT_SYSTRACE) || defined(CONFIG_DT_SYSTRACE_MODULE)
asmlinkage sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
#else
asmlinkage const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
#endif /* CONFIG_DT_SYSTRACE || CONFIG_DT_SYSTRACE_MODULE */
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_syscall_max] = &sys_ni_syscall,
#include <asm/syscalls_64.h>
};
