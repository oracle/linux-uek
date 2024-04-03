// SPDX-License-Identifier: GPL-2.0
/* System call table for i386. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <asm/asm-offsets.h>
#include <asm/syscall.h>

#ifdef CONFIG_IA32_EMULATION
/* On X86_64, we use struct pt_regs * to pass parameters to syscalls */
#define __SYSCALL_I386(nr, sym, qual) extern asmlinkage long sym(const struct pt_regs *);
#define __sys_ni_syscall __ia32_sys_ni_syscall
#else /* CONFIG_IA32_EMULATION */
#define __SYSCALL_I386(nr, sym, qual) extern asmlinkage long sym(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
extern asmlinkage long sys_ni_syscall(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
#define __sys_ni_syscall sys_ni_syscall
#endif /* CONFIG_IA32_EMULATION */

#include <asm/syscalls_32.h>
#undef __SYSCALL_I386

/*
 * The sys_call_table[] is no longer used for system calls, but
 * kernel/trace/trace_syscalls.c still wants to know the system
 * call address.
 */
#ifdef CONFIG_X86_32
#define __SYSCALL_I386(nr, sym, qual) [nr] = sym,

const sys_call_ptr_t sys_call_table[__NR_syscall_compat_max+1] = {
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_syscall_compat_max] = &__sys_ni_syscall,
#include <asm/syscalls_32.h>
};
#undef __SYSCALL_I386
#endif

#ifdef CONFIG_IA32_EMULATION
#define __SYSCALL_I386(nr, sym, qual) case nr: return sym(regs);
long ia32_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	switch (nr) {
	#include <asm/syscalls_32.h>
	default: return __sys_ni_syscall(regs);
	}
};
#else /* CONFIG_IA32_EMULATION */
#define __SYSCALL_I386(nr, sym, qual) case nr: return sym(bx, cx, dx, si, di, bp);
long ia32_sys_call(unsigned long bx, unsigned long cx, unsigned long dx,
		   unsigned long si, unsigned long di, unsigned long bp,
		   int nr)
{
	switch (nr) {
	#include <asm/syscalls_32.h>
	default: return __sys_ni_syscall(bx, cx, dx, si, di, bp);
	}
};
#endif /* CONFIG_IA32_EMULATION */

#undef __SYSCALL_I386
