// SPDX-License-Identifier: GPL-2.0
/* System call table for x86-64. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/syscalls.h>
#include <asm/asm-offsets.h>
#include <asm/syscall.h>

extern asmlinkage long sys_ni_syscall(void);

SYSCALL_DEFINE0(ni_syscall)
{
	return sys_ni_syscall();
}

#define __SYSCALL_64(nr, sym, qual) extern asmlinkage long sym(const struct pt_regs *);
#define __SYSCALL_X32(nr, sym, qual) __SYSCALL_64(nr, sym, qual)
#include <asm/syscalls_64.h>
#undef __SYSCALL_64
#undef __SYSCALL_X32

/*
 * The sys_call_table[] is no longer used for system calls, but
 * kernel/trace/trace_syscalls.c still wants to know the system
 * call address.
 */
#define __SYSCALL_64(nr, sym, qual) [nr] = sym,
#define __SYSCALL_X32(nr, sym, qual)

const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	/*
	 * Smells like a compiler bug -- it doesn't work
	 * when the & below is removed.
	 */
	[0 ... __NR_syscall_max] = &__x64_sys_ni_syscall,
#include <asm/syscalls_64.h>
};

#undef __SYSCALL_64
#undef __SYSCALL_X32

#define __SYSCALL_64(nr, sym, qual) case nr: return sym(regs);
#define __SYSCALL_X32(nr, sym, qual)

long x64_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	switch (nr) {
	#include <asm/syscalls_64.h>
	default: return __x64_sys_ni_syscall(regs);
	}
};

#undef __SYSCALL_64
#undef __SYSCALL_X32

#ifdef CONFIG_X86_X32_ABI

#define __SYSCALL_64(nr, sym, qual)
#define __SYSCALL_X32(nr, sym, qual)  case nr: return sym(regs);

long x32_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	switch (nr) {
	#include <asm/syscalls_64.h>
	default: return __x64_sys_ni_syscall(regs);
	}
};

#undef __SYSCALL_64
#undef __SYSCALL_X32

#endif
