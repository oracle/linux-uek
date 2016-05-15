/*
 * light weight syscall handler, invoked from trap table
 */

/*
The "lightweight" syscall mechanism is very simple:
 - parameters (if any) are passed as normal in the input 
   registers, with %i0 containing the index of the requested
   function
 - return values are also in the input registers:
     %i0 = 0 for success otherwise -errno
     %i1, %i2, %i3 are function return values

Other things to note about the environment in which these
calls are executed, and resulting constraints:
 1. Primary context is the user's, not kernel. You probably
    should not touch any user memory, but if you must,
    then use ASI_AIUP and be aware that a fault may
    kill the system.
 2. The stack pointer points to user memory. So don't
    use the stack, and don't change the stack pointer
    or frame pointer.
 3. All the windowed registers belong to the user, so
    be very careful what you mess with. For example,
    %i7 is the caller's return pointer.
 4. You can't make any (conventional) procedure calls,
    since a save instruction could cause a spill trap.
 5. Interrupts are off until you get to 'done'. Be aware!
 6. Be sure you know what you're doing before using or
    modifying this
*/

#include <asm/asm-offsets.h>
#define LW_SYS_GETCPU 0
#define LW_SYS_LWP_INFO 1
#define LW_SYS_MAX 2
	
lw_syscall:
	cmp	%i0, LW_SYS_GETCPU
	be,pn	%xcc, lw_sys_getcpu
	nop
	cmp	%i0, LW_SYS_LWP_INFO
	be,pt	%xcc, lw_sys_lwp_info
	mov	-EINVAL, %i0
	done
	
lw_sys_getcpu:
	__GET_CPUID(%i1)
	mov	%g0, %i0
	done
	nop
	
lw_sys_lwp_info:
	TRAP_LOAD_THREAD_REG(%g6, %g1)
	ldx     [%g6 + TI_TASK], %g4
	ldx     [%g4 + AOFF_task_utime], %i1
	ldx     [%g4 + AOFF_task_stime], %i2
	mov     ASM_HZ, %i3
	mov	%g0, %i0
	done
