/*

 x86 function call convention, 64-bit:
 -------------------------------------
  arguments           |  callee-saved      | extra caller-saved | return
 [callee-clobbered]   |                    | [callee-clobbered] |
 ---------------------------------------------------------------------------
 rdi rsi rdx rcx r8-9 | rbx rbp [*] r12-15 | r10-11             | rax, rdx [**]

 ( rsp is obviously invariant across normal function calls. (gcc can 'merge'
   functions when it sees tail-call optimization possibilities) rflags is
   clobbered. Leftover arguments are passed over the stack frame.)

 [*]  In the frame-pointers case rbp is fixed to the stack frame.

 [**] for struct return values wider than 64 bits the return convention is a
      bit more complex: up to 128 bits width we return small structures
      straight in rax, rdx. For structures larger than that (3 words or
      larger) the caller puts a pointer to an on-stack return struct
      [allocated in the caller's stack frame] into the first argument - i.e.
      into rdi. All other arguments shift up by one in this case.
      Fortunately this case is rare in the kernel.

For 32-bit we have the following conventions - kernel is built with
-mregparm=3 and -freg-struct-return:

 x86 function calling convention, 32-bit:
 ----------------------------------------
  arguments         | callee-saved        | extra caller-saved | return
 [callee-clobbered] |                     | [callee-clobbered] |
 -------------------------------------------------------------------------
 eax edx ecx        | ebx edi esi ebp [*] | <none>             | eax, edx [**]

 ( here too esp is obviously invariant across normal function calls. eflags
   is clobbered. Leftover arguments are passed over the stack frame. )

 [*]  In the frame-pointers case ebp is fixed to the stack frame.

 [**] We build with -freg-struct-return, which on 32-bit means similar
      semantics as on 64-bit: edx can be used for a second return value
      (i.e. covering integer and structure sizes up to 64 bits) - after that
      it gets more complex and more expensive: 3-word or larger struct returns
      get done in the caller's frame and the pointer to the return struct goes
      into regparm0, i.e. eax - the other arguments shift up and the
      function's register parameters degenerate to regparm=2 in essence.

*/

#include <asm/dwarf2.h>
#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <linux/stringify.h>

/*
 * 64-bit system call stack frame layout defines and helpers,
 * for assembly code:
 */

#define R15		  0
#define R14		  8
#define R13		 16
#define R12		 24
#define RBP		 32
#define RBX		 40

/* arguments: interrupts/non tracing syscalls only save up to here: */
#define R11		 48
#define R10		 56
#define R9		 64
#define R8		 72
#define RAX		 80
#define RCX		 88
#define RDX		 96
#define RSI		104
#define RDI		112
#define ORIG_RAX	120       /* + error_code */
/* end of arguments */

/* cpu exception frame or undefined in case of fast syscall: */
#define RIP		128
#define CS		136
#define EFLAGS		144
#define RSP		152
#define SS		160

#define ARGOFFSET	R11
#define SWFRAME		ORIG_RAX

	.macro ZERO_EXTRA_REGS
	xorq    %r15, %r15
	xorq    %r14, %r14
	xorq    %r13, %r13
	xorq    %r12, %r12
	xorq    %rbp, %rbp
	xorq    %rbx, %rbx
	.endm

	.macro SAVE_ARGS addskip=0, save_rcx=1, save_r891011=1
	subq  $9*8+\addskip, %rsp
	CFI_ADJUST_CFA_OFFSET	9*8+\addskip
	movq_cfi rdi, 8*8
	movq_cfi rsi, 7*8
	movq_cfi rdx, 6*8

	.if \save_rcx
	movq_cfi rcx, 5*8
	.endif

	movq_cfi rax, 4*8

	.if \save_r891011
	movq_cfi r8,  3*8
	movq_cfi r9,  2*8
	movq_cfi r10, 1*8
	movq_cfi r11, 0*8
	.endif

	.endm

#define ARG_SKIP	(9*8)

	.macro RESTORE_ARGS rstor_rax=1, addskip=0, rstor_rcx=1, rstor_r11=1, \
			    rstor_r8910=1, rstor_rdx=1
	.if \rstor_r11
	movq_cfi_restore 0*8, r11
	.endif

	.if \rstor_r8910
	movq_cfi_restore 1*8, r10
	movq_cfi_restore 2*8, r9
	movq_cfi_restore 3*8, r8
	.endif

	.if \rstor_rax
	movq_cfi_restore 4*8, rax
	.endif

	.if \rstor_rcx
	movq_cfi_restore 5*8, rcx
	.endif

	.if \rstor_rdx
	movq_cfi_restore 6*8, rdx
	.endif

	movq_cfi_restore 7*8, rsi
	movq_cfi_restore 8*8, rdi

	.if ARG_SKIP+\addskip > 0
	addq $ARG_SKIP+\addskip, %rsp
	CFI_ADJUST_CFA_OFFSET	-(ARG_SKIP+\addskip)
	.endif
	.endm

	.macro LOAD_ARGS offset, skiprax=0
	movq \offset(%rsp),    %r11
	movq \offset+8(%rsp),  %r10
	movq \offset+16(%rsp), %r9
	movq \offset+24(%rsp), %r8
	movq \offset+40(%rsp), %rcx
	movq \offset+48(%rsp), %rdx
	movq \offset+56(%rsp), %rsi
	movq \offset+64(%rsp), %rdi
	.if \skiprax
	.else
	movq \offset+72(%rsp), %rax
	.endif
	.endm

#define REST_SKIP	(6*8)

	.macro SAVE_REST
	subq $REST_SKIP, %rsp
	CFI_ADJUST_CFA_OFFSET	REST_SKIP
	movq_cfi rbx, 5*8
	movq_cfi rbp, 4*8
	movq_cfi r12, 3*8
	movq_cfi r13, 2*8
	movq_cfi r14, 1*8
	movq_cfi r15, 0*8
	.endm

	.macro RESTORE_REST
	movq_cfi_restore 0*8, r15
	movq_cfi_restore 1*8, r14
	movq_cfi_restore 2*8, r13
	movq_cfi_restore 3*8, r12
	movq_cfi_restore 4*8, rbp
	movq_cfi_restore 5*8, rbx
	addq $REST_SKIP, %rsp
	CFI_ADJUST_CFA_OFFSET	-(REST_SKIP)
	.endm

	.macro SAVE_ALL
	SAVE_ARGS
	SAVE_REST
	.endm

	.macro RESTORE_ALL addskip=0
	RESTORE_REST
	RESTORE_ARGS 1, \addskip
	.endm

	.macro icebp
	.byte 0xf1
	.endm


/*
 * IBRS related macros
 */

/*
 * STUFF_RSB needs a working stack where we would push the return address.
 * For the actual act of stuffing the RSB, we need "near CALL instructions
 * with non-zero displacement" (thus the pause instruction.)
 *
 * Once we are done, we reclaim stack by moving the RSP.
 *
 * The primary side effect is to fill up the RSB.
 *
 * This ensures that there will be no RSB underflow -- which could have lead
 * to the CPU speculating using return addresses in control of user space.
 * That specific scenario could have arisen when scheduling from a shallow
 * stack to a deep one.)
 *
 * If SMEP is enabled, then this is a non issue because that stops the CPU from
 * executing higher CPL instructions.
 *
 * We want to do this as early as possible before any schedule() happens.
 */
#define __ASM_STUFF_RSB                        \
       call    1901f;                          \
       pause;                                  \
1901:  call    1902f;                          \
       pause;                                  \
1902:  call    1903f;                          \
       pause;                                  \
1903:  call    1904f;                          \
       pause;                                  \
1904:  call    1905f;                          \
       pause;                                  \
1905:  call    1906f;                          \
       pause;                                  \
1906:  call    1907f;                          \
       pause;                                  \
1907:  call    1908f;                          \
       pause;                                  \
1908:  call    1909f;                          \
       pause;                                  \
1909:  call    1910f;                          \
       pause;                                  \
1910:  call    1911f;                          \
       pause;                                  \
1911:  call    1912f;                          \
       pause;                                  \
1912:  call    1913f;                          \
       pause;                                  \
1913:  call    1914f;                          \
       pause;                                  \
1914:  call    1915f;                          \
       pause;                                  \
1915:  call    1916f;                          \
       pause;                                  \
1916:  call    1917f;                          \
       pause;                                  \
1917:  call    1918f;                          \
       pause;                                  \
1918:  call    1919f;                          \
       pause;                                  \
1919:  call    1920f;                          \
       pause;                                  \
1920:  call    1921f;                          \
       pause;                                  \
1921:  call    1922f;                          \
       pause;                                  \
1922:  call    1923f;                          \
       pause;                                  \
1923:  call    1924f;                          \
       pause;                                  \
1924:  call    1925f;                          \
       pause;                                  \
1925:  call    1926f;                          \
       pause;                                  \
1926:  call    1927f;                          \
       pause;                                  \
1927:  call    1928f;                          \
       pause;                                  \
1928:  call    1929f;                          \
       pause;                                  \
1929:  call    1930f;                          \
       pause;                                  \
1930:  call    1931f;                          \
       pause;                                  \
1931:  call    1932f;                          \
       pause;                                  \
1932:                                          \
       add $(32*8), %rsp;

.macro STUFF_RSB
	ALTERNATIVE __stringify(__ASM_STUFF_RSB), "", X86_FEATURE_SMEP
.endm


.macro PUSH_MSR_REGS
	pushq	%rax
	pushq	%rcx
	pushq	%rdx
.endm

.macro POP_MSR_REGS
	popq	%rdx
	popq	%rcx
	popq	%rax
.endm

.macro WRMSR_ASM msr_nr:req eax_val:req
	movl	\msr_nr, %ecx
	movl	$0, %edx
	movl	\eax_val, %eax
	wrmsr
.endm

.macro ENABLE_IBRS
	testl	$1, dynamic_ibrs
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_FEATURE_ENABLE_IBRS
	POP_MSR_REGS
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm

.macro DISABLE_IBRS
	testl	$1, dynamic_ibrs
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_FEATURE_DISABLE_IBRS
	POP_MSR_REGS
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm

.macro ENABLE_IBRS_CLOBBER
	testl	$1, dynamic_ibrs
	jz	.Lskip_\@
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_FEATURE_ENABLE_IBRS
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm

.macro DISABLE_IBRS_CLOBBER
	testl	$1, dynamic_ibrs
	jz	.Lskip_\@
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_FEATURE_DISABLE_IBRS
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm

.macro ENABLE_IBRS_SAVE_AND_CLOBBER save_reg:req
	testl	$1, dynamic_ibrs
	jz	.Lskip_\@
	movl	$MSR_IA32_SPEC_CTRL, %ecx
	rdmsr
	movl	%eax, \save_reg

	movl	$0, %edx
	movl	$SPEC_CTRL_FEATURE_ENABLE_IBRS, %eax
	wrmsr
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm

.macro RESTORE_IBRS_CLOBBER save_reg:req
	testl	$1, dynamic_ibrs
	jz	.Lskip_\@
	/* Set IBRS to the value saved in the save_reg */
	movl    $MSR_IA32_SPEC_CTRL, %ecx
	movl    $0, %edx
	movl    \save_reg, %eax
	wrmsr
	jmp	.Ldone_\@
.Lskip_\@:
	movl $SPEC_CTRL_FEATURE_ENABLE_IBRS, \save_reg
	lfence
.Ldone_\@:
.endm
