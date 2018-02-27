#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <asm/spec_ctrl.h>

#include <linux/stringify.h>

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


/*
 * 64-bit system call stack frame layout defines and helpers, for
 * assembly code (note that the seemingly unnecessary parentheses
 * are to prevent cpp from inserting spaces in expressions that get
 * passed to macros):
 */

#define R15		  (0)
#define R14		  (8)
#define R13		 (16)
#define R12		 (24)
#define RBP		 (32)
#define RBX		 (40)

/* arguments: interrupts/non tracing syscalls only save up to here: */
#define R11		 (48)
#define R10		 (56)
#define R9		 (64)
#define R8		 (72)
#define RAX		 (80)
#define RCX		 (88)
#define RDX		 (96)
#define RSI		(104)
#define RDI		(112)
#define ORIG_RAX	(120)       /* + error_code */
/* end of arguments */

/* cpu exception frame or undefined in case of fast syscall: */
#define RIP		(128)
#define CS		(136)
#define EFLAGS		(144)
#define RSP		(152)
#define SS		(160)

#define ARGOFFSET	R11
#define SWFRAME		ORIG_RAX

	.macro SAVE_ARGS addskip=0, norcx=0, nor891011=0
	subq  $9*8+\addskip, %rsp
	CFI_ADJUST_CFA_OFFSET	9*8+\addskip
	movq  %rdi, 8*8(%rsp)
	CFI_REL_OFFSET	rdi, 8*8
	movq  %rsi, 7*8(%rsp)
	CFI_REL_OFFSET	rsi, 7*8
	movq  %rdx, 6*8(%rsp)
	CFI_REL_OFFSET	rdx, 6*8
	.if \norcx
	.else
	movq  %rcx, 5*8(%rsp)
	CFI_REL_OFFSET	rcx, 5*8
	.endif
	movq  %rax, 4*8(%rsp)
	CFI_REL_OFFSET	rax, 4*8
	.if \nor891011
	.else
	movq  %r8, 3*8(%rsp)
	CFI_REL_OFFSET	r8,  3*8
	movq  %r9, 2*8(%rsp)
	CFI_REL_OFFSET	r9,  2*8
	movq  %r10, 1*8(%rsp)
	CFI_REL_OFFSET	r10, 1*8
	movq  %r11, (%rsp)
	CFI_REL_OFFSET	r11, 0*8
	.endif
	.endm

#define ARG_SKIP	(9*8)

	.macro RESTORE_ARGS skiprax=0, addskip=0, skiprcx=0, skipr11=0, \
			    skipr8910=0, skiprdx=0
	.if \skipr11
	.else
	movq (%rsp), %r11
	CFI_RESTORE r11
	.endif
	.if \skipr8910
	.else
	movq 1*8(%rsp), %r10
	CFI_RESTORE r10
	movq 2*8(%rsp), %r9
	CFI_RESTORE r9
	movq 3*8(%rsp), %r8
	CFI_RESTORE r8
	.endif
	.if \skiprax
	.else
	movq 4*8(%rsp), %rax
	CFI_RESTORE rax
	.endif
	.if \skiprcx
	.else
	movq 5*8(%rsp), %rcx
	CFI_RESTORE rcx
	.endif
	.if \skiprdx
	.else
	movq 6*8(%rsp), %rdx
	CFI_RESTORE rdx
	.endif
	movq 7*8(%rsp), %rsi
	CFI_RESTORE rsi
	movq 8*8(%rsp), %rdi
	CFI_RESTORE rdi
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
	movq %rbx, 5*8(%rsp)
	CFI_REL_OFFSET	rbx, 5*8
	movq %rbp, 4*8(%rsp)
	CFI_REL_OFFSET	rbp, 4*8
	movq %r12, 3*8(%rsp)
	CFI_REL_OFFSET	r12, 3*8
	movq %r13, 2*8(%rsp)
	CFI_REL_OFFSET	r13, 2*8
	movq %r14, 1*8(%rsp)
	CFI_REL_OFFSET	r14, 1*8
	movq %r15, (%rsp)
	CFI_REL_OFFSET	r15, 0*8
	.endm

	.macro RESTORE_REST
	movq (%rsp),     %r15
	CFI_RESTORE r15
	movq 1*8(%rsp),  %r14
	CFI_RESTORE r14
	movq 2*8(%rsp),  %r13
	CFI_RESTORE r13
	movq 3*8(%rsp),  %r12
	CFI_RESTORE r12
	movq 4*8(%rsp),  %rbp
	CFI_RESTORE rbp
	movq 5*8(%rsp),  %rbx
	CFI_RESTORE rbx
	addq $REST_SKIP, %rsp
	CFI_ADJUST_CFA_OFFSET	-(REST_SKIP)
	.endm

	.macro ZERO_REST
	xorq    %r15, %r15
	xorq    %r14, %r14
	xorq    %r13, %r13
	xorq    %r12, %r12
	xorq    %rbp, %rbp
	xorq    %rbx, %rbx
	.endm

	.macro SAVE_ALL
	SAVE_ARGS
	SAVE_REST
	.endm

	.macro RESTORE_ALL addskip=0
	RESTORE_REST
	RESTORE_ARGS 0, \addskip
	.endm

	.macro icebp
	.byte 0xf1
	.endm

/*
 * IBRS related macros
 */

#define __ASM_STUFF_RSB                        \
       call    1f;                             \
       pause;                                  \
1:     call    2f;                             \
       pause;                                  \
2:     call    3f;                             \
       pause;                                  \
3:     call    4f;                             \
       pause;                                  \
4:     call    5f;                             \
       pause;                                  \
5:     call    6f;                             \
       pause;                                  \
6:     call    7f;                             \
       pause;                                  \
7:     call    8f;                             \
       pause;                                  \
8:     call    9f;                             \
       pause;                                  \
9:     call    10f;                            \
       pause;                                  \
10:    call    11f;                            \
       pause;                                  \
11:    call    12f;                            \
       pause;                                  \
12:    call    13f;                            \
       pause;                                  \
13:    call    14f;                            \
       pause;                                  \
14:    call    15f;                            \
       pause;                                  \
15:    call    16f;                            \
       pause;                                  \
16:    call    17f;                            \
       pause;                                  \
17:    call    18f;                            \
       pause;                                  \
18:    call    19f;                            \
       pause;                                  \
19:    call    20f;                            \
       pause;                                  \
20:    call    21f;                            \
       pause;                                  \
21:    call    22f;                            \
       pause;                                  \
22:    call    23f;                            \
       pause;                                  \
23:    call    24f;                            \
       pause;                                  \
24:    call    25f;                            \
       pause;                                  \
25:    call    26f;                            \
       pause;                                  \
26:    call    27f;                            \
       pause;                                  \
27:    call    28f;                            \
       pause;                                  \
28:    call    29f;                            \
       pause;                                  \
29:    call    30f;                            \
       pause;                                  \
30:    call    31f;                            \
       pause;                                  \
31:    call    32f;                            \
       pause;                                  \
32:                                            \
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
	testl	$SPEC_CTRL_IBRS_INUSE, dynamic_ibrs
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
	testl	$SPEC_CTRL_IBRS_INUSE, dynamic_ibrs
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_FEATURE_DISABLE_IBRS
	POP_MSR_REGS
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm

.macro SET_IBPB
	ALTERNATIVE "jmp .Lskip_\@", "", X86_FEATURE_SPEC_CTRL
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_PRED_CMD, $SPEC_CTRL_FEATURE_SET_IBPB
	POP_MSR_REGS
.Lskip_\@:
.endm

.macro ENABLE_IBRS_CLOBBER
	testl	$SPEC_CTRL_IBRS_INUSE, dynamic_ibrs
	jz	.Lskip_\@
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_FEATURE_ENABLE_IBRS
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm

.macro DISABLE_IBRS_CLOBBER
	testl	$SPEC_CTRL_IBRS_INUSE, dynamic_ibrs
	jz	.Lskip_\@
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_FEATURE_DISABLE_IBRS
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm

.macro ENABLE_IBRS_SAVE_AND_CLOBBER save_reg:req
	testl	$SPEC_CTRL_IBRS_INUSE, dynamic_ibrs
	jz	.Lskip_\@
	movl	$MSR_IA32_SPEC_CTRL, %ecx
	rdmsr
	movl	%eax, \save_reg
	/* For 32-bit we have the following conventions - kernel is built with */
	movl	$0, %edx
	movl	$SPEC_CTRL_FEATURE_ENABLE_IBRS, %eax
	wrmsr
	jmp	.Ldone_\@
.Lskip_\@:
	movl $SPEC_CTRL_FEATURE_ENABLE_IBRS, \save_reg
	lfence
.Ldone_\@:
.endm

.macro RESTORE_IBRS_CLOBBER save_reg:req
	testl	$SPEC_CTRL_IBRS_INUSE, dynamic_ibrs
	jz	.Lskip_\@
	/* Set IBRS to the value saved in the save_reg */
	movl    $MSR_IA32_SPEC_CTRL, %ecx
	movl    $0, %edx
	movl    \save_reg, %eax
	wrmsr
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm
