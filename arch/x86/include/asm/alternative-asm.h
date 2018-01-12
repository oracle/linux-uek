#ifdef __ASSEMBLY__

#include <asm/asm.h>

#ifdef CONFIG_SMP
	.macro LOCK_PREFIX
1:	lock
	.section .smp_locks,"a"
	.balign 4
	.long 1b - .
	.previous
	.endm
#else
	.macro LOCK_PREFIX
	.endm
#endif

.macro altinstruction_entry orig alt feature orig_len alt_len
	.align 8
	.quad \orig
	.quad \alt
	.word \feature
	.byte \orig_len
	.byte \alt_len
.endm

.macro ALTERNATIVE oldinstr, newinstr, feature
140:
	\oldinstr
141:
	.skip -(((144f-143f)-(141b-140b)) > 0) * ((144f-143f)-(141b-140b)),0x90
142:
	.pushsection .altinstructions,"a"
	altinstruction_entry 140b,143f,\feature,142b-140b,144f-143f
	.popsection

	.pushsection .altinstr_replacement,"ax"
143:
	\newinstr
144:
	.popsection
.endm

#endif  /*  __ASSEMBLY__  */
