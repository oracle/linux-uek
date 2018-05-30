/* Copyright (C) 2018 Oracle, Inc. */

#ifndef _ASM_ARM64_DTRACE_SDT_ARCH_H
#define _ASM_ARM64_DTRACE_SDT_ARCH_H

#include <asm/dtrace_arch.h>

#define NOP_INSTR	0xd503201f
#define MOV_INSTR	0xd2800000	/* mov x0, #0x0  - default = false */

#define __DTRACE_SDT_ISENABLED_PROTO void
#define __DTRACE_SDT_ISENABLED_ARGS

extern asm_instr_t dtrace_sdt_peek(asm_instr_t *addr);
extern void dtrace_sdt_poke(asm_instr_t *addr, asm_instr_t opcode);
extern void dtrace_sdt_start(void *arg);
extern void dtrace_sdt_stop(void *arg);

#endif /* _ASM_ARM64_DTRACE_SDT_ARCH_H */
