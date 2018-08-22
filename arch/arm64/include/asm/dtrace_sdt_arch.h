/* Copyright (C) 2018 Oracle, Inc. */

#ifndef _ASM_ARM64_DTRACE_SDT_ARCH_H
#define _ASM_ARM64_DTRACE_SDT_ARCH_H

#include <asm/dtrace_arch.h>

#define NOP_INSTR	0xd503201f
#define MOV_INSTR	0xd2800000	/* mov x0, #0x0  - default = false */

#define __DTRACE_SDT_ISENABLED_PROTO void
#define __DTRACE_SDT_ISENABLED_ARGS

#endif /* _ASM_ARM64_DTRACE_SDT_ARCH_H */
