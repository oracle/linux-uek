/* Copyright (C) 2013,2014 Oracle, Inc. */

#ifndef _SPARC_DTRACE_ARCH_H
#define _SPARC_DTRACE_ARCH_H

typedef uint32_t	asm_instr_t;

#define SDT_TRAMP_SIZE		11
#define DTRACE_PDATA_SIZE	64
#define DTRACE_PDATA_EXTRA	(dtrace_sdt_nprobes * SDT_TRAMP_SIZE * \
				 sizeof(asm_instr_t))
#define DTRACE_PDATA_MAXSIZE	(DTRACE_PDATA_SIZE + DTRACE_PDATA_EXTRA)

#endif /* _SPARC_DTRACE_ARCH_H */
