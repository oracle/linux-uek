/* Copyright (C) 2013,2014 Oracle, Inc. */

#ifndef _SPARC_DTRACE_ARCH_H
#define _SPARC_DTRACE_ARCH_H

#include <linux/module.h>

typedef uint32_t	asm_instr_t;

/*
 * Maximum size (in instruction count) of SDT and FBT trampolines.
 */
#define SDT_TRAMP_SIZE			11
#define FBT_TRAMP_SIZE			13

/*
 * Maximum number of SDT and FBT probes.  The actual number available to DTRACE
 * may be lower due to runtime filtering of troublesome functions.
 */
#define DTRACE_SDT_MAX(mp)		(mp->sdt_probec)
#define DTRACE_FBT_MAX(mp)		(mp->num_ftrace_callsites)

/*
 * The following macros are used to partition the PDATA memory block.  The SDT
 * trampolines are stored first, followed by the FBT trampolines.
 *
 * DTRACE_PD_SDT_OFF:
 *	Offset (in the PDATA memory block) for space to store SDT trampolines.
 * DTRACE_PD_FBT_OFF:
 *	Offset (in the PDATA memory block) for space to store FBT trampolines.
 * DTRACE_PD_MAXSIZE:
 *	Maximum size of the PDATA memory block (if no SDT or FBT probes get
 *	filtered out).
 * DTRACE_PD_MAXSIZE:
 *	Maximum size of the PDATA memory bock for the kernel pseudo-module.
 *	There is a separate macro for this because (at boot time) the maximum
 *	number of SDT and FBT probes is stored in global constants.  Wehn the
 *	kernel pseudo-module is initialized, the value of those constants is
 *	assigned to the appropriate module struct members so that the macros
 *	above (DTRACE_SDT_MAX and DTRACE_FBT_MAX) can be used after that point.
 */
#define DTRACE_PD_SDT_OFF_(sc, fc)	0
#define DTRACE_PD_SDT_OFF(mp)		DTRACE_PD_SDT_OFF_(DTRACE_SDT_MAX(mp), \
							   DTRACE_FBT_MAX(mp))
#define DTRACE_PD_FBT_OFF_(sc, fc)	(DTRACE_PD_SDT_OFF_((sc), (fc)) + \
					 (sc) * SDT_TRAMP_SIZE * \
					 sizeof(asm_instr_t))
#define DTRACE_PD_FBT_OFF(mp)		DTRACE_PD_FBT_OFF_(DTRACE_SDT_MAX(mp), \
							   DTRACE_FBT_MAX(mp))
#define DTRACE_PD_MAXSIZE_(sc, fc)	(DTRACE_PD_FBT_OFF_((sc), (fc)) + \
					 (fc) * FBT_TRAMP_SIZE * \
					 sizeof(asm_instr_t))
#define DTRACE_PD_MAXSIZE(mp)		DTRACE_PD_MAXSIZE_(DTRACE_SDT_MAX(mp), \
							   DTRACE_FBT_MAX(mp))

#define DTRACE_PD_MAXSIZE_KERNEL	DTRACE_PD_MAXSIZE_(dtrace_sdt_nprobes, \
							   dtrace_fbt_nfuncs)

#endif /* _SPARC_DTRACE_ARCH_H */
