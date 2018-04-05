/*
 * FILE:	fasttrap_arm64.c
 * DESCRIPTION:	DTrace - fasttrap provider implementation for arm64
 *
 * Copyright (c) 2010, 2018, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/insn.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "fasttrap_impl.h"

static int has_jump_table(const asm_instr_t *addr, size_t size)
{
	const asm_instr_t	*end = addr + size;

	while (addr < end) {
		/*
		 * If we encounter a branch-to-register instruction, we assume
		 * it is part of a jump table implementation.
		 */
		if (aarch64_insn_is_br(addr[0]))
			return 1;

		addr++;
	}

	return 0;
}

static uint64_t *fasttrap_all_offsets(asm_instr_t *text, size_t size,
				      uint64_t *np)
{
	uint64_t	*offs = NULL;
	uint64_t	noffs;
	asm_instr_t	*instr;
	asm_instr_t	*end;

	/*
	 * Two passes are taken through this section of code.  The first time
	 * around we merely count the number of probe points.  The second time,
	 * we actually record their locations.
	 */
again:
	noffs = 0;
	instr = text;
	end = text + size;

	while (instr < end) {
		if (offs)
			offs[noffs] = (uint64_t)
					((uintptr_t)instr - (uintptr_t)text);
		noffs++;

		instr++;
	}

	if (offs == NULL) {
		/*
		 * No matching offsets found - we are done.
		 */
		if (noffs == 0)
			goto fail;

		/*
		 * We know how many tracepoint locations there are for this
		 * probe, so allocate a member to record them, and kick off the
		 * second pass.
		 */
		offs = kmalloc(sizeof(uint64_t) * noffs, GFP_KERNEL);
		if (!offs)
			goto fail;

		goto again;
	}

	*np = noffs;

	return offs;

fail:
	*np = 0;
	kfree(offs);

	return NULL;
}

uint64_t *fasttrap_glob_offsets(fasttrap_probe_spec_t *probe, uint64_t *np)
{
	size_t		size = probe->ftps_size;
	asm_instr_t	*text = NULL;
	asm_instr_t	*instr;
	asm_instr_t	*end;
	uint64_t	*offs = NULL;
	uint64_t	noffs;
	int		ret = 0;
	char		ostr[sizeof(instr) * 2 + 1];	/* 2 chars / byte + 1 */

	if (!IS_ALIGNED(size, sizeof(instr[0])))
		goto fail;

	text = kmalloc(size, GFP_KERNEL);
	if (!text)
		goto fail;

	ret = dtrace_copy_code(probe->ftps_pid, (uint8_t *)text,
			       probe->ftps_pc, size);
	if (ret != 0)
		goto fail;

	/*
	 * From this point on, size will be a count of instructions rather than
	 * a byte count.  We already verified earlier on that it is a multiple
	 * of the instruction size.
	 */
	size /= sizeof(instr[0]);

	if (has_jump_table(text, size))
		goto fail;

	if (probe->ftps_glen == 1 && probe->ftps_gstr[0] == '*') {
		offs = fasttrap_all_offsets(text, size, &noffs);
		goto out;
	}

	/*
	 * Two passes are taken through this section of code.  The first time
	 * around we merely count the number of probe points.  The second time,
	 * we actually record their locations.
	 */
again:
	noffs = 0;
	instr = text;
	end = text + size;

	while (instr < end) {
		uint64_t	off = (uint64_t)
					((uintptr_t)instr - (uintptr_t)text);

		snprintf(ostr, sizeof(ostr), "%llx", off);
		if (dtrace_gmatch(ostr, probe->ftps_gstr)) {
			if (offs)
				offs[noffs] = off;
			noffs++;
		}

		instr++;
	}

	if (offs == NULL) {
		/*
		 * No matching offsets found - we are done.
		 */
		if (noffs == 0)
			goto fail;

		/*
		 * We know how many tracepoint locations there are for this
		 * probe, so allocate member to record them, and kick off the
		 * second pass.
		 */
		offs = kmalloc(sizeof(uint64_t) * noffs, GFP_KERNEL);
		if (!offs)
			goto fail;

		goto again;
	}

out:
	kfree(text);

	*np = noffs;

	return offs;

fail:
	kfree(offs);
	kfree(text);

	*np = 0;
	return NULL;
}

uint64_t fasttrap_pid_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
			     int aframes)
{
	struct pt_regs	*regs = this_cpu_core->cpu_dtrace_regs;
	uint64_t	*st;
	uint64_t	val;

	if (regs == NULL)
		return 0;

	if (argno < 8)
		return regs->regs[argno];

	pagefault_disable();
	st = (uint64_t *)regs->sp;
	__copy_from_user_inatomic_nocache(&val, (void *)&st[argno - 8],
					  sizeof(st[0]));
	pagefault_enable();

	return val;
}

uint64_t fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg,
			      int argno, int aframes)
{
	return fasttrap_pid_getarg(arg, id, parg, argno, aframes);
}

static void fasttrap_map_args(fasttrap_probe_t *probe, struct pt_regs *regs,
			      int argc, uintptr_t *argv)
{
	int		i, x, cap = min(argc, (int)probe->ftp_nargs);
	uintptr_t	*st = (uintptr_t *)regs->sp;

	for (i = 0; i < cap; i++) {
		x = probe->ftp_argmap[i];

		if (x < 8)
			argv[i] = regs->regs[x];
		else {
			pagefault_disable();
			__copy_from_user_inatomic_nocache(&argv[i],
							  (void *)&st[x - 8],
							  sizeof(st[0]));
			pagefault_enable();
		}
	}

	while (i < argc)
		argv[i++] = 0;
}

void fasttrap_pid_probe_arch(fasttrap_probe_t *ftp, struct pt_regs *regs)
{
	if (ftp->ftp_argmap == NULL) {
		dtrace_probe(ftp->ftp_id, regs->regs[0], regs->regs[1],
					  regs->regs[2], regs->regs[3],
					  regs->regs[4], regs->regs[5],
					  regs->regs[6]);
	} else {
		uintptr_t	t[7];

		fasttrap_map_args(ftp, regs, sizeof(t) / sizeof(t[0]), t);
		dtrace_probe(ftp->ftp_id, t[0], t[1], t[2], t[3],
			     t[4], t[5], t[6]);
	}
}

void fasttrap_pid_retprobe_arch(fasttrap_probe_t *ftp, struct pt_regs *regs)
{
	/*
	 * FIXME: The first argument to the probe should be the offset in the
	 *	  function that the return occured at, but uprobes doesn't give
	 *	  us that information (or so it seems).
	 */
	dtrace_probe(ftp->ftp_id, 0, regs->regs[0], regs->regs[1], 0, 0, 0, 0);
}

void fasttrap_set_enabled(struct pt_regs *regs)
{
	regs->regs[0] = 1;
}
