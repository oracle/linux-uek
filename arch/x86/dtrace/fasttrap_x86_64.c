/*
 * FILE:	fasttrap_x86_64.c
 * DESCRIPTION:	DTrace - fasttrap provider implementation for x86
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

#define DISASM_REX_PREFIX(pfx)	(((pfx) & 0xf0) == 0x40)
#define DISASM_MODRM_REG(modrm)	(((modrm) >> 3) & 0x07)

static int has_jump_table(const asm_instr_t *addr, size_t size)
{
	const asm_instr_t	*end = addr + size;

	while (addr < end) {
		int	len;

		/*
		 * Register-dependent jump instructions start with a 0xff byte
		 * and have the modrm.reg field set to 4.  Such instructions
		 * tend to be used for jump tables.
		 */
		if ((addr[0] == 0xff && DISASM_MODRM_REG(addr[1]) == 4) ||
		    (DISASM_REX_PREFIX(addr[0]) && addr[1] == 0xff &&
		     DISASM_MODRM_REG(addr[2]) == 4))
			return 1;

		len = dtrace_instr_size(addr);

		/*
		 * If we encounter a problem decoding an instruction, we will
		 * assume that there might be a jump table.  Better safe than
		 * sorry...
		 */
		if (len < 0)
			return 1;

		addr += len;
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
		int		len;

		/*
		 * If we fail to decode an instruction, it is time to give up.
		 */
		len = dtrace_instr_size(instr);
		if (len < 0)
			goto fail;

		if (offs)
			offs[noffs] = (uint64_t)(instr - text);
		noffs++;

		instr += len;
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
	char		ostr[sizeof(instr) * 2 + 1];

	text = kmalloc(size, GFP_KERNEL);
	if (!text)
		goto fail;

	ret = dtrace_copy_code(probe->ftps_pid, (uint8_t *)text,
			       probe->ftps_pc, size);
	if (ret != 0)
		goto fail;

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
		int		len;
		uint64_t	off = (uint64_t)(instr - text);

		/*
		 * If we fail to decode an instruction, it is time to give up.
		 */
		len = dtrace_instr_size(instr);
		if (len < 0)
			goto fail;

		snprintf(ostr, sizeof(ostr), "%llx", off);
		if (dtrace_gmatch(ostr, probe->ftps_gstr)) {
			if (offs)
				offs[noffs] = off;
			noffs++;
		}

		instr += len;
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

	switch (argno) {
	case 0:
		return regs->di;
	case 1:
		return regs->si;
	case 2:
		return regs->dx;
	case 3:
		return regs->cx;
	case 4:
		return regs->r8;
	case 5:
		return regs->r9;
	}

	ASSERT(argno > 5);

	pagefault_disable();
	st = (uint64_t *)regs->sp;
	__copy_from_user_inatomic_nocache(&val, (void *)&st[argno - 6 + 1],
					  sizeof(st[0]));
	pagefault_enable();

	return val;
}

uint64_t fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg,
			      int argno, int aframes)
{
	struct pt_regs	*regs = this_cpu_core->cpu_dtrace_regs;
	uint64_t	*st;
	uint64_t	val;

	if (regs == NULL)
		return 0;

	switch (argno) {
	case 0:
		return regs->di;
	case 1:
		return regs->si;
	case 2:
		return regs->dx;
	case 3:
		return regs->cx;
	case 4:
		return regs->r8;
	case 5:
		return regs->r9;
	}

	ASSERT(argno > 5);

	pagefault_disable();
	st = (uint64_t *)regs->sp;
	__copy_from_user_inatomic_nocache(&val, (void *)&st[argno - 6],
					  sizeof(st[0]));
	pagefault_enable();

	return val;
}

static void fasttrap_map_args(fasttrap_probe_t *probe, struct pt_regs *regs,
			      int argc, uintptr_t *argv)
{
	int		i, x, cap = min(argc, (int)probe->ftp_nargs);
	uintptr_t	*st = (uintptr_t *)regs->sp;

	for (i = 0; i < cap; i++) {
		switch (x = probe->ftp_argmap[i]) {
		case 0:
			argv[i] = regs->di;
			break;
		case 1:
			argv[i] = regs->si;
			break;
		case 2:
			argv[i] = regs->dx;
			break;
		case 3:
			argv[i] = regs->cx;
			break;
		case 4:
			argv[i] = regs->r8;
			break;
		case 5:
			argv[i] = regs->r9;
			break;
		default:
			ASSERT(x > 5);

			__copy_from_user_inatomic_nocache(&argv[i],
							  (void *)&st[x - 6],
							  sizeof(st[0]));
		}
	}

	while (i < argc)
		argv[i++] = 0;
}

void fasttrap_pid_probe_arch(fasttrap_probe_t *ftp, struct pt_regs *regs)
{
	if (ftp->ftp_argmap == NULL) {
		dtrace_probe(ftp->ftp_id, regs->di, regs->si, regs->dx,
			     regs->cx, regs->r8, regs->r9, 0);
	} else {
		uintptr_t	t[6];

		fasttrap_map_args(ftp, regs, sizeof(t) / sizeof(t[0]), t);
		dtrace_probe(ftp->ftp_id, t[0], t[1], t[2], t[3],
			     t[4], t[5], 0);
	}
}

void fasttrap_pid_retprobe_arch(fasttrap_probe_t *ftp, struct pt_regs *regs)
{
	/*
	 * FIXME: The first argument to the probe should be the offset in the
	 *	  function that the return occure at, but uprobes doesn't give
	 *	  us that information (or so it seems).
	 */
	dtrace_probe(ftp->ftp_id, 0, regs->ax, regs->dx, 0, 0, 0, 0);
}

void fasttrap_set_enabled(struct pt_regs *regs)
{
	regs->ax = 1;
}

