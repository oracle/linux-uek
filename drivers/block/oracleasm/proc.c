/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * Copyright (C) 2006 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/module.h>
#include <linux/proc_fs.h>

#include "proc.h"
#include "masklog.h"

static struct proc_dir_entry *asm_proc;
#define ASM_PROC_PATH "fs/oracleasm"

int init_oracleasm_proc(void)
{
	int rc;

	asm_proc = proc_mkdir(ASM_PROC_PATH, NULL);
	if (asm_proc == NULL) {
		rc = -ENOMEM; /* shrug */
		goto out;
	}

	rc = mlog_init_proc(asm_proc);
	if (rc)
		remove_proc_entry(ASM_PROC_PATH, NULL);

out:
	return rc;
}

void exit_oracleasm_proc(void)
{
	mlog_remove_proc(asm_proc);
	remove_proc_entry(ASM_PROC_PATH, NULL);
}
