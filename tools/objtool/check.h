/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#ifndef _CHECK_H
#define _CHECK_H

#include <stdbool.h>
#include "elf.h"
#include "cfi.h"
#include "arch.h"
#include "orc.h"
#include <linux/hashtable.h>

struct insn_state {
	struct cfi_reg cfa;
	struct cfi_reg regs[CFI_NUM_REGS];
	int stack_size;
	unsigned char type;
	bool bp_scratch;
	bool drap, end, uaccess, df;
	unsigned int uaccess_stack;
	int drap_reg, drap_offset;
	struct cfi_reg vals[CFI_NUM_REGS];
};

struct alt_group {
	/*
	 * Pointer from a replacement group to the original group.  NULL if it
	 * *is* the original group.
	 */
	struct alt_group *orig_group;

	/* First and last instructions in the group */
	struct instruction *first_insn, *last_insn;
};

struct instruction {
	struct list_head list;
	struct hlist_node hash;
	struct list_head call_node;
	struct section *sec;
	unsigned long offset;
	unsigned int len;
	enum insn_type type;
	unsigned long immediate;

	u16 dead_end		: 1,
	   ignore		: 1,
	   ignore_alts		: 1,
	   hint			: 1,
	   save			: 1,
	   restore		: 1,
	   retpoline_safe	: 1,
	   entry		: 1;
		/* 8 bit hole */

	u8 visited;
	u8 ret_offset;
	struct alt_group *alt_group;
	struct symbol *call_dest;
	struct instruction *jump_dest;
	struct instruction *first_jump_src;
	struct reloc *jump_table;
	struct list_head alts;
	struct symbol *func;
	struct list_head stack_ops;
	struct insn_state state;
	struct orc_entry orc;
};

struct objtool_file {
	struct elf *elf;
	struct list_head insn_list;
	DECLARE_HASHTABLE(insn_hash, 16);
	struct list_head return_thunk_list;
	bool ignore_unreachables, c_file, hints, rodata;
};

#define VISITED_BRANCH         0x01
#define VISITED_BRANCH_UACCESS 0x02
#define VISITED_BRANCH_MASK    0x03
#define VISITED_ENTRY          0x04

int check(const char *objname, bool orc);

struct instruction *find_insn(struct objtool_file *file,
			      struct section *sec, unsigned long offset);

#define for_each_insn(file, insn)					\
	list_for_each_entry(insn, &file->insn_list, list)

#define sec_for_each_insn(file, sec, insn)				\
	for (insn = find_insn(file, sec, 0);				\
	     insn && &insn->list != &file->insn_list &&			\
			insn->sec == sec;				\
	     insn = list_next_entry(insn, list))


#endif /* _CHECK_H */
