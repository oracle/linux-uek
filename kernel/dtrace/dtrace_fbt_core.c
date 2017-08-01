/*
 * FILE:        dtrace_fbt_core.c
 * DESCRIPTION: DTrace - FBT common code
 *
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
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

#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/dtrace_fbt.h>

struct dt_fbt_bl_entry {
	struct rb_node		dfbe_node;
	unsigned long		dfbe_addr;
	const char		*dfbe_name;
};

static struct rb_root dt_fbt_root = RB_ROOT;

dt_fbt_bl_entry_t *
dtrace_fbt_bl_add(unsigned long addr, const char *name)
{
	struct rb_node **p = &dt_fbt_root.rb_node;
	struct rb_node *parent = NULL;
	struct dt_fbt_bl_entry *entry;

	/*
	 * If no address was given, we need to do a symbol name lookup:
	 *  - If no symbol name was given, we cannot add anything.
	 *  - If the lookup failed, we cannot add anything.
	 */
	if (addr == 0) {
		if (name == NULL)
			return NULL;

		addr = kallsyms_lookup_name(name);

		if (addr == 0)
			return NULL;
	}

	/* Find place in the tree. */
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, dt_fbt_bl_entry_t, dfbe_node);

		if (addr > entry->dfbe_addr)
			p = &parent->rb_right;
		else if (addr < entry->dfbe_addr)
			p = &parent->rb_left;
		else
			return NULL;		/* no duplicates please */
	}

	/* Create a new blacklist entry. */
	if ((entry = kmalloc(sizeof(*entry), GFP_KERNEL)) == NULL)
		return NULL;

	entry->dfbe_name = name;
	entry->dfbe_addr = addr;

	/* Update the tree. */
	rb_link_node(&entry->dfbe_node, parent, p);
	rb_insert_color(&entry->dfbe_node, &dt_fbt_root);

	return entry;
}

/*
 * Iterators for blacklisted symbols. The iteration happens in sort order by
 * virtual memory address. Symbols with pending resolution are inored.
 */
dt_fbt_bl_entry_t *
dtrace_fbt_bl_first(void)
{
	struct rb_node *node = rb_first(&dt_fbt_root);

	if (node == NULL)
		return (NULL);

	return (rb_entry(node, dt_fbt_bl_entry_t, dfbe_node));
}

dt_fbt_bl_entry_t *
dtrace_fbt_bl_next(dt_fbt_bl_entry_t *entry)
{
	struct rb_node *node = rb_next(&entry->dfbe_node);

	if (node == NULL)
		return (NULL);

	return (rb_entry(node, dt_fbt_bl_entry_t, dfbe_node));
}

unsigned long
dtrace_fbt_bl_entry_addr(dt_fbt_bl_entry_t *entry)
{
	if (entry == NULL)
		return (0);

	return (entry->dfbe_addr);
}

const char *
dtrace_fbt_bl_entry_name(dt_fbt_bl_entry_t *entry)
{
	if (entry == NULL)
		return (NULL);

	return (entry->dfbe_name);
}
