/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple .tmp_module.objnames reader.
 *
 * (C) 2014, 2024 Oracle, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LINUX_MODULE_OBJNAMES_H
#define _LINUX_MODULE_OBJNAMES_H

#include <stdio.h>
#include <stddef.h>

/*
 * modules.builtin.objs iteration state.
 */
struct module_objnames_iter {
	FILE *f;
	char *line;
	size_t line_size;
};

/*
 * Construct a module_objnames.objs iterator.
 */
struct module_objnames_iter *
module_objnames_iter_new(const char *module_objnames_file);

/*
 * Iterate, returning a new null-terminated array of object file names, and a
 * new dynamically-allocated module name.  (The module name passed in is freed.)
 *
 * The array of object file names should be freed by the caller: the strings it
 * points to are owned by the iterator, and should not be freed.
 */

char ** __attribute__((__nonnull__))
module_objnames_iter_next(struct module_objnames_iter *i, char **module_name);

void
module_objnames_iter_free(struct module_objnames_iter *i);

#endif
