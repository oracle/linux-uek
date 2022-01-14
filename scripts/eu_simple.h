/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Simplifying wrappers for functions in elfutils, and functions to
 * feed them data.
 *
 * (C) 2014, 2017 Oracle, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LINUX_EU_SIMPLE_H
#define _LINUX_EU_SIMPLE_H

#include <stdio.h>
#include <stddef.h>
#include <elfutils/libdwfl.h>

/*
 * Iteration state for simple_dwfl_new_multi().
 */
struct simple_dwfl_multi {
	char **paths;
	ssize_t i;
	Dwfl *dwfl;
	Dwarf_Die *last_die;
};

/*
 * Wrap up dwfl_new() complexities.
 */
Dwfl *simple_dwfl_new(const char *file_name, Dwfl_Module **module);

/*
 * A variant of simple_dwfl_new() that iterates over multiple object files.
 * (Used for thin archives.)
 *
 * Takes ownership of the paths, until free.
 */
struct simple_dwfl_multi *simple_dwfl_new_multi(char **paths);

/*
 * A variant of dwfl_nextcu() that crosses file boundaries as needed,
 * using the state in the simple_dwfl_multi.
 */
Dwarf_Die *simple_dwfl_nextcu(struct simple_dwfl_multi *multi);

/*
 * Free a simple_dwfl_new_multi: return its contained paths so the caller
 * free them again.  (They are not changed, so the caller can just hang on to
 * them if preferred.)
 */
char **simple_dwfl_free_multi(struct simple_dwfl_multi *multi);

/*
 * The converse of simple_dwfl_new().
 */
void simple_dwfl_free(Dwfl *dwfl);

/*
 * modules_thick.builtin iteration state.
 */
struct modules_thick_iter {
	FILE *f;
	char *line;
	size_t line_size;
};

/*
 * Construct a modules_thick.builtin iterator.
 */
struct modules_thick_iter *
modules_thick_iter_new(const char *modules_thick_file);

/*
 * Iterate, returning a new null-terminated array of object file names, and a
 * new dynamically-allocated module name.  (The module name passed in is freed.)
 *
 * The array of object file names should be freed by the caller: the strings it
 * points to are owned by the iterator, and should not be freed.
 */

char ** __attribute__((__nonnull__))
modules_thick_iter_next(struct modules_thick_iter *i, char **module_name);

void
modules_thick_iter_free(struct modules_thick_iter *i);

#endif
