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

#endif
