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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "module_objnames.h"

/*
 * Read a .tmp_module.objnames.objs file and translate it into a stream of
 * (module name, object file names).
 */

/*
 * Construct a module_objnames iterator.
 */
struct module_objnames_iter *
module_objnames_iter_new(const char *module_objnames_file)
{
	struct module_objnames_iter *i;

	i = calloc(1, sizeof(struct module_objnames_iter));
	if (i == NULL)
		return NULL;

	i->f = fopen(module_objnames_file, "r");

	if (i->f == NULL) {
		fprintf(stderr, "Cannot open builtin module file %s: %s\n",
			module_objnames_file, strerror(errno));
		return NULL;
	}

	return i;
}

/*
 * Iterate, returning a new null-terminated array of object file names, and a
 * new dynamically-allocated module name.  (The module name passed in is freed.)
 *
 * The array of object file names should be freed by the caller: the strings it
 * points to are owned by the iterator, and should not be freed.
 */

char ** __attribute__((__nonnull__))
module_objnames_iter_next(struct module_objnames_iter *i, char **module_name)
{
	size_t npaths = 1;
	char **module_paths;
	char *trailing_linefeed;
	char *object_name;
	char *p;
	char *one_object;
	size_t j = 0;

	/*
	 * Read in all module entries, building the next arrayful of object
	 * file names for return.
	 *
	 * The first word of an entry is the module name: the second and
	 * subsequent words are object file names (there must be at least
	 * one, and may be more than one).
	 */

	/*
	 * Reinvocation of exhausted iterator. Return NULL, once.
	 */
retry:
	if (getline(&i->line, &i->line_size, i->f) < 0) {
		if (ferror(i->f)) {
			fprintf(stderr, "Error reading from .tmp_module.objnames file:"
				" %s\n", strerror(errno));
			exit(1);
		}
		rewind(i->f);
		return NULL;
	}

	if (i->line[0] == '\0')
		goto retry;

	trailing_linefeed = strchr(i->line, '\n');
	if (trailing_linefeed != NULL)
		*trailing_linefeed = '\0';

	/*
	 * Slice the line in two at the first space: the elements past it are the
	 * object file names.
	 */
	if (strchr(i->line, ' ') == NULL) {
		fprintf(stderr, "Invalid line in .tmp_module.objnames: %s\n",
			i->line);
		exit(1);
	}

	p = strchr(i->line, ' ');
	*p = '\0';
	p++;
	object_name = p;
	free(*module_name);
	*module_name = strdup(i->line);

	/*
	 * The array size may be an overestimate if any object file names
	 * start or end with spaces (very unlikely) but cannot be an
	 * underestimate.  (Check for it anyway.)
	 */

	for (npaths = 0, one_object = object_name;
	     one_object != NULL;
	     npaths++, one_object = strchr(one_object + 1, ' '));

	module_paths = malloc((npaths + 1) * sizeof(char *));
	if (!module_paths) {
		fprintf(stderr, "%s: out of memory on module %s\n", __func__,
			*module_name);
		exit(1);
	}


	while ((one_object = strsep(&object_name, " ")) != NULL) {
		if (j >= npaths) {
			fprintf(stderr, "%s: num_objs overflow on module "
				"%s: this is a bug.\n", __func__,
				*module_name);
			exit(1);
		}

		module_paths[j++] = one_object;
	}

	module_paths[npaths] = NULL;

	return module_paths;
}

/*
 * Free an iterator. Can be called while iteration is underway, so even
 * state that is freed at the end of iteration must be freed here too.
 */
void
module_objnames_iter_free(struct module_objnames_iter *i)
{
	if (i == NULL)
		return;
	fclose(i->f);
	free(i->line);
	free(i);
}
