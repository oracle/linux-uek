/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple modules_builtin reader.
 *
 * (C) 2014, 2022 Oracle, Inc.  All rights reserved.
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

#include "modules_builtin.h"

/*
 * Read a modules.builtin.objs file and translate it into a stream of
 * name / module-name pairs.
 */

/*
 * Construct a modules.builtin.objs iterator.
 */
struct modules_builtin_iter *
modules_builtin_iter_new(const char *modules_builtin_file)
{
	struct modules_builtin_iter *i;

	i = calloc(1, sizeof(struct modules_builtin_iter));
	if (i == NULL)
		return NULL;

	i->f = fopen(modules_builtin_file, "r");

	if (i->f == NULL) {
		fprintf(stderr, "Cannot open builtin module file %s: %s\n",
			modules_builtin_file, strerror(errno));
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
modules_builtin_iter_next(struct modules_builtin_iter *i, char **module_name)
{
	size_t npaths = 1;
	char **module_paths;
	char *last_slash;
	char *last_dot;
	char *trailing_linefeed;
	char *object_name = i->line;
	char *dash;
	int composite = 0;

	/*
	 * Read in all module entries, computing the suffixless, pathless name
	 * of the module and building the next arrayful of object file names for
	 * return.
	 *
	 * Modules can consist of multiple files: in this case, the portion
	 * before the colon is the path to the module (as before): the portion
	 * after the colon is a space-separated list of files that should be
	 * considered part of this module.  In this case, the portion before the
	 * name is an "object file" that does not actually exist: it is merged
	 * into built-in.a without ever being written out.
	 *
	 * All module names have - translated to _, to match what is done to the
	 * names of the same things when built as modules.
	 */

	/*
	 * Reinvocation of exhausted iterator. Return NULL, once.
	 */
retry:
	if (getline(&i->line, &i->line_size, i->f) < 0) {
		if (ferror(i->f)) {
			fprintf(stderr, "Error reading from modules_builtin file:"
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
	 * Slice the line in two at the colon, if any.  If there is anything
	 * past the ': ', this is a composite module.  (We allow for no colon
	 * for robustness, even though one should always be present.)
	 */
	if (strchr(i->line, ':') != NULL) {
		char *name_start;

		object_name = strchr(i->line, ':');
		*object_name = '\0';
		object_name++;
		name_start = object_name + strspn(object_name, " \n");
		if (*name_start != '\0') {
			composite = 1;
			object_name = name_start;
		}
	}

	/*
	 * Figure out the module name.
	 */
	last_slash = strrchr(i->line, '/');
	last_slash = (!last_slash) ? i->line :
		last_slash + 1;
	free(*module_name);
	*module_name = strdup(last_slash);
	dash = *module_name;

	while (dash != NULL) {
		dash = strchr(dash, '-');
		if (dash != NULL)
			*dash = '_';
	}

	last_dot = strrchr(*module_name, '.');
	if (last_dot != NULL)
		*last_dot = '\0';

	/*
	 * Multifile separator? Object file names explicitly stated:
	 * slice them up and shuffle them in.
	 *
	 * The array size may be an overestimate if any object file
	 * names start or end with spaces (very unlikely) but cannot be
	 * an underestimate.  (Check for it anyway.)
	 */
	if (composite) {
		char *one_object;

		for (npaths = 0, one_object = object_name;
		     one_object != NULL;
		     npaths++, one_object = strchr(one_object + 1, ' '));
	}

	module_paths = malloc((npaths + 1) * sizeof(char *));
	if (!module_paths) {
		fprintf(stderr, "%s: out of memory on module %s\n", __func__,
			*module_name);
		exit(1);
	}

	if (composite) {
		char *one_object;
		size_t i = 0;

		while ((one_object = strsep(&object_name, " ")) != NULL) {
			if (i >= npaths) {
				fprintf(stderr, "%s: num_objs overflow on module "
					"%s: this is a bug.\n", __func__,
					*module_name);
				exit(1);
			}

			module_paths[i++] = one_object;
		}
	} else
		module_paths[0] = i->line;	/* untransformed module name */

	module_paths[npaths] = NULL;

	return module_paths;
}

/*
 * Free an iterator. Can be called while iteration is underway, so even
 * state that is freed at the end of iteration must be freed here too.
 */
void
modules_builtin_iter_free(struct modules_builtin_iter *i)
{
	if (i == NULL)
		return;
	fclose(i->f);
	free(i->line);
	free(i);
}
