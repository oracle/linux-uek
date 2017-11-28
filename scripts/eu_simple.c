/*
 * Convenience wrappers for functions in elfutils.
 *
 * (C) 2014, 2017 Oracle, Inc.  All rights reserved.
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

#include <elfutils/libdwfl.h>
#include <elfutils/version.h>

#include <eu_simple.h>

#ifndef __GNUC__
#define __attribute__((foo))
#endif

#define __unused__ __attribute__((__unused__))

/*
 * A version of dwfl_report_elf() that compensates for parameter changes in
 * newer elfutils.
 */
static Dwfl_Module *private_dwfl_report_elf(Dwfl *dwfl, const char *name,
					    const char *file_name, int fd,
					    GElf_Addr base)
{
#if _ELFUTILS_PREREQ(0,156)
	return dwfl_report_elf(dwfl, name, file_name, fd, base, 0);
#else
	return dwfl_report_elf(dwfl, name, file_name, fd, base);
#endif
}

/*
 * Stub libdwfl callback, use only the ELF handle passed in.
 */
static int no_debuginfo(Dwfl_Module *mod __unused__,
			void **userdata __unused__,
			const char *modname __unused__,
			Dwarf_Addr base __unused__,
			const char *file_name __unused__,
			const char *debuglink_file __unused__,
			GElf_Word debuglink_crc __unused__,
			char **debuginfo_file_name __unused__)
{
	return -1;
}

/*
 * Wrap up dwfl_new() complexities.
 */
Dwfl *simple_dwfl_new(const char *file_name, Dwfl_Module **module)
{
	const char *err;
	static Dwfl_Callbacks cb = { .find_debuginfo = no_debuginfo,
				     .section_address = dwfl_offline_section_address };
	Dwfl *dwfl = dwfl_begin(&cb);
	Dwfl_Module *mod;

	if (dwfl == NULL) {
		err = "initialize libdwfl";
		goto fail;
	}

	mod = private_dwfl_report_elf(dwfl, "", file_name, -1, 0);
	if (mod == NULL) {
		err = "open object file with libdwfl";
		goto fail;
	}
	if (module)
		*module = mod;

	if (dwfl_report_end(dwfl, NULL, NULL) != 0) {
		err = "finish opening object file with libdwfl";
		goto fail;
	}

	return dwfl;
 fail:
	fprintf(stderr, "Cannot %s for %s: %s\n", err, file_name,
		dwfl_errmsg(dwfl_errno()));
	exit(1);
}

/*
 * A variant of simple_dwfl_new() that iterates over multiple object files.
 * (Used for thin archives.)
 *
 * Takes ownership of the paths, until free.
 */
struct simple_dwfl_multi *
simple_dwfl_new_multi(char **paths)
{
	struct simple_dwfl_multi *multi;

	multi = malloc(sizeof (struct simple_dwfl_multi));
	if (multi == NULL)
		return NULL;

	multi->paths = paths;
	multi->i = -1;
	multi->dwfl = NULL;
	multi->last_die = NULL;

	return multi;
}

/*
 * A variant of dwfl_nextcu() that crosses file boundaries as needed,
 * using the state in the simple_dwfl_multi.
 */
Dwarf_Die *
simple_dwfl_nextcu(struct simple_dwfl_multi *multi)
{
	Dwarf_Addr junk;

	/*
	 * Switch object files as needed (and always, the first time).
	 */

	if (multi->i >= 0)
		multi->last_die = dwfl_nextcu(multi->dwfl, multi->last_die, &junk);

	while (multi->last_die == NULL) {
		simple_dwfl_free(multi->dwfl);
		if (multi->paths[++multi->i] == NULL) {
			multi->i = -1;
			multi->dwfl = NULL;
			multi->last_die = NULL;
			return NULL;
		}

		multi->dwfl = simple_dwfl_new(multi->paths[multi->i], NULL);
		multi->last_die = dwfl_nextcu(multi->dwfl, multi->last_die,
					      &junk);
	}
	return multi->last_die;
}

/*
 * Free a simple_dwfl_new_multi: return its contained paths so the caller can
 * free them again.  (They are not changed, so the caller can just hang on to
 * them if preferred.)
 */
char **
simple_dwfl_free_multi(struct simple_dwfl_multi *multi)
{
	char **paths = multi->paths;
	simple_dwfl_free(multi->dwfl);
	free(multi);
	return paths;
}

/*
 * The converse of simple_dwfl_new().
 */
void simple_dwfl_free(Dwfl *dwfl)
{
	if (dwfl != NULL) {
		dwfl_report_end(dwfl, NULL, NULL);
		dwfl_end(dwfl);
	}
}


/*
 * Read a modules_thick.builtin file and translate it into a stream of
 * arguments suitable for simple_dwfl_new_multi().
 */

/*
 * Construct a modules_thick.builtin iterator.
 */
struct modules_thick_iter *
modules_thick_iter_new(const char *modules_thick_file)
{
	struct modules_thick_iter *i;

	i = calloc(1, sizeof (struct modules_thick_iter));
	if (i == NULL)
		return NULL;

	i->f = fopen(modules_thick_file, "r");

	if (i->f == NULL) {
		fprintf(stderr, "Cannot open builtin module file %s: "
			"%s\n", modules_thick_file, strerror(errno));
		return NULL;
	}

	return i;
}

/*
 * Iterate, returning a new null-terminated array of object
 * file names, and a new dynamically-allocated module name.
 * (The module name passed in is freed.)
 */

char **  __attribute__((__nonnull__))
modules_thick_iter_next(struct modules_thick_iter *i,
    char **module_name)
{
	char **last_module_paths = NULL;

	/*
	 * Reinvocation of exhausted iterator. Return NULL, once.
	 */
	if (i->module_npaths < 0) {
		i->module_npaths = 0;
		return NULL;
	}

	/*
	 * Read in all module entries, computing the suffixless, pathless name
	 * of the module and building the next arrayful of object file names for
	 * return.
	 *
	 * Modules can consist of multiple files: in this case, the line
	 * contains a colon, and the portion before it is the path to the module
	 * (as before): the portion after the colon is a file that should be
	 * considered part of this module.  All files that are part of a given
	 * module are consecutive in the file, with the same module path.
	 * All module names have - translated to _, to match what is done to
	 * the names of the same things when built as modules.
	 *
	 * Note that we do not know the value of the current arrayful until we
	 * have read the *next* line, or (if it was the last) until we have hit
	 * the end of the file.  This makes the logic in the loop somewhat
	 * contorted (the desire to not repeat this contortion in multiple
	 * places is why this function exists at all).
	 */

	while (getline(&i->line, &i->line_size, i->f) >= 0) {
		char *last_slash;
		char *last_dot;
		char *trailing_linefeed;
		char *object_name = i->line;
		char *dash;

		if (i->line[0] == '\0')
			continue;

		/*
		 * Slice the line in two at the multifile separator, if any.
		 */
		if (strchr(i->line, ':') != NULL) {
			object_name = strchr(i->line, ':');
			*object_name = '\0';
			object_name++;
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

		trailing_linefeed = strchr(object_name, '\n');
		if (trailing_linefeed != NULL)
			*trailing_linefeed = '\0';

		/*
		 * Module name changed?  Remember that we have to return a bunch
		 * of module names, and stash them, and the last module name
		 * away: we will be returning them this time.
		 *
		 * Check for multifileness in multiple ways, to prevent
		 * buggy duplicate single-file module names from causing null
		 * pointer dereferences.
		 */
		if (i->module_paths != NULL &&
		    (i->last_module_name == NULL ||
		     strcmp(i->last_module_name, *module_name) != 0)) {
			char *swap;

			swap = i->last_module_name;
			i->last_module_name = *module_name;
			*module_name = swap;
			last_module_paths = i->module_paths;
			i->module_paths = NULL;
			i->module_npaths = 0;
			/*
			 * module_name now holds the name from the last pass:
			 * the name that we will return.
			 */
		} else if (i->last_module_name == NULL) {
			/*
			 * First pass? Note the last module name.
			 *
			 * Dup it because we are sure to do a second loop, and
			 * we do not want to free the last module name by
			 * accident (since only in this case does it alias
			 * *module_name).
			 */
			i->last_module_name = strdup(*module_name);
		}

		/*
		 * Add the entry just read to module_paths.
		 */

		i->module_npaths++;
		i->module_paths = realloc(i->module_paths,
					  (i->module_npaths + 1) *
					  sizeof (char *));
		if (!i->module_paths) {
			fprintf(stderr, "out of memory\n");
			exit(1);
		}
		i->module_paths[i->module_npaths - 1] = strdup(object_name);
		i->module_paths[i->module_npaths] = NULL;

		/*
		 * If we have a complete set of paths waiting to go, send them
		 * out.
		 */
		if (last_module_paths)
			return last_module_paths;
	}
	if (ferror(i->f)) {
		fprintf(stderr, "Error reading from modules_thick file: %s\n",
			strerror(errno));
		exit(1);
	}
	rewind(i->f);

	/*
	 * There will be one lingering module to send back, if any modules were
	 * read at all. (If not, this will just return NULL.)
	 */
	free(*module_name);
	*module_name = i->last_module_name;
	last_module_paths = i->module_paths;
	i->module_paths = NULL;
	i->module_npaths = -1;
	return last_module_paths;
}

/*
 * Free an iterator. Can be called while iteration is underway, so even
 * state that is freed at the end of iteration must be freed here too.
 */
void
modules_thick_iter_free(struct modules_thick_iter *i)
{
	size_t j;
	if (i == NULL)
		return;
	fclose(i->f);
	free(i->line);
	for (j = 0; j < i->module_npaths; j++)
		free(i->module_paths[j]);
	free(i->module_paths);
	free(i);
}
