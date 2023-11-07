/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ctfmerge.c: Read in CTF extracted from generated object files from a
 * specified directory and generate a CTF archive whose members are the
 * deduplicated CTF derived from those object files, split up by kernel
 * module.
 *
 * Copyright (c) 2019, 2023, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE 1
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctf-api.h>
#include "modules_builtin.h"

static ctf_file_t *output;

static int private_ctf_link_add_ctf(ctf_file_t *fp,
				    const char *name)
{
#if !defined (CTF_LINK_FINAL)
	return ctf_link_add_ctf(fp, NULL, name);
#else
	/* Non-upstreamed, erroneously-broken API.  */
	return ctf_link_add_ctf(fp, NULL, name, NULL, 0);
#endif
}

/*
 * Add a file to the link.
 */
static void add_to_link(const char *fn)
{
	if (private_ctf_link_add_ctf(output, fn) < 0)
	{
		fprintf(stderr, "Cannot add CTF file %s: %s\n", fn,
			ctf_errmsg(ctf_errno(output)));
		exit(1);
	}
}

/*
 * Add a CU mapping to the link.
 *
 * CU mappings for built-in modules are added by suck_in_modules, below: here,
 * we only want to add mappings for names ending in '.ko.ctf', i.e. external
 * modules, which appear only in the filelist (since they are not built-in).
 * The pathnames are stripped off because modules don't have any, and hyphens
 * are translated into underscores.
 */
static void add_cu_mappings(const char *fn)
{
	const char *last_slash;
	const char *modname = fn;
	char *dynmodname = NULL;
	char *dash;
	size_t n;

	last_slash = strrchr(modname, '/');
	if (last_slash)
		last_slash++;
	else
		last_slash = modname;
	modname = last_slash;
	if (strchr(modname, '-') != NULL)
	{
		dynmodname = strdup(last_slash);
		dash = dynmodname;
		while (dash != NULL) {
			dash = strchr(dash, '-');
			if (dash != NULL)
				*dash = '_';
		}
		modname = dynmodname;
	}

	n = strlen(modname);
	if (strcmp(modname + n - strlen(".ko.ctf"), ".ko.ctf") == 0) {
		char *mod;

		n -= strlen(".ko.ctf");
		mod = strndup(modname, n);
		ctf_link_add_cu_mapping(output, fn, mod);
		free(mod);
	}
	free(dynmodname);
}

/*
 * Add the passed names as mappings to "vmlinux".
 */
static void add_builtins(const char *fn)
{
	if (ctf_link_add_cu_mapping(output, fn, "vmlinux") < 0)
	{
		fprintf(stderr, "Cannot add CTF CU mapping from %s to \"vmlinux\"\n",
			ctf_errmsg(ctf_errno(output)));
		exit(1);
	}
}

/*
 * Do something with a file, line by line.
 */
static void suck_in_lines(const char *filename, void (*func)(const char *line))
{
	FILE *f;
	char *line = NULL;
	size_t line_size = 0;

	f = fopen(filename, "r");
	if (f == NULL) {
		fprintf(stderr, "Cannot open %s: %s\n", filename,
			strerror(errno));
		exit(1);
	}

	while (getline(&line, &line_size, f) >= 0) {
		size_t len = strlen(line);

		if (len == 0)
			continue;

		if (line[len-1] == '\n')
			line[len-1] = '\0';

		func(line);
	}
	free(line);

	if (ferror(f)) {
		fprintf(stderr, "Error reading from %s: %s\n", filename,
			strerror(errno));
		exit(1);
	}

	fclose(f);
}

/*
 * Pull in modules.builtin.objs and turn it into CU mappings.
 */
static void suck_in_modules(const char *modules_builtin_name)
{
	struct modules_builtin_iter *i;
	char *module_name = NULL;
	char **paths;

	i = modules_builtin_iter_new(modules_builtin_name);
	if (i == NULL) {
		fprintf(stderr, "Cannot iterate over builtin module file.\n");
		exit(1);
	}

	while ((paths = modules_builtin_iter_next(i, &module_name)) != NULL) {
		size_t j;

		for (j = 0; paths[j] != NULL; j++) {
			char *alloc = NULL;
			char *path = paths[j];
			/*
			 * If the name doesn't start in ./, add it, to match the names
			 * passed to add_builtins.
			 */
			if (strncmp(paths[j], "./", 2) != 0) {
				char *p;
				if ((alloc = malloc(strlen(paths[j]) + 3)) == NULL) {
					fprintf(stderr, "Cannot allocate memory for "
						"builtin module object name %s.\n",
						paths[j]);
					exit(1);
				}
				p = alloc;
				p = stpcpy(p, "./");
				p = stpcpy(p, paths[j]);
				path = alloc;
			}
			if (ctf_link_add_cu_mapping(output, path,
						    module_name) < 0) {
				fprintf(stderr, "Cannot add path -> module mapping for "
					"%s -> %s: %s\n", path, module_name,
					ctf_errmsg(ctf_errno(output)));
				exit(1);
			}
			free (alloc);
		}
		free(paths);
	}
	free(module_name);
	modules_builtin_iter_free(i);
}

/*
 * Strip the leading .ctf. off all the module names: transform the default name
 * from _CTF_SECTION into shared_ctf, and chop any trailing .ctf off (since that
 * derives from the intermediate file used to keep the CTF out of the final
 * module).
 */
static char *transform_module_names(ctf_file_t *fp __attribute__((__unused__)),
				    const char *name,
				    void *arg __attribute__((__unused__)))
{
	if (strcmp(name, ".ctf") == 0)
		return strdup("shared_ctf");

	if (strncmp(name, ".ctf", 4) == 0) {
		size_t n = strlen (name);
		if (strcmp(name + n - 4, ".ctf") == 0)
			n -= 4;
		return strndup(name + 4, n - 4);
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	int err;
	const char *output_file;
	unsigned char *file_data = NULL;
	size_t file_size;
	FILE *fp;

	if (argc != 5) {
		fprintf(stderr, "Syntax: ctfarchive output-file objects.builtin modules.builtin\n");
		fprintf(stderr, "                   filelist\n");
		exit(1);
	}

	output_file = argv[1];

	/*
	 * First pull in the input files and add them to the link.
	 */

	output = ctf_create(&err);
	if (!output) {
		fprintf(stderr, "Cannot create output CTF archive: %s\n",
			ctf_errmsg(err));
		return 1;
	}

	suck_in_lines(argv[4], add_to_link);

	/*
	 * Make sure that, even if all their types are shared, all modules have
	 * a ctf member that can be used as a child of the shared CTF.
	 */
	suck_in_lines(argv[4], add_cu_mappings);

	/*
	 * Then pull in the builtin objects list and add them as
	 * mappings to "vmlinux".
	 */

	suck_in_lines(argv[2], add_builtins);

	/*
	 * Finally, pull in the object -> module mapping and add it
	 * as appropriate mappings.
	 */
	suck_in_modules(argv[3]);

	/*
	 * Arrange to fix up the module names.
	 */
	ctf_link_set_memb_name_changer(output, transform_module_names, NULL);

	/*
	 * Do the link.
	 */
	if (ctf_link(output, CTF_LINK_SHARE_DUPLICATED |
                     CTF_LINK_EMPTY_CU_MAPPINGS) < 0)
		goto ctf_err;

	/*
	 * Write the output.
	 */

	file_data = ctf_link_write(output, &file_size, 4096);
	if (!file_data)
		goto ctf_err;

	fp = fopen(output_file, "w");
	if (!fp)
		goto err;

	while ((err = fwrite(file_data, file_size, 1, fp)) == 0);
	if (ferror(fp)) {
		errno = ferror(fp);
		goto err;
	}
	if (fclose(fp) < 0)
		goto err;
	free(file_data);
	ctf_file_close(output);

	return 0;
err:
	free(file_data);
	fprintf(stderr, "Cannot create output CTF archive: %s\n",
		strerror(errno));
	return 1;
ctf_err:
	fprintf(stderr, "Cannot create output CTF archive: %s\n",
		ctf_errmsg(ctf_errno(output)));
	return 1;
}
