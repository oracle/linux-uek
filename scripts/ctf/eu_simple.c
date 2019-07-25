/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Convenience wrappers for functions in elfutils.
 *
 * (C) 2014, 2019 Oracle, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>

#include <elfutils/libdwfl.h>
#include <elfutils/version.h>

#include "eu_simple.h"

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

	static Dwfl_Callbacks cb = {
		.find_debuginfo = no_debuginfo,
		.section_address = dwfl_offline_section_address
	};
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

	multi = malloc(sizeof(struct simple_dwfl_multi));
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
		multi->last_die = dwfl_nextcu(multi->dwfl, multi->last_die,
					      &junk);

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
