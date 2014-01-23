/*
 * Convenience wrappers for functions in elfutils.
 *
 * (C) 2014 Oracle, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
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
Dwfl *simple_dwfl_new(const char *file_name)
{
	const char *err;
	static Dwfl_Callbacks cb = { .find_debuginfo = no_debuginfo,
				     .section_address = dwfl_offline_section_address };
	Dwfl *dwfl = dwfl_begin(&cb);

	if (dwfl == NULL) {
		err = "initialize libdwfl";
		goto fail;
	}

	if (private_dwfl_report_elf(dwfl, "", file_name, -1, 0) == NULL) {
		err = "open object file with libdwfl";
		goto fail;
	}

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
 * The converse of simple_dwfl_new().
 */
void simple_dwfl_free(Dwfl *dwfl)
{
	dwfl_report_end(dwfl, NULL, NULL);
	dwfl_end(dwfl);
}
