/*
 * FILE:	dtrace_util.c
 * DESCRIPTION:	DTrace - utility functions
 *
 * Copyright (c) 2010, 2016, Oracle and/or its affiliates. All rights reserved.
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

#include <linux/dtrace_cpu.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>

#include "dtrace.h"

int dtrace_badattr(const dtrace_attribute_t *a)
{
	return a->dtat_name > DTRACE_STABILITY_MAX ||
	       a->dtat_data > DTRACE_STABILITY_MAX ||
	       a->dtat_class > DTRACE_CLASS_MAX;
}

/*
 * Allocate a chunk of virtual memory in kernel space, and zero it out.  This
 * allocation might fail (which will report a backtrace in the kernel log, yet
 * it is harmless).
 */
void *dtrace_vzalloc_try(unsigned long size)
{
	return __vmalloc(size,
			 GFP_NOWAIT | __GFP_FS | __GFP_IO | __GFP_NOMEMALLOC |
			 __GFP_NORETRY | __GFP_NOWARN | __GFP_ZERO,
			 PAGE_KERNEL);
}
EXPORT_SYMBOL(dtrace_vzalloc_try);

/*
 * Return a duplicate copy of a string.  If the specified string is NULL, this
 * function returs a zero-length string.
 */
char *dtrace_strdup(const char *str)
{
	return kstrdup(str ? str : "", GFP_KERNEL);
}

/*
 * Compare two strings using safe loads.
 */
int dtrace_strncmp(char *s1, char *s2, size_t limit)
{
	uint8_t			c1, c2;
	volatile uint16_t	*flags;

	if (s1 == s2 || limit == 0)
		return 0;

	flags = (volatile uint16_t *)&this_cpu_core->cpuc_dtrace_flags;

	do {
		if (s1 == NULL)
			c1 = '\0';
		else
			c1 = dtrace_load8((uintptr_t)s1++);

		if (s2 == NULL)
			c2 = '\0';
		else
			c2 = dtrace_load8((uintptr_t)s2++);

		if (c1 != c2)
			return (c1 - c2);
	} while (--limit && c1 != '\0' && !(*flags & CPU_DTRACE_FAULT));

	return 0;
}

/*
 * Compute strlen(s) for a string using safe memory accesses.  The additional
 * len parameter is used to specify a maximum length to ensure completion.
 */
size_t dtrace_strlen(const char *s, size_t lim)
{
	uint_t	len;

	for (len = 0; len != lim; len++) {
		if (dtrace_load8((uintptr_t)s++) == '\0')
			break;
	}

	return len;
}

#define DTRACE_ISALPHA(c)	(((c) >= 'a' && (c) <= 'z') || \
				 ((c) >= 'A' && (c) <= 'Z'))
int dtrace_badname(const char *s)
{
	char	c;

	if (s == NULL || (c = *s++) == '\0')
		return 0;

	if (!DTRACE_ISALPHA(c) && c != '-' && c!= '_' && c != '.')
		return 1;

	while ((c = *s++) != '\0') {
		if (!DTRACE_ISALPHA(c) && (c < '0' || c > '9') &&
		    c != '-' && c!= '_' && c != '.' && c != '`')
			return 1;
	}

	return 0;
}

void dtrace_cred2priv(const cred_t *cr, uint32_t *privp, kuid_t *uidp)
{
#ifdef FIXME
/*
 * This should probably be rewritten based on capabilities in the cred_t struct.
 */
	uint32_t	priv;

	if (cr == NULL)
		priv = DTRACE_PRIV_ALL;
	else {
		const cred_t	*lcr = get_cred(cr);

		if (PRIV_POLICY_ONLY(lcr, PRIV_ALL, FALSE))
			priv = DTRACE_PRIV_ALL;
		else {
			*uidp = lcr->uid;
			priv = 0;

			if (PRIV_POLICY_ONLY(lcr, PRIV_DTRACE_KERNEL, FALSE))
				priv |= DTRACE_PRIV_KERNEL | DTRACE_PRIV_USER;
			else if (PRIV_POLICY_ONLY(lcr, PRIV_DTRACE_USER,
						  FALSE))
				priv |= DTRACE_PRIV_USER;

			if (PRIV_POLICY_ONLY(lcr, PRIV_DTRACE_PROC, FALSE))
				priv |= DTRACE_PRIV_PROC;
			if (PRIV_POLICY_ONLY(lcr, PRIV_PROC_OWNER, FALSE))
				priv |= DTRACE_PRIV_OWNER;
		}

		put_cred(cr);
	}

	*privp = priv;
#else
	*privp = DTRACE_PRIV_ALL;

	if (cr != NULL) {
		const cred_t	*lcr = get_cred(cr);

		*uidp = lcr->uid;
		put_cred(cr);
	}
#endif
}

