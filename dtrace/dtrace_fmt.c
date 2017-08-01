/*
 * FILE:	dtrace_fmt.c
 * DESCRIPTION:	DTrace - format string implementation
 *
 * Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.
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

#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "dtrace.h"

uint16_t dtrace_format_add(dtrace_state_t *state, char *str)
{
	char		*fmt, **new;
	uint16_t	ndx;

	fmt = dtrace_strdup(str);
	if (fmt == NULL)
		return 0;

	for (ndx = 0; ndx < state->dts_nformats; ndx++) {
		if (state->dts_formats[ndx] == NULL) {
			state->dts_formats[ndx] = fmt;

			return ndx + 1;
		}
	}

	if (state->dts_nformats == UINT16_MAX) {
		kfree(fmt);

		return 0;
	}

	ndx = state->dts_nformats;
	new = vmalloc((ndx + 1) * sizeof (char *));
	if (new == NULL) {
		kfree(fmt);
		return 0;
	}

	state->dts_nformats++;

	if (state->dts_formats != NULL) {
		ASSERT(ndx != 0);
		memcpy(new, state->dts_formats, ndx * sizeof (char *));
		vfree(state->dts_formats);
	}

	state->dts_formats = new;
	state->dts_formats[ndx] = fmt;

	return ndx + 1;
}

void dtrace_format_remove(dtrace_state_t *state, uint16_t format)
{
	char	*fmt;

	ASSERT(state->dts_formats != NULL);
	ASSERT(format <= state->dts_nformats);
	ASSERT(state->dts_formats[format - 1] != NULL);

	fmt = state->dts_formats[format - 1];
	kfree(fmt);
	state->dts_formats[format - 1] = NULL;
}

void dtrace_format_destroy(dtrace_state_t *state)
{
	int	i;

	if (state->dts_nformats == 0) {
		ASSERT(state->dts_formats == NULL);
		return;
	}

	ASSERT(state->dts_formats != NULL);

	for (i = 0; i < state->dts_nformats; i++) {
		char	*fmt = state->dts_formats[i];

		if (fmt == NULL)
			continue;

		kfree(fmt);
	}

	vfree(state->dts_formats);
	state->dts_nformats = 0;
	state->dts_formats = NULL;
}
