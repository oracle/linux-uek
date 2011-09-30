/*
 * FILE:	dtrace_fmt.c
 * DESCRIPTION:	Dynamic Tracing: format functions
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/slab.h>

#include "dtrace.h"

uint16_t dtrace_format_add(dtrace_state_t *state, char *str)
{
	char		*fmt, **new;
	uint16_t	ndx;

	fmt = dtrace_strdup(str);

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

	ndx = state->dts_nformats++;
	new = kmalloc((ndx + 1) * sizeof (char *), GFP_KERNEL);

	if (state->dts_formats != NULL) {
		ASSERT(ndx != 0);
		memcpy(new, state->dts_formats, ndx * sizeof (char *));
		kfree(state->dts_formats);
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

	kfree(state->dts_formats);
	state->dts_nformats = 0;
	state->dts_formats = NULL;
}
