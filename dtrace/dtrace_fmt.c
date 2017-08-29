/*
 * FILE:	dtrace_fmt.c
 * DESCRIPTION:	Dynamic Tracing: format functions
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2010-2014 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
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
