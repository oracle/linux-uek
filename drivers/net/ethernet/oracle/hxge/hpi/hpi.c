/*****************************************************************************
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
*
* Copyright 2009, 2011 Oracle America, Inc. All rights reserved.
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License version 2 only, as published by
* the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for
* more details (a copy is included in the LICENSE file that accompanied this
* code).
*
* You should have received a copy of the GNU General Public License version 2
* along with this program; If not,
* see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 or
* visit www.oracle.com if you need additional information or have any
* questions.
*
******************************************************************************/

#include "linux/version.h"
#include "hpi.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif

//DECLARE_MUTEX(hpidebuglock);
int hpi_debug_init = 0;
uint64_t hpi_debug_level = 0;

void
hpi_debug_msg(uint64_t level, char *fmt, ...)
{
	char msg_buffer[1024];
	va_list ap;

	if ((level & hpi_debug_level) ||
	    (level & HPI_REG_CTL) || (level & HPI_ERR_CTL)) {

                va_start(ap, fmt);
                (void) vsprintf(msg_buffer, fmt, ap);
                va_end(ap);

		HPI_DEBUG("%s",msg_buffer);
	}
}

void
hpi_rtrace_buf_init(rtrace_t *rt)
{
	int i;

	rt->next_idx = 0;
	rt->last_idx = MAX_RTRACE_ENTRIES - 1;
	rt->wrapped = FALSE;
	for (i = 0; i < MAX_RTRACE_ENTRIES; i++) {
		rt->buf[i].ctl_addr = TRACE_CTL_INVALID;
		rt->buf[i].val_l32 = 0;
		rt->buf[i].val_h32 = 0;
	}
}

void
hpi_rtrace_update(boolean_t wr, rtrace_t *rt,
		    uint32_t addr, uint64_t val)
{
}
