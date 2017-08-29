#ifndef _LINUX_DTRACE_FASTTRAP_H
#define _LINUX_DTRACE_FASTTRAP_H

/* 
 * DTrace Dynamic Tracing Software: Fasttrap Provider
 * 
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

/*
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
 * Copyright 2009 -- 2013 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/dtrace/universal.h>
#include <linux/dtrace/fasttrap_defines.h>

typedef enum fasttrap_probe_type {
	DTFTP_NONE = 0,
	DTFTP_ENTRY,
	DTFTP_RETURN,
	DTFTP_OFFSETS,
	DTFTP_POST_OFFSETS,
	DTFTP_IS_ENABLED
} fasttrap_probe_type_t;

typedef struct fasttrap_probe_spec {
	pid_t ftps_pid;
	fasttrap_probe_type_t ftps_type;
	char ftps_func[DTRACE_FUNCNAMELEN];
	char ftps_mod[DTRACE_MODNAMELEN];
	uint64_t ftps_pc;
	uint64_t ftps_size;
	uint64_t ftps_noffs;
	uint64_t ftps_offs[1];
} fasttrap_probe_spec_t;

typedef uint8_t		fasttrap_instr_t;

typedef struct fasttrap_instr_query {
	uint64_t ftiq_pc;
	pid_t ftiq_pid;
	fasttrap_instr_t ftiq_instr;
} fasttrap_instr_query_t;

/*
 * Include after the definitions, to get ioctl()s when fasttrap.h is included.
 * fasttrap_ioctl.h also #includes this header, to get structures when it is
 * included itself, as is done by headers_check.
 */

#include <linux/dtrace/fasttrap_ioctl.h>

#endif /* _LINUX_DTRACE_FASTTRAP_H */
