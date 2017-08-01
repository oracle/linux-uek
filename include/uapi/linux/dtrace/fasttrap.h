/*
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * Copyright (c) 2009, 2013, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _LINUX_DTRACE_FASTTRAP_H
#define _LINUX_DTRACE_FASTTRAP_H

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
