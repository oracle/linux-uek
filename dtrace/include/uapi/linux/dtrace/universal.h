#ifndef _LINUX_DTRACE_UNIVERSAL_H_
#define _LINUX_DTRACE_UNIVERSAL_H_

/*
 * DTrace Dynamic Tracing Software: Universal Constants and Typedefs
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

#define	DTRACE_CPUALL		-1	/* all CPUs */
#define	DTRACE_IDNONE		0	/* invalid probe identifier */
#define	DTRACE_EPIDNONE		0	/* invalid enabled probe identifier */
#define	DTRACE_AGGIDNONE	0	/* invalid aggregation identifier */
#define	DTRACE_AGGVARIDNONE	0	/* invalid aggregation variable ID */
#define	DTRACE_CACHEIDNONE	0	/* invalid predicate cache */
#define	DTRACE_PROVNONE		0	/* invalid provider identifier */
#define	DTRACE_METAPROVNONE	0	/* invalid meta-provider identifier */
#define	DTRACE_ARGNONE		-1	/* invalid argument index */

#define DTRACE_PROVNAMELEN	64
#define DTRACE_MODNAMELEN	64
#define DTRACE_FUNCNAMELEN	128
#define DTRACE_NAMELEN		64
#define DTRACE_FULLNAMELEN	(DTRACE_PROVNAMELEN + DTRACE_MODNAMELEN + \
				 DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 4)
#define DTRACE_ARGTYPELEN	128

typedef uint16_t	dtrace_actkind_t;	/* action kind */

typedef uint32_t	dtrace_aggid_t;		/* aggregation identifier */
typedef uint32_t	dtrace_cacheid_t;	/* predicate cache identifier */
typedef uint32_t	dtrace_epid_t;		/* enabled probe identifier */
typedef uint32_t	dtrace_optid_t;		/* option identifier */
typedef uint32_t	dtrace_specid_t;	/* speculation identifier */

typedef uint64_t	dtrace_aggvarid_t;	/* aggregation variable id */
typedef uint64_t	dtrace_genid_t;		/* generation identifier */
typedef uint64_t	dtrace_optval_t;	/* option value */

#endif /* _LINUX_DTRACE_UNIVERSAL_H_ */
