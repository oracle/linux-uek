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

#ifndef _LINUX_DTRACE_UNIVERSAL_H_
#define _LINUX_DTRACE_UNIVERSAL_H_

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
