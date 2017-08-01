/*
 * Dynamic Tracing for Linux - Kernel Types
 *
 * Copyright (c) 2009, 2017, Oracle and/or its affiliates. All rights reserved.
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

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _DTRACE_TYPES_H
#define _DTRACE_TYPES_H

/*
 * This file contains types needed to parse the DTrace shared userspace/ kernel
 * headers, and a few others (it has not been gardened to remove constants used
 * only by the DTrace core).  Userspace has its own version of these types
 * (mostly from <unistd.h>).
 * 
 * This file is compiled both in a normal kernel environment and in a peculiar
 * halfway-house environment used for headers_checking of <ioctl.h>, in which
 * among other things, no config.h symbols are available.  As a result, you
 * should be careful about #including kernel headers here: many will break
 * headers_check if added.  So far, it has always been sufficient to add them to
 * dtrace/dtrace.h instead; if this turns out to be insufficient later (perhaps
 * because DTrace core files cease to #include all of <dtrace.h>), the
 * HEADERS_CHECK #define may prove useful to disable kernel-only portions of
 * this file.
 */

#include <asm/bitsperlong.h>
#include <linux/dtrace_os.h>
#include <linux/jiffies.h>

typedef unsigned char	uchar_t;
typedef unsigned int	uint_t;
typedef unsigned long	ulong_t;

typedef long		intptr_t;

#define UINT8_MAX		(0xff)
#define UINT8_MIN		0
#define UINT16_MAX		(0xffff)
#define UINT16_MIN		0
#define UINT32_MAX		(0xffffffff)
#define UINT32_MIN		0
#define UINT64_MAX		(~0ULL)
#define UINT64_MIN		(0)
#define INT64_MAX		((long long)(~0ULL>>1))
#define INT64_MIN		(-INT64_MAX - 1LL)

#define NBBY			(__BITS_PER_LONG / sizeof (long))

/*
 * This is a bit unusual, but OpenSolaris seems to like it.  Basically, the
 * values below are the number of time units (sec, milli, micro, nano) that
 * comprise 1 second.  As such, it is the value of the respective multiplier.
 */
#define SEC			1
#define MILLISEC		1000
#define MICROSEC		1000000
#define NANOSEC			1000000000

typedef enum {
	TRUE = -1,
	FALSE = 0
} boolean_t;


#define DTRACE_ACCESS_KERNEL	0x1

#define DTRACE_CRA_PROC				0x0001
#define DTRACE_CRA_PROC_CONTROL			0x0002
#define DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER	0x0004
#define DTRACE_CRA_PROC_DESTRUCTIVE_CREDCHG	0x0010
#define DTRACE_CRA_KERNEL			0x0020
#define DTRACE_CRA_KERNEL_DESTRUCTIVE		0x0040

#define DTRACE_CRA_ALL		(DTRACE_CRA_PROC | \
				 DTRACE_CRA_PROC_CONTROL | \
				 DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER | \
				 DTRACE_CRA_PROC_DESTRUCTIVE_CREDCHG | \
				 DTRACE_CRA_KERNEL | \
				 DTRACE_CRA_KERNEL_DESTRUCTIVE)

#define DTRACE_CRV_ALLPROC	0x01
#define DTRACE_CRV_KERNEL	0x02
#define DTRACE_CRV_ALL		(DTRACE_CRV_ALLPROC | DTRACE_CRV_KERNEL)

#define DTRACE_MATCH_FAIL	-1
#define DTRACE_MATCH_NEXT	0
#define DTRACE_MATCH_DONE	1

#define DTRACE_COND_OWNER	0x01
#define DTRACE_COND_USERMODE	0x02

#define P2ROUNDUP(x, a)	(-(-(x) & -(a)))

#if (BITS_PER_LONG == 64) || defined(CONFIG_KTIME_SCALAR)
#define KTIME_INIT(s, ns)	((s64)(s) * NSEC_PER_SEC + (s64)(ns))
#else
# define KTIME_INIT(n, ns)	{ .sec = (s), .nsec = (ns) }
#endif
#define ktime_lt(t0, t1)	(t0 < t1)
#define ktime_le(t0, t1)	(t0 <= t1)
#define ktime_ge(t0, t1)	(t0 >= t1)
#define ktime_gt(t0, t1)	(t0 > t1)
#define ktime_cp(t0, t1)	(t0 = t1)

#define SECS_TO_JIFFIES(s)	(((s) * SEC_CONVERSION) >> SEC_JIFFIE_SC)

/*
 * Translate between kernel config options and userspace-compatible definitions.
 */
#ifdef CONFIG_64BIT
#define _LP64 1
#endif
#ifdef __LITTLE_ENDIAN 
#define _LITTLE_ENDIAN 1
#endif

#endif /* _DTRACE_TYPES_H */
