/*
 * Copyright (c) 2014, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_int_user.h: This file defines special internal data structures used
 *   to communicate between libsif and the sif driver.
 *   This file is included both from user space and kernel space so
 *   it must not contain any kernel/user specific header file includes.
 *   This file is internal to libsif/sif driver since it relies on HW specific
 *   include files.
 */

#ifndef _SIF_INT_USER_H
#define _SIF_INT_USER_H


#include "psif_hw_data.h"

/* Do this the brute force way, since structs are used in user-space */
#if defined(__x86_64__) || defined(__sparc__) || defined(__aarch64__)
#define SIF_CACHE_BYTES 64
#else
#define SIF_CACHE_BYTES 64
#endif

/* We use the extension here to communicate with the driver
 * (for correct debugfs reporting)
 */

/* sif_sq_sw flags definition
 */
enum sq_sw_state {
	FLUSH_SQ_IN_PROGRESS = 0,
	FLUSH_SQ_IN_FLIGHT   = 1,
};

struct sif_sq_sw {
	struct psif_sq_sw d;	/* Hardware visible descriptor */
	__u8 fill[SIF_CACHE_BYTES - sizeof(struct psif_sq_sw)]; /* separate the cache lines */
	__u16 last_seq;         /* Last used sq seq.num (req. sq->lock) */
	__u16 head_seq;         /* Last sq seq.number seen in a compl (req. cq->lock) */
	__u16 trusted_seq;	/* Last next_seq that was either generate or exist in the cq */
	__u8 tsl;               /* Valid after transition to RTR */
	unsigned long flags;    /* Flags, using unsigned long due to test_set/test_and_set_bit */
};

/* sif_rq_sw flags definition
 */
enum rq_sw_state {
	FLUSH_RQ_IN_PROGRESS = 0,
	FLUSH_RQ_IN_FLIGHT   = 1,
	FLUSH_RQ_FIRST_TIME  = 2,
	RQ_IS_INVALIDATED    = 3,
};

struct sif_rq_sw {
	struct psif_rq_sw d;	/* Hardware visible descriptor */
	__u8 fill[SIF_CACHE_BYTES - sizeof(struct psif_rq_sw)]; /* separate the cache lines */
	atomic_t length;	/* current length of queue as #posted - #completed */
	__u32 next_seq;	/* First unused sequence number */
	unsigned long flags;    /* Flags, using unsigned long due to test_set/test_and_set_bit */
};

enum cq_sw_state {
	CQ_POLLING_NOT_ALLOWED = 0,
	CQ_POLLING_IGNORED_SEQ = 1,
	FLUSH_SQ_FIRST_TIME    = 2,
};

struct sif_cq_sw {
	struct psif_cq_sw d;	/* Hardware visible descriptor */
	__u8 fill[SIF_CACHE_BYTES - sizeof(struct psif_cq_sw)]; /* separate the cache lines */
	__u32 next_seq;		/* First unused sequence number */
	__u32 cached_head;	/* Local copy kept in sync w/hw visible head_indx */
	__u32 last_hw_seq;	/* Last next_seq reported in completion for req_notify_cq */
	__u32 armed;		/* Set if req_notify_cq has been called but event not processed */
	__u32 miss_cnt;		/* Number of in-flight completions observed by poll_cq */
	__u32 miss_occ;		/* Number of times 1 or more in-flight completions was seen */
	unsigned long flags;    /* Flags, using unsigned long due to test_set/test_and_set_bit */
};

#endif
