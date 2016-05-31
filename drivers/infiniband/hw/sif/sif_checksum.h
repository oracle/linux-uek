/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_checksum.h: Utilities for SIF specific 32 bit checksums
 */
#ifndef _SIF_CHECKSUM_H
#define _SIF_CHECKSUM_H

/*
 *   32 bit "IP/TCP"-like checksumming - modified from 16 to 32 bit
 *   from kernel/lib/checksum.c:
 */

u64 csum32_partial(const void *buff, int len, u64 wsum);

/*
 * Fold a partial checksum
 */
static inline u32 csum32_fold(u64 csum)
{
	u64 sum = (__force u64)csum;

	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);
	return (__force u32)~sum;
}

#endif
