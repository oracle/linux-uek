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
 * sif_checksum.c: Utilities for SIF specific 32 bit checksums
 *
 */
#include <net/checksum.h>
#include <asm/byteorder.h>
#include "sif_checksum.h"
#include <linux/module.h>

/*
 *   32 bit "IP/TCP"-like checksumming - modified from 16 to 32 bit
 *   from kernel/lib/checksum.c:
 */

static inline u32 from64to32(u64 x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return x;
}


static u64 do_csum32(const unsigned char *buff, int len)
{
	int unaligned;
	u64 result = 0;

	if (len <= 0)
		goto out;
	unaligned = 3 & (unsigned long) buff;
	if (1 & (unsigned long) buff) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 24);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long) buff) {
#ifdef __LITTLE_ENDIAN
			result += (*(u32 *) buff) << 16;
#else
			result += *(u32 *) buff;
#endif
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			if (4 & (unsigned long) buff) {
				result += *(u32 *) buff;
				len -= 4;
				buff += 4;
			}
			if (len >= 8) {
				const unsigned char *end = buff + ((unsigned int)len & ~7);
				unsigned int carry = 0;

				do {
					u64 w = *(u64 *) buff;

					buff += 8;
					result += carry;
					result += w;
					carry = (w > result);
				} while (buff < end);
				result += carry;
				result = (result & 0xffffffff) + (result >> 32);
			}
			if (len & 4) {
				result += *(u32 *) buff;
				len -= 4;
				buff += 4;
			}
		}
		if (len & 2) {
#ifdef __LITTLE_ENDIAN
			result += (*(unsigned short *) buff) << 16;
#else
			result += *(unsigned short *) buff;
#endif
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 24);
#endif
	result = from64to32(result);
	switch (unaligned) {
	case 1:
		result = ((result >> 8) & 0xffffff) | ((result & 0xff) << 24);
		break;
	case 2:
		result = ((result >> 16) & 0xffff) | ((result & 0xffff) << 16);
		break;
	case 3:
		result = ((result >> 24) & 0xff) | ((result & 0xffffff) << 8);
		break;
	default:
		break;
	}
out:
	return result;
}


u64 csum32_partial(const void *buff, int len, u64 wsum)
{
	u64 sum = (__force u64)wsum;
	u64 result = do_csum32(buff, len);

	/* add in old sum, and carry.. */
	result += sum;
	if (sum > result)
		result += 1;
	return (__force u64)result;
}
EXPORT_SYMBOL(csum32_partial);
