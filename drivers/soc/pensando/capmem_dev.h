/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018-2021, Pensando Systems Inc.
 */

#ifndef __CAPMEM_H__
#define __CAPMEM_H__

#define CAPMEM_NAME		"capmem"
#define CAPMEM_DEV		"/dev/capmem"
#define CAPMEM_IOCTL_NUM	0xcc

struct capmem_range {
	uint64_t	start;
	uint64_t	len;
	int		type;
};
enum {
	CAPMEM_TYPE_DEVICE,
	CAPMEM_TYPE_COHERENT,
	CAPMEM_TYPE_NONCOHERENT
};

struct capmem_ranges_args {
	struct capmem_range *range;
	int nranges;
};

#define CAPMEM_MAX_RANGES	64

#define CAPMEM_GET_NRANGES	_IOR(CAPMEM_IOCTL_NUM, 1, int)
#define CAPMEM_GET_RANGES	_IOWR(CAPMEM_IOCTL_NUM, 2, struct capmem_ranges_args)

#endif
