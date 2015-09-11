/*
 * Copyright (C) 2014 Oracle Corporation
 */

#ifndef _UAPI_VLDC_H
#define _UAPI_VLDC_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct vldc_data_t {
	u64		src_addr;
	u64		dst_addr;
	u64		length;
};

#define VLDC_IOCTL_BASE		'V'

#define VLDC_IOCTL_READ_COOKIE	_IOR(VLDC_IOCTL_BASE, 1, struct vldc_data_t)
#define VLDC_IOCTL_WRITE_COOKIE	_IOW(VLDC_IOCTL_BASE, 2, struct vldc_data_t)

#endif /* _UAPI_VLDC_H */
