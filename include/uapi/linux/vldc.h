/*
 * Copyright (C) 2014 Oracle Corporation
 */

#ifndef _UAPI_VLDC_H
#define _UAPI_VLDC_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct vldc_ioctl_cookierw_arg {
	u64		ubuf;
	u64		hv_ra;
	u32		len;
};

#define VLDC_IOCTL_BASE		'V'

#define VLDC_IOCTL_READ_COOKIE	_IOR(VLDC_IOCTL_BASE, 1, \
				struct vldc_ioctl_cookierw_arg)
#define VLDC_IOCTL_WRITE_COOKIE	_IOW(VLDC_IOCTL_BASE, 2, \
				struct vldc_ioctl_cookierw_arg)

#endif /* _UAPI_VLDC_H */
