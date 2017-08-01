/*
 * Dynamic Tracing for Linux
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
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

#ifndef _DTRACE_DEV_H_
#define _DTRACE_DEV_H_

#define DT_DEV_DTRACE_MINOR	(16)
#define DT_DEV_HELPER_MINOR	(DT_DEV_DTRACE_MINOR + 1)
#define DT_DEV_PROFILE_MINOR	(DT_DEV_HELPER_MINOR + 1)
#define DT_DEV_SYSTRACE_MINOR	(DT_DEV_PROFILE_MINOR + 1)
#define DT_DEV_FBT_MINOR	(DT_DEV_SYSTRACE_MINOR + 1)
#define DT_DEV_SDT_MINOR	(DT_DEV_FBT_MINOR + 1)
#define DT_DEV_FASTTRAP_MINOR	(DT_DEV_SDT_MINOR + 1)
#define DT_DEV_LOCKSTAT_MINOR	(DT_DEV_FASTTRAP_MINOR + 1)
#define DT_DEV_DT_TEST_MINOR	(DT_DEV_LOCKSTAT_MINOR + 1)
#define DT_DEV_DT_PERF_MINOR	(DT_DEV_DT_TEST_MINOR + 1)

extern int dtrace_dev_init(void);
extern void dtrace_dev_exit(void);

#endif /* _DTRACE_DEV_H_ */
