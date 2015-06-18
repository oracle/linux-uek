/* bnx2fc_compat_uek3.h: bnx2fc compatible header for UEK3
 *
 * Copyright (c) 2014 Oracle Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Joe Jin <joe.jin@oracle.com>
 */
#ifndef _BNX2FC_COMPAT_UEK3_H_
#define _BNX2FC_COMPAT_UEK3_H_

/* define this to modify less in .c files from vendor */
#define __BNX2FC_UEK__

/* include/scsi/libfcoe.h
 * fcoe_ctlr->cdev
 */
#define _DEFINE_FCOE_CTLR_CDEV_

/* include/scsi/fcoe_sysfs.h
 * struct fcoe_sysfs_function_template;
 */
#define _DEFINE_FCOE_SYSFS_

/* include/linux/highmem.h
 * kmap_atomic() with one parameter
 */
#define _DEFINE_KMAP_ATOMIC_

/* include/linux/ethtool.h
 * __ethtool_get_settings()
 */
#define _DEFINE_ETHTOOL_GET_

/* include/linux/netdevice.h
 * dev_get_stats() with more than one parameters
 */
#define _DEFINE_DEV_GET_STATS_

#endif /* _BNX2FC_COMPAT_UEK3_H_ */
