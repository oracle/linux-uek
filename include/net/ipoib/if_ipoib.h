/*
 * Copyright (c) 2014 Oracle Inc. All rights reserved.
 */
#ifndef WITHOUT_ORACLE_EXTENSIONS
#ifndef _NET_IPOIB_IF_H
#define _NET_IPOIB_IF_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/netdevice.h>
extern int ipoib_get_netdev_pkey(struct net_device *dev, u16 *pkey);
#endif	/* __KERNEL__ */

#endif /* _NET_IPOIB_IF_H */
#endif /* !WITHOUT_ORACLE_EXTENSIONS */
