/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2014-2016 Broadcom Corporation
 * Copyright (c) 2016-2017 Broadcom Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/pci.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#if !defined(NEW_FLOW_KEYS) && defined(HAVE_FLOW_KEYS)
#include <net/flow_keys.h>
#endif
#include <linux/sched.h>


#ifndef SWITCHDEV_SET_OPS
#define SWITCHDEV_SET_OPS(netdev, ops) ((netdev)->switchdev_ops = (ops))
#endif
