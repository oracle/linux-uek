/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2014-2015 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/rtnetlink.h>

/* The forced speed, in units of 1Mb. All values 0 to INT_MAX are legal. */

#define SPEED_10		10
#define SPEED_100		100
#define SPEED_1000		1000
#define SPEED_2500		2500
#define SPEED_5000		5000
#define SPEED_10000		10000
#define SPEED_20000		20000
#define SPEED_25000		25000
#define SPEED_40000		40000
#define SPEED_50000		50000
#define SPEED_56000		56000
#define SPEED_100000		100000

#define SPEED_UNKNOWN		-1

#define NETDEV_UDP_TUNNEL_PUSH_INFO	0x001C

static DEFINE_MUTEX(rtnl_mutex);

static inline void udp_tunnel_get_rx_info(struct net_device *dev)
{
	ASSERT_RTNL();
	call_netdevice_notifiers(NETDEV_UDP_TUNNEL_PUSH_INFO, dev);
}
