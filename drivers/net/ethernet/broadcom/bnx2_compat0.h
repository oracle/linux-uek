/* bnx2_compat0.h: Broadcom NX2 network driver.
 *
 * Copyright (c) 2013 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This file is included by both bnx2.c and cnic.c so that CFLAGS that affect
 * struct bnx2 will be set the same in both drivers.
 *
 * Written by: Michael Chan  (mchan@broadcom.com)
 */


#ifndef BNX2_COMPAT0_H
#define BNX2_COMPAT0_H

/* CFLAGs that affect struct sizes should be defined here */

#if (LINUX_VERSION_CODE >= 0x020618)
#define BNX2_NEW_NAPI	1
#endif

#if (LINUX_VERSION_CODE >= 0x30000) && !defined(HAVE_NDO_VLAN_RX_REGISTER)
#define NEW_VLAN
#endif


#endif
