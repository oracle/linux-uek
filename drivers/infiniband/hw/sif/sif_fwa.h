/*
 * Copyright (c) 2013, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_fwa.h: Low level access to a SIF device
 *
 *   Allows access to low level functions such as (re)programming the EPSC flash
 *   via direct access to the EPSC protocol proxied via Netlink.
 *   Requires CAP_NETADMIN privileges.
 */

#ifndef __SIF_FWA_H
#define __SIF_FWA_H
#include <linux/list.h>

struct sif_dev;

/* The max size we support sending/receiving from user space
 * in a single netlink message.
 * Limited by a 4k max netlink message size:
 */
#define MAX_FWA_NL_PAYLOAD 0x800

/* Per instance data structure */
struct sif_fwa {
	struct list_head list;   /* Linkage for the global list */
};

/* Called from sif_init/exit to set up/clean up global data structures
 * such as netlink communication and device registry:
 */
int sif_fwa_init(void);
void sif_fwa_exit(void);

/* Called from probe to register a new device */
int sif_fwa_register(struct sif_dev *sdev);

/* Called from remove to unregister a device */
void sif_fwa_unregister(struct sif_dev *sdev);

/* Value definition for the fwa module parameter: */
#define SIF_FWA_MR_ENABLE	   0x1   /* Enable FWA mode */

#endif
