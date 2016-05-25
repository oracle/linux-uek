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
 * sif_enl.h: Protocol definitions for the netlink protocol for EPSC access from
 *   user space. Shared between kernel and user space.
 */

#ifndef _SIF_ENL_H
#define _SIF_ENL_H

/* Supported packet types */
enum sif_enl_cmd_type {
	SIF_ENL_CMD_NONE,
	SIF_ENL_CMD_REQ,     /* Request to an EPS */
	SIF_ENL_CMD_RSP,     /* Response from an EPS */
	SIF_ENL_CMD_REQ_DRV, /* Driver requests */
	SIF_ENL_CMD_RSP_DRV, /* Driver response */
	SIF_ENL_CMD_MAX
};

/* Supported attributes */
enum sif_test_attr {
	SIF_ENL_A_CMD,
	SIF_ENL_A_COMPLEX,
	SIF_ENL_A_BUS,
	SIF_ENL_A_DEVFN,
	SIF_ENL_A_PAYLOAD,
	SIF_ENL_A_DATA,
	SIF_ENL_A_INDEX,
	SIF_ENL_A_MAX
};


/* attribute policy */
static struct nla_policy sif_enl_policy[SIF_ENL_A_MAX] = {
	[SIF_ENL_A_CMD] =	{ .type = NLA_U32 },
	[SIF_ENL_A_COMPLEX] =	{ .type = NLA_U16 },
	[SIF_ENL_A_BUS] =	{ .type = NLA_U16 },
	[SIF_ENL_A_DEVFN] =	{ .type = NLA_U16 },
	[SIF_ENL_A_PAYLOAD]  =	{ .type = NLA_UNSPEC },
	[SIF_ENL_A_DATA]  =	{ .type = NLA_UNSPEC },
	[SIF_ENL_A_INDEX] =	{ .type = NLA_U32 }
};


#endif
