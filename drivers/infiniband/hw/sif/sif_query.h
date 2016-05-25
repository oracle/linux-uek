/*
 * Copyright (c) 2012, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_query.h: SIF implementation of some of IB query APIs
 */

#ifndef _SIF_QUERY_H
#define _SIF_QUERY_H
#include "psif_hw_data.h"
#include "sif_epsc.h"
#include "sif_fwa.h"

/* Max size of firmware version info */
#define MAX_FW_VERSION_INFO_SZ 4096

/* DMA mapped structure to receive query data in
 * We only need one of these and we protect user access to
 * it with sif_epsc->lock
 */

struct sif_epsc_data {
	struct psif_epsc_device_attr dev;
	struct psif_epsc_port_attr port[2];
	struct psif_epsc_log_stat log;

	/* fixed buffer space for special FWA client needs */
	char fw_version[MAX_FW_VERSION_INFO_SZ]; /* Data area for firmware version info */
	char flash[MAX_FWA_NL_PAYLOAD];  /* Data area for flash support */
	char epsc_cli[MAX_FWA_NL_PAYLOAD]; /* Data area for EPSC CLI response*/
	char vimm_agent[MAX_FWA_NL_PAYLOAD]; /* Data area for VIMM agent */
	char log_data_area[0];  /* Data area will be allocated right after this struct */
};

int sif_query_device(struct ib_device *ibdev, struct ib_device_attr *props);

int sif_query_port(struct ib_device *ibdev, u8 port, struct ib_port_attr *props);
int sif_query_gid(struct ib_device *ibdev, u8 port_num, int index, union ib_gid *gid);
int sif_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
		u16 *pkey);

int sif_calc_ipd(struct sif_dev *sdev, u8 port, enum ib_rate static_rate,
		 u8 *ipd);

int sif_modify_device(struct ib_device *ibdev,
		int device_modify_mask,
		struct ib_device_modify *device_modify);

int sif_modify_port(struct ib_device *ibdev,
		u8 port, int port_modify_mask,
		struct ib_port_modify *props);

/* Populate ldev with host endian query_device info requested from the epsc */
int epsc_query_device(struct sif_dev *sdev, struct psif_epsc_device_attr *ldev);


static inline bool epsc_gva_permitted(struct sif_dev *sdev)
{
	/* None of the planned SIBS versions supports GVA2GPA for EPSC mappings */
	return !IS_SIBS(sdev) && sdev->pdev->revision != 2 && !sif_feature(passthrough_query_qp);
}

static inline bool eps_version_ge(struct sif_eps *es, u16 major, u16 minor)
{
	return EPSC_API_VERSION(es->ver.epsc_major, es->ver.epsc_minor) >=
		EPSC_API_VERSION(major, minor);
}

static inline bool eps_fw_version_ge(struct sif_eps *es, u16 major, u16 minor)
{
	return EPSC_API_VERSION(es->ver.fw_major, es->ver.fw_minor) >=
		EPSC_API_VERSION(major, minor);
}

static inline bool eps_fw_version_lt(struct sif_eps *es, u16 major, u16 minor)
{
	return EPSC_API_VERSION(es->ver.fw_major, es->ver.fw_minor) <
		EPSC_API_VERSION(major, minor);
}


#endif
