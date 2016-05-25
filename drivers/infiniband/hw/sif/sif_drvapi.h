/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_drvapi.h: Device specific operations available via the FWA access path
 *
 */
#ifndef _SIF_DRVAPI_H
#define _SIF_DRVAPI_H


enum sif_drv_opcode {
	SIF_DRV_CMD_EPSA_SETUP,     /* Set up the standard communication link towards an EPS-A */
	SIF_DRV_CMD_EPSA_TEARDOWN,  /* Terminate the communication link with an EPS-A */
};

struct epsa_setup {
	enum psif_eps_a_core epsa; /* Which EPS-A to operate on */
	u32 req_size; /* Size in number of reqs of the EPS-A req/rsp queues (only 2**n sizes supported) */
};


struct sif_drv_req {
	enum sif_drv_opcode opcode;
	union {
		struct epsa_setup epsa; /* The EPS-A number for the operation */
	} u;
};

struct sif_drv_rsp {
	enum sif_drv_opcode opcode;    /* The opcode of the driver operation */
	struct psif_epsc_csr_rsp eps_rsp;  /* If status != EPSC_SUCCESS an opt. err resp. from the EPSC */
};


static inline enum psif_mbox_type epsa_to_mbox(enum psif_eps_a_core epsa)
{
	switch (epsa) {
	case PSIF_EPS_A_1:
		return MBOX_EPSA0;
	case PSIF_EPS_A_2:
		return MBOX_EPSA1;
	case PSIF_EPS_A_3:
		return MBOX_EPSA2;
	case PSIF_EPS_A_4:
		return MBOX_EPSA3;
	default:
		break;
	}
	return (enum psif_mbox_type)-1;
}


#endif
