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
 * sif_ireg.h: support functions used in setup of sif as an IB HCA
 */

#ifndef __SIF_IREG_H
#define __SIF_IREG_H

/* User context of a user level ib call */
struct sif_ucontext {
	struct ib_ucontext ib_uc;
	struct sif_pd *pd;  /* A protection domain for completion queues */
	struct sif_cb *cb;  /* The collect buffer for the user process */
	u32 abi_version;  /* User level library's abi version */
};

static inline struct sif_ucontext *to_sctx(struct ib_ucontext *context)
{
	return container_of(context, struct sif_ucontext, ib_uc);
}

int sif_register_ib_device(struct sif_dev *sdev);
void sif_unregister_ib_device(struct sif_dev *sdev);

#endif
