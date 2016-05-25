/*
 * Copyright (c) 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_idr.c: Synchronized ID ref allocation
 */

#include "sif_idr.h"

int sif_idr_init(struct sif_idr *sidr, int id_min, int id_max)
{
	int ret = 0;
	idr_init(&sidr->idr);
	mutex_init(&sidr->lock);
	sidr->id_min = id_min;
	sidr->id_max = id_max;
	return ret;
}


void sif_idr_deinit(struct sif_idr *sidr)
{
	idr_destroy(&sidr->idr);
}


int sif_idr_alloc(struct sif_idr *sidr, void *ref, gfp_t gfp_mask)
{
	int index;

	mutex_lock(&sidr->lock);
	index = idr_alloc(&sidr->idr, ref, sidr->id_min, sidr->id_max, gfp_mask);
	mutex_unlock(&sidr->lock);
	return index;
}

void sif_idr_remove(struct sif_idr *sidr, int index)
{
	mutex_lock(&sidr->lock);
	idr_remove(&sidr->idr, index);
	mutex_unlock(&sidr->lock);
}
