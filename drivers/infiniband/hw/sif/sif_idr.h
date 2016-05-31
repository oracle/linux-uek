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
 * sif_idr.h: simple id allocation and deallocation for SIF
 */

#ifndef _SIF_IDR_H
#define _SIF_IDR_H
#include <linux/version.h>
#include <linux/idr.h>
#include <linux/mutex.h>

/* Synchronized ID ref allocation */

struct sif_idr {
	struct idr idr;
	struct mutex lock;
	int id_min;
	int id_max;
};

int sif_idr_init(struct sif_idr *sidr, int id_min, int id_max);
void sif_idr_deinit(struct sif_idr *sidr);

int sif_idr_alloc(struct sif_idr *sidr, void *ref, gfp_t gfp_mask);
void sif_idr_remove(struct sif_idr *sidr, int index);


#endif
