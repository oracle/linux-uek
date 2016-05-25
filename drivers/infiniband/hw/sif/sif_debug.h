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
 * sif_debug.h: Use of debugfs for dumping internal data structure info
 */

#ifndef __SIF_DEBUG_H
#define __SIF_DEBUG_H

struct sif_dev;

/* Set up/tear down the debugfs structures */
int sif_dfs_register(struct sif_dev *sdev);
void sif_dfs_unregister(struct sif_dev *sdev);

/* Symlink to ib device name (to be called after ib_register_device */
void sif_dfs_link_to_ibdev(struct sif_dev *sdev);

int sif_dfs_add_qp(struct sif_dev *sdev, struct sif_qp *qp);
void sif_dfs_remove_qp(struct sif_qp *qp);

/* A generic callback function for printing a table entry
 * in a debug fs file:
 */
typedef void (*sif_dfs_printer)(struct seq_file *s,
				struct sif_dev *,
				loff_t pos);

#endif
