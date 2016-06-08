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
 * sif_r3.h: Special handling specific for psif revision 3 and earlier
 */

#ifndef _SIF_R3_H
#define _SIF_R3_H

struct sif_wa_stats {
	/* Destroying QPs with a retry in progress */
	u64 wa3714[2];
};

void sif_r3_pre_init(struct sif_dev *sdev);
int sif_r3_init(struct sif_dev *sdev);
void sif_r3_deinit(struct sif_dev *sdev);

/* WA for #3714 */
int reset_qp_flush_retry(struct sif_dev *sdev, u8 flush_idx);
void sif_r3_recreate_flush_qp(struct sif_dev *sdev, u8 flush_idx);

/* WA for #4074 */
int pre_process_wa4074(struct sif_dev *sdev, struct sif_qp *qp);
int post_process_wa4074(struct sif_dev *sdev, struct sif_qp *qp);
int sq_flush_wa4074(struct sif_dev *sdev, struct sif_qp *qp);

/* Single file for the wa statistics */
void sif_dfs_print_wa_stats(struct sif_dev *sdev, char *buf);
#endif
