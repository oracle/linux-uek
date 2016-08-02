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

enum wa4059_stats_counter {
	SND_INTR_KEEP_ALIVE_WA4059_CNT   = 0,
	SND_THREAD_KEEP_ALIVE_WA4059_CNT = 1,
	WA4059_CNT_MAX                   = 2,
};

enum wa3714_stats_counter {
	FLUSH_RETRY_WA3714_CNT     = 0,
	FLUSH_RETRY_WA3714_ERR_CNT = 1,
	WA3714_CNT_MAX             = 2,
};

enum wa4074_stats_counter {
	PRE_WA4074_CNT           = 0,
	POST_WA4074_CNT          = 1,
	POST_WA4074_ERR_CNT      = 2,
	WRS_CSUM_CORR_WA4074_CNT = 3,
	RCV_SND_GEN_WA4074_CNT   = 4,
	WA4074_CNT_MAX           = 5,
};

struct sif_wa_stats {
	/* Destroying QPs with a retry in progress */
	atomic64_t wa3714[WA3714_CNT_MAX];
	/* Duplicate flushed in error completions */
	atomic64_t wa4074[WA4074_CNT_MAX];
	/* Mailbox writes from host to EPS sometimes get misplaced */
	atomic64_t wa4059[WA4059_CNT_MAX];
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

/* Single file for the wa statistics */
void sif_dfs_print_wa_stats(struct sif_dev *sdev, char *buf);
#endif
