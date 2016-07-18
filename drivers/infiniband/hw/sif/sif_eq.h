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
 * sif_eq.h: Event queues and interrupt handling
 */

#ifndef _SIF_EQ_H
#define _SIF_EQ_H
#include "psif_hw_csr.h"

extern uint sif_cq_eq_max;

struct sif_dev;
struct psif_epsc_csr_rsp;
struct sif_eq;
struct sif_cq;
struct sif_eps;

struct sif_eq_base {
	size_t max_cnt;	/* Number of available event queues in hw */
	size_t min_sw_entry_cnt;	/* Number of required event queue entries per port for EPSC EQ */
	size_t cnt;	/* Number of configured hardware event queues */
	u16 irq_moderation; /* Interrupt total moderation */
	atomic_t eq_sel_seq;  /* A "sequence number" used to select EQ for CQs (EPSC only) */
	struct sif_eq *eq;  /* Dyn.alloc'ed array of sz cnt of eq.desc setup */
};


/* Set up the event queues for an EPS using info about #of queues from the @cqe
 * which contains a host byte order copy of the successful response
 * to the configuration request to the EPS in question
 */
int sif_eq_init(struct sif_dev *sdev, struct sif_eps *es, struct psif_epsc_csr_rsp *cqe);

void sif_eq_deinit(struct sif_dev *sdev, struct sif_eps *es);

int sif_enable_msix(struct sif_dev *s);
int sif_disable_msix(struct sif_dev *sdev);

/* Request irq for all eqs still not requested for */
int sif_eq_request_irq_all(struct sif_eps *es);

/* Printer for debugfs eq file */
void sif_dfs_print_eq(struct seq_file *s, struct sif_dev *sdev, loff_t pos);

/* Printer for debugfs int channel file */
void sif_dfs_print_irq_ch(struct seq_file *s, struct sif_dev *sdev, loff_t pos);

/* simple allocation of EQ channel for CQs: */
u32 sif_get_eq_channel(struct sif_dev *sdev, struct sif_cq *cq);
bool sif_check_valid_eq_channel(struct sif_dev *sdev, int comp_vector);

#endif
