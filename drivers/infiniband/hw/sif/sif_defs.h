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
 * sif_defs.h: Div. utility definitions and auxiliary data structures
 */

#ifndef __SIF_DEFS_H
#define __SIF_DEFS_H
#include "psif_hw_data.h"
#include "sif_mmu.h"
#include "sif_pd.h"
#include "sif_sq.h"
#include "sif_cq.h"
#include "sif_mem.h"
#include "sif_rq.h"
#include "sif_ireg.h"

/* Needed by print funcs */
#define xprintf(x, format, arg...) \
	do {\
		if (x)	\
			(x)->buf += sprintf((x)->buf, format, ## arg);	\
		else \
			printk(format, ## arg); \
	} while (0)

struct xchar {
	char *buf;
};

#define GREATER_16(a, b) ((s16)((s16)(a) - (s16)(b)) > 0)


#define XFILE struct xchar
#include "psif_hw_print.h"

enum sif_tab_type;

enum psif_wr_type sif_invalidate_opcode(enum sif_tab_type type);

enum ib_wc_opcode sif2ib_wc_opcode(enum psif_wc_opcode opcode);
enum psif_wc_opcode ib2sif_wc_opcode(enum ib_wc_opcode opcode);

enum ib_wc_status sif2ib_wc_status(enum psif_wc_status status);
enum psif_wc_status ib2sif_wc_status(enum ib_wc_status status);

enum ib_wr_opcode sif2ib_wr_op(enum psif_wr_type op);
enum psif_wr_type ib2sif_wr_op(enum ib_wr_opcode op, bool is_dr);

enum psif_qp_trans ib2sif_qp_type(enum ib_qp_type type);

enum psif_qp_state ib2sif_qp_state(enum ib_qp_state state);
enum ib_qp_state sif2ib_qp_state(enum psif_qp_state state);

enum ib_mig_state sif2ib_mig_state(enum psif_migration mstate);
enum psif_migration ib2sif_mig_state(enum ib_mig_state mstate);

enum ib_mtu sif2ib_path_mtu(enum psif_path_mtu mtu);
enum psif_path_mtu ib2sif_path_mtu(enum ib_mtu mtu);
enum kernel_ulp_type sif_find_kernel_ulp_caller(void);

/* TBD: IB datastructure dump functions - remove/replace? */
const char *ib_event2str(enum ib_event_type e);

static inline struct sif_pd *to_spd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct sif_pd, ibpd);
}

static inline struct sif_shpd *to_sshpd(struct ib_shpd *ibshpd)
{
	return container_of(ibshpd, struct sif_shpd, ibshpd);
}

/* Generic table handling functions:
 * For xx in cq,rq,sq:
 *
 *      Return element# @index in the xx queue referred by q:
 *
 *    struct psif_xx_entry *get_xx_entry(struct sif_xx *q, int index);
 *
 *      @ptr: Kernel virtual address offset into an entry in the xx queue @q
 *      Return value: The corresponding dma address.
 *
 *    u64 xxe_to_dma(struct sif_xx *q, void* ptr);

 *  TBD: Document the rest of the macro defined generic calls
 */


#define sif_define_entry_funcs(type, dtype) \
static inline struct psif_##type##_entry \
	*get_##type##_entry(struct sif_##type *q, unsigned dtype seq)\
{\
	return (struct psif_##type##_entry *) sif_mem_kaddr(q->mem, (seq & q->mask) * q->extent); \
} \
static inline u64 get_##type##e_dma(struct sif_##type *q, unsigned dtype seq) \
{\
	return sif_mem_dma(q->mem, (seq & q->mask) * q->extent); \
} \
static inline int type##_is_empty(struct sif_##type *q, unsigned dtype head, unsigned dtype tail)\
{\
	return (head == tail); \
} \
static inline dtype type##_length(struct sif_##type *q, dtype head, dtype tail)\
{\
	return tail - head;\
} \

sif_define_entry_funcs(cq, int)
sif_define_entry_funcs(rq, int)
sif_define_entry_funcs(sq, short)

static inline void *sq_sgl_offset(struct sif_sq *sq, struct psif_sq_entry *sqe)
{
	return (u8 *)sqe + sq->sgl_offset;
}

/* Define an architecture independent write combining flush:
 * According to documentation, we should have been able to use
 * mmiowb() but on x86_64 mmiowb does not contain the necessary sfence instruction.
 */

#if defined(__i386__)
#define wc_wmb() asm volatile("lock; addl $0,0(%%esp) " ::: "memory")
#elif defined(__x86_64__)
#define wc_wmb() asm volatile("sfence" ::: "memory")
#elif defined(__ia64__)
#define wc_wmb() asm volatile("fwb" ::: "memory")
#else
#define wc_wmb() wmb()
#endif

#endif
