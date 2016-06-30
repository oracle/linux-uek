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
 * sif_qp.h: Interface to internal IB queue pair logic for sif
 */

#ifndef __SIF_QP_H
#define __SIF_QP_H
#include "psif_hw_data.h"
#include "sif_rq.h"
#include "sif_sq.h"
#include "sif_ibqp.h"

struct sif_dev;
struct seq_file;
struct sif_sq;
struct sif_rq;

#define CB_LENGTH 256
#define CB_KICK_ALIGN 64
#define CB_KICK_MASK  (CB_KICK_ALIGN - 1)

enum sif_qp_flags {
	SIF_QPF_EOIB          = 0x1,
	SIF_QPF_IPOIB         = 0x2,
	SIF_QPF_FORCE_SQ_MODE = 0x1000,   /* Set by vendor specific flag to enforce use of SQ mode */
	SIF_QPF_NO_EVICT      = 0x2000,   /* Special fake qp with do_not_evict set (see #3552) */
	SIF_QPF_KI_STENCIL    = 0x4000,   /* Special stencil qp set up for efficient key invalidates */
	SIF_QPF_DYNAMIC_MTU   = 0x8000,   /* Set by vendor specific flag to enforce use of dynamic MTU */
	SIF_QPF_FLUSH_RETRY   = 0x10000,  /* Special fake rc qp to flush retry (see #3714) */
	SIF_QPF_USER_MODE     = 0x20000,  /* User (udata != NULL) and not kernel verbs */
	SIF_QPF_PMA_PXY       = 0x100000, /* Performance management interface QP type */
	SIF_QPF_SMI           = 0x200000, /* Subnet management interface QP type */
	SIF_QPF_GSI           = 0x400000, /* General services interface QP type */
	SIF_QPF_HW_OWNED      = 0x1000000,/* Indicates HW ownership */
};

struct dentry;

/*
 * TBD - not suitable for kernel.org:
 * As for now, the stack unwind is done at sif_create_qp() within sif driver.
 * Picking UEK version 4.1.12 as a starting point to have this,
 * as UEK kernel has ib_create_qp->ib_create_qp_ex.
 * Thus, set it to 4 based on what is implemented in Oracle Kernel
 * to retrieve the ULP.
*/
#define STACK_UNWIND_LEVEL 4
/*
 * sif_create_qp        = __builtin_return_address(0)
 * ib_create_qp         = __builtin_return_address(1)
 * ib_create_qp_ex      = __builtin_return_address(2)
 * if (rdma_cm)
 * rdma_create_qp       = __builtin_return_address(3)
 * ULP                  = __builtin_return_address(4)
*/

/* The enum to determine what is the ULP caller
 */
enum kernel_ulp_type {
	OTHER_ULP    = 0,
	RDS_ULP	     = 1,
	IPOIB_CM_ULP = 2,
	IPOIB_ULP    = 3,
};

struct sif_qp_init_attr {
	struct sif_pd *pd;
	enum psif_qp_trans qp_type;
	enum sif_proxy_type proxy;
	enum psif_tsu_qos qosl;
	enum kernel_ulp_type ulp_type; /* the ulp caller hint */
	bool user_mode;
	int sq_hdl_sz;
};


enum qp_persistent_state {
	SIF_QPS_IN_RESET  = 0,
};

struct sif_qp {
	volatile struct psif_qp d;	/* Hardware QPSC entry */
	struct ib_qp ibqp ____cacheline_internodealigned_in_smp;

	/* Data area for query_qp results: */
	struct psif_query_qp qqp ____cacheline_internodealigned_in_smp;

	/* Pack the members used in critical path in as few cache lines as possible */
	union {
		u16 submask[2];
		u32 mask;
	} traffic_patterns;              /* heuristic mask to determine the traffic pattern */
	enum kernel_ulp_type ulp_type; /* the ulp caller hint */
	atomic_t refcnt;               /* qp refcnt to sync between destroy qp and event handling. */
	struct completion can_destroy; /* use to synchronize destroy qp with event handling */
	struct mutex lock ____cacheline_internodealigned_in_smp;
	int qp_idx;			/* qp and sq index */
	int rq_idx;
	u32 max_inline_data;		/* Requested max inline for this QP */

	/* Next 6 members are copy from the qp state */
	u32 remote_qp;
	u32 magic;
	bool nocsum;
	enum psif_tsu_qos qosl;
	u8 tsl;
	u16 remote_lid;

	u16 eps_tag;			/* Value to use for the eps_tag field (proxy_qp) */
	short port;			/* IB port number (= sif port# + 1) */
	u32 flags;
	enum ib_qp_state last_set_state;
	enum psif_qp_trans type;	/* PSIF transport type set up for this QP */

	/* The following members are not used in critical path */
	u16 pkey_index;			/* Default PKEY index as set by IB_QP_PKEY */
	enum ib_mtu mtu;		/* Currently set mtu */
	enum ib_qp_state tracked_state; /* TBD: This is stupid: Make SQD fail as MLX for SQD */
	struct dentry *dfs_qp;		/* Raw qp dump debugfs handle - used by sif_debug.c */
	bool sq_cmpl_map_valid;

	int srq_idx;			/* WA #3952: Track SRQ for modify_srq(used only for pQP) */
	atomic64_t arm_srq_holdoff_time;/* Wait-time,if the pQP is held for a prev modify_srq */
	unsigned long persistent_state; /* the atomic flag to determine the QP reset */

	u64 ipoib_tx_csum_l3;
	u64 ipoib_tx_csum_l4;
	u64 ipoib_rx_csum_l3_ok;
	u64 ipoib_rx_csum_l3_err;
	u64 ipoib_rx_csum_l4_ok;
	u64 ipoib_rx_csum_l4_err;
	u64 ipoib_tx_lso_pkt;
	u64 ipoib_tx_lso_bytes;
};


/* Definition of PSIF EPSA tunneling QP using IB_QPT_RESERVED1 */
#define IB_QPT_EPSA_TUNNELING IB_QPT_RESERVED1

/* Command used to invalidate a collect buffer by writing to offset 0xff8 */
#define PSIF_WR_CANCEL_CMD_BE 0xff00000000000000ULL

/* HEURISTIC BITS used for TX/RX direction. */
#define HEUR_RX_DIRECTION (~1ULL)
#define HEUR_TX_DIRECTION (1ULL)

static inline bool supports_offload(struct sif_qp *qp)
{
	return qp->flags & (SIF_QPF_EOIB | SIF_QPF_IPOIB);
}

static inline int psif_supported_trans(enum psif_qp_trans type)
{
	return type != PSIF_QP_TRANSPORT_RSVD1;
}

static inline bool is_xini_qp(struct sif_qp *qp)
{
	return qp->ibqp.qp_type == IB_QPT_XRC_INI;
}

static inline bool is_xtgt_qp(struct sif_qp *qp)
{
	return qp->ibqp.qp_type == IB_QPT_XRC_TGT;
}

static inline bool is_xrc_qp(struct sif_qp *qp)
{
	return qp->type == PSIF_QP_TRANSPORT_XRC;
}

static inline bool is_reliable_qp(enum psif_qp_trans type)
{
	return type == PSIF_QP_TRANSPORT_RC || type == PSIF_QP_TRANSPORT_XRC;
}

static inline bool multipacket_qp(enum psif_qp_trans type)
{
	switch (type) {
	case PSIF_QP_TRANSPORT_RC:
	case PSIF_QP_TRANSPORT_UC:
	case PSIF_QP_TRANSPORT_XRC:
		return true;
	default:
		return false;
	}
}

static inline bool is_epsa_tunneling_qp(enum ib_qp_type type)
{
	return type == IB_QPT_EPSA_TUNNELING;
}

static inline struct sif_qp *to_sqp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct sif_qp, ibqp);
}

struct sif_qp *create_qp(struct sif_dev *sdev,
			struct ib_qp_init_attr *init_attr,
			struct sif_qp_init_attr *sif_attr);

int destroy_qp(struct sif_dev *sdev, struct sif_qp *qp);


int modify_qp(struct sif_dev *sdev, struct sif_qp *qp,
	struct ib_qp_attr *qp_attr, int qp_attr_mask,
	bool fail_on_same_state, struct ib_udata *udata);

enum ib_qp_state get_qp_state(struct sif_qp *qp);

/* Line printers for debugfs files */
void sif_dfs_print_qp(struct seq_file *s, struct sif_dev *sdev, loff_t pos);
void sif_dfs_print_ipoffload(struct seq_file *s, struct sif_dev *sdev, loff_t pos);

/* SIF specific type of handling of a modify QP operation:
 *
 */
enum sif_mqp_type {
	SIF_MQP_ERR, /* Illegal transition */
	SIF_MQP_SW,  /* Software handled transition */
	SIF_MQP_HW,  /* Hardware handled transition */
	SIF_MQP_IGN, /* Silently ignored transition req */
	SIF_MQP_MAX
};

u64 sif_qqp_dma_addr(struct sif_dev *sdev, struct sif_qp *qps);

/* Internal query qp implementation - stores a host order query qp state in lqqp */
int epsc_query_qp(struct sif_qp *qp, struct psif_query_qp *lqqp);

/* EPSC configuration to forward PMA responses to the remapped qp_idx */
int notify_epsc_pma_qp(struct sif_dev *sdev, int qp_idx, short port);

enum sif_mqp_type sif_modify_qp_is_ok(
	struct sif_qp *qp,
	enum ib_qp_state cur_state,
	enum ib_qp_state next_state,
	enum ib_qp_attr_mask mask
);

static inline enum psif_mbox_type proxy_to_mbox(enum sif_proxy_type proxy)
{
	switch (proxy) {
	case SIFPX_EPSA_1:
		return MBOX_EPSA0;
	case SIFPX_EPSA_2:
		return MBOX_EPSA1;
	case SIFPX_EPSA_3:
		return MBOX_EPSA2;
	case SIFPX_EPSA_4:
		return MBOX_EPSA3;
	default:
		break;
	}
	return (enum psif_mbox_type) -1;
}

int modify_qp_hw_wa_qp_retry(struct sif_dev *sdev, struct sif_qp *qp,
		    struct ib_qp_attr *qp_attr, int qp_attr_mask);

static inline bool has_rq(struct sif_qp *qp)
{
	return qp->rq_idx >= 0;
}

bool has_srq(struct sif_dev *sdev, struct sif_qp *qp);

static inline bool ib_legal_path_mtu(enum ib_mtu mtu)
{
	return (mtu >= IB_MTU_256) && (mtu <= IB_MTU_4096);
}

struct sif_sq *get_sq(struct sif_dev *sdev, struct sif_qp *qp);
struct sif_rq *get_rq(struct sif_dev *sdev, struct sif_qp *qp);

#endif
