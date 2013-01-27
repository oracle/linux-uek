/*
 * Copyright (c) 2005 Cisco Systems.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef IB_SRP_H
#define IB_SRP_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>

#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_sa.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_fmr_pool.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0))
enum {
	SRP_PATH_REC_TIMEOUT_MS	= 1000,
	SRP_ABORT_TIMEOUT_MS	= 5000,
	SRP_CONN_ERR_TIMEOUT	= 30,

	SRP_PORT_REDIRECT	= 1,
	SRP_DLID_REDIRECT	= 2,
	SRP_STALE_CONN		= 3,

	SRP_MAX_LUN		= 512,
	SRP_DEF_SG_TABLESIZE	= 12,

	SRP_RQ_SHIFT    	= 6,
	SRP_RQ_SIZE		= 1 << SRP_RQ_SHIFT,
	SRP_SQ_SIZE		= SRP_RQ_SIZE - 1,
	SRP_CQ_SIZE		= SRP_SQ_SIZE + SRP_RQ_SIZE,

	SRP_TAG_TSK_MGMT	= 1 << (SRP_RQ_SHIFT + 1),

	SRP_FMR_SIZE		= 256,
	SRP_FMR_POOL_SIZE	= 1024,
	SRP_FMR_DIRTY_SIZE	= SRP_FMR_POOL_SIZE / 4
};

#define SRP_OP_RECV		(1 << 31)

enum srp_target_state {
	SRP_TARGET_LIVE,
	SRP_TARGET_CONNECTING,
	SRP_TARGET_DEAD,
	SRP_TARGET_REMOVED
};

enum srp_request_type {
	SRP_REQ_NORMAL,
	SRP_REQ_TASK_MGMT,
};

struct srp_device {
	struct list_head	dev_list;
	struct ib_device       *dev;
	struct ib_pd	       *pd;
	struct ib_mr	       *mr;
	struct ib_event_handler	event_handler;
	struct ib_fmr_pool     *fmr_pool;
	int			fmr_page_shift;
	int			fmr_page_size;
	u64			fmr_page_mask;
};

struct srp_host {
	struct srp_device      *srp_dev;
	u8			port;
	struct device		dev;
	struct list_head	target_list;
	spinlock_t		target_lock;
	struct completion	released;
	struct list_head	list;
};

struct srp_request {
	struct list_head	list;
	struct scsi_cmnd       *scmnd;
	struct srp_iu	       *cmd;
	struct srp_iu	       *tsk_mgmt;
	struct ib_pool_fmr     *fmr;
	struct completion	done;
	short			index;
	u8			cmd_done;
	u8			tsk_status;
};

struct srp_target_port {
	__be64			id_ext;
	__be64			ioc_guid;
	__be64			service_id;
	__be64			initiator_ext;
	u16			io_class;
	struct srp_host	       *srp_host;
	struct Scsi_Host       *scsi_host;
	char			target_name[32];
	unsigned int		scsi_id;

	struct ib_sa_path_rec	path;
	__be16			orig_dgid[8];
	struct ib_sa_query     *path_query;
	int			path_query_id;

	struct ib_cm_id	       *cm_id;
	struct ib_cq	       *cq;
	struct ib_qp	       *qp;

	int			max_ti_iu_len;
	s32			req_lim;

	int			zero_req_lim;

	unsigned		rx_head;
	struct srp_iu	       *rx_ring[SRP_RQ_SIZE];

	unsigned		tx_head;
	unsigned		tx_tail;
	struct srp_iu	       *tx_ring[SRP_SQ_SIZE + 1];

	struct list_head	free_reqs;
	struct list_head	req_queue;
	struct srp_request	req_ring[SRP_SQ_SIZE];

	struct work_struct	work;
	int			work_in_progress;

	struct list_head	list;
	struct completion	done;
	int			status;
	enum srp_target_state	state;
	int			qp_in_error;
	struct timer_list	qp_err_timer;
	int			active_cmd;
};

struct srp_iu {
	u64			dma;
	void		       *buf;
	size_t			size;
	enum dma_data_direction	direction;
};

#else

enum {
	SRP_PATH_REC_TIMEOUT_MS	= 1000,
	SRP_ABORT_TIMEOUT_MS	= 5000,
	SRP_CONN_ERR_TIMEOUT	= 30,

	SRP_PORT_REDIRECT	= 1,
	SRP_DLID_REDIRECT	= 2,
	SRP_STALE_CONN		= 3,

	SRP_MAX_LUN		= 512,
	SRP_DEF_SG_TABLESIZE	= 12,

	SRP_RQ_SHIFT    	= 6,
	SRP_RQ_SIZE		= 1 << SRP_RQ_SHIFT,

	SRP_SQ_SIZE		= SRP_RQ_SIZE - 1,
	SRP_RSP_SQ_SIZE		= 1,
	SRP_REQ_SQ_SIZE		= SRP_SQ_SIZE - SRP_RSP_SQ_SIZE,
	SRP_TSK_MGMT_SQ_SIZE	= 1,
	SRP_CMD_SQ_SIZE		= SRP_REQ_SQ_SIZE - SRP_TSK_MGMT_SQ_SIZE,

	SRP_TAG_TSK_MGMT	= 1 << (SRP_RQ_SHIFT + 1),

	SRP_FMR_SIZE		= 512,
	SRP_FMR_MIN_SIZE	= 128,
	SRP_FMR_POOL_SIZE	= 1024,
	SRP_FMR_DIRTY_SIZE	= SRP_FMR_POOL_SIZE / 4,

	SRP_MAP_ALLOW_FMR	= 0,
	SRP_MAP_NO_FMR		= 1,
};

#define SRP_OP_RECV		(1 << 31)

enum srp_target_state {
	SRP_TARGET_LIVE,
	SRP_TARGET_CONNECTING,
	SRP_TARGET_DEAD,
	SRP_TARGET_REMOVED
};

enum srp_request_type {
	SRP_REQ_NORMAL,
	SRP_REQ_TASK_MGMT,
};

struct srp_device {
	struct list_head	dev_list;
	struct ib_device       *dev;
	struct ib_pd	       *pd;
	struct ib_mr	       *mr;
	struct ib_event_handler	event_handler;
	struct ib_fmr_pool     *fmr_pool;
	u64			fmr_page_mask;
	int			fmr_page_size;
	int			fmr_max_size;
};

struct srp_host {
	struct srp_device      *srp_dev;
	u8			port;
	struct device		dev;
	struct list_head	target_list;
	spinlock_t		target_lock;
	struct completion	released;
	struct list_head	list;
};

struct srp_request {
	struct list_head	list;
	struct scsi_cmnd       *scmnd;
	struct srp_iu	       *cmd;
	struct srp_iu	       *tsk_mgmt;
	struct ib_pool_fmr    **fmr_list;
	u64		       *map_page;
	struct srp_direct_buf  *indirect_desc;
	dma_addr_t		indirect_dma_addr;
	short			nfmr;
	struct completion	done;
	short			index;
	u8			cmd_done;
	u8			tsk_status;
};

struct srp_target_port {
	/* These are RW in the hot path, and commonly used together */
	struct list_head	free_reqs;
	s32			req_lim;

	/* These are read-only in the hot path */
	struct ib_cq	       *send_cq ____cacheline_aligned_in_smp;
	struct ib_cq	       *recv_cq;
	struct ib_qp	       *qp;
	u32			lkey;
	u32			rkey;
	enum srp_target_state	state;

	/* Everything above this point is used in the hot path of
	 * command processing. Try to keep them packed into cachelines.
	 */

	__be64			id_ext;
	__be64			ioc_guid;
	__be64			service_id;
	__be64			initiator_ext;
	u16			io_class;
	struct srp_host	       *srp_host;
	struct Scsi_Host       *scsi_host;
	char			target_name[32];
	unsigned int		scsi_id;
	unsigned int		sg_tablesize;

	struct ib_sa_path_rec	path;
	__be16			orig_dgid[8];
	struct ib_sa_query     *path_query;
	int			path_query_id;

	struct ib_cm_id	       *cm_id;

	int			max_ti_iu_len;

	int			zero_req_lim;

	unsigned		rx_head;
	struct srp_iu	       *rx_ring[SRP_RQ_SIZE];

	unsigned		tx_head;
	unsigned		tx_tail;
	struct srp_iu	       *tx_ring[SRP_SQ_SIZE + 1];

	struct list_head	req_queue;
	struct srp_request	req_ring[SRP_SQ_SIZE];

	struct work_struct	work;
	int			work_in_progress;

	struct list_head	list;
	struct completion	done;
	int			status;
	unsigned int		max_iu_len;
	unsigned int		cmd_sg_cnt;
	unsigned int		indirect_size;
	bool			allow_ext_sg;
	int			qp_in_error;
	struct timer_list	qp_err_timer;
	int			active_cmd;
};

struct srp_iu {
	u64			dma;
	void		       *buf;
	size_t			size;
	enum dma_data_direction	direction;
};

struct srp_map_state {
	struct ib_pool_fmr    **next_fmr;
	struct srp_direct_buf  *desc;
	u64		       *pages;
	dma_addr_t		base_dma_addr;
	u32			fmr_len;
	u32			total_len;
	unsigned int		npages;
	unsigned int		nfmr;
	unsigned int		ndesc;
	struct scatterlist     *unmapped_sg;
	int			unmapped_index;
	dma_addr_t		unmapped_addr;
};
#endif
#endif /* IB_SRP_H */
