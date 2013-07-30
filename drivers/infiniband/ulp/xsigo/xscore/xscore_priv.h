/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
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
 *
 */

#ifndef _XSCORE_PRIV_H_
#define _XSCORE_PRIV_H_

#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/err.h>
#include <linux/dma-mapping.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_cm.h>

#include <linux/version.h>

#include <rdma/ib_addr.h>
#include <rdma/ib_fmr_pool.h>
#include <asm/byteorder.h>

#include "xs_compat.h"
#include "xscore_xds.h"
#include "xsmp_common.h"
#include "xsmp_session.h"

#define MODULE_NAME "XSCORE"

#define XSCORE_WQ_XDDS_HANDLER    0x1
#define XSCORE_WQ_PORT_EVENTH     0x2
#define XSCORE_WQ_XSMP_PROC_MSG   0x3
#define XSCORE_DWQ_POLL_WORK	  0x4
#define XSCORE_DWQ_SM_WORK        0x5

extern int xscore_debug;
extern unsigned long xscore_wait_time;
extern int xscore_force_sm_change;
extern struct mutex xscore_port_mutex;
extern unsigned long xscore_wq_state;
extern unsigned long xscore_wq_jiffies;
extern unsigned long xscore_last_wq;

enum {
	DEBUG_IB_INFO = 0x00000001,
	DEBUG_IB_FUNCTION = 0x00000002,
	DEBUG_XDS_INFO = 0x00000004,
	DEBUG_XDS_FUNCTION = 0x00000008,
	DEBUG_XSMP_INFO = 0x00000010,
	DEBUG_XSMP_FUNCTION = 0x00000020,
	DEBUG_UADM_INFO = 0x00000040,
	DEBUG_UADM_FUNCTION = 0x00000080,
	DEBUG_XDDS_INFO = 0x00000100,
	DEBUG_XDDS_FUNCTION = 0x00000200,
};

#define PRINT(level, x, fmt, arg...)                                    \
	printk(level "%s: " fmt, MODULE_NAME, ##arg)

#define PRINT_CONDITIONAL(level, x, condition, fmt, arg...)             \
	do {                                                            \
		if (condition)                                         \
			printk(level "%s: %s: " fmt,                    \
			MODULE_NAME, x, ##arg);                  \
	} while (0)

#define IB_PRINT(fmt, arg...)                   \
	PRINT(KERN_INFO, "IB", fmt, ##arg)
#define IB_ERROR(fmt, arg...)                   \
	PRINT(KERN_ERR, "IB", fmt, ##arg)

#define IB_FUNCTION(fmt, arg...)                                \
	PRINT_CONDITIONAL(KERN_INFO,                            \
			"IB",                                 \
			(xscore_debug & DEBUG_IB_FUNCTION),     \
			fmt, ##arg)

#define IB_INFO(fmt, arg...)                                    \
	PRINT_CONDITIONAL(KERN_INFO,                            \
			"IB",                                 \
			(xscore_debug & DEBUG_IB_INFO),         \
			fmt, ##arg)

#define XDS_PRINT(fmt, arg...)                   \
	PRINT(KERN_INFO, "XDS", fmt, ##arg)
#define XDS_ERROR(fmt, arg...)                   \
	PRINT(KERN_ERR, "XDS", fmt, ##arg)

#define XDS_FUNCTION(fmt, arg...)                                \
	PRINT_CONDITIONAL(KERN_INFO,                            \
			"XDS",                                 \
			(xscore_debug & DEBUG_XDS_FUNCTION),     \
			fmt, ##arg)

#define XDS_INFO(fmt, arg...)                                    \
	PRINT_CONDITIONAL(KERN_INFO,                            \
			"XDS",                                 \
			(xscore_debug & DEBUG_XDS_INFO),         \
			fmt, ##arg)

#define XSMP_PRINT(fmt, arg...)                   \
	PRINT(KERN_INFO, "XSMP", fmt, ##arg)
#define XSMP_ERROR(fmt, arg...)                   \
	PRINT(KERN_ERR, "XSMP", fmt, ##arg)

#define XSMP_FUNCTION(fmt, arg...)                                \
	PRINT_CONDITIONAL(KERN_INFO,                            \
		"XSMP",                                 \
		(xscore_debug & DEBUG_XSMP_FUNCTION),     \
		fmt, ##arg)

#define XSMP_INFO(fmt, arg...)                                    \
		PRINT_CONDITIONAL(KERN_INFO,                            \
		"XSMP",                                 \
		(xscore_debug & DEBUG_XSMP_INFO),         \
		fmt, ##arg)

#define UADM_PRINT(fmt, arg...)                   \
	PRINT(KERN_INFO, "UADM", fmt, ##arg)
#define UADM_ERROR(fmt, arg...)                   \
	PRINT(KERN_ERR, "UADM", fmt, ##arg)

#define UADM_FUNCTION(fmt, arg...)                                \
	PRINT_CONDITIONAL(KERN_INFO,                            \
			"UADM",                                 \
			(xscore_debug & DEBUG_UADM_FUNCTION),     \
			fmt, ##arg)

#define UADM_INFO(fmt, arg...)                                    \
	PRINT_CONDITIONAL(KERN_INFO,                            \
			"UADM",                                 \
			(xscore_debug & DEBUG_UADM_INFO),         \
			fmt, ##arg)

#define XDDS_PRINT(fmt, arg...)                   \
	PRINT(KERN_INFO, "XDDS", fmt, ##arg)
#define XDDS_ERROR(fmt, arg...)                   \
	PRINT(KERN_ERR, "XDDS", fmt, ##arg)

#define XDDS_FUNCTION(fmt, arg...)                                \
	PRINT_CONDITIONAL(KERN_INFO,                            \
			"XDDS",                                 \
			(xscore_debug & DEBUG_XDDS_FUNCTION),     \
			fmt, ##arg)

#define XDDS_INFO(fmt, arg...)                                    \
	PRINT_CONDITIONAL(KERN_INFO,                            \
			"XDDS",                                 \
			(xscore_debug & DEBUG_XDDS_INFO),         \
			fmt, ##arg)

/*
 * This structure represents context for the HCA
 */
struct xscore_dev {
	struct list_head port_list;
	struct ib_device *device;
	struct ib_pd *pd;
	struct ib_mr *mr;
	struct ib_event_handler event_handler;
	u64 fw_ver;
	u32 hw_ver;
	u32 vendor_part_id;
	u8 is_shca;
};

enum {
	PORT_XDS_PORT_NOT_ACTIVE_COUNTER,
	PORT_XDS_SA_QUERY_ERROR_COUNTER,
	PORT_XDS_SA_QUERY_TOUT_COUNTER,
	PORT_XDS_SA_QUERY_COUNTER,
	PORT_XDS_XDS_QUERY_ERROR_COUNTER,
	PORT_XDS_XDS_QUERY_TOUT_COUNTER,
	PORT_XDS_XDS_QUERY_COUNTER,
	PORT_XDS_LIST_COUNT_ZERO_COUNTER,
	PORT_XDS_LIST_COUNT_COUNTER,
	PORT_MAX_COUNTERS
};
enum {
	XDS_RECP_START = 1,
	XDS_RECP_QUERY_IB_DONE,
	XDS_RECP_SAUPDATE_DONE,
	XDS_RECP_SAREC_DONE,
	XDS_RECP_CREATEMAD_DONE,
	XDS_RECP_CREATEAH_DONE,
	XDS_RECP_SENDMAD_DONE,
	XDS_RECP_FREEMAD_DONE,
	XDS_RECP_DONE
};

/*
 * This represents context fo each port
 */
/* TBD Add state in this a- PORT_ACTIVE ,b- XDS RECORD/ NO XDS RECORD */
struct xscore_port {
	spinlock_t lock;
	struct xscore_dev *xs_dev;	/* Back pointer to HCA context */
	struct list_head port_list;
	struct list_head gport_list;
	unsigned long flags;
#define	XSCORE_PORT_SHUTDOWN		1
#define	XSCORE_PORT_LID_CHANGE		2
#define	XSCORE_PORT_PROCFS_CREATED	3
#define	XSCORE_SP_PRESENT		4
#define	XSCORE_SP_NOT_PRESENT		5
#define XSCORE_FORCE_SM_CHANGE		6
#define XSCORE_PORT_SMLID_CHANGE	7
	u8 port_num;
	struct workqueue_struct *port_wq;
	struct delayed_work poll_work;
	enum ib_event_type pevent;
	struct work_struct ework;
	int poll_interval;
	int rec_poller_state;
	unsigned long rec_poller_time;
	struct ib_mad_agent *mad_agent;
	struct ib_mad_send_buf *send_buf;
	struct completion sa_query_done;
	int sa_query_status;
	struct completion xds_query_done;
	struct xcm_list xcm_list;
	struct ib_mad_recv_wc *mad_recv_wc;
	u64 guid;
	union ib_gid sgid;
	u16 lid;
	u16 sm_lid;
	u16 xds_lid;
	u64 xds_guid;
	enum rdma_link_layer link_layer;
	struct ib_ud_ctx *ib_ud_ctx;
	struct list_head xsmp_list;
	u32 counters[PORT_MAX_COUNTERS];
};

#define XS_UD_COPY_MSG          0x1

static inline void xscore_set_wq_state(unsigned long state)
{
}

static inline void xscore_clear_wq_state(unsigned long state)
{
}

extern int xs_vpci_bus_init(void);
extern void xs_vpci_bus_remove(void);

extern int xs_ud_create(struct xscore_port *pinfop,
			void (*callback) (void *, void *, int), void *arg);
extern void xs_ud_destroy(struct xscore_port *pinfop);

extern int xs_ud_send_msg(struct xscore_port *pinfop, uint8_t *macp,
			  void *msgp, int len, int flags);
extern void xs_ud_free(void *msg);

void xsmp_module_init(void);
void xsmp_module_destroy(void);
void xsmp_allocate_xsmp_session(struct xscore_port *port, u64 guid, u16 lid);
void xsmp_cleanup_stale_xsmp_sessions(struct xscore_port *port, int force);
/* Externs*/
extern struct ib_sa_client xscore_sa_client;

#endif /* _XSCORE_PRIV_H_ */
