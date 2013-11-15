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

#ifndef __VHBA_OSDEF_H__
#define __VHBA_OSDEF_H__

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/idr.h>
#include <linux/dma-mapping.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/dmapool.h>
#include <linux/spinlock.h>
#include <linux/completion.h>

#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_eh.h>

#include <scsi/scsi_transport_fc.h>

#include <rdma/ib_verbs.h>
#include "xscore.h"
#include "xsmp_common.h"

#define xg_spin_lock_irqsave(lock, flags)			\
	spin_lock_irqsave(lock, flags);

#define xg_spin_unlock_irqrestore(lock, flags)			\
	spin_unlock_irqrestore(lock, flags);

#define xg_spin_lock_irq(lock)					\
	spin_lock_irq(lock);

#define xg_spin_unlock_irq(lock)				\
	spin_unlock_irq(lock);

#define IB_WC_MSG_LEN                   (128+8)

#define VHBA_DEFAULT_SCSI_TIMEOUT		60	/* 60 seconds */
#define EXTEND_CMD_TIMEOUT			80	/* 80 seconds */
#define IB_CMD_TIMEOUT_DELTA		3	/* 3 seconds */
#define DEFER_LIST_TIMEOUT                70	/* 70 seconds */
#define WQ_PERIODIC_TIMER			5	/* 5 seconds */
#define PERIODIC_DEFER_CNT		(DEFER_LIST_TIMEOUT/WQ_PERIODIC_TIMER)

#define VHBA_MAX_SCSI_RETRY			60
#define FORCE_FLUSH_DEFE_LIST			1
#define NO_FORCE_FLUSH_DEFE_LIST		0

#define INVALID_FIELD_IN_CDB	       0x24

#define VHBA_STATE_NOT_ACTIVE           0
#define VHBA_STATE_ACTIVE               1
#define VHBA_STATE_SCAN                 2
#define VHBA_STATE_BUSY			3

#define VHBA_QID_ENABLE				1
#define VHBA_MAX_VH_Q_DEPTH			16
#define VHBA_MAX_VH_Q_COUNT			4

/* SCSI maximum CDB size */
#define MAX_CMDSZ				16
#define MAX_OUTSTANDING_COMMANDS		1024
#define MAX_IO_DESCRIPTORS			32
#define MAX_FIBRE_TARGETS			128
#define MAX_FIBRE_LUNS                    256
#define MAX_FIBRE_LUNS_MORE               256

#define MAX_BUSES				1
#define MAX_TARGETS				MAX_FIBRE_TARGETS
#define MAX_VHBA_QUEUES				4

#define REQUEST_ENTRY_CNT_24XX		1024	/* Number of request entries */

/*
 * Status entry SCSI status bit definitions
 */
/* Reserved bits BIT_12-BIT_15 */
#define SS_MASK						0xfff
#define SS_RESIDUAL_UNDER				BIT_11
#define SS_RESIDUAL_OVER				BIT_10
#define SS_SENSE_LEN_VALID				BIT_9
#define SS_RESPONSE_INFO_LEN_VALID			BIT_8

#define SS_RESERVE_CONFLICT				(BIT_4 | BIT_3)
#define SS_BUSY_CONDITION				BIT_3
#define SS_CONDITION_MET				BIT_2
#define SS_CHECK_CONDITION				BIT_1

/*
 * Status entry completion status
 */
#define CS_COMPLETE			0x0	/* No errors */
#define CS_INCOMPLETE			0x1	/* Incomplete transfer of cmd */
#define CS_DMA				0x2	/* A DMA direction error. */
#define CS_TRANSPORT			0x3	/* Transport error */
#define CS_RESET			0x4	/* SCSI bus reset occurred */
#define CS_ABORTED			0x5	/* System aborted command */
#define CS_TIMEOUT			0x6	/* Timeout error */
#define CS_DATA_OVERRUN			0x7	/* Data overrun */

#define CS_DATA_UNDERRUN		0x15	/* Data Underrun */
#define CS_QUEUE_FULL			0x1C	/* Queue Full */
#define CS_PORT_UNAVAILABLE		0x28	/* Port unavailable */
						/* (selection timeout) */
#define CS_PORT_LOGGED_OUT		0x29	/* Port Logged Out */
#define CS_PORT_CONFIG_CHG		0x2A	/* Port Configuration Changed */
#define CS_PORT_BUSY			0x2B	/* Port Busy */
#define CS_COMPLETE_CHKCOND		0x30	/* Error? */
#define CS_BAD_PAYLOAD			0x80	/* Driver defined */
#define CS_UNKNOWN			0x81	/* Driver defined */
#define CS_RETRY			0x82	/* Driver defined */
#define CS_LOOP_DOWN_ABORT		0x83	/* Driver defined */

#define WWN_SIZE				8

#define LINK_DOWN				0
#define LINK_UP					1
#define LINK_DEAD				2

#define TGT_LOST				1
#define TGT_FOUND				0
#define TGT_DEAD				2

#define LUN_ID_SCHEME

struct xt_cm_private_data {
	u64 vid;
	u16 qp_type;
	u16 max_ctrl_msg_size;
	u32 data_qp_type;
} __packed;

struct xg_scsi_lun {
	u8 scsi_lun[8];
};

struct _vhba_init_ {
	u8 port_id[3];
	u8 vp_index;
	u16 n_port_handle;
	u16 lun;
};

struct vhba_io_cmd {
	u8 cmd[MAX_CMDSZ];
	u32 cmd_len;
	u8 *buf[6];
	u32 buf_size[6];
};

#define ADD_VHBA				1
#define DELETE_VHBA				2
#define SEND_NOP				3
#define SEND_DISK_READ				4
#define SEND_DISK_WRITE				5
#define SET_LID					6

typedef union {
	u16 extended;
	struct {
		u8 reserved;
		u8 standard;
	} id;
} target_id_t;

#define COMMAND_TYPE_7  0x18
struct cmd_type_7 {
	u8 entry_type;		/* Entry type */
	u8 entry_count;		/* Entry count */
	u8 sys_define;		/* System defined */
	u8 entry_status;	/* Entry Status */

	u32 handle;		/* System handle */

	u16 nport_handle;	/* N_PORT handle */
	u16 timeout;		/* Command timeout */
#define FW_MAX_TIMEOUT          0x1999

	u16 dseg_count;		/* Data segment count */
	u16 reserved_1;

	u8 lun[8];		/* FCP LUN (BE) */

	u16 task_mgmt_flags;	/* Task management flags */

#define TMF_CLEAR_ACA           BIT_14
#define TMF_TARGET_RESET        BIT_13
#define TMF_LUN_RESET           BIT_12
#define TMF_CLEAR_TASK_SET      BIT_10
#define TMF_ABORT_TASK_SET      BIT_9
#define TMF_READ_DATA           BIT_1
#define TMF_WRITE_DATA          BIT_0

	u8 task;
#define TSK_SIMPLE              0
#define TSK_HEAD_OF_QUEUE       1
#define TSK_ORDERED             2
#define TSK_ACA                 4
#define TSK_UNTAGGED            5

	u8 crn;

	u8 fcp_cdb[MAX_CMDSZ];	/* SCSI command words */
	u32 byte_count;		/* Total byte count */

	u8 port_id[3];		/* PortID of destination port */
	u8 vp_index;

	u32 dseg_0_address[2];	/* Data segment 0 address */
	u32 dseg_0_len;		/* Data segment 0 length  */

	u32 rkey1;		/* Xg extensions to IOCBS  */
	u32 rkey2;		/* to accomodate           */
	u32 rkey3;		/* rkeys for dsds          */
	u32 rkey4;
	u32 rkey5;

	u32 xg_rsvd[11];
};

#define CONTINUE_A64_TYPE       0x0A	/* Continuation A64 entry  */
struct cont_a64_entry {
	u8 entry_type;		/* Entry type */
	u8 entry_count;		/* Entry count */
	u8 sys_define;		/* System defined */
	u8 entry_status;	/* Entry Status */
	u32 dseg_0_address[2];	/* Data segment 0 address */
	u32 dseg_0_length;	/* Data segment 0 length  */
	u32 dseg_1_address[2];	/* Data segment 1 address */
	u32 dseg_1_length;	/* Data segment 1 length  */
	u32 dseg_2_address[2];	/* Data segment 2 address */
	u32 dseg_2_length;	/* Data segment 2 length  */
	u32 dseg_3_address[2];	/* Data segment 3 address */
	u32 dseg_3_length;	/* Data segment 3 length  */
	u32 dseg_4_address[2];	/* Data segment 4 address */
	u32 dseg_4_length;	/* Data segment 4 length  */

	u32 rkey1;		/* Xg extensions to IOCBS */
	u32 rkey2;		/* to accomodate          */
	u32 rkey3;		/* rkeys for dsds         */
	u32 rkey4;
	u32 rkey5;

	u32 xg_rsvd[11];
};

#define STATUS_TYPE     0x03	/* Status entry */
struct sts_entry_24xx {
	u8 entry_type;		/* Entry type */
	u8 entry_count;		/* Entry count */
	u8 sys_define;		/* System defined */
	u8 entry_status;	/* Entry Status */

	u32 handle;		/* System handle */

	u16 comp_status;	/* Completion status */
	u16 ox_id;		/* OX_ID used by the firmware */

	u32 residual_len;	/* Residual transfer length */

	u16 reserved_1;
	u16 state_flags;	/* State flags */
#define SF_TRANSFERRED_DATA     BIT_11
#define SF_FCP_RSP_DMA          BIT_0

	u16 reserved_2;
	u16 scsi_status;	/* SCSI status */
#define SS_CONFIRMATION_REQ             BIT_12

	u32 rsp_residual_count;	/* FCP RSP residual count */

	u32 sense_len;		/* FCP SENSE length */
	u32 rsp_data_len;	/* FCP response data length */

	u8 data[28];		/* FCP response/sense information */
};

/*
* Status entry completion status
*/
#define CS_DATA_REASSEMBLY_ERROR 0x11	/* Data Reassembly Error */
#define CS_ABTS_BY_TARGET        0x13	/* Target send ABTS to abort IOCB */
#define CS_FW_RESOURCE           0x2C	/* Firmware Resource Unavailable */
#define CS_TASK_MGMT_OVERRUN     0x30	/* Task management overrun (8+) */
#define CS_ABORT_BY_TARGET       0x47	/* Abort By Target */

#define STATUS_CONT_TYPE         0x10	/* Status continuation entry */
struct sts_cont_entry {
	u8 entry_type;		/* Entry type */
	u8 entry_count;		/* Entry count */
	u8 sys_define;		/* System defined */
	u8 entry_status;	/* Entry Status */
	u8 data[60];		/* data */
};

#define MARKER_TYPE     0x04	/* Marker entry */
struct mrk_entry_24xx {
	u8 entry_type;		/* Entry type */
	u8 entry_count;		/* Entry count */
	u8 handle_count;	/* Handle count */
	u8 entry_status;	/* Entry Status */

	u32 handle;		/* System handle */

	u16 nport_handle;	/* N_PORT handle */

	u8 modifier;		/* Modifier (7-0) */
#define MK_SYNC_ID_LUN  0	/* Synchronize ID/LUN */
#define MK_SYNC_ID      1	/* Synchronize ID */
#define MK_SYNC_ALL     2	/* Synchronize all ID/LUN */
	u8 reserved_1;

	u8 reserved_2;
	u8 vp_index;

	u16 reserved_3;

	u8 lun[8];		/* FCP LUN (BE) */
	u8 reserved_4[40];
};

typedef struct {
	u8 data[60];
	u32 signature;
#define RESPONSE_PROCESSED      0xDEADDEAD	/* Signature */
} response_t;

#define ABORT_IOCB_TYPE 0x33
struct abort_entry_24xx {
	u8 entry_type;		/* Entry type */
	u8 entry_count;		/* Entry count */
	u8 handle_count;	/* Handle count */
	u8 entry_status;	/* Entry Status */

	u32 handle;		/* System handle */

	u16 nport_handle;	/* N_PORT handle */
	/* or Completion status */

	u16 options;		/* Options */
#define AOF_NO_ABTS             BIT_0	/* Do not send any ABTS */

	u32 handle_to_abort;	/* System handle to abort */

	u8 reserved_1[32];

	u8 port_id[3];		/* PortID of destination port */
	u8 vp_index;

	u8 reserved_2[12];
};

#define TSK_MGMT_IOCB_TYPE      0x14
struct tsk_mgmt_entry {
	u8 entry_type;		/* Entry type */
	u8 entry_count;		/* Entry count */
	u8 handle_count;	/* Handle count */
	u8 entry_status;	/* Entry Status */

	u32 handle;		/* System handle */

	u16 nport_handle;	/* N_PORT handle */

	u16 reserved_1;

	u16 delay;		/* Activity delay in seconds */

	u16 timeout;		/* Command timeout */

	u8 lun[8];		/* FCP LUN (BE) */

	u32 control_flags;	/* Control Flags */
#define TCF_NOTMCMD_TO_TARGET   BIT_31
#define TCF_LUN_RESET           BIT_4
#define TCF_ABORT_TASK_SET      BIT_3
#define TCF_CLEAR_TASK_SET      BIT_2
#define TCF_TARGET_RESET        BIT_1
#define TCF_CLEAR_ACA           BIT_0

	u8 reserved_2[20];

	u8 port_id[3];		/* PortID of destination port */
	u8 vp_index;

	u8 reserved_3[12];
};

struct scsi_xg_vhba_host;

#define MAX_VHBAS  32

/* Messages on Data QP */
#define INIT_BLOCK            0x1
#define WRITE_INDEX_UPDATE    0x2
#define RING_UPDATE           0x5

#define READ_INDEX_UPDATE     0x7

/* Messages on Control QP */
#define ENABLE_VHBA_Q       0x1
#define DISABLE_VHBA_Q      0x2
#define TGT_RESET           0x3
#define LINK_RESET          0x4
#define ABORT_CMD			0x5
#define LUN_RESET			0x6

#define ENABLE_RSP            0x7
#define DISC_INFO_UPDATE      0x8
#define DISC_INFO_CONT_UPDATE 0x9
#define PLINK_STATUS_UPDATE   0xA
#define TGT_STATUS_UPDATE     0xB
#define VHBA_HEART_BEAT       0x13	/* 0x0xC ~ 0x12 for FC HBA API */

/* 24 bit FC port id ... */
typedef union {
	u32 b24:24;

	struct {
		u8 d_id[3];
		u8 rsvd_1;
	} r;

	struct {
		u8 al_pa;
		u8 area;
		u8 domain;
		u8 rsvd_1;
	} b;
} port_id_t;

/* Ring related structures ... */
struct init_block {
	u8 type;
	u8 entry_size;
	u16 ring_size;
	u32 _reserved;

	u32 read_index_rkey;
	u32 base_addr_rkey;

	u64 read_index_addr;
	u64 base_addr;
};

struct enable_msg {
	u8 type;
	u8 rsvd;
	u8 rsvd1;
	u8 rsvd2;
	u64 resource_id;
};

struct heart_beat_msg {
	u8 type;
	u8 rsvd;
	u8 rsvd1;
	u8 rsvd2;
	u64 resource_id;
};

struct enable_rsp {
	u8 type;
	u8 rsvd;
	u8 rsvd1;
	u8 vp_index;
	u32 rsvd2;
	u64 resource_id;
};

struct vhba_link_status {
	u8 type;
	u8 _reserved1;
	u16 phy_link_status;
	u32 conn_down_timeout;
};

struct tgt_info {
	u16 lun_count;
	u16 loop_id;
	u32 persistent_binding;
	u32 port_id;
	u8 media_type;
	u8 _reserved[3];
	u8 wwpn[WWN_SIZE];
	u8 lun_map[MAX_FIBRE_LUNS >> 3];
	u16 lun_ids[MAX_FIBRE_LUNS];
	u8 wwnn[WWN_SIZE];
};

struct vhba_discovery_msg {
	u8 type;
	u8 _reserved1;
	u16 queue_number;
	u16 target_count;
	u16 cont_count;
	/* Tgts (at the most 1 struct tgt_info) */
	struct tgt_info tgt_data[1];
	u32 fcid;
};

struct vhba_discovery_cont_msg {
	u8 type;
	u8 seg_num;
	u16 target_count;
	/* Tgts (at the most 1 struct tgt_info) */
	struct tgt_info tgt_data[1];
};

struct vhba_write_index_msg {
	u8 type;
	u8 _reserved1;
	u16 write_index;
	u32 _reserved;
};

struct vhba_tgt_status_msg {
	u8 type;
	u8 media_type;
	u8 rscn_addr_format;
	u8 flag;
	u16 loop_id;
	u16 _reserved3;
	u8 wwpn[WWN_SIZE];
	u32 port_id;
	u32 persistent_binding;
	u16 lun_count;
	u16 _reserved4;
	u8 lun_map[MAX_FIBRE_LUNS >> 3];
	u16 lun_ids[MAX_FIBRE_LUNS];
	u8 wwnn[WWN_SIZE];
	u32 port_down_timeout;
};

struct vhba_abort_cmd {
	u8 type;
	u8 _reserved1;
	u8 _reserved2;
	u8 _reserved3;
	u16 vhba_id;
	u16 _reserved4;
	u32 handle_to_abort;
	u8 port_id[3];
	u8 _reserved5;
};

struct vhba_lun_reset_msg {
	u8 type;
	u8 _reserved1;
	u8 _reserved2;
	u8 flag;
	u16 vhba_id;
	u16 lun;
	u8 wwpn[WWN_SIZE];
};

struct vhba_tgt_reset_msg {
	u8 type;
	u8 _reserved1;
	u8 _reserved2;
	u8 flag;
	u16 vhba_id;
	u16 _reserved3;
	u8 wwpn[WWN_SIZE];
};

struct vhba_link_reset_msg {
	u8 type;
	u8 _reserved1;
	u16 vhba_id;
};

#define MAX_VHBA_MSG_SIZE sizeof(struct init_block)
#define MAX_VHBA_NAME_SIZE 16
#define MAX_CHASSIS_NAME_SIZE 32
#define MAX_SESSION_NAME_SIZE 32	/* Server Profile Name Size */

#define BIT_0   0x1
#define BIT_1   0x2
#define BIT_2   0x4
#define BIT_3   0x8
#define BIT_4   0x10
#define BIT_5   0x20
#define BIT_6   0x40
#define BIT_7   0x80
#define BIT_8   0x100
#define BIT_9   0x200
#define BIT_10  0x400
#define BIT_11  0x800
#define BIT_12  0x1000
#define BIT_13  0x2000
#define BIT_14  0x4000
#define BIT_15  0x8000

#define LSB(x)  ((u8)(x))
#define MSB(x)  ((u8)((u16)(x) >> 8))

#define LSW(x)  ((u16)(x))
#define MSW(x)  ((u16)((u32)(x) >> 16))

#define LSD(x)        ((u32)((u64)(x)))
#define MSD(x)        ((u32)((((u64)(x)) >> 16) >> 16))

#define CMD_SP(cmnd)          ((cmnd)->SCp.ptr)

#define TMF_WRITE_DATA         BIT_0

#define TMF_READ_DATA          BIT_1

#define CMD_SP(cmnd)            ((cmnd)->SCp.ptr)
#define CMD_COMPL_STATUS(cmnd)  ((cmnd)->SCp.this_residual)
#define CMD_RESID_LEN(cmnd)     ((cmnd)->SCp.buffers_residual)
#define CMD_SCSI_STATUS(cmnd)   ((cmnd)->SCp.Status)
#define CMD_ACTUAL_SNSLEN(cmnd) ((cmnd)->SCp.Message)
#define CMD_ENTRY_STATUS(cmnd)  ((cmnd)->SCp.have_data_in)

#define DEC_REF_CNT(x) do { \
				if (atomic_dec_and_test(&x->ref_cnt)) { \
					wake_up(&x->delete_wq); \
				} \
			} while (0)

static inline u8 *host_to_fcp_swap(u8 *, u32);

/**
 * host_to_fcp_swap() -
 * @fcp:
 * @bsize:
 *
 * Returns
 */
static inline u8 *host_to_fcp_swap(u8 *fcp, u32 bsize)
{
	u32 *ifcp = (u32 *) fcp;
	u32 *ofcp = (u32 *) fcp;
	u32 iter = bsize >> 2;

	for (; iter; iter--)
		*ofcp++ = swab32(*ifcp++);

	return fcp;
}

#define VHBA_IO_STATE_ACTIVE		0
#define VHBA_IO_STATE_ABORTING		1
#define VHBA_IO_STATE_ABORTED		2
#define VHBA_IO_STATE_ABORT_FAILED	3
#define VHBA_IO_STATE_ABORT_NEEDED	4
#define VHBA_IO_STATE_TIMEDOUT		5
#define VHBA_IO_STATE_RESET		6

#define SRB_STATE_NO_DEFER_LIST	0
#define SRB_STATE_DEFER_LIST	1

struct srb {
	struct list_head list;

	struct scsi_xg_vhba_host *ha;	/* HA the SP is queued on */
	struct scsi_cmnd *cmd;	/* Linux SCSI command pkt */
	struct timer_list timer;	/* Command timer */
	u16 flags;

	/* Request state */
	u16 state;

	/* Target/LUN queue pointers. */
	struct os_tgt *tgt_queue;
	struct os_lun *lun_queue;

	/* Single transfer DMA context */
	dma_addr_t dma_handle;

	u32 request_sense_length;
	u8 *request_sense_ptr;
	u32 queue_num;

	/* Suspend delay */
	int delay;

	u32 tot_dsds;

	void *pool_fmr[6];

	/* Raw completion info for use by failover ? */
	u8 fo_retry_cnt;	/* Retry count this request */
	u8 err_id;		/* error id */
#define SRB_ERR_PORT    1	/* Request failed -- "port down" */
#define SRB_ERR_LOOP    2	/* Request failed -- "loop down" */
#define SRB_ERR_DEVICE  3	/* Request failed -- "device error" */
#define SRB_ERR_OTHER   4

	int iocb_handle;
	void *unaligned_sg;
	int use_copy;
	void *bounce_buffer;
	int bounce_buf_len;
	int use_sg_orig;
	struct scatterlist *lcl_sg;
	int lcl_sg_cnt;
	int abort_cnt;

	u16 error_flag;		/* if page_list allocation fails */
};

#define MAX_SRB_SIZE sizeof(struct srb)

/*
* SRB flag definitions
*/
#define SRB_TIMEOUT             BIT_0	/* Command timed out */
#define SRB_DMA_VALID           BIT_1	/* Command sent to ISP */
#define SRB_WATCHDOG            BIT_2	/* Command on watchdog list */
#define SRB_ABORT_PENDING       BIT_3	/* Command abort sent to device */

#define SRB_ABORTED             BIT_4	/* Command aborted command already */
#define SRB_RETRY               BIT_5	/* Command needs retrying */
#define SRB_GOT_SENSE           BIT_6	/* Command has sense data */
#define SRB_FAILOVER            BIT_7	/* Command in failover state */

#define SRB_BUSY                BIT_8	/* Command is in busy retry state */
#define SRB_FO_CANCEL           BIT_9	/* Command don't need to do failover */
#define SRB_IOCTL               BIT_10	/* IOCTL command. */
#define SRB_TAPE                BIT_11	/* FCP2 (Tape) command. */

/*
* SRB state definitions
*/
#define SRB_FREE_STATE          0	/*   returned back */
#define SRB_PENDING_STATE       1	/*   queued in LUN Q */
#define SRB_ACTIVE_STATE        2	/*   in Active Array */
#define SRB_DONE_STATE          3	/*   queued in Done Queue */
#define SRB_RETRY_STATE         4	/*   in Retry Queue */
#define SRB_SUSPENDED_STATE     5	/*   in suspended state */
#define SRB_NO_QUEUE_STATE      6	/*   is in between states */
#define SRB_ACTIVE_TIMEOUT_STATE 7	/*   in Active Array but timed out */
#define SRB_FAILOVER_STATE      8	/*   in Failover Queue */
#define SRB_SCSI_RETRY_STATE    9	/*   in Scsi Retry Queue */

struct vhba_ib_stats {
	u64 cqp_dn_cnt;
	u64 cqp_up_cnt;
	u64 cqp_send_err_cnt;
	u64 cqp_recv_err_cnt;
	u64 cqp_remote_disconn_cnt;
	u64 dqp_dn_cnt;
	u64 dqp_up_cnt;
	u64 dqp_send_err_cnt;
	u64 dqp_recv_err_cnt;
	u64 dqp_remote_disconn_cnt;
	u64 curr_outstanding_reqs;
	u64 total_req_q_fulls;
	u64 total_outstding_q_wraps;
} __packed;

struct vhba_xsmp_stats {
	u64 install_msg_cnt;
	u64 delete_msg_cnt;
	u64 update_msg_cnt;
	u64 cfg_stats_msg_cnt;
	u64 clr_stats_msg_cnt;
	u64 sync_begin_msg_cnt;
	u64 sync_end_msg_cnt;
	u64 oper_req_msg_cnt;
	u64 unknown_msg_cnt;
	u64 xt_state_dn_cnt;
	u64 tca_lid_changed_cnt;
	u64 abort_all_cnt;
	u64 boot_msg_cnt;
	u64 last_unknown_msg;
	u64 last_msg;
} __packed;

struct vhba_io_stats {
	u64 total_read_reqs;
	u64 total_write_reqs;
	u64 total_task_mgmt_reqs;
	u64 total_read_mbytes;
	u64 total_write_mbytes;
	u64 total_io_rsp;
	u64 total_copy_ios;
	u64 total_copy_page_allocs;
	u64 total_copy_page_frees;
	atomic_t vh_q_full_cnt[VHBA_MAX_VH_Q_COUNT];
	atomic_t num_vh_q_reqs[VHBA_MAX_VH_Q_COUNT];
	u64 qcmd_busy_ret_cnt;
} __packed;

struct vhba_fmr_stats {
	u64 map_cnt;
	u64 unmap_cnt;
	u64 map_fail_cnt;
	u64 unaligned_io_cnt;
	u64 unaligned_ptr_cnt;
	u64 total_fmr_ios;
} __packed;

struct vhba_fc_stats {
	u64 link_dn_cnt;
	u64 link_dead_cnt;
	u64 link_up_cnt;
	u64 rscn_up_cnt;
	u64 rscn_dn_cnt;
	u64 rscn_dead_cnt;
	u64 rscn_multiple_up_cnt;
	u64 rscn_multiple_dn_cnt;
	u64 last_up_tgt;
	u64 last_dn_tgt;
	u64 last_dead_tgt;
	u64 disc_info_cnt;
	u64 enable_resp_cnt;
	u64 enable_msg_cnt;
} __packed;

struct vhba_scsi_stats {
	u64 invalid_tgt_cnt;
	u64 invalid_lun_cnt;
	u64 abort_success_cnt;
	u64 abort_fail_cnt;
	u64 dev_reset_success_cnt;
	u64 dev_reset_fail_cnt;
	u64 bus_reset_success_cnt;
	u64 bus_reset_fail_cnt;
	u64 host_reset_success_cnt;
	u64 host_reset_fail_cnt;
} __packed;

struct vhba_ha_stats {
	struct vhba_ib_stats ib_stats;
	struct vhba_io_stats io_stats;
	struct vhba_fmr_stats fmr_stats;
	struct vhba_fc_stats fc_stats;
	struct vhba_scsi_stats scsi_stats;
} __packed;

#define VHBA_NAME_LEN               16
#define VHBA_LVM_NAME_LEN           128
#define VHBA_MAX_BOOT_DEV           6
#define VHBA_MAX_MOUNT_DEV          6
#define VHBA_MOUNT_OPT_LEN          32

struct host_san_mount_lvm {
	u8 logical_vol_group[VHBA_LVM_NAME_LEN];
	u8 logical_vol[VHBA_LVM_NAME_LEN];
};

struct host_san_vhba_list_sts {
	u8 vh_name[VHBA_NAME_LEN];
	u64 wwn;
	u16 lun;
	u8 tgt_num;		/* target number to expose */
};

typedef union {
	u8 wwpn_t[WWN_SIZE];
	u64 wwpn_val;
} xg_tgt_wwpn;

struct scsi_xg_vhba_host {
	struct list_head list;
	u8 host_str[16];
	atomic_t vhba_flags;
	struct vhba_ha_stats stats;
	struct virtual_hba *vhba;
	int vhba_num;

	struct proc_dir_entry *vhba_proc;
	struct proc_dir_entry *vhba_proc_target;

	u8 *vhba_name[MAX_VHBA_NAME_SIZE];

	u64 tca_guid;
	u16 tca_lid;

	/* SCSI Info */
	struct Scsi_Host *host;
	unsigned long host_no;
	unsigned long instance;
	u16 max_tgt_id;
	u16 max_luns;
	u16 max_targets;
	u32 target_count;
	struct srb *status_srb;
	u32 lun_count;
	struct list_head disc_ports;
	/* OS target queue pointers */
	struct os_tgt *otgt[MAX_FIBRE_TARGETS];

	struct {
		u32 init_done:1;
		u32 online:1;
		u32 reset_active:1;
		u32 process_response_queue:1;
		u32 enable_target_reset:1;
	} flags;

	/* Boot info */
	u16 boot_count;
	struct host_san_vhba_list_sts sanboot[VHBA_MAX_BOOT_DEV];

	/* Mount info */
	u16 mount_count;
	struct host_san_vhba_list_sts sanmount[VHBA_MAX_MOUNT_DEV];
	u16 mount_type;		/* 1 = logical vol
				   2 = direct mount
				   0 = vhba */

	/* name of direct mount device: ex: /dev/sdb */
	u8 direct_mount_dev[VHBA_LVM_NAME_LEN];

	/* logical volume group and logical volume */
	struct host_san_mount_lvm host_lvm_info;

	/* mount options */
	u8 mount_options[VHBA_MOUNT_OPT_LEN];

	u8 discs_ready_flag;

	/* IB Info */
	u64 resource_id;
	struct ib_link_info *link;
	u32 control_qp_handle;
	u32 control_qpn;
	u32 data_qp_handle;
	u32 data_qpn;
	struct xt_cm_private_data ctrl_pvt;
	struct xt_cm_private_data data_pvt;
	atomic_t qp_status;
	struct init_block init_blk;
	struct vhba_write_index_msg *send_write_index_msg;

	u32 max_cont_segs;

	u8 sync_flag;

	/* QL Info */
	u32 vp_index;
	u16 revision;
	u8 ports;

	/* FMR */
	void *fmr_pool;
	void *request_ring_fmr;
	void *rindex_fmr;
	void *scratch;

	atomic_t link_state;
	u32 device_flags;

#define SRB_MIN_REQ     128

	atomic_t dqp_send_buf_consumed;

	/* Req ring lock, rings, and indexes */
	dma_addr_t request_dma;	/* Physical address */
	struct cmd_type_7 *request_ring;	/* Base virtual address */
	struct cmd_type_7 *request_ring_ptr;	/* Current address */
	u16 req_ring_rindex_dummy;	/* Current index */
	s16 req_ring_windex;	/* Current index */
	u16 req_q_cnt;		/* Number of available entries */
	u16 request_q_length;
	dma_addr_t req_ring_rindex_dma;
	u32 *req_ring_rindex;

	/* Outstanding commands */
	struct srb *outstanding_cmds[MAX_OUTSTANDING_COMMANDS];
	u32 current_outstanding_cmd;
	void *send_buf_ptr[REQUEST_ENTRY_CNT_24XX];
	struct ib_wc recv_buf_ptr[64];

	/* Defer list */
	struct list_head defer_list;
	atomic_t defer_cnt;
	atomic_t periodic_def_cnt;
	atomic_t ib_link_down_cnt;
	atomic_t ib_status;

	/* Lock order: First hold host_lock before holding list_lock */
	spinlock_t list_lock ____cacheline_aligned;
	spinlock_t io_lock ____cacheline_aligned;
};

struct xsvhba_conn {
	u8 type;
	int state;
	struct xscore_conn_ctx ctx;
};

struct xsvhba_work {
	struct work_struct work;
	xsmp_cookie_t xsmp_hndl;
	struct virual_hba *vhba;
	u8 *msg;
	u32 idr;
	int len;
	int status;
};

struct virtual_hba {
	struct scsi_xg_vhba_host *ha;
	struct vhba_xsmp_msg *cfg;
	struct list_head list;
	wait_queue_head_t timer_wq;
	wait_queue_head_t delete_wq;

	struct xsvhba_conn ctrl_conn;
	struct xsvhba_conn data_conn;
	struct xsmp_session_info xsmp_info;
	xsmp_cookie_t xsmp_hndl;

	atomic_t ref_cnt;
	atomic_t vhba_state;
	atomic_t reconnect_flag;
	u32 idr;
	int sync_needed;
	int reconn_try_cnt;
	int reconn_attempt;
	int qp_count;
	u64 cs_timeout_count;
	atomic_t abort_count;
	int qp_poll_count;
	int heartbeat_count;
	u64 resource_id;
	int scanned_once;
	int scan_reqd;
	int xg_init_done;
	struct proc_dir_entry *admin_down_proc;
	struct work_struct work;
};

#define WWN_SIZE 8

#define TQF_ONLINE              0	/* Device online to OS */
#define TQF_SUSPENDED           1
#define TQF_RETRY_CMDS          2

#define VHBA_ALLOC_FMR          0x40
#define VHBA_NO_TARGET_STATE    0x200
#define VHBA_ADMIN_DOWN_STATE   0x400

#define VHBA_DATA_QP            0x1
#define VHBA_CONTROL_QP         0x2
#define VHBA_BOTH_QP            0x3

#define VHBA_READY              0
#define VHBA_DRAINING           1
#define VHBA_ABORTING           2
#define VHBA_DELETING           3
#define VHBA_DELETED            4

#define FCS_UNCONFIGURED        1
#define FCS_DEVICE_DEAD         2
#define FCS_DEVICE_LOST         3
#define FCS_ONLINE              4
#define FCS_NOT_SUPPORTED       5

struct os_lun {
	struct fc_lun *fclun;	/* FC LUN context pointer */
	u32 lun_id;

	unsigned long q_flag;

	u_long q_timeout;	/* total command timeouts */
	atomic_t q_timer;	/* suspend timer */
	u32 q_count;		/* current count */
	u32 q_max;		/* maxmum count lun can be suspended */
	u8 q_state;		/* lun State */

	u_long io_cnt;		/* total xfer count since boot */
	u_long out_cnt;		/* total outstanding IO count */
	u_long w_cnt;		/* total writes */
	u_long r_cnt;		/* total reads */
	u_long avg_time;	/*  */
};

struct os_tgt {
	/* LUN context pointer */
	struct os_lun *olun[MAX_FIBRE_LUNS_MORE];
	struct fc_port *fcport;
	unsigned long flags;
	struct scsi_xg_vhba_host *ha;

	/* Persistent binding information */
	port_id_t d_id;
	u8 node_name[WWN_SIZE];
	u8 port_name[WWN_SIZE];
	u8 init_done;
	atomic_t ncmds;
	u16 state;
};

#define FCF_TAPE_PRESENT	BIT_0
typedef struct fc_port {
	struct list_head list;
	struct list_head fcluns;

	u8 node_name[WWN_SIZE];
	u8 port_name[WWN_SIZE];
	port_id_t d_id;
	u16 loop_id;

	u8 port_type;

	atomic_t state;
	u32 flags;

	struct os_tgt *tgt_queue;
	u16 os_target_id;

	u8 device_type;
	u8 unused;

	u8 bound;
	u16 lun_count;

	u8 lun_map[MAX_FIBRE_LUNS >> 3];
	u16 lun_ids[MAX_FIBRE_LUNS];
	u32 persistent_binding;

	struct fc_rport *rport;
	u32 supported_classes;

} fc_port_t;

struct fc_lun {
	struct list_head list;

	u16 lun;
	atomic_t state;
	u8 device_type;

	u8 max_path_retries;
	u32 flags;
};

#define TGT_Q(ha, t)       (ha->otgt[t])
#define LUN_Q(ha, t, l)    (TGT_Q(ha, t)->olun[l])
#define GET_LU_Q(ha, t, l)	\
	((TGT_Q(ha, t) != NULL) ? TGT_Q(ha, t)->olun[l] : NULL)

extern struct virtual_hba vhba_g;
extern struct idr vhba_idr_table;
extern rwlock_t vhba_global_lock;
extern u32 vhba_current_idr;
extern atomic_t vhba_count;
extern struct workqueue_struct *vhba_workqueuep;

#define MAX_LUNS 0xffff

#endif /* __VHBA_OSDEF_H__ */
