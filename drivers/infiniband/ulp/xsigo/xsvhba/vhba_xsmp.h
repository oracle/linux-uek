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

#ifndef __VHBA_XSMP_H__
#define __VHBA_XSMP_H__

#include <linux/types.h>
#include <rdma/ib_verbs.h>
#include <linux/workqueue.h>

#include "xscore.h"
#include "xsmp_common.h"
#include "vhba_os_def.h"

extern int vhba_xsmp_init(void);
extern void vhba_xsmp_exit(void);

#define XSMP_VHBA_INSTALL             1
#define XSMP_VHBA_DELETE              2
#define XSMP_VHBA_UPDATE              3
#define XSMP_VHBA_ADMIN_UP            4
#define XSMP_VHBA_ADMIN_DOWN          5
#define XSMP_VHBA_OPER_UP             6
#define XSMP_VHBA_OPER_DOWN           7
#define XSMP_VHBA_OPER_READY          8
#define XSMP_VHBA_STATS_REQ           9
#define XSMP_VHBA_STATS              10
#define XSMP_VHBA_SYNC_BEGIN         11
#define XSMP_VHBA_SYNC_END           12
#define XSMP_VHBA_INFO_REQUEST       13
#define XSMP_VHBA_OPER_REQ           14
#define XSMP_VHBA_BOOT_INFO          15
#define XSMP_VHBA_TYPE_MAX           16

#define VHBA_PORT_RATE_CHANGED        0x1
#define VHBA_TAPE_SUPPORT_CHANGED     0x2
#define VHBA_IDT_CHANGED              0x4
#define VHBA_ET_CHANGED               0x8
#define VHBA_SCSI_Q_DPTH_CHANGED      0x10
#define VHBA_LDT_CHANGED              0x20
#define VHBA_ADMINSTATE_CHANGED       0x100
#define VHBA_TGT_RESET_CHANGED        0x40
#define VHBA_LUNS_PER_TGT_CHANGED     0x80

#define ADMINSTATE_DOWN               0x0
#define ADMINSTATE_UP                 0x1

#define MAX_NUM_LINKS			32
enum vhba_xsmp_error_codes {
	VHBA_NACK_INVALID,	/* 0 */
	VHBA_NACK_DUP_NAME,	/* 1 */
	VHBA_NACK_DUP_VID,	/* 2 */
	VHBA_NACK_LIMIT_REACHED,	/* 3 */
	VHBA_NACK_ALLOC_ERROR,	/* 4 */
	VHBA_NACK_INVALID_STATE,	/* 5 */
	VHBA_NACK_DEVICE_BUSY,	/* 6 */

	VHBA_NACK_INS_APP_TIMEOUT,	/* 7 */
	VHBA_NACK_UNINST_APP_TIMEOUT,	/* 8 */
	VHBA_NACK_INS_APP_ERROR,	/* 9 */
	VHBA_NACK_UNINS_APP_ERROR,	/* 10 */
	VHBA_NACK_GENERAL_ERROR,	/* 11 */
	VHBA_NACK_LOCAL_DISABLED,	/* 12 */

	VHBA_NACK_HA_GROUP_NAME_MISMATCH,	/* 13 */
	VHBA_NACK_HA_MAC_ADDRESS_MISMATCH,	/* 14 */
	VHBA_NACK_HA_MTU_SIZE_MISMATCH,	/* 15 */

	VHBA_NACK_LA_GROUP_NAME_MISMATCH,	/* 16 */
	VHBA_NACK_LA_MAC_ADDRESS_MISMATCH,	/* 17 */
	VHBA_NACK_LA_MTU_SIZE_MISMATCH,	/* 18 */
	VHBA_NACK_LA_POLICY_MISMATCH,	/* 19 */

	VHBA_NACK_CODE_MAX,	/* 20 */
};

/* Ack and Nack sent out in the 'code' field */
#define  XSMP_VHBA_ACK          (1 << 6)
#define  XSMP_VHBA_NACK         (1 << 7)

#define H_TO_N 0
#define N_TO_H 1

#define ntohq be64_to_cpu
#define htonq cpu_to_be64
#define VHBA_NAME_LEN               16
#define VHBA_MAX_BOOT_DEV           6
#define VHBA_MAX_MOUNT_DEV          6
#define VHBA_LVM_NAME_LEN           128
#define VHBA_MOUNT_OPT_LEN          32

struct san_vhba_list_sts {
	u8 vh_name[VHBA_NAME_LEN];
	u64 wwn;
	u16 lun;
} __packed;

struct vhba_boot_info {
	/* standard header fields */
	u8 type;
	u8 code;
	u16 length;

	u64 resource_id;

	/* Count of boot devices specified */
	u16 boot_count;
	struct san_vhba_list_sts boot_devlist[VHBA_MAX_BOOT_DEV];

	u16 mount_type;		/* 1 = use logical vol group, 0 = use vhba */
	u8 logical_vol_group[VHBA_LVM_NAME_LEN];
	u8 logical_vol[VHBA_LVM_NAME_LEN];
	u8 direct_mount_dev[VHBA_LVM_NAME_LEN];
	u8 mount_options[VHBA_MOUNT_OPT_LEN];

	u16 mount_count;	/* count of mount devices */
	struct san_vhba_list_sts mount_devlist[VHBA_MAX_MOUNT_DEV];

	/*
	 * Padding reserves u8s to make the V* message size = 960.
	 * If you add new variables to the structure,
	 * you should adjust the paddings
	 */
	u8 reserved[214];
} __packed;

struct vhba_xsmp_msg {
	union {
		struct {
			u8 type;
			u8 code;
			u16 length;
			u32 bit_mask;

			u64 resource_id;
			u64 wwn;
			u64 tca_guid;

			u16 tca_lid;
			u16 vhba_flag;
			u32 bandwidth;

			u32 tapesupport;
			u32 interruptdelaytimer;

			u32 executionthrottle;
			u32 scsiqueuedepth;

			u32 linkdowntimeout;
			u32 adminstate;

			u32 enabletargetreset;
			u32 maxlunspertarget;

			u32 num_queues;	/* Maximum 4  (0 .. 3) */
			u8 vm_index;
			u8 lunmask_enable;
			u16 tca_slot;

			u8 vh_name[VHBA_NAME_LEN];

			struct {
				/*
				* Right now only one target,
				* LUN combination per queue (default q 0)
				* Actual rates are used only in I/O card side
				*/
				u8 target[WWN_SIZE];
				u32 lun;
			} __packed
			    q_classification[MAX_VHBA_QUEUES];

			uint32_t mtu;

		} __packed;
		uint8_t bytes[512];
	};
} __packed;

#define MAX_XSMP_MSG_SIZE sizeof(struct vhba_xsmp_msg)

struct _vhba_stats_config_msg {
	u8 type;
	u8 code;
	u16 length;

	u32 data_class_id;
	u32 collection_interval;
	u32 updatesper_interval;
	u32 updatefrequency;

	/*
	 * Padding reserves u8s to make the V* message size = 512.
	 * If you add new variables to the structure,
	 * you should adjust the paddings
	 */
	u8 reserved[492];
} __packed;

union _stats_obj_union {
	struct vhba_xsmp_msg gen_config;
	struct _vhba_stats_config_msg stats_config;

	/*
	 * Padding reserves u8s to make the V* message size = 512.
	 * If you add new variables to the structure,
	 * you should adjust the paddings
	 */
	u8 reserved[368];
} __packed;

struct _vhba_stats {
	u8 type;		/* Stats type (MIMM stats id) */
	u8 code;		/* NACK reason */
	u16 length;
	u8 action;		/* clear = 1, otherwise = get */
	u8 reserv[3];
	u64 vid;
	u64 statscookie;
	u64 totalio;
	u64 readbytecount;
	u64 writebytecount;
	u64 outstandingrequestcount;
	u64 iorequestcount;
	u64 readrequestcount;
	u64 writerequestcount;
	u64 taskmanagementrequestcount;
	u64 targetcount;
	u64 luncount;
	u64 xsmpxtdowncount;
	u64 xsmpxtoperstaterequestcount;
	u64 mapfmrcount;
	u64 ummapfmrcount;
	u64 usedmapfmrcount;
	u64 abortcommandcount;
	u64 resetluncommandcount;
	u64 resettargetcommandcount;
	u64 resetbuscommandcount;
	u64 linkdowncount;
	u64 discinfoupdatecount;
	u64 targetlostcount;
	u64 targetfoundcount;
	u64 cqpdisconnectcount;
	u64 dqpdisconnectcount;
	u64 cqpibsenterrorcount;
	u64 dqpibsenterrorcount;
	u64 cqpibreceiveerrorcount;
	u64 dqpibreceiverrrorcount;
	u64 cqpibremotedisconnecterrorcount;
	u64 dqpibremotedisconnecterrorcount;

	/*
	 * Padding reserves u8s to make the V* message size = 512.
	 * If you add new variables to the structure,
	 * you should adjust the paddings
	 */
	u8 reserved[240];
} __packed;

struct vhba_wq_msg {
	struct work_struct *work;
	u32 idr;
	void *data;
	struct ib_link_info *link;
};

extern void vhba_receive_handler(xsmp_cookie_t xsmp_hndl, u8 *data,
				 int length);
extern void vhba_abort_handler(xsmp_cookie_t xsmp_hndl);

extern int vhba_xsmp_service_id;

int vhba_create(xsmp_cookie_t xsmp_hndl, struct vhba_xsmp_msg *msg);
int vhba_delete(u64 resource_id);
int vhba_update(xsmp_cookie_t xsmp_hndl, struct vhba_xsmp_msg *msg);
int vhba_config_stats(xsmp_cookie_t xsmp_hndl,
		      union _stats_obj_union *vhba_stats_cfg);

int vhba_create_context(struct vhba_xsmp_msg *, struct virtual_hba *);
void vhba_add_context(struct virtual_hba *);
struct virtual_hba *vhba_remove_context(u64);
struct virtual_hba *vhba_get_context_by_idr(u32);
struct virtual_hba *vhba_get_context_by_resource_id(u64);
int vhba_check_context(struct virtual_hba *);

#define VHBA_XT_STATE_DOWN (0x40000000)
#define VHBA_XT_INFO_CHANGE (0x80000000)

extern int vhba_debug;
extern unsigned long vhba_wait_time;
extern struct vhba_xsmp_stats vhba_xsmp_stats;

extern void vhba_xsmp_stats_req(struct work_struct *work);
extern int vhba_xsmp_notify(xsmp_cookie_t xsmp_hndl, u64 resource_id,
			    int notifycmd);
extern int vhba_xsmp_send_msg(xsmp_cookie_t xsmp_hndl, u8 *data, int length);
extern int vhba_xsmp_ack(xsmp_cookie_t xsmp_hndl, u8 *data, int length);
int vhba_xsmp_ack(xsmp_cookie_t xsmp_hndl, u8 *data, int length);
int vhba_xsmp_nack(xsmp_cookie_t xsmp_hndl, u8 *data, int length,
		   enum vhba_xsmp_error_codes);
int stop_stats_collection(void);
int insert_iocb(struct virtual_hba *, int val, void **r_ptr);

#define DEBUG 1

#define TRC_ERRORS		0x000001
#define TRC_INIT		0x000002
#define TRC_XSMP		0x000004
#define TRC_XSMP_ERRS		0x000008
#define TRC_IB			0x000010
#define TRC_IB_ERRS		0x000020
#define TRC_SCSI		0x000040
#define TRC_SCSI_ERRS		0x000080
#define TRC_FMR			0x000100
#define TRC_FMR_ERRS		0x000200
#define TRC_IO			0x000400
#define TRC_UNALIGNED		0x000800
#define TRC_PROC		0x001000
#define TRC_ERR_RECOV		0x002000
#define TRC_TIMER		0x004000
#define TRC_CQP			0x008000
#define TRC_SCAN		0x010000
#define TRC_MGMT		0x020000
#define TRC_STATS		0x040000
#define TRC_FUNCS		0x080000
#define TRC_WQ			0x100000
#define TRC_INFO		0x200000

#ifdef DEBUG
#define eprintk(vhba, fmt, args...)				\
{								\
	struct virtual_hba *v_hba = (struct virtual_hba *)vhba; \
	if (v_hba != NULL) {					\
		if ((v_hba->cfg) && (v_hba->cfg->vh_name))	\
			pr_info("<vhba %s> %s: " fmt,	\
				(char *) (v_hba->cfg->vh_name),	\
				 __func__ , ## args);		\
	} else {						\
		pr_info("%s: " fmt, __func__ , ## args);		\
	}							\
}
#else
#define eprintk(fmt, args...)
#endif

#ifdef DEBUG
#define dprintk(level, vhba, fmt, args...)				\
do {									\
	struct virtual_hba *v_hba = (struct virtual_hba *)vhba;		\
	if ((vhba_debug & level) == level) {				\
		if (v_hba != NULL) {					\
			if ((v_hba->cfg) && (v_hba->cfg->vh_name))	\
				pr_info("<vhba %s> %s: " fmt,	\
					(char *) (v_hba->cfg->vh_name),	\
					__func__ , ## args);		\
		} else {						\
				pr_info("%s: " fmt, __func__	\
					, ## args);			\
		}							\
	}								\
} while (0)

#define vhba_debug(level, vhba, fmt, args...)				\
do {									\
	struct virtual_hba *v_hba = (struct virtual_hba *)vhba;		\
	if ((vhba_debug & level) == level) {				\
		if (v_hba != NULL) {					\
			if ((v_hba->cfg) && (v_hba->cfg->vh_name))	\
				pr_info("<vhba %s> %32s: " fmt,\
					(char *)(v_hba->cfg->vh_name),	\
					__func__ , ## args);		\
		} else  {						\
				pr_info("%s: " fmt, __func__,	\
					 ## args);			\
		}							\
	}								\
} while (0)
#else
#define dprintk(level, vhba, fmt, args...)
#endif

#define assert(expr)						\
do {								\
	if (!(expr)) {						\
		pr_info("Assertion failed! %s,%s,%s,line=%d\n",	\
			#expr, __FILE__, __func__, __LINE__);	\
	}							\
} while (0)

int vhba_purge_pending_ios(struct virtual_hba *vhba);

#endif /* __VHBA_XSMP_H__ */
