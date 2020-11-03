/* SPDX-License-Identifier: GPL-2.0 */
/*  Marvell OcteonTx2 RPM driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 */
#include "rvu.h"
#include "cgx.h"
/**
 * struct lmac
 * @wq_cmd_cmplt:      waitq to keep the process blocked until cmd completion
 * @cmd_lock:          Lock to serialize the command interface
 * @resp:              command response
 * @link_info:         link related information
 * @mac_to_index_bmap: Mac address to CGX table index mapping
 * @event_cb:          callback for linkchange events
 * @event_cb_lock:     lock for serializing callback with unregister
 * @cmd_pend:          flag set before new command is started
 *                     flag cleared after command response is received
 * @cgx:               parent cgx port
 * @lmac_id:           lmac port id
 * @name:              lmac port name
 */
struct lmac {
	wait_queue_head_t wq_cmd_cmplt;
	struct mutex cmd_lock;
	u64 resp;
	struct cgx_link_user_info link_info;
	struct rsrc_bmap mac_to_index_bmap;
	struct cgx_event_cb event_cb;
	spinlock_t event_cb_lock;
	bool cmd_pend;
	struct cgx *cgx;
	u8 lmac_id;
	char *name;
};

struct cgx {
	void __iomem            *reg_base;
	struct pci_dev          *pdev;
	u8                      cgx_id;
	u8                      lmac_count;
	struct lmac             *lmac_idmap[MAX_LMAC_PER_CGX];
	struct                  work_struct cgx_cmd_work;
	struct                  workqueue_struct *cgx_cmd_workq;
	struct list_head        cgx_list;
	u64                     hw_features;
	struct cgx_mac_ops     *mac_ops;
};

/* Function Declarations */
void cgx_write(struct cgx *cgx, u64 lmac, u64 offset, u64 val);
u64 cgx_read(struct cgx *cgx, u64 lmac, u64 offset);
struct lmac *lmac_pdata(u8 lmac_id, struct cgx *cgx);
int cgx_fwi_cmd_send(u64 req, u64 *resp, struct lmac *lmac);
int cgx_fwi_cmd_generic(u64 req, u64 *resp, struct cgx *cgx, int lmac_id);
