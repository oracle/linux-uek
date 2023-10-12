/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver - block extension interface
 *
 * Copyright (C) 2023 Marvell.
 *
 */

#include "mbox.h"

/**
 * struct mbox_op - Extension block driver mbox op
 * @start: start offset of mbox id the driver supports
 * @end: end offset of mbox id the driver supports
 * @handler: Top level mbox handler
 */
struct mbox_op {
	u32 start;
	u32 end;
	int (*handler)(struct otx2_mbox *mbox, int devid,
		       struct mbox_msghdr *req);
};

/**
 * struct rvu_eblock_driver_ops - Extension block driver ops
 * @name: block name
 * @probe: probe device and instantiate device instance
 * @remove: remove all device instances
 * @init: initialize the hardware block
 * @setup: setup all hardware resources
 * @free: free all hardware resources
 * @register_interrupt: register all eblock interrupts
 * @unregister_interrupt: unregister all eblock interrupts
 * @mbox_op: handle for mbox operation
 */
struct rvu_eblock_driver_ops {
	char *name;

	/* All ops goes here */
	void *(*probe)(struct rvu *rvu, int blkaddr);
	void (*remove)(struct rvu_block *hwblock, void *priv_data);
	int (*init)(struct rvu_block *hwblock, void *priv_data);
	int (*setup)(struct rvu_block *hwblock, void *priv_data);
	void (*free)(struct rvu_block *hwblock, void *priv_data);
	int (*register_interrupt)(struct rvu_block *hwblock, void *priv_data);
	void (*unregister_interrupt)(struct rvu_block *hwblock,
				     void *priv_data);
	struct mbox_op *mbox_op;
};

struct rvu_block;

void rvu_eblock_module_init(void);
void rvu_eblock_module_exit(void);
int rvu_eblock_init(void);
void rvu_eblock_exit(void);
void rvu_eblock_device_add(struct rvu *rvu, struct rvu_block *hwblock,
			  int blkaddr);
int rvu_eblock_register_driver(const struct rvu_eblock_driver_ops *ops);
void rvu_eblock_unregister_driver(struct rvu_eblock_driver_ops *ops);
int rvu_eblock_mbox_handler(struct otx2_mbox *mbox, int devid,
			    struct mbox_msghdr *req);

/* Eblock drivers part of RVU AF driver module */
void ree_eb_module_init(void);
void ree_eb_module_exit(void);
