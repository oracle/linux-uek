/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2021 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/debugfs.h>
#include "cnf10k_rfoe.h"

#ifndef _OTX2_BPHY_DEBUGFS_H_
#define _OTX2_BPHY_DEBUGFS_H_

typedef void (*otx2_bphy_debugfs_reader)(char *buffer, size_t buffer_size,
					 void *priv);

void otx2_bphy_debugfs_init(void);

void *otx2_bphy_debugfs_add_file(const char *name,
				 size_t buffer_size,
				 void *priv,
				 otx2_bphy_debugfs_reader reader);

void otx2_bphy_debugfs_remove_file(void *entry);

void otx2_bphy_debugfs_exit(void);

void cnf10k_rfoe_debugfs_create(struct cnf10k_rfoe_drv_ctx *ctx);
void cnf10k_rfoe_debugfs_remove(struct cnf10k_rfoe_drv_ctx *ctx);

#endif
