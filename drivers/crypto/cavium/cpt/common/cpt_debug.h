// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT_DEBUG_H
#define __CPT_DEBUG_H

#define DEFINE_CPT_DEBUG_PARM(name) \
static int name; \
module_param(name, uint, 0000); \
MODULE_PARM_DESC(name, \
"Debug level (0=disabled, 1=mbox msgs, 2=enc/dec reqs, 4=engine grps, >6=all)")

enum {
	CPT_DBG_MBOX_MSGS	= 0x0001, /* Mailbox mesages */
	CPT_DBG_ENC_DEC_REQS	= 0x0002, /* Encryption/decryption requests */
	CPT_DBG_ENGINE_GRPS	= 0x0004, /* Engine groups configuration */
	CPT_DBG_MAX_LEVEL
};

void cpt_set_dbg_level(int level);
int cpt_is_dbg_level_en(int level);

#endif /*__CPT_DEBUG_H */
