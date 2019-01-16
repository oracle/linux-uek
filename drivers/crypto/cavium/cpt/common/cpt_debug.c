// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/printk.h>
#include "cpt_debug.h"

static int debug_level;

void cpt_set_dbg_level(int level)
{
	if (level >= (2*CPT_DBG_MAX_LEVEL-2))
		debug_level = -1;
	else
		debug_level = level;
}
EXPORT_SYMBOL_GPL(cpt_set_dbg_level);

int cpt_is_dbg_level_en(int level)
{
	return (debug_level & level);
}
EXPORT_SYMBOL_GPL(cpt_is_dbg_level_en);
