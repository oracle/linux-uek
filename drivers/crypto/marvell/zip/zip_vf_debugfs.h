/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX and OcteonTX2 ZIP Virtual Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ZIP_VF_DEBUGFS_H__
#define __ZIP_VF_DEBUGFS_H__

#include "zip_vf.h"

struct zip_vf_registers {
	char *reg_name;
	u64 reg_offset;
};

int __init zip_vf_debugfs_init(void);
void __exit zip_vf_debugfs_exit(void);

#endif /* __ZIP_VF_DEBUGFS_H__ */
