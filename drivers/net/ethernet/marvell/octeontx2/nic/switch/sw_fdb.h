/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell switch driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */
#ifndef SW_FDB_H_
#define SW_FDB_H_

int sw_fdb_add_to_list(struct net_device *dev, u8 *mac, bool add_fdb);
void sw_fdb_deinit(void);
int sw_fdb_init(void);

#endif // SW_FDB_H
