/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell switch driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */
#ifndef SW_FIB_H_
#define SW_FIB_H_

int sw_fib_add_to_list(struct net_device *dev,
		       struct fib_entry *entry, int cnt);

void sw_fib_deinit(void);
int sw_fib_init(void);

#endif // SW_FIB_H
