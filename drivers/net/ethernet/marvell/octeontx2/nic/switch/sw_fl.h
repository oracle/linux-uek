/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell switch driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */
#ifndef SW_FL_H_
#define SW_FL_H_

void sw_fl_deinit(void);
int sw_fl_init(void);
int sw_fl_setup_ft_block_ingress_cb(enum tc_setup_type type,
				    void *type_data, void *cb_priv);

#endif // SW_FL_H
