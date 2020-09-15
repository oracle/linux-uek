/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 NPA driver
 *
 * Copyright (C) 2020 Marvell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Initializa aura pool pair */
int npa_aura_pool_init(int pool_size, int buf_size, u32 *aura_handle,
		       struct device *owner);
/* Teardown aura pool pair */
int npa_aura_pool_fini(const u32 aura_handle, struct device *owner);
u64 npa_alloc_buf(u32 aura);
void npa_free_buf(u32 aura, u64 buf);
/* Get PF function used for aura */
u16 npa_pf_func(u32 aura);
