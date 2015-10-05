/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "vnic.h"
#include "vnic_data.h"
#include "vnic_fip.h"

MODULE_AUTHOR(DRV_AUTH);
MODULE_DESCRIPTION(DRV_DESC);
MODULE_LICENSE(DRV_LIC);
MODULE_VERSION(DRV_VER);

static int __init mlx4_ib_init(void)
{
	vnic_dbg_func("module_init");

	if (vnic_param_check())
		goto err;
	if (vnic_mcast_init())
		goto err;
	if (vnic_ports_init())
		goto free_mcast;

	return 0;

free_mcast:
	vnic_mcast_cleanup();
err:
	return -EINVAL;
}

static void __exit mlx4_ib_cleanup(void)
{
	vnic_dbg_func("module_exit");
	vnic_ports_cleanup();
	vnic_dbg_mark();
	vnic_mcast_cleanup();
}

module_init(mlx4_ib_init);
module_exit(mlx4_ib_cleanup);
