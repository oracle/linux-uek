/* Broadcom NetXtreme-C/E network driver.
 *  *
 *   * Copyright (c) 2016-2017 Broadcom Limited
 *    *
 *     * This program is free software; you can redistribute it and/or modify
 *      * it under the terms of the GNU General Public License as published by
 *       * the Free Software Foundation.
 *        */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/filter.h>
#include "bnxt_compat.h"


bool xdp_rxq_info_is_reg(struct xdp_rxq_info *xdp_rxq)
{
	return (xdp_rxq->reg_state == REG_STATE_REGISTERED);
}
