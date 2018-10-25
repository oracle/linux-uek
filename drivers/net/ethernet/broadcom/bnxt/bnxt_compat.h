/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2016-2017 Broadcom Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef BNXT_COMPAT_H
#define BNXT_COMPAT_H


#define ETH_RESET_AP (1<<8)

#define REG_STATE_REGISTERED	0x1

bool xdp_rxq_info_is_reg(struct xdp_rxq_info *xdp_rxq);

void pcie_print_link_status(struct pci_dev *dev);

#endif
