/* SPDX-License-Identifier: GPL-2.0 */
/*  Marvell OcteonTx2 RPM driver
 *
 * Copyright (C) 2020 Marvell.
 */

#ifndef RPM_H
#define RPM_H

#include <linux/bits.h>

/* PCI device IDs */
#define PCI_DEVID_CN10K_RPM		0xA060

/* Registers */
#define RPMX_CMRX_SW_INT                0x180
#define RPMX_CMRX_SW_INT_W1S            0x188
#define RPMX_CMRX_SW_INT_ENA_W1S        0x198
#define RPMX_CMRX_LINK_CFG		0x1070
#define RPMX_MTI_PCS100X_CONTROL1       0x20000
#define RPMX_MTI_LPCSX_CONTROL(id)     (0x30000 | ((id) * 0x100))
#define RPMX_MTI_PCS_LBK                BIT_ULL(14)

#define RPMX_CMRX_LINK_RANGE_MASK	GENMASK_ULL(19, 16)
#define RPMX_CMRX_LINK_BASE_MASK	GENMASK_ULL(11, 0)
#define RPMX_MTI_STAT_RX_STAT_PAGES_COUNTERX 0x12000
#define RPMX_MTI_STAT_TX_STAT_PAGES_COUNTERX 0x13000
#define RPMX_MTI_STAT_DATA_HI_CDC            0x10038

#define RPM_LMAC_FWI			0xa

/* Function Declarations */
int rpm_get_nr_lmacs(void *rpmd);
u8 rpm_get_lmac_type(void *rpmd, int lmac_id);
int rpm_lmac_internal_loopback(void *rpmd, int lmac_id, bool enable);
int rpm_get_tx_stats(void *rpmd, int lmac_id, int idx, u64 *tx_stat);
int rpm_get_rx_stats(void *rpmd, int lmac_id, int idx, u64 *rx_stat);
#endif /* RPM_H */
