/* SPDX-License-Identifier: GPL-2.0
 * Marvell GTI Watchdog driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define OCTEONTX_INSTALL_WDOG           0xc2000c01
#define OCTEONTX_REMOVE_WDOG            0xc2000c02

/* Kernel exception simulation wrapper for the NMI callback */
extern void el1_nmi_callback(void);
void nmi_kernel_callback(struct pt_regs *regs);
extern void __iomem *g_gti_devmem;
