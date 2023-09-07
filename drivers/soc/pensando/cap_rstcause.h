// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#ifndef __CAP_RSTCAUSE_H__
#define __CAP_RSTCAUSE_H__

#define CAP_RSTCAUSE_EV_REBOOT		BIT(0)
#define CAP_RSTCAUSE_EV_PANIC		BIT(1)
#define CAP_RSTCAUSE_EV_PCIE_RESET	BIT(2)

void cap_rstcause_set(u32 mask);

#endif
