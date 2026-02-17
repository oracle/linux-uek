// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */
#include "../rvu.h"

bool is_pf_cgxcpltmapped(struct rvu *rvu, u8 pf)
{
	if (!is_cnf20ka(rvu->pdev))
		return false;

	return (pf >= PF_CPLTMAP_BASE && pf < (PF_CPLTMAP_BASE + 16));
}

bool is_pf_cpltmapped(struct rvu *rvu, u8 pf)
{
	/* CNF20ka BPHY RPM is managed by ODP application
	 * PTP is supported by this BPHY RPM
	 */
	return (is_cnf20ka(rvu->pdev) && is_pf_cgxcpltmapped(rvu, pf));
}
