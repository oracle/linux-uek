/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020-2022, Pensando Systems Inc.
 */

#ifndef __PENPCIE_DEV_H__
#define __PENPCIE_DEV_H__

#define PENPCIE_NAME		"penpcie"
#define PENPCIE_DEV		"/dev/penpcie"

struct pcie_rw {
	uint64_t pciepa;
	size_t size;
	union {
		void *rdvalp;
		uint64_t wrval;
	};
};

#define PCIE_IOCTL_NUM		'P'
#define PCIE_PCIEP_REGRD	_IOWR(PCIE_IOCTL_NUM, 1, struct pcie_rw)

int pciep_regrd32(const uint64_t pciepa, uint32_t *val);

#endif
