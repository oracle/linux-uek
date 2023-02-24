/* SPDX-License-Identifier: GPL-2.0
 * PCIe PTM (Precision Time Management) EP driver
 *
 * Copyright (c) 2023 Marvell.
 */
#ifndef __PTM_EP_H__
#define __PTM_EP_H__

/*
 * This register only supported on cn10k.
 * The documentation for this register is not clear, and the current
 * implementation works for 0x418, and should work for all multiple
 * of 8 addresses.  It has not been tested for multiple of 4 addresses,
 * nor for addresses with bit 16 set.
 */
#define PEMX_PFX_CSX_PFCFGX(pem, pf, offset)      ((0x8e0000008000 | (u64)pem << 36 \
						| pf << 18 \
						| ((offset >> 16) & 1) << 16 \
						| (offset >> 3) << 3) \
						+ (((offset >> 2) & 1) << 2))

#define PEMX_CFG_WR(a)			(0x8E0000000018ull | (u64)a << 36)
#define PEMX_CFG_RD(a)			(0x8E0000000020ull | (u64)a << 36)
#define PEMX_CFG_WR_PF			18

/* Config space registers   */
#define PCIEEPX_PTM_REQ_STAT		(cn10k ? 0x3a8 : 0x474)
#define PCIEEPX_PTM_REQ_T4L		(cn10k ? 0x3c4 : 0x490)
#define PCIEEPX_PTM_REQ_T4M		(cn10k ? 0x3c8 : 0x494)


/* Octeon CSRs   */
#define PEMX_PTM_CTL			0x8e0000000098ULL
#define PEMX_PTM_CTL_CAP		(1ULL << 10)
#define PEMX_PTM_LCL_TIME		0x8e00000000a0ULL /* PTM time */
#define PEMX_PTM_MAS_TIME		0x8e00000000a8ULL /* PTP time */

static u32 read_pcie_config32(int ep_pem, int cfg_addr);
static void npu_csr_write(u64 csr_addr, uint64_t val);
static uint64_t npu_csr_read(u64 csr_addr);

#endif
