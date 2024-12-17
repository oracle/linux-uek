// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */
#include <linux/xarray.h>
#include <linux/bitfield.h>
#include "api.h"

/* Channel is a 12bit field.
 * 4096 channels are assigned as below across RPM, LBK, SDP and CPT interfaces.
 * This mapping considers only the devices on the compute chiplet on O20 series
 * of silicons.
 *
 * RPM::LMAC mappings are simialr to CN10K silicons ie 16 channels per LMAC.
 * LBK:: CN20K supports 128 LBK channels.
 * SDP: CN20K supports 512 SDP rings hence 512 channels.
 * CPT: CN20K supports up to 16 ingress queues and also supports BP individually
 * to each of the 16 queues. Hence 16 channels. When CPT is sending pkts to
 * NIXRX, PNUM/CHAN[3:0] represents CPT queue numbers. Also CPT will add
 * 1st pass or original channel value in CPT_PARSE_HSR_S. NIXRX will extract
 * this and pass it NPC.
 *
 * - For non-CPT (non-inline) packets, NIX_RX_PARSE_S[CHAN] = NPC_RESULT_S[CHAN]
 * - For CPT packets, NIX_RX_PARSE_S[CHAN] = CPT_PARSE_HDR_S[CHANNEL] | <value>
 *   value is NIX_AF_RX_CPT_CHAN_CFG[value].
 *   Using this value SW can still use 2048 to 4095 channels for CPT 2nd pass
 *   similar to CN10K.
 *
 * ----------------------------------------------------------------------------
 *|             |  11 |  10 |  9 |  8 |  7 |  6 |  5 |  4 |  3 |  2 |  1 |  0 |
 * ----------------------------------------------------------------------------
 *|Compute: RPM:|        1  |  0 |   RPM   |     LMAC     |        TC         |
 * ----------------------------------------------------------------------------
 *|LBK_CHAN:    |                        1 |             LBK_CHAN             |
 * ----------------------------------------------------------------------------
 *|SDP_CHAN:    |                   1 |             SDP_CHAN                  |
 * ----------------------------------------------------------------------------
 *|CPT_CHAN:    |                                         |   CPT_QUEUE/CHAN  |
 * ----------------------------------------------------------------------------
 */

#define NIX_CHAN_LBK_BASE		BIT_ULL(7)
#define NIX_CHAN_SDP_BASE		BIT_ULL(8)
#define NIX_CHAN_RPM_BASE		BIT_ULL(10)
#define NIX_CHAN_CPT_BASE		(0x00ULL)

int rvu_cn20k_set_channels_base(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u64 nix_const;
	int blkaddr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, 0);
	if (blkaddr < 0)
		return blkaddr;

	nix_const = rvu_read64(rvu, blkaddr, NIX_AF_CONST);

	/* Setting number of cgx_links needs to be revisited after
	 * new CONST csrs are defined in hardware.
	 */
	hw->cgx = (nix_const >> 12) & 0xFULL;
	hw->lmac_per_cgx = (nix_const >> 8) & 0xFULL;
	hw->cgx_links = hw->cgx * hw->lmac_per_cgx;
	hw->lbk_links = (nix_const >> 24) & 0xFULL;
	hw->sdp_links = (nix_const >> 28) & 0xFULL;
	hw->cpt_links = (nix_const >> 44) & 0xFULL;

	/* No Programmable channels */
	if (!(nix_const & BIT_ULL(60)))
		return 0;

	hw->cap.programmable_chans = true;

	hw->cpt_chan_base = NIX_CHAN_CPT_BASE;
	hw->lbk_chan_base = NIX_CHAN_LBK_BASE;
	hw->sdp_chan_base = NIX_CHAN_SDP_BASE;
	hw->cgx_chan_base = NIX_CHAN_RPM_BASE;

	return 0;
}

static void rvu_cn20k_x2p_p2x_link_cfg(struct rvu *rvu)
{
 /* TODO */
}

void rvu_cn20k_cpt_chan_cfg(struct rvu *rvu)
{
	int blkaddr, qidx, nix_blkaddr;
	u64 val;

	if (!is_cn20k(rvu->pdev))
		return;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_CPT, 0);
	if (blkaddr < 0)
		return;

	nix_blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, 0);
	if (nix_blkaddr < 0)
		return;

	/* Configure the X2P Link register with the cpt base channel number and
	 * range of channels it should propagate to X2P
	 */
	val = (ilog2(CPT_AF_MAX_RXC_QUEUES) << 16);
	val |= (u64)rvu->hw->cpt_chan_base;

	for (qidx = 0; qidx < CPT_AF_MAX_RXC_QUEUES; qidx++) {
		rvu_write64(rvu, blkaddr,
			    CPT_AF_RXC_QUEX_X2PX_LINK_CFG(qidx, 0), val);
		rvu_write64(rvu, blkaddr,
			    CPT_AF_RXC_QUEX_X2PX_LINK_CFG(qidx, 1), val);
	}

	/* For 2nd pass
	 * NIX_RX_PARSE_S[CHAN] =
	 * CPT_PARSE_HDR_S[CHANNEL] & NIX_AF_RX_CPT_CHAN_CFG[MASK_VALUE]) |
	 * NIX_AF_RX_CPT_CHAN_CFG[VALUE]
	 * Setup mask & value such that, the 12bit is set for 2nd pass pkts.
	 */
	rvu_write64(rvu, nix_blkaddr,
		    NIX_AF_RX_CPT_CHAN_CFG, (0x7FFULL << 12) | 0x800);
}
