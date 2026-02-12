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
 *|SDP_CHAN:    |              1 |                  SDP_CHAN                  |
 * ----------------------------------------------------------------------------
 *|CPT_CHAN:    |                                         |   CPT_QUEUE/CHAN  |
 * ----------------------------------------------------------------------------
 */

#define NIX_CHAN_LBK_BASE		BIT_ULL(7)
#define NIX_CHAN_SDP_BASE		BIT_ULL(9)
#define NIX_CHAN_RPM_BASE		BIT_ULL(10)
#define NIX_CHAN_CPT_BASE		(0x00ULL)

#define RPM_TYPES			BIT_ULL(63)

int rvu_cn20k_set_channels_base(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u64 nix_const, nix_const3;
	int blkaddr, num_xcb;
	int rpm_usx_cnt;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, 0);
	if (blkaddr < 0)
		return blkaddr;

	nix_const = rvu_read64(rvu, blkaddr, NIX_AF_CONST);

	hw->cgx = (nix_const >> 12) & 0xFULL;
	hw->lmac_per_cgx = (nix_const >> 8) & 0xFULL;
	hw->cgx_links = hw->cgx * hw->lmac_per_cgx;

	/* CN20K supports RPM_USX along with RPM200 */
	nix_const3 = rvu_read64(rvu, blkaddr, NIX_AF_CONST3);
	rpm_usx_cnt = (nix_const3 >> 44) & 0xFULL;
	if ((nix_const & RPM_TYPES) && rpm_usx_cnt) {

		/* lmac_per_cgx is used for the PF to (CGX,LMAC) mapping
		 * and vice versa. Though the CN20k supports RPM200(with 4 lmacs)
		 * it is enumerated last. Update lmac_per_cgx with RPM_USX info.
		 */
		hw->lmac_per_cgx = (nix_const3 >> 40) & 0xFULL;
		hw->cgx_links += rpm_usx_cnt * hw->lmac_per_cgx;
	}

	/* CNF20K supports chiplet RPMs connected via XCB links.
	 * Add their LMACs to the total CGX links.
	 */
	num_xcb = (nix_const3 >> 48) & 0xFULL;
	if (num_xcb) {
		hw->cplt_links = (nix_const3 >> 56) & 0x1FULL;
		hw->cgx_links += hw->cplt_links;
	}

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

static inline void rvu_cn20k_x2p_p2x_link_cfg(struct rvu *rvu)
{
 /* TODO */
}

void rvu_cn20k_cpt_chan_cfg(struct rvu *rvu)
{
	int blkaddr, nix_blkaddr;
	u64 val;

	if (!is_cn20k(rvu->pdev) ||
	    !is_block_implemented(rvu->hw, BLKADDR_CPT0))
		return;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_CPT, 0);
	if (blkaddr < 0)
		return;

	nix_blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, 0);
	if (nix_blkaddr < 0)
		return;

	/* Configure the X2P Link register with the cpt base channel number.
	 * Range of channels is fixed to 2^4=16
	 */
	val = (u64)rvu->hw->cpt_chan_base & 0xFFF;

	rvu_write64(rvu, blkaddr, CPT_AF_RXC_QUE_X2PX_LINK_CFG(0), val);
	rvu_write64(rvu, blkaddr, CPT_AF_RXC_QUE_X2PX_LINK_CFG(1), val);

	/* For 2nd pass
	 * NIX_RX_PARSE_S[CHAN] =
	 * CPT_PARSE_HDR_S[CHANNEL] & NIX_AF_RX_CPT_CHAN_CFG[MASK_VALUE]) |
	 * NIX_AF_RX_CPT_CHAN_CFG[VALUE]
	 * Setup mask & value such that, the 12bit is set for 2nd pass pkts.
	 */
	rvu_write64(rvu, nix_blkaddr,
		    NIX_AF_RX_CPT_CHAN_CFG, (0x7FFULL << 12) | 0x800);
}

void rvu_cn20k_lbk_set_channels(struct rvu *rvu)
{
	struct pci_dev *pdev = NULL;
	void __iomem *base;
	u64 lbk_const, cfg;
	u16 chans;

	pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM,
			      PCI_DEVID_OCTEONTX2_LBK, pdev);
	if (!pdev)
		return;

	base = pci_ioremap_bar(pdev, 0);
	if (!base)
		goto err_put;

	lbk_const = readq(base + LBK_CONST);
	chans = FIELD_GET(CN20K_LBK_CONST_CHANS, lbk_const);
	chans =	(chans > CN20K_MAX_LBK_CHANS) ? CN20K_MAX_LBK_CHANS : chans;

	cfg = readq(base + CN20K_LBKX_LINK_CFG_P2X);
	cfg &= ~(CN20K_LBK_LINK_CFG_RANGE_MASK | CN20K_LBK_LINK_CFG_BASE_MASK);
	cfg |=	FIELD_PREP(CN20K_LBK_LINK_CFG_RANGE_MASK, ilog2(chans));
	cfg |=	FIELD_PREP(CN20K_LBK_LINK_CFG_BASE_MASK, rvu->hw->lbk_chan_base);
	writeq(cfg, base + CN20K_LBKX_LINK_CFG_P2X);

	cfg = readq(base + CN20K_LBKX_LINK_CFG_X2P);
	cfg &= ~(CN20K_LBK_LINK_CFG_RANGE_MASK | CN20K_LBK_LINK_CFG_BASE_MASK);
	cfg |=	FIELD_PREP(CN20K_LBK_LINK_CFG_RANGE_MASK, ilog2(chans));
	cfg |=	FIELD_PREP(CN20K_LBK_LINK_CFG_BASE_MASK, rvu->hw->lbk_chan_base);
	writeq(cfg, base + CN20K_LBKX_LINK_CFG_X2P);

	iounmap(base);

err_put:
	pci_dev_put(pdev);
}
