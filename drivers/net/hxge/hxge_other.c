/*****************************************************************************
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
*
* Copyright 2009, 2011 Oracle America, Inc. All rights reserved.
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License version 2 only, as published by
* the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for
* more details (a copy is included in the LICENSE file that accompanied this
* code).
*
* You should have received a copy of the GNU General Public License version 2
* along with this program; If not,
* see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 or
* visit www.oracle.com if you need additional information or have any
* questions.
*
******************************************************************************/

#include "hpi/hpi_vir.h"
#include "hpi/hpi_rxdma.h"
#include "hxge.h"
#include "hxge_peu_hw.h"

extern void hxge_disable_interrupts(struct hxge_adapter *hxgep);

int hxge_read_mac_addr (struct hxge_hw *hw)
{
	return 0;
}

void hxge_check_options(struct hxge_adapter *adapter)
{

}

/* Get the status of the link */
int
hxge_peu_get_link_status(struct hxge_adapter *hxgep)
{
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	cip_link_stat_t	link_stat;
	
	HXGE_REG_RD32(handle, CIP_LINK_STAT, &link_stat.value);

	/* XPCS0 is the XAUI connector, the other two are part of IHL */
	if (link_stat.bits.xpcs0_link_up) 
		return 1;
	else 
		return 0;
}


/* See if device error rate exceeded, or if it's ok to continue using
 * the hxge device.  This is sort of a first-order approximation to
 * an intelligent/heuristical running health check.
 *
 * We want to allow for some RealWorld "Stuff Happens" (and it does,
 * especially in a network environment), but still not let a kroaked
 * hxge swamp the system with error handling/reporting (and, at 10Gb,
 * errors can accumulate at a prodigous rate).
 *
 * Returns TRUE (non-zero) if ok to continue (e.g., recover/reset the
 * device/subsystem) using hxge; FALSE (zero) to give up.
 */

int
hxge_ok_to_continue(struct hxge_adapter *hxgep)
{
	/* Check hard device error rate */
	if (hxgep->statsp->hard_errors >= HARD_ERROR_THRESHOLD) {
		if (((hxgep->statsp->hard_errors * HZ * 86400)
		      / (jiffies + 1 - hxgep->ifup_time)) /* +1 no div-by-0 */
		    > HARD_ERROR_RATELIMIT) {
			return 0;
		}
	}

	/* Check soft (generally, "recoverable") device error rate */
	if (hxgep->statsp->soft_errors >= SOFT_ERROR_THRESHOLD) {
		if (((hxgep->statsp->soft_errors * HZ * 86400)
		      / (jiffies + 1 - hxgep->ifup_time)) /* +1 no div-by-0 */
		    > SOFT_ERROR_RATELIMIT) {
			return 0;
		}
	}

	/* For now, ignore "line" errors, even though this could
	 * conceivably impose a huge interrupt load on host CPU(s).
	 */

	return (TRUE);		/* Error rates within limits, keep going */
}

int
hxge_block_reset(struct hxge_adapter *hxgep, int device)
{
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	block_reset_t reset_reg;
	int count = 5; /* # msecs to wait */
	
	HXGE_REG_RD32(handle, BLOCK_RESET, &reset_reg.value);

	if (device & LDV_TXDMA) {
		reset_reg.bits.tdc_rst = 1;
	}
	if (device & LDV_RXDMA) {
		reset_reg.bits.rdc_rst = 1;
	}
	if (device & LDV_VMAC) {
		reset_reg.bits.vmac_rst = 1;
	}
	if (device & LDV_PFC) {
		reset_reg.bits.pfc_rst = 1;
	}

	HXGE_REG_WR32(handle, BLOCK_RESET, reset_reg.value);
	while (--count && (reset_reg.bits.tdc_rst || reset_reg.bits.rdc_rst ||
		reset_reg.bits.vmac_rst || reset_reg.bits.pfc_rst)) {
		HXGE_REG_RD32(handle, BLOCK_RESET, &reset_reg.value);
		msleep(1);
	}

	if (!count) {
		HXGE_ERR(hxgep, "hxge_block_reset: Reset of PEU blocks did not complete: 0x%8.8x", reset_reg.value);
		return -1;
	}
	return 0;
}




/* hxge_peu_deverr_init -- Initialize PEU & Device Error interrupt mask
 *
 * put here for lack of any other likely place to put it...
 */
 
int
hxge_peu_deverr_init(struct hxge_adapter *hxgep)
{
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	int regv, status=0;

	/* Initialize global PEU-related error handling */

        HXGE_REG_RD32(handle, PEU_INTR_STAT, &regv);
	if (regv) {		/* We're likely doomed if any set! */
		/* While an interesting case (error flags should probably
		 * not be set), do not count against hxgep->hard_errors */
		if (regv & ~2) { /* Ignore MSIX_PARERR here */
			HXGE_ERR(hxgep, "hxge_peu_deverr_init: Error! PEU_INTR_STAT 0x%8.8x hardware error flags set",
				 (unsigned int)regv);
			status = regv;	/* Return error */
		}
	}

	/* MSIX_PARERR sometimes erroneously asserted on poweron. If set
	 * here, assume that's the case, and mask it out. We risk missing
	 * a real MSIX_PARERR, but subsequent system reset/reboot should
	 * clear this condition, and re-enable trap on MSIX_PARERR */

	regv = regv & 2;	/* Ignore MSIX_PARERR if initially asserted */
	if (regv) {		/* Other than to note that detail in syslog */
		HXGE_ERR(hxgep, "hxge_peu_deverr_init: MSIX workaround applied");
	}
        HXGE_REG_WR32(handle, PEU_INTR_MASK, regv); /* 0 = no disables */

	/* Initialize Device Error interrupt */

	HXGE_REG_RD32(handle, DEV_ERR_STAT, &regv);
	if (regv) {		/* We're in trouble if any set! */
		/* While an interesting case (error flags should probably
		 * not be set), do not count against hxgep->hard_errors */
		if (regv & ~1) { /* Ignore MSIX_PARERR->PEU_ERR1 here */
			HXGE_ERR(hxgep, "hxge_deverr_init: Error! DEV_ERR_STAT 0x%8.8x hardware error flags set",
			 regv);
		status = regv;	/* Return error */
		}
	}
	HXGE_REG_WR32(handle, DEV_ERR_MASK, 0); /* 0 = no disables */

	return status;
}



/* General Hydra error interrupt handler
 *
 * Called from Device Error Interrupt (ldv 31) service, not RX DMA
 *
 * NB: *data is Device Error ldv 31, not an RX DMA channel ldv!
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
irqreturn_t hxge_peu_deverr_intr(int irq, void *data, struct pt_regs *regs)
#else
irqreturn_t hxge_peu_deverr_intr(int irq, void *data)
#endif
{
	struct hxge_ldv *ldvp = (struct hxge_ldv *)data; /* Device Error ldv */
	struct hxge_adapter *hxgep = ldvp->ldgp->hxgep;
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	peu_intr_stat_t psts, pclr;
	int peu_fatal_flag = 0;
	int regv32;		/* Temp/holding 32-bit register value */

        HXGE_REG_RD32(handle, PEU_INTR_STAT, &psts.value);

	HXGE_ERR(hxgep, "hxge_peu_deverr_intr: PEU hardware error interrupt (0x%8.8x)!",
		 (unsigned int)psts.value);

	pclr.value = psts.value;

	/* All "PEU" errors are hard device errors.  One might quibble
	 * over tdc_pioacc_err and rdc_pioacc_err being more specifically
	 * accountable under "RX" or "TX" errors (e.g., for ifconfig).
	 */

	hxgep->statsp->hard_errors++;

	if (psts.bits.spc_acc_err) {
		HXGE_ERR(hxgep, "hxge_peu_errors: spc_acc_err");
		hxgep->statsp->peu_spc_acc_err++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		pclr.bits.spc_acc_err = 0;
	}

	if (psts.bits.tdc_pioacc_err) {
		HXGE_ERR(hxgep, "hxge_peu_errors: tdc_pioacc_err");
		hxgep->statsp->peu_pioacc_err++;
		hxgep->statsp->tx_oerrors++; /* Tx summary count */
		pclr.bits.tdc_pioacc_err = 0;
	}

	if (psts.bits.rdc_pioacc_err) {
		HXGE_ERR(hxgep, "hxge_peu_errors: rdc_pioacc_err");
		hxgep->statsp->peu_pioacc_err++;
		hxgep->statsp->rx_ierrors++; /* Rx summary count */
		pclr.bits.rdc_pioacc_err = 0;
	}

	if (psts.bits.pfc_pioacc_err) {
		HXGE_ERR(hxgep, "hxge_peu_errors: pfc_pioacc_err");
		hxgep->statsp->peu_pioacc_err++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		pclr.bits.pfc_pioacc_err = 0;
	}

	if (psts.bits.vmac_pioacc_err) {
		HXGE_ERR(hxgep, "hxge_peu_errors: vmac_pioacc_err");
		hxgep->statsp->peu_pioacc_err++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		pclr.bits.vmac_pioacc_err = 0;
	}

	if (psts.bits.cpl_hdrq_parerr) {
		HXGE_ERR(hxgep, "hxge_peu_errors: cpl_hdrq_parerr");
		hxgep->statsp->peu_pcie_parerr++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		peu_fatal_flag = TRUE; /* PEU unrecoverable error */
		pclr.bits.cpl_hdrq_parerr = 0;
	}

	if (psts.bits.cpl_dataq_parerr) {
		HXGE_ERR(hxgep, "hxge_peu_errors: cpl_dataq_parerr");
		hxgep->statsp->peu_pcie_parerr++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		peu_fatal_flag = TRUE; /* PEU unrecoverable error */
		pclr.bits.cpl_dataq_parerr = 0;
	}

	if (psts.bits.retryram_xdlh_parerr) {
		HXGE_ERR(hxgep, "hxge_peu_errors: retryram_xdlh_parerr");
		hxgep->statsp->peu_pcie_parerr++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		peu_fatal_flag = TRUE; /* PEU unrecoverable error */
		pclr.bits.retryram_xdlh_parerr = 0;
	}

	if (psts.bits.retrysotram_xdlh_parerr) {
		HXGE_ERR(hxgep, "hxge_peu_errors: retrysotram_xdlh_parerr");
		hxgep->statsp->peu_pcie_parerr++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		peu_fatal_flag = TRUE; /* PEU unrecoverable error */
		pclr.bits.retrysotram_xdlh_parerr = 0;
	}

	if (psts.bits.p_hdrq_parerr) {
		HXGE_ERR(hxgep, "hxge_peu_errors: p_hdrq_parerr");
		hxgep->statsp->peu_pcie_parerr++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		peu_fatal_flag = TRUE; /* PEU unrecoverable error */
		pclr.bits.p_hdrq_parerr = 0;
	}

	if (psts.bits.p_dataq_parerr) {
		HXGE_ERR(hxgep, "hxge_peu_errors: p_dataq_parerr");
		hxgep->statsp->peu_pcie_parerr++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		peu_fatal_flag = TRUE; /* PEU unrecoverable error */
		pclr.bits.p_dataq_parerr = 0;
	}

	if (psts.bits.np_hdrq_parerr) {
		HXGE_ERR(hxgep, "hxge_peu_errors: np_hdrq_parerr");
		hxgep->statsp->peu_pcie_parerr++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		peu_fatal_flag = TRUE; /* PEU unrecoverable error */
		pclr.bits.np_hdrq_parerr = 0;
	}

	if (psts.bits.np_dataq_parerr) {
		HXGE_ERR(hxgep, "hxge_peu_errors: np_dataq_parerr");
		hxgep->statsp->peu_pcie_parerr++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		peu_fatal_flag = TRUE; /* PEU unrecoverable error */
		pclr.bits.np_dataq_parerr = 0;
	}

	if (psts.bits.eic_msix_parerr) {
		HXGE_REG_RD32(handle, MSIX_PERR_LOC, &regv32);
		HXGE_ERR(hxgep, "hxge_peu_errors: eic_msix_parerr: 0x%8.8x", regv32);
		hxgep->statsp->peu_hcr_msix_parerr++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		peu_fatal_flag = TRUE; /* PEU unrecoverable error */
		pclr.bits.eic_msix_parerr = 0;
	}

	if (psts.bits.hcr_parerr) {
		HXGE_REG_RD32(handle, HCR_PERR_LOC, &regv32);
		HXGE_ERR(hxgep, "hxge_peu_errors: hcr_parerr: 0x%8.8x", regv32);
		hxgep->statsp->peu_hcr_msix_parerr++;
		hxgep->statsp->peu_errors++; /* PEU/generic summary count */
		peu_fatal_flag = TRUE; /* PEU unrecoverable error */
		pclr.bits.hcr_parerr = 0;
	}

	if (pclr.value) {
		HXGE_ERR(hxgep, "hxge_peu_deverr_intr: Unknown/unexpected/reserved PEU_INTR_STAT bits 0x%8.8x", pclr.value);
	}

	/* Now that we have "logged" the errors, try to recover from
	 * whatever happened.
	 *
	 * Unlike lesser errors, PEU_INTR_STAT errors are NOT RW1C bits.
	 * Rather, one must externally (to PEU_INTR_STAT register) clear
	 * the underlying fault conditions.
	 *
	 * Errors in the PEU block are irrecoverable from program con-
	 * trol, the Hydra needs a PCI bus reset (aka, reset/reboot the
	 * host OS). Other errors are -- in theory -- recoverable by
	 * resetting (and reinitializing) the hardware subsystem.
	 */

	/* Check hxge viability */
	
	if (peu_fatal_flag) {
		/* Irrecoverable ("FATAL") PEU-class error, time to die. */
		HXGE_ERR(hxgep, "hxge_peu_deverr_intr: PEU FATAL error");
		HXGE_ERR(hxgep, "                      Taking hxge device down");
		hxge_disable_interrupts(hxgep);
		set_bit(SHUTDOWN_ADAPTER, &hxgep->work_q.command);
		schedule_work(&hxgep->work_to_do);
	} else if (hxge_ok_to_continue(hxgep)) {

		/* Error should/could be recoverable by resetting
		 * subsystem involved; reset and restart Hydra
		 * logic subsystem (resume operation) */

		if (psts.bits.tdc_pioacc_err) {
			hxge_disable_tx_ints(hxgep);
			set_bit(RESET_TDC, &hxgep->work_q.command);
			schedule_work(&hxgep->work_to_do);
		}
		if (psts.bits.rdc_pioacc_err) {
			hxge_disable_rx_ints(hxgep, NULL, -1);
			set_bit(RESET_RDC, &hxgep->work_q.command);
			schedule_work(&hxgep->work_to_do);
		}
		if (psts.bits.pfc_pioacc_err) {
			set_bit(RESET_PFC, &hxgep->work_q.command);
			schedule_work(&hxgep->work_to_do);
		}
		if (psts.bits.vmac_pioacc_err) {
			set_bit(RESET_VMAC, &hxgep->work_q.command);
			schedule_work(&hxgep->work_to_do);
		}
	} else {
		/* Too many errors,  "hxge_shutdown" the hxge device */
		HXGE_ERR(hxgep, "hxge_peu_deverr_intr: Excessive hardware error rate");
		HXGE_ERR(hxgep, "                      Taking hxge device down");
		hxge_disable_interrupts(hxgep);
		set_bit(SHUTDOWN_ADAPTER, &hxgep->work_q.command);
		schedule_work(&hxgep->work_to_do);
	}
		
	return (IRQ_HANDLED);
}

int hxge_link_intr (struct hxge_adapter *hxgep, int cmd)
{
        return -1;

}
