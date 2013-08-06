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

#ifndef        _HXGE_PEU_HW_H
#define        _HXGE_PEU_HW_H

#define        PIO_BASE_ADDR                           0X000000
#define        PIO_LDSV_BASE_ADDR                      0X800000
#define        PIO_LDMASK_BASE_ADDR                    0XA00000

#define        HCR_REG                                 (PIO_BASE_ADDR + 0x2000)
#define        BLOCK_RESET                             (PIO_BASE_ADDR + 0x8000)
#define        PEU_INTR_STAT                           (PIO_BASE_ADDR + 0x8148)
#define        PEU_INTR_MASK                           (PIO_BASE_ADDR + 0x814C)
#define        MSIX_PERR_LOC                           (PIO_BASE_ADDR + 0x8174)
#define        HCR_PERR_LOC                            (PIO_BASE_ADDR + 0x8178)
#define        PHY_DEBUG_TRAINING_VEC                  (PIO_BASE_ADDR + 0x80F4)
#define        PEU_DEBUG_TRAINING_VEC                  (PIO_BASE_ADDR + 0x80F8)
#define        DEV_ERR_STAT                            (PIO_BASE_ADDR + 0x8380)
#define        DEV_ERR_MASK                            (PIO_BASE_ADDR + 0x8384)
#define        CIP_LINK_STAT                           (PIO_BASE_ADDR + 0x801C)
#define        LD_GRP_CTRL                             (PIO_BASE_ADDR + 0x8300)
#define        LD_INTR_TIM_RES                         (PIO_BASE_ADDR + 0x8390)
#define        LDSV0                                   (PIO_LDSV_BASE_ADDR + 0x0)
#define        LDSV1                                   (PIO_LDSV_BASE_ADDR + 0x4)
#define        LD_INTR_MASK                            (PIO_LDMASK_BASE_ADDR + 0x0)
#define        LD_INTR_MGMT                            (PIO_LDMASK_BASE_ADDR + 0x4)
#define        SID                                     (PIO_LDMASK_BASE_ADDR + 0x8)

/*
 * Register: DevErrStat         DEV_ERR_STAT           (PIO_BASE_ADDR + 0x8380)
 *     also: DevErrMask         DEV_ERR_MASK           (PIO_BASE_ADDR + 0x8384)
 * Device Error Status / Mask
 * Description: Device Error Status logs errors that cannot be
 * attributed to a given dma channel. It does not duplicate errors
 * already observable via specific block logical device groups.
 * Device Error Status bits [31:16] feed LDSV0.devErr0 Device Error
 * Status bits [15:0] feed LDSV1.devErr1
 * Fields:
 *     Set to 1 if Reorder Buffer/Reorder Table has a single bit
 *     ecc/parity error. This error condition is asserted by TDC to
 *     PEU.
 *     Set to 1 if RX Ctrl or Data FIFO has a single bit ecc error.
 *     This error condition is asserted by RDC to PEU.
 *     Set to 1 if any of the external block accesses have resulted
 *     in error or if a parity error was detected in the SPROM
 *     internal ram. Refer to peuIntrStat for the errors that
 *     contribute to this bit.
 *     Set to 1 if Reorder Buffer/Reorder Table has a double bit
 *     ecc/parity error. This error condition is asserted by TDC to
 *     PEU.
 *     Set to 1 if RX Ctrl or Data FIFO has a double bit ecc error.
 *     This error condition is asserted by RDC to PEU.
 *     Set to 1 if any PEU ram (MSI-X, retrybuf/sot, p/np/cpl queues)
 *     has a parity error Refer to peuIntrStat for the errors that
 *     contribute to this bit.
 */

typedef union {
       uint32_t value;
       struct {
#if defined(__BIG_ENDIAN)
               uint32_t        rsrvd:13;
               uint32_t        tdc_err0:1;
               uint32_t        rdc_err0:1;
               uint32_t        rsrvd1:1;
               uint32_t        rsrvd2:12;
               uint32_t        vnm_pio_err1:1;
               uint32_t        tdc_err1:1;
               uint32_t        rdc_err1:1;
               uint32_t        peu_err1:1;
#else
               uint32_t        peu_err1:1;
               uint32_t        rdc_err1:1;
               uint32_t        tdc_err1:1;
               uint32_t        vnm_pio_err1:1;
               uint32_t        rsrvd2:12;
               uint32_t        rsrvd1:1;
               uint32_t        rdc_err0:1;
               uint32_t        tdc_err0:1;
               uint32_t        rsrvd:13;
#endif
       } bits;
} dev_err_stat_t;



/*
 * Register: BlockReset         BLOCK_RESET            (PIO_BASE_ADDR + 0x8000)
 * Block Reset
 * Description: Soft resets to modules. Blade domain modules are
 * reset by setting the corresponding block reset to 1. Shared domain
 * resets are sent to SPI for processing and corresponding action by
 * SPI. Shared domains are reset only if all the blades have
 * requested a reset for that block. Below is an example scenario :
 * s/w initiates the reset by writing '1' to the dpmRst bit dpmRst
 * bit remains '1' until dpmRstStat is detected to be 1. Once
 * dpmRstStat is detected to be 1, even if s/w writes 1 to this bit
 * again no new reset will be initiated to the shared domain, ie,
 * DPM. dpmRstStat is driven by external i/f (shared domain status
 * provided by SPI) dpmRstStat bit will show '1' as long as the input
 * stays at 1 or until s/w reads the status and is cleared only after
 * s/w reads it and if dpmRstStat is 0 by then.
 * If Host wants to reset entire Hydra it should do so through the
 * mailbox. In this case, the message interprettation is upto the
 * software. Writing a '1' to any of these bits generates a single
 * pulse to the SP module which then controls the reset of the
 * respective block.
 *
 * Fields:
 *     1 : indicates that an active reset has been applied to the SP
 *     based on the request from all of the blades. Clears on Read
 *     provided the reset to SP has been deasserted by then by SPI.
 *     Setting to 1 allows this blade to request Service Processor
 *     (Shared) reset. However, SP reset can only occur if all blades
 *     agree. The success of reset request is indicated by spRstStat
 *     = 1 which is wired-AND of request from all the blades. Current
 *     request can be removed by writing a '0' to this bit. This bit
 *     clears automatically on detecting spRstStat = 1.
 *     Enable blade to service processor (Shared) reset voter
 *     registration = 1, disabled = 0
 *     Issue power reset to the EP Core Clears to 0, writing 0 has no
 *     effect.
 *     Issue core reset to the EP Core Clears to 0, writing 0 has no
 *     effect.
 *     Issue system reset (sysPor) to the PIPE Core This issues reset
 *     to the EP core, PCIe domains of Tdc, Rdc, and CIP. This shuts
 *     down the PCIe clock until Pipe core comes out of reset. The
 *     status of the Pipe core can be read by reading out the
 *     cipLinkStat register's pipe core status and pcie reset status
 *     bits. Clears to 0, writing 0 has no effect.
 *     1 : indicates that an active reset has been applied to the
 *     NMAC based on the request from all of the blades. Clears on
 *     Read provided the reset to NMAC has been deasserted by then by
 *     SPI.
 *     1 : indicates that an active reset has been applied to the TDP
 *     based on the request from all of the blades. Clears on Read
 *     provided the reset to TDP has been deasserted by then by SPI.
 *     1 : indicates that an active reset has been applied to the DPM
 *     based on the request from all of the blades. Clears on Read
 *     provided the reset to DPM has been deasserted by then by SPI.
 *     This bit is effective only if sharedVoterEn (bit 24 of this
 *     reg) has been enabled. Writing '1' sends a request to SP to
 *     reset NMAC if sharedVoterEn=1. Intended for backdoor access.
 *     The success of reset request is indicated by nmacRstStat = 1
 *     which is wired-AND of request from all the blades. This also
 *     means that the reset request is successful only if all the
 *     blades requested for reset of this block. Current request can
 *     be removed by writing a '0' to this bit. This bit clears
 *     automatically on detecting nmacRstStat = 1.
 *     This bit is effective only if sharedVoterEn (bit 24 of this
 *     reg) has been enabled. Writing '1' sends a request to SP to
 *     reset TDP if sharedVoterEn=1. Intended for backdoor access.
 *     Intended for backdoor access. The success of reset request is
 *     indicated by tdpRstStat = 1 which is wired-AND of request from
 *     all the blades. This also means that the reset request is
 *     successful only if all the blades requested for reset of this
 *     block. Current request can be removed by writing a '0' to this
 *     bit. This bit clears automatically on detecting tdpRstStat =
 *     1.
 *     This bit is effective only if sharedVoterEn (bit 24 of this
 *     reg) has been enabled. Writing '1' sends a request to SP to
 *     reset DPM if sharedVoterEn=1. Intended for backdoor access.
 *     Intended for backdoor access. The success of reset request is
 *     indicated by dpmRstStat = 1 which is wired-AND of request from
 *     all the blades. This also means that the reset request is
 *     successful only if all the blades requested for reset of this
 *     block. Current request can be removed by writing a '0' to this
 *     bit. This bit clears automatically on detecting dpmRstStat =
 *     1.
 *     Setting to 1 generates tdcCoreReset and tdcPcieReset to the
 *     TDC block. The reset will stay asserted for atleast 4 clock
 *     cycles. Clears to 0, writing 0 has no effect.
 *     Setting to 1 generates rdcCoreReset and rdcPcieReset to the
 *     RDC block. The reset will stay asserted for atleast 4 clock
 *     cycles. Clears to 0, writing 0 has no effect.
 *     Setting to 1 generates reset to the PFC block. The reset will
 *     stay asserted for atleast 4 clock cycles. Clears to 0, writing
 *     0 has no effect.
 *     Setting to 1 generates reset to the VMAC block. The reset will
 *     stay asserted for atleast 4 clock cycles. Clears to 0, writing
 *     0 has no effect.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(__BIG_ENDIAN)
		uint32_t	rsrvd:13;
		uint32_t	sp_rst_stat:1;
		uint32_t	sp_rst:1;
		uint32_t	shared_voter_en:1;
		uint32_t	epcore_pwr_rst:1;
		uint32_t	epcore_core_rst:1;
		uint32_t	pipe_sys_rst:1;
		uint32_t	nmac_rst_stat:1;
		uint32_t	tdp_rst_stat:1;
		uint32_t	dpm_rst_stat:1;
		uint32_t	rsrvd1:1;
		uint32_t	nmac_rst:1;
		uint32_t	tdp_rst:1;
		uint32_t	dpm_rst:1;
		uint32_t	rsrvd2:1;
		uint32_t	tdc_rst:1;
		uint32_t	rdc_rst:1;
		uint32_t	pfc_rst:1;
		uint32_t	vmac_rst:1;
		uint32_t	rsrvd3:1;
#else
		uint32_t	rsrvd3:1;
		uint32_t	vmac_rst:1;
		uint32_t	pfc_rst:1;
		uint32_t	rdc_rst:1;
		uint32_t	tdc_rst:1;
		uint32_t	rsrvd2:1;
		uint32_t	dpm_rst:1;
		uint32_t	tdp_rst:1;
		uint32_t	nmac_rst:1;
		uint32_t	rsrvd1:1;
		uint32_t	dpm_rst_stat:1;
		uint32_t	tdp_rst_stat:1;
		uint32_t	nmac_rst_stat:1;
		uint32_t	pipe_sys_rst:1;
		uint32_t	epcore_core_rst:1;
		uint32_t	epcore_pwr_rst:1;
		uint32_t	shared_voter_en:1;
		uint32_t	sp_rst:1;
		uint32_t	sp_rst_stat:1;
		uint32_t	rsrvd:13;
#endif
	} bits;
} block_reset_t;


/*
 * Register: CipLinkStat        CIP_LINK_STAT          (PIO_BASE_ADDR + 0x801C)
 * Link Status Register
 * Description: This register returns the Link status
 * Fields:
 *     NMAC XPCS-2 Link Status
 *     NMAC XPCS-1 Link Status
 *     NMAC XPCS-0 Link Status
 *     '1' indicates that pipe core went down suddenly when its reset
 *     sources are at deactivated level. When this happens, the PCIe
 *     domain logics are reset including the EP core, TDC/RDC PCIe
 *     domains. All these logics, EP Core, and the pipe core are held
 *     at reset until s/w writes 1 to this bit to clear status which
 *     will also bring the PCIe domain out of reset
 *     pipe core clock & reset status 1: core is up & running, ie,
 *     PIPE core is out of reset and clock is ON
 *     PCIe domain reset status 1: PCIe domain logics including EP
 *     core are out of reset; This also implies that PCIe clock is up
 *     and running
 *     EP Core XDM Link State
 *     EP Core RDM Link State
 *     EP Core LTSSM State
 */
typedef union {
	uint32_t value;
	struct {
#if defined(__BIG_ENDIAN)
		uint32_t	rsrvd:13;
		uint32_t	xpcs2_link_up:1;
		uint32_t	xpcs1_link_up:1;
		uint32_t	xpcs0_link_up:1;
		uint32_t	rsrvd1:6;
		uint32_t	surprise_pipedn:1;
		uint32_t	pipe_core_stable:1;
		uint32_t	pcie_domain_stable:1;
		uint32_t	xmlh_link_up:1;
		uint32_t	rdlh_link_up:1;
		uint32_t	xmlh_ltssm_state:5;
#else
		uint32_t	xmlh_ltssm_state:5;
		uint32_t	rdlh_link_up:1;
		uint32_t	xmlh_link_up:1;
		uint32_t	pcie_domain_stable:1;
		uint32_t	pipe_core_stable:1;
		uint32_t	surprise_pipedn:1;
		uint32_t	rsrvd1:6;
		uint32_t	xpcs0_link_up:1;
		uint32_t	xpcs1_link_up:1;
		uint32_t	xpcs2_link_up:1;
		uint32_t	rsrvd:13;
#endif
	} bits;
} cip_link_stat_t;


/*
 * Register: PeuIntrStat        PEU_INTR_STAT          (PIO_BASE_ADDR + 0x8148)
 *     also: PeuIntrMask        PEU_INTR_MASK          (PIO_BASE_ADDR + 0x814C)
 * PEU Interrupt Status / Mask
 * Description: Returns the parity error status of all of the PEU
 * RAMs, and external (to peu) block pio access errors. External
 * block pio access errors could be due to either host or SPI
 * initiated accesses. These fields are RO and can be cleared only
 * through a cip reset All these errors feed to devErrStat.peuErr1
 * which in turn feed to LDSV1.devErr1
 * Partity Error bits: These bits log the very first parity error
 * detected in a particular memory. The corresponding memory location
 * is logged in respective perrLoc registers. External Block PIO
 * Access Error bits: These bits log the very first error that
 * resulted in access error. The corresponding address is logged in
 * respective accErrLog registers.
 * These bits can be set by writing a '1' to the corresponding
 * mirror bit in the peuIntrStatMirror register.
 * Note: PEU RAM Parity Errors and their corresponding interrupt:
 * When these bits are set and the device error status interrupt is
 * not masked, the PEU attempts to send the corresponding interrupt
 * back to the RC. Depending on which ram is impacted and the
 * corresponding logic impacted in the EP core, a coherent interrupt
 * message may not be sent in all cases. For the times when the EP
 * core is unable to send an interrupt, the SPI interface is to be
 * used for error diagnosis as the PEU interrupt status is logged
 * regardless of whether the interrupt is sent to the RC. The
 * following data was collected via simulation: -Parity error
 * impacted rams that likely will be able to send an interrupt:
 * npDataq, pDataq, cplDataq, hcr. -Parity error impacted rams that
 * may not be able to send an interrupt: npHdrq, pHdrq, cplHdrq, MSIx
 * table, retryram, retrysot.
 *
 * Fields:
 *     Error indication from SPROM Controller for Sprom Download
 *     access This error indicates that a parity error was detected
 *     from SRAM. For more details, please refer to SPROM Controller
 *     PRM.
 *     Error indication from TDC for PIO access The error location
 *     and type are logged in tdcPioaccErrLog
 *     Error indication from RDC for PIO access The error location
 *     and type are logged in rdcPioaccErrLog
 *     Error indication from PFC for PIO access The error location
 *     and type are logged in pfcPioaccErrLog
 *     Error indication from VMAC for PIO access The error location
 *     and type are logged in vmacPioaccErrLog
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 *     memory in PCIe data path and value unknown until packet flow
 *     starts.
 */
typedef union {
	uint32_t value;
	struct {
#if defined(__BIG_ENDIAN)
		uint32_t	rsrvd:11;
		uint32_t	spc_acc_err:1;
		uint32_t	tdc_pioacc_err:1;
		uint32_t	rdc_pioacc_err:1;
		uint32_t	pfc_pioacc_err:1;
		uint32_t	vmac_pioacc_err:1;
		uint32_t	rsrvd1:6;
		uint32_t	cpl_hdrq_parerr:1;
		uint32_t	cpl_dataq_parerr:1;
		uint32_t	retryram_xdlh_parerr:1;
		uint32_t	retrysotram_xdlh_parerr:1;
		uint32_t	p_hdrq_parerr:1;
		uint32_t	p_dataq_parerr:1;
		uint32_t	np_hdrq_parerr:1;
		uint32_t	np_dataq_parerr:1;
		uint32_t	eic_msix_parerr:1;
		uint32_t	hcr_parerr:1;
#else
		uint32_t	hcr_parerr:1;
		uint32_t	eic_msix_parerr:1;
		uint32_t	np_dataq_parerr:1;
		uint32_t	np_hdrq_parerr:1;
		uint32_t	p_dataq_parerr:1;
		uint32_t	p_hdrq_parerr:1;
		uint32_t	retrysotram_xdlh_parerr:1;
		uint32_t	retryram_xdlh_parerr:1;
		uint32_t	cpl_dataq_parerr:1;
		uint32_t	cpl_hdrq_parerr:1;
		uint32_t	rsrvd1:6;
		uint32_t	vmac_pioacc_err:1;
		uint32_t	pfc_pioacc_err:1;
		uint32_t	rdc_pioacc_err:1;
		uint32_t	tdc_pioacc_err:1;
		uint32_t	spc_acc_err:1;
		uint32_t	rsrvd:11;
#endif
	} bits;
} peu_intr_stat_t;

/*
 * Register: PhyDebugTrainingVec
 * peuPhy Debug Training Vector
 * Description: peuPhy Debug Training Vector register.
 * Fields:
 *     Hard-coded value for peuPhy wrt global debug training block
 *     signatures.
 *     Blade Number, the value read depends on the blade this block
 *     resides
 *     debug training vector the sub-group select value of 0 selects
 *     this vector
 */
typedef union {
       uint32_t value;
       struct {
#if defined(__BIG_ENDIAN)
               uint32_t        dbg_msb:1;
               uint32_t        bld_num:3;
               uint32_t        phydbg_training_vec:28;
#else
               uint32_t        phydbg_training_vec:28;
               uint32_t        bld_num:3;
               uint32_t        dbg_msb:1;
#endif
       } bits;
} phy_debug_training_vec_t;

/*
 * Register: PeuDebugTrainingVec
 * PEU Debug Training Vector
 * Description: PEU Debug Training Vector register.
 * Fields:
 *     Hard-coded value for PEU (VNMy - core clk domain) wrt global
 *     debug training block signatures.
 *     Blade Number, the value read depends on the blade this block
 *     resides
 *     debug training vector the sub-group select value of 0 selects
 *     this vector
 *     Hard-coded value for PEU (VNMy - core clk domain) wrt global
 *     debug training block signatures.
 *     Blade Number, the value read depends on the blade this block
 *     resides
 *     debug training vector the sub-group select value of 0 selects
 *     this vector
 */
typedef union {
       uint32_t value;
       struct {
#if defined(__BIG_ENDIAN)
               uint32_t        dbgmsb_upper:1;
               uint32_t        bld_num_upper:3;
               uint32_t        peudbg_upper_training_vec:12;
               uint32_t        dbgmsb_lower:1;
               uint32_t        bld_num_lower:3;
               uint32_t        peudbg_lower_training_vec:12;
#else
               uint32_t        peudbg_lower_training_vec:12;
               uint32_t        bld_num_lower:3;
               uint32_t        dbgmsb_lower:1;
               uint32_t        peudbg_upper_training_vec:12;
               uint32_t        bld_num_upper:3;
               uint32_t        dbgmsb_upper:1;
#endif
       } bits;
} peu_debug_training_vec_t;

/*
 * Register: SID
 * System Interrupt Data
 * Description: System Interrupt Data (MSI Vectors)
 * Fields:
 *     Data sent along with the interrupt
 */
typedef union {
       uint32_t value;
       struct {
#if defined(__BIG_ENDIAN)
               uint32_t        rsrvd:27;
               uint32_t        data:5;
#else
               uint32_t        data:5;
               uint32_t        rsrvd:27;
#endif
       } bits;
} sid_t;

/*
 * Register: LdIntrTimRes
 * Logical Device Interrupt Timer Resolution
 * Description: Logical Device Interrupt Timer Resolution
 * Fields:
 *     Timer resolution in 250 MHz cycles
 */
typedef union {
       uint32_t value;
       struct {
#if defined(__BIG_ENDIAN)
               uint32_t        rsrvd:12;
               uint32_t        res:20;
#else
               uint32_t        res:20;
               uint32_t        rsrvd:12;
#endif
       } bits;
} ld_intr_tim_res_t;

/*
 * Register: LdIntrMask
 * Logical Device Interrupt Mask
 * Description: Logical Device Interrupt Mask
 * Fields:
 *     Flag1 mask for logical device N (0-31)
 *     Flag0 mask for logical device N (0-31)
 */
typedef union {
       uint32_t value;
       struct {
#if defined(__BIG_ENDIAN)
               uint32_t        rsrvd:30;
               uint32_t        ldf1_mask:1;
               uint32_t        ldf0_mask:1;
#else
               uint32_t        ldf0_mask:1;
               uint32_t        ldf1_mask:1;
               uint32_t        rsrvd:30;
#endif
       } bits;
} ld_intr_mask_t;


/*
 * Register: LdIntrMgmt
 * Logical Device Interrupt Management
 * Description: Logical Device Interrupt Management
 * Fields:
 *     SW arms the logical device for interrupt. Cleared by HW after
 *     interrupt issued. (1 = arm)
 *     Timer set by SW. Hardware counts down.
 */
typedef union {
       uint32_t value;
       struct {
#if defined(__BIG_ENDIAN)
               uint32_t        arm:1;
               uint32_t        rsrvd:25;
               uint32_t        timer:6;
#else
               uint32_t        timer:6;
               uint32_t        rsrvd:25;
               uint32_t        arm:1;
#endif
       } bits;
} ld_intr_mgmt_t;


/*
 * Register: LdGrpCtrl
 * Logical Device Group Control
 * Description: LD Group assignment
 * Fields:
 *     Logical device group number of this logical device
 */
typedef union {
       uint32_t value;
       struct {
#if defined(__BIG_ENDIAN)
               uint32_t        rsrvd:27;
               uint32_t        num:5;
#else
               uint32_t        num:5;
               uint32_t        rsrvd:27;
#endif
       } bits;
} ld_grp_ctrl_t;



#define HCR_ADDR_LO             0xC
#define HCR_ADDR_HI             0x10




#endif /* _HXGE_PEU_HW_H */
