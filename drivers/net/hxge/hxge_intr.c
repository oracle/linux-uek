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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
extern irqreturn_t hxge_pfc_intr(int irq, void *data, struct pt_regs *regs);
extern irqreturn_t hxge_vmac_intr(int irq, void *data, struct pt_regs *regs);
extern irqreturn_t hxge_rx_intr(int irq, void *data, struct pt_regs *regs);
extern irqreturn_t hxge_rx_deverr_intr(int irq, void *data, struct pt_regs *regs);
extern irqreturn_t hxge_tx_intr(int irq, void *data, struct pt_regs *regs);
extern irqreturn_t hxge_tx_deverr_intr(int irq, void *data, struct pt_regs *regs);
extern irqreturn_t hxge_peu_deverr_intr(int irq, void *data, struct pt_regs *regs);
#else
extern irqreturn_t hxge_pfc_intr(int irq, void *data);
extern irqreturn_t hxge_vmac_intr(int irq, void *data);
extern irqreturn_t hxge_rx_intr(int irq, void *data);
extern irqreturn_t hxge_rx_deverr_intr(int irq, void *data);
extern irqreturn_t hxge_tx_intr(int irq, void *data);
extern irqreturn_t hxge_tx_deverr_intr(int irq, void *data);
extern irqreturn_t hxge_peu_deverr_intr(int irq, void *data);
#endif

extern int hxge_get_option(const char *str, int *val);

static void hxge_dump_ints(struct hxge_adapter *hxgep);
static void hxge_enable_ldg_ints(struct hxge_ldg *ldgp);
void hxge_teardown_interrupt(struct hxge_adapter *hxgep);


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static irqreturn_t hxge_deverr_intr (int irq, void *data, struct pt_regs *regs)
#else
static irqreturn_t hxge_deverr_intr (int irq, void *data)
#endif
{
	struct hxge_ldv *ldvp = (struct hxge_ldv *)data;
	struct hxge_adapter *hxgep = ldvp->ldgp->hxgep;
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	dev_err_stat_t dsts;
	hpi_status_t hsts;

	dsts.value = 0;
	hsts = hpi_fzc_sys_err_stat_get(handle, &dsts);
	if (hsts != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hxge_deverr_intr: Can't read DEV_ERR_STAT register");
		/* Not clear what to do now...probably go down in flames...
		 * fake up a DEV_ERR_STAT with lotsa bits set, and see if
		 * the individual handlers have anything to report.  We
		 * should probably down/reset the whole device.
		 */
		dsts.value = 0xF; /* TDC/RDC/PEU/VMAC "errors" */
	}

	if (!dsts.value) {
		HXGE_ERR(hxgep, "hxge_deverr_intr: DEV_ERR_STAT register empty:");
        	return (IRQ_NONE);
	}

	HXGE_DBG(hxgep, "hxge_deverr_intr: Device Error Interrupt! (0x%8.8x)",
		 dsts.value);

	/* Look for TX, RX, or general (VMAC/PEU) and "dispatch" */

	if (dsts.bits.tdc_err0 || dsts.bits.tdc_err1) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
		hxge_tx_deverr_intr(irq, ldvp, regs);
#else
		hxge_tx_deverr_intr(irq, ldvp);
#endif
		dsts.bits.tdc_err0 = 0;
		dsts.bits.tdc_err1 = 0;
	}

	if (dsts.bits.rdc_err0 || dsts.bits.rdc_err1) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
		hxge_rx_deverr_intr(irq, ldvp, regs);
#else
		hxge_rx_deverr_intr(irq, ldvp);
#endif
		dsts.bits.rdc_err0 = 0;
		dsts.bits.rdc_err1 = 0;
	}

	if (dsts.bits.vnm_pio_err1 || dsts.bits.peu_err1) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
		hxge_peu_deverr_intr(irq, ldvp, regs);
#else
		hxge_peu_deverr_intr(irq, ldvp);
#endif
		dsts.bits.vnm_pio_err1 = 0;
		dsts.bits.peu_err1 = 0;
	}

	if (dsts.value) {
		HXGE_ERR(hxgep, "hxge_deverr_intr: Unexpected/unknown DEV_ERR_STAT flags: %8.8x", dsts.value);
	}

	return (IRQ_HANDLED);
}

/**
 * hxge_intr - Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 * @pt_regs: CPU registers structure
 **/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static irqreturn_t
hxge_intr(int irq, void *data, struct pt_regs *regs)
#else
static irqreturn_t
hxge_intr(int irq, void *data)
#endif
{
	struct hxge_ldg *ldgp = (struct hxge_ldg *)data;
	struct hxge_ldv *ldvp;
	irqreturn_t status = IRQ_NONE;
	int ldf0, ldf1;


	list_for_each_entry(ldvp, &ldgp->ldv_list, ldg_list) {

		/* Check if there is an interrupt for this device */
		get_ldf_flags(ldvp, &ldf0, &ldf1);
		if (!ldf0 && !ldf1)
			continue;

		/* We're banking on the fact that IRQ_NONE is zero; otherwise
		   this neat trick won't work! */
		switch (ldvp->dev_type) {

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
		case LDV_TXDMA :
			status |= hxge_tx_intr(irq, ldvp, regs);
			break;
		case LDV_VMAC :
			status |= hxge_vmac_intr(irq, ldvp, regs);
			break;
		case LDV_PFC :
			status |= hxge_pfc_intr(irq, ldvp, regs);
			break;
		case LDV_DEVERR :
			status |= hxge_deverr_intr(irq, ldvp, regs);
			break;
		case LDV_RXDMA :
			status |= hxge_rx_intr(irq, ldvp, regs);
			break;
#else
		case LDV_TXDMA :
			status |= hxge_tx_intr(irq, ldvp);
			break;
		case LDV_VMAC :
			status |= hxge_vmac_intr(irq, ldvp);
			break;
		case LDV_PFC :
			status |= hxge_pfc_intr(irq, ldvp);
			break;
		case LDV_DEVERR :
			status |= hxge_deverr_intr(irq, ldvp);
			break;
		case LDV_RXDMA :
			status |= hxge_rx_intr(irq, ldvp);
			break;
#endif

		default : HXGE_ERR_PRINT("hxge_intr: Unknown device %d", ldvp->ldv);
			status = IRQ_HANDLED;
		}
	}

	/* Enable interrutps for this logical device group */
	if (status == IRQ_HANDLED)
		hxge_enable_ldg_ints(ldgp);

        return status;
}



/* Basic utility routine that enables or disables interrupts for the 
   devices (blocks) within hydra that are supported */
static int hxge_interrupt_mgmt(struct hxge_adapter *hxgep, int enable_int,
				int mask_int, int dev_type, 
				struct hxge_ldg *dev, int channel)
{
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	struct hxge_ldv *ldvp;
	struct hxge_ldg *ldgp;
	int status;
	int arm = FALSE;
	uint8_t masks = (uint8_t)LD_IM_MASK;


	if (hxgep->intr_type == POLLING_TYPE)
		return 0;

	/* If interrutps are enabled, then
		a) arm the logical device groups
		b) Enable the timer as well
	*/
	if (enable_int) 
		arm = TRUE;

	/* If mask_int is not true, then clear the LDF masks for the devices */
	if (!mask_int)
		masks = 0;

	list_for_each_entry(ldgp, &hxgep->ldgvp->ldgp, list) {
		if (dev && (dev != ldgp))
			continue;
		if (mask_int >= 0) {
			list_for_each_entry(ldvp, &ldgp->ldv_list, ldg_list) {
				if (ldvp->dev_type & dev_type) {
					if (channel >= 0) {
				 	   if (dev_type == LDV_RXDMA)
					      channel += HXGE_RDMA_LD_START;
					   else if (dev_type == LDV_TXDMA)
					      channel += HXGE_TDMA_LD_START;
					   if (channel != ldvp->ldv)
						continue;
					}
					ldvp->ldf_masks = masks;
					status = hpi_intr_mask_set(handle, 
							ldvp->ldv, masks);
					if (status != HPI_SUCCESS) {
						HXGE_ERR(hxgep, "hpi_intr_mask_set failed");
						return -1;
					}
				}
			}
		}
		if (enable_int >= 0) {
			ldgp->arm = arm;
			status = hpi_intr_ldg_mgmt_set(handle, 
					ldgp->ldg, arm, ldgp->timer);
			if (status != HPI_SUCCESS) {
				HXGE_ERR(hxgep, "hpi_intr_ldg_mgmt_set failed");
				return -1;
			}
		}
	}
	return 0;
}

void get_ldf_flags(struct hxge_ldv *ldvp, int *ldf0, int *ldf1)
{
        hpi_handle_t    handle = ldvp->ldgp->hxgep->hw.hw_addr;
        uint32_t vector0, vector1;

        *ldf0 = 0;
        *ldf1 = 0;

        if (hpi_ldsv_ldfs_get(handle, ldvp->ldgp->ldg, &vector0, &vector1)
		!= HPI_SUCCESS) {
		HXGE_ERR_PRINT("get_ldf_flags: hpi_ldsv_ldfs_get failed");
	}
	
        /* Only check for regular LDF0 interrupt. LDF1 implies error and
           is handled in a separate context. Also, LDF0 implies that the
           RCR Threshold and/or RCR Timeout bits in the RDC control/status
           register is set */
        *ldf0 = ((vector0 &  (1 << ldvp->ldv)) != 0);

        /* LDF1 indicates fatal error happened. Have to parse the RDC control
           register for the exact error(s) */
        *ldf1 = ((vector1 &  (1 << ldvp->ldv)) != 0);
}


void hxge_enable_interrupts(struct hxge_adapter *hxgep)
{
	hxge_interrupt_mgmt(hxgep, 1, 0, LDV_ALL, NULL, -1);
}

void hxge_disable_interrupts(struct hxge_adapter *hxgep)
{
	hxge_interrupt_mgmt(hxgep, 0, 1, LDV_ALL, NULL, -1);
}

void hxge_enable_rx_ints(struct hxge_adapter *hxgep, struct hxge_ldg *dev,
			int rdc)
{  
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	struct hxge_ldv *ldvp;
	struct hxge_ldg *ldgp;
	rdc_stat_t cs;
	int channel;

	if (hxgep->intr_type == POLLING_TYPE)
		return;

	/* For Rx devices, re-enable the mailbox interrupt
           and couple of RCR bits. These are 1-shot and potentially need
	   to be reset */
        list_for_each_entry(ldgp, &hxgep->ldgvp->ldgp, list) {
		if (dev && (dev != ldgp))
			continue;
                list_for_each_entry(ldvp, &ldgp->ldv_list, ldg_list) {
			if (ldvp->dev_type != LDV_RXDMA)
				continue;
			channel = ldvp->ldv-HXGE_RDMA_LD_START;
			if ((rdc >= 0) && (channel != rdc))
				continue;

			/* set up the CS register. The rcr timeout and 
			 * threshold were cleared in process_rx, when the
			 * cs register was read. If those bits are cleared
			 * here, we could wipe out a potential pending 
			 * threshold and/or timeout interrupt inadvertantly
			 * (related to CR 6774415). So, clear all bits except
			 * ptrs and pkts read when processing interrupts
			 */

			cs.value = (ldvp->data & 
			       (RDC_STAT_PKTREAD_MASK | RDC_STAT_PTRREAD_MASK));
                        cs.bits.mex = 1;

#ifdef DETECT_RCR_FULL
			/* Temporary Check: To detect RCR Full conditions
			 * till we resolve the alignment requirement  issues
			 * with RCR and RBRs
			 */
			do {
				rdc_stat_t curr_cs;
				hpi_rxdma_control_status(handle, OP_GET,
			   	  ldvp->ldv-HXGE_RDMA_LD_START, &curr_cs);
				if (curr_cs.bits.rcr_full) {
					HXGE_ERR(hxgep, "hxge_enable_rx_ints: RCR Full caught!");
				}
			} while (0);
#endif
					
                        /* read nothing; don't want to write
                           random old value in cs back! */
                        if (hpi_rxdma_control_status(handle, OP_SET, 
					ldvp->ldv-HXGE_RDMA_LD_START, &cs) != 
					HPI_SUCCESS) {
				HXGE_ERR(hxgep, "hxge_enable_rx_ints: Failed to read Rx channel %d",ldvp->ldv-HXGE_RDMA_LD_START);
			}
	
		}
	}
	hxge_interrupt_mgmt(hxgep, -1, 0, LDV_RXDMA, dev, rdc);
}

void hxge_disable_rx_ints(struct hxge_adapter *hxgep, struct hxge_ldg *ldgp, 
			  int rdc)
{
	hxge_interrupt_mgmt(hxgep, -1, 1, LDV_RXDMA, ldgp, rdc);
}

void hxge_enable_tx_ints(struct hxge_adapter *hxgep, struct hxge_ldg *ldgp)
{
	hxge_interrupt_mgmt(hxgep, -1, 0, LDV_TXDMA, ldgp, -1);
}

static void hxge_enable_ldg_ints(struct hxge_ldg *ldgp)
{
	hxge_interrupt_mgmt(ldgp->hxgep , 1, -1, LDV_ALL, ldgp, -1);
}

void hxge_disable_ldg_ints(struct hxge_ldg *ldgp)
{
	hxge_interrupt_mgmt(ldgp->hxgep , 0, -1, LDV_ALL, ldgp, -1);
}

void hxge_disable_tx_ints(struct hxge_adapter *hxgep)
{
	hxge_interrupt_mgmt(hxgep, -1, 1, LDV_TXDMA, NULL, -1);
}



/* Set up the hydra registers related to interrupt management. However,
   interrupts are only enabled when the interaface is brought up i.e in
   hxge_up 
*/
int hxge_set_hw_interrupt_regs (struct hxge_adapter *hxgep)
{
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	hpi_status_t	status = HPI_SUCCESS;
	fzc_sid_t 	sid;
	int		i;
	struct hxge_ldv *ldvp;
	struct hxge_ldg *ldgp;

	/* Configure the initial timer resolution */
	if (hpi_fzc_ldg_timer_res_set (handle, hxgep->ldgvp->tmres)
		!= HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_fzc_ldg_timer_res_set failed");
		return -1;
	}
		

	/* Set up the logical device groups and relate them to the logical
	   devices. Also program the sid values  */

	i = 0;
	list_for_each_entry(ldgp, &hxgep->ldgvp->ldgp, list) {
		list_for_each_entry(ldvp, &ldgp->ldv_list, ldg_list) {
			HXGE_DBG(hxgep, "Setting LDV %d->LDG %d",ldvp->ldv,ldgp->ldg);
			status = hpi_fzc_ldg_num_set(handle, ldvp->ldv, 
					ldgp->ldg);
			if (status != HPI_SUCCESS) {
				HXGE_ERR(hxgep, "hpi_fzc_ldg_num_set failed");
				return -1;
			}
		}
		sid.vector = i++; /* just has to be unique for each entry */
		sid.ldg = ldgp->ldg;
		if (hpi_fzc_sid_set(handle, sid) != HPI_SUCCESS) {
			HXGE_ERR(hxgep, "hpi_fzc_sid_set failed");
			return -1;
		}
	}

	return 0;
          
}

/* Return the number of logical device groups that we want to support. This
   is purely programmatic. The assumption in picking the number of groups
   is the best potential combination that would minimize interrupt latency
   and maximize throughput */

static int get_num_ldgs(struct hxge_adapter *hxgep, struct ldv_array *ldv)
{
        int nldgs = 0;
        int i;

        /* Each Tx channel has its own group */
        nldgs += hxgep->max_tdcs;
        for (i = 0; i < hxgep->max_tdcs; i++) {
                ldv->type =  LDV_TXDMA;
                ldv->dev_no = HXGE_TDMA_LD_START+i;
                ldv++;
        }

        /* Each Rx channel */
        nldgs += hxgep->max_rdcs;
        for (i = 0; i < hxgep->max_rdcs; i++) {
                ldv->type =  LDV_RXDMA;
                ldv->dev_no = HXGE_RDMA_LD_START+i;
                ldv++;
        }

        /* VMAC */
        nldgs++;
        ldv->type = LDV_VMAC;
        ldv->dev_no = HXGE_VMAC_LD;
        ldv++;

        /* PFC */
        nldgs++;
        ldv->type = LDV_PFC;
        ldv->dev_no = HXGE_PFC_LD;
        ldv++;

        /* Device Errors */
        nldgs++;
        ldv->type = LDV_DEVERR;
        ldv->dev_no = HXGE_SYS_ERROR_LD;

        return nldgs;
}


static void
hxge_ldg_uninit(struct hxge_adapter *hxgep)
{
        struct hxge_ldv *ldvp, *loc_ldvp;
        struct hxge_ldg *ldgp, *loc_ldgp;

        list_for_each_entry_safe(ldvp, loc_ldvp, &hxgep->ldgvp->ldvp, list) 
                kfree(ldvp);

        list_for_each_entry_safe(ldgp, loc_ldgp, &hxgep->ldgvp->ldgp, list) 
                kfree(ldgp);

        kfree(hxgep->ldgvp);

}

static void hxge_dump_ints(struct hxge_adapter *hxgep)
{
        struct hxge_ldgv *ldgvp;
        struct hxge_ldv *ldvp;
        struct hxge_ldg *ldgp;

	HXGE_DBG(hxgep, "Hydra Interrupt Structure =>");
	ldgvp = hxgep->ldgvp;
	HXGE_DBG(hxgep, "  Timer resolution = 0x%x",ldgvp->tmres);
	HXGE_DBG(hxgep, "  Max groups = 0x%x",ldgvp->max_ldgs);
	HXGE_DBG(hxgep, "  Max devices = 0x%x",ldgvp->max_ldvs);
	HXGE_DBG(hxgep, "  No. of groups = 0x%x",ldgvp->nldgs);
	HXGE_DBG(hxgep, "  No. of devices = 0x%x",ldgvp->nldvs);

        list_for_each_entry(ldgp, &hxgep->ldgvp->ldgp, list) {
		HXGE_DBG(hxgep, "");
		HXGE_DBG(hxgep, "   Logical Group %d =>",ldgp->ldg);
		HXGE_DBG(hxgep, "      Vector = %d",ldgp->vector);
		HXGE_DBG(hxgep, "      No. of devices= %d",ldgp->nldvs);
		HXGE_DBG(hxgep, "      arm = %d",ldgp->arm);
		list_for_each_entry(ldvp, &ldgp->ldv_list, ldg_list) {
			HXGE_DBG(hxgep, "");
			HXGE_DBG(hxgep, "      Logical Device %d =>",ldvp->ldv);
			HXGE_DBG(hxgep, "         Dev type =  %d",ldvp->dev_type);
			HXGE_DBG(hxgep, "         use_timer = %d",ldvp->use_timer);
			HXGE_DBG(hxgep, "         ldv_flags = 0x%x",ldvp->ldv_flags);
			HXGE_DBG(hxgep, "         ldf_mask = 0x%x",ldvp->ldf_masks);
		}
	}

}

/* Set up the Hydra interrupt structures - LDV and LDG */
static int
hxge_ldg_init(struct hxge_adapter *hxgep, int num_ints_required,
                int num_ints_available, struct ldv_array *ldv_arr)
{
        struct hxge_ldgv *ldgvp;
        struct hxge_ldv *ldvp;
        struct hxge_ldg *ldgp = NULL;
        int ldg_assigned = -1;
        int i;


        ldgvp = kzalloc(sizeof(struct hxge_ldgv), GFP_KERNEL);
	if (!ldgvp)
	{
		HXGE_ERR(hxgep, "Could not allocate ldgv structure");
		return -1;
	}
        hxgep->ldgvp = ldgvp;

	HXGE_DBG(hxgep, "hxge_ldg_init: num_ints_avail=%d, num_ints_reqd=%d",num_ints_available,num_ints_required);

        /* num_ints_required is what we want for the number of LDVs. However,
           number of interrupts available defines how many LDGs we can have */
        ldgvp->max_ldgs = num_ints_available;
        ldgvp->max_ldvs = num_ints_required;
        if (num_ints_required > HXGE_INT_MAX_LDG) {
                HXGE_ERR(hxgep, "hxge_ldg_init: bad interrupt request");
                return -1;
        }

        INIT_LIST_HEAD(&ldgvp->ldvp);
        INIT_LIST_HEAD(&ldgvp->ldgp);
        ldgvp->tmres = HXGE_TIMER_RESO;

        /* Allocate the bins and fill then later. If we have fewer LDGs than
           LDVs, then after we have reached the last LDG, lump the remaining
           LDVs into that LDG */
        for (i = 0; i < ldgvp->max_ldvs; i++) {
                ldvp = kzalloc(sizeof(struct hxge_ldv), GFP_KERNEL);
		INIT_LIST_HEAD(&ldvp->ldg_list);
		INIT_LIST_HEAD(&ldvp->list);
                ldgvp->nldvs++;
                list_add_tail(&ldvp->list, &ldgvp->ldvp);
                if (i < ldgvp->max_ldgs) { /* not the last LDG */
                        ldgp = kzalloc(sizeof(struct hxge_ldg), GFP_KERNEL);
			if (!ldgp) {
				HXGE_ERR(hxgep, "Alloc failed for ldg structure");
				hxge_teardown_interrupt(hxgep);
				return -1;
			}
                        ldgp->vector = -1;
			INIT_LIST_HEAD(&ldgp->ldv_list);
			INIT_LIST_HEAD(&ldgp->list);
                        list_add_tail(&ldgp->list, &ldgvp->ldgp);
                        ldgp->hxgep = hxgep;
                        ldgp->intr_handler = hxge_intr;
                        ldgvp->nldgs++;
                        ++ldg_assigned;
                        ldgp->ldg = ldg_assigned;
                }
		/* add LDV to the LDG list */
                list_add_tail(&ldvp->ldg_list, &ldgp->ldv_list);
                ldgp->nldvs++;
                ldvp->ldgp = ldgp;
                ldvp->dev_type = ldv_arr[i].type;
                ldvp->ldv = ldv_arr[i].dev_no;
                /* mask interrupts for all devices for starters */
                ldvp->ldf_masks = (uint8_t)LD_IM_MASK;
        }

        /* Go through the devices we care about and assign interrupt handlers 
	   to them. Also enable timers for those devices we want it for  */
        list_for_each_entry(ldvp, &ldgvp->ldvp, list) {
           switch (ldvp->dev_type) {
                case LDV_RXDMA :
                        ldvp->intr_handler = hxge_rx_intr;
                        ldgp->timer = HXGE_TIMER_LDG;
                        break;
                case LDV_TXDMA :
                        ldvp->intr_handler = hxge_tx_intr;
                        ldgp->timer = HXGE_TIMER_LDG;
                        break;
                case LDV_VMAC :
                        ldvp->intr_handler = hxge_vmac_intr;
                        ldgp->timer = HXGE_TIMER_LDG;
                        break;
                case LDV_PFC :
                        ldvp->intr_handler = hxge_pfc_intr;
                        ldgp->timer = HXGE_TIMER_LDG;
                        break;
                case LDV_DEVERR :
                        ldvp->intr_handler = hxge_deverr_intr;
                        break;
                default:
                        HXGE_ERR(hxgep, "hxge_ldg_init: Unsupported device type, %d",ldvp->dev_type);
                        hxge_ldg_uninit(hxgep);
                        return -1;
            }
        }

	hxge_dump_ints(hxgep);

        return 0;
}

/* Tear down the interrupt infrastructure. Typically, this is called when
   an interface is taken down so that the precious interrupt resources are
   freed for use by others */
void hxge_teardown_interrupt(struct hxge_adapter *hxgep)
{
        struct hxge_ldv *ldvp;
        struct hxge_ldg *ldgp;

	/* Nothing to do if polling */
	if (hxgep->intr_type == POLLING_TYPE)
		return;


        list_for_each_entry(ldgp, &hxgep->ldgvp->ldgp, list) {
                ldvp = list_entry(ldgp->ldv_list.next, struct hxge_ldv,
                                                        ldg_list);
                if (ldgp->vector > 0)
                        free_irq(ldgp->vector, ldgp);
        }

        switch (hxgep->intr_type) {
                case MSIX_TYPE :
                        pci_disable_msix(hxgep->pdev);
                        break;
                case MSI_TYPE:
                        pci_disable_msi(hxgep->pdev);
                        break;
        }

#ifdef CONFIG_PCI_MSI
        if (hxgep->intr_type == MSIX_TYPE)
                kfree(hxgep->msix);
#endif
        hxge_ldg_uninit(hxgep);
}

static int hxge_request_irqs(struct net_device *netdev)
{
        struct hxge_adapter *hxgep = netdev_priv(netdev);
        struct hxge_ldv *ldvp;
        struct hxge_ldg *ldgp;
        int i = 0, status;

        list_for_each_entry(ldgp, &hxgep->ldgvp->ldgp, list) {
#ifdef CONFIG_PCI_MSI
                if ((hxgep->intr_type == MSI_TYPE) ||
                        (hxgep->intr_type == INTx_TYPE))
                        ldgp->vector = hxgep->pdev->irq;
                else
                        ldgp->vector = hxgep->msix[i].vector;
#else
                ldgp->vector = hxgep->pdev->irq;
#endif
                ldvp = list_entry(ldgp->ldv_list.next,
                                struct hxge_ldv, ldg_list);
                snprintf(ldgp->irq_name, HXGE_MAX_IRQNAME, "%s_int%d",netdev->name, i);
		HXGE_DBG(hxgep, "Allocating interrupt: irq=%d, dev=%d, intr_name=%s",ldgp->vector,ldvp->ldv, ldgp->irq_name);
                /* If multiple blocks belong to the same group,
                   then pass in the LDG pointer; otherwise, pass in LDV
                  (this saves one indirection on interrupt side) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
                status = request_irq(ldgp->vector, ldgp->intr_handler,
				     SA_SHIRQ, ldgp->irq_name, ldgp);
#else
                status = request_irq(ldgp->vector, ldgp->intr_handler,
				     IRQF_SHARED, ldgp->irq_name, ldgp);
#endif
                if (status) {
			HXGE_ERR(hxgep, "request_irq() failed, returned %d",
				 status);
                        /* no irq allocation done for ldvp. So, reset vector */
                        ldgp->vector = -1;
                        return status;
                }
                i++;
        }

	return 0;
}

/* This routine sets up the interupt infrastructure for Hydra such as the
   LDV and LDG for the various functional blocks and allocates IRQs (either
   legacy or MSIX) by requesting it from the kernel. Finally, it sets the
   appropriate hardware state indicating LDGs and enabling the appropriate
   interrupts for the required blocks */
int hxge_setup_interrupt (struct net_device *netdev)
{
        struct hxge_adapter *hxgep = netdev_priv(netdev);
        int num_ints_required,num_ints_available, i;
#ifdef CONFIG_PCI_MSI
        struct msix_entry *ptr, *msix_ent = NULL;
#endif
        struct ldv_array ldv_arr[HXGE_INT_MAX_LD];
        int intr_type, status;

	if (hxge_get_option("intr_type", &intr_type)) {
		HXGE_ERR(hxgep, "hxge_setup_interrupt: intry_type invalid");
		return -1;
	}
	
	hxgep->intr_type = intr_type;
	if (hxgep->intr_type == POLLING_TYPE)
	{
		HXGE_DBG(hxgep, "hxge_setup_interrupt: intr_type = polling, do nothing");
		return 0;
	}


        /* Determine the number of logical device groups needed */
        memset(ldv_arr, 0xff, sizeof(ldv_arr));
        num_ints_required = get_num_ldgs(hxgep, ldv_arr);

#ifdef CONFIG_PCI_MSI
        switch (intr_type) {
                case MSIX_TYPE :
                        hxgep->intr_type = MSIX_TYPE;
                        msix_ent = kzalloc( num_ints_required *
                                sizeof(struct msix_entry), GFP_KERNEL);
                        if (!msix_ent) {
                                HXGE_ERR(hxgep, "hxge_setup_interrupt: Could not allocate msix entries");
                                return -1;
                        }
                        hxgep->msix = msix_ent;
                        for (i = 0, ptr = msix_ent; i < num_ints_required; i++,ptr++)
                        	ptr->entry = i;

                        /* Keep trying till we get available vectors */
                        num_ints_available = num_ints_required;
                        while ((status = pci_enable_msix(hxgep->pdev, msix_ent,
                                        num_ints_available)) > 0)
			{
                                num_ints_available = status;
				HXGE_ERR(hxgep, "pci_enable_msix: status=%d",status);
			}

                        if (status < 0) {
                                HXGE_ERR(hxgep, "hxge_setup_interrupt: pci_enable_msix failed, status=%d",status);
                                kfree(msix_ent);
				hxgep->msix = NULL;
                                return -1;
                        }
			HXGE_DBG(hxgep, "hxge_setup_interrupt: Interrupt type is MSIX_TYPE; %d interrupts available", num_ints_available);
                        break;
                case MSI_TYPE :
                        num_ints_available = 1;
                        if (!pci_enable_msi(hxgep->pdev)) {
                                hxgep->intr_type = MSI_TYPE;
				HXGE_DBG(hxgep, "hxge_setup_interrupt: Interrupt type is MSI");
                                break;
                        }
                        /* fall through; reverting to INTx */
                        HXGE_DBG(hxgep, "hxge_setup_interrupt: No MSI, using INTx");
                case INTx_TYPE :
                        num_ints_available = 1;
                        hxgep->intr_type = INTx_TYPE;
                        break;
                default :
                        HXGE_ERR(hxgep, "hxge_setup_interrupt: Bad type");
                        return -1;
        }

#else
        num_ints_available = 1;
        hxgep->intr_type = INTx_TYPE;
#endif

	if (num_ints_available < 1) {
		HXGE_ERR(hxgep, "num_ints_available should be atleast 1");
		return -1;
	}
		


        /* Initialize Hydra interrupt data structures */
        status = hxge_ldg_init(hxgep, num_ints_required, num_ints_available,
                                ldv_arr);
        if (status) {
                HXGE_ERR(hxgep, "hxge_setup_interrupt: hxge_ldv_interrupt_init failed");
#ifdef CONFIG_PCI_MSI
		if (msix_ent) /* implies MSIX_TYPE */
                	kfree(msix_ent);
#endif
                return -1;
        }

        /* Request for IRQs (in the case of msix, for each vector assigned) */
        if (hxge_request_irqs(netdev)) {
                HXGE_ERR(hxgep, "hxge_setup_interrupt: request_irq failed");
                hxge_teardown_interrupt(hxgep);
                return -1;
        }

        /* Enable the hardware interrupt registers. Setup the LDG and LDV
           registers for the respective blocks */
        if (hxge_set_hw_interrupt_regs(hxgep)) {
                HXGE_ERR(hxgep, "hxge_setup_interrupt: hxge_set_hw_interrupt failed");
                hxge_teardown_interrupt(hxgep);
                return -1;
        }

        return 0;
}
	
