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


#include "hpi/hpi_vmac.h"
#include "hxge_vmac.h"
#include "hxge.h"


int hxge_vmac_init(struct hxge_adapter * hxgep);
int hxge_tx_vmac_init(struct hxge_adapter * hxgep);
int hxge_rx_vmac_init(struct hxge_adapter * hxgep);
int hxge_tx_vmac_enable(struct hxge_adapter * hxgep);
int hxge_tx_vmac_disable(struct hxge_adapter * hxgep);
int hxge_rx_vmac_enable(struct hxge_adapter * hxgep);
int hxge_rx_vmac_disable(struct hxge_adapter * hxgep);
int hxge_tx_vmac_reset(struct hxge_adapter * hxgep);
int hxge_rx_vmac_reset(struct hxge_adapter * hxgep);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
irqreturn_t hxge_vmac_intr(int irq, void *data, struct pt_regs *regs);
#else
irqreturn_t hxge_vmac_intr(int irq, void *data);
#endif

int hxge_set_promisc(struct hxge_adapter * hxgep, boolean_t on);

extern int hxge_get_option (const char *option_name, int *value);


int
hxge_vmac_init(struct hxge_adapter * hxgep)
{
	if (hxge_tx_vmac_reset(hxgep))
		goto fail;

	if (hxge_rx_vmac_reset(hxgep))
		goto fail;


	if (hxge_tx_vmac_enable(hxgep))
		goto fail;

	if (hxge_rx_vmac_enable(hxgep))
		goto fail;

	return 0;
fail:
  	HXGE_ERR(hxgep, "hxge_vmac_init failed");	
	return -1;
}


int 
hxge_vmac_uninit(struct hxge_adapter * hxgep)
{
	if (hxge_tx_vmac_disable(hxgep))
		goto fail;

	if (hxge_rx_vmac_disable(hxgep))
		goto fail;

	return 0;
fail:
	HXGE_ERR(hxgep, "hxge_vmac_uninit failed");
	return -1;
}



/* Initialize the TxVMAC sub-block */

int
hxge_tx_vmac_init(struct hxge_adapter * hxgep)
{
	int		rs;
	uint64_t	config;
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	struct net_device *netdev = hxgep->netdev;


	/* When setting the size of the Tx, one must account for the
           CRC and the internal header of 16 bytes. There are no pad bytes
           in the internal header because we guarantee internal header is 
           16-byte aligned and so, payload that follows has the right 2-byte
           alignment as well */

	hxgep->vmac.maxframesize = netdev->mtu + ETH_HLEN + VLAN_HLEN + 
					CRC_LENGTH + TX_PKT_HEADER_SIZE;
	hxgep->vmac.minframesize = MINIMUM_ETHERNET_FRAME_SIZE;

	/* CFG_VMAC_TX_EN is done separately */
	config = CFG_VMAC_TX_CRC_INSERT | CFG_VMAC_TX_PAD;

	if ((rs = hpi_vmac_tx_config(handle, INIT, config,
	    		hxgep->vmac.maxframesize)) != HPI_SUCCESS) 
	{
		HXGE_ERR(hxgep, "hxge_tx_vmac_init: hpi_vmac_tx_config failed");
		return  -1;
	}

	hxgep->vmac.tx_config = config;

	if (hxgep->vmac.is_jumbo == TRUE) {
		HXGE_DBG(hxgep, "hxge_tx_vmac_init: Jumbo enabled, MTU %d", hxgep->vmac.maxframesize);
	} else {
		HXGE_DBG(hxgep, "hxge_tx_vmac_init: Jumbo disabled, MTU %d",hxgep->vmac.maxframesize);
	}

	return  0;
}

/* Initialize the RxVMAC sub-block */

int
hxge_rx_vmac_init(struct hxge_adapter * hxgep)
{
	int		rs;
	uint64_t	xconfig;
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	int 		stripcrc;
	int 		promisc;
	struct net_device *netdev = hxgep->netdev;


	hxgep->vmac.rx_max_framesize = netdev->mtu + ETH_HLEN + VLAN_HLEN +
						CRC_LENGTH;

	/* CFG_VMAC_RX_EN is done separately */
	xconfig = CFG_VMAC_RX_PASS_FLOW_CTRL_FR;
	hxge_get_option("strip_crc", &stripcrc);
	if (stripcrc)
		xconfig |= CFG_VMAC_RX_STRIP_CRC;

	if (hxge_get_option("promiscuous",&promisc) < 0) {
		HXGE_ERR(hxgep, "hxge_rx_vmac_init: promiscuous invalid");
		return -1;
	}

	if (promisc || (netdev->flags & IFF_PROMISC))  {
		HXGE_DBG(hxgep, "hxge_rx_vmac_init: Set to promiscuous mode");
		xconfig |=  CFG_VMAC_RX_PROMISCUOUS_MODE;
	}

	if ((rs = hpi_vmac_rx_config(handle, INIT, xconfig, hxgep->vmac.rx_max_framesize))
	    != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hxge_rx_vmac_init: hpi_vmac_rx_config failed");
		return  -1;
	}

	hxgep->vmac.rx_config = xconfig;

	return  0;
}
 
int 
hxge_vmac_rx_set_framesize(struct hxge_adapter *hxgep, uint16_t frame_size)
{
	if (hpi_vmac_rx_set_framesize(hxgep->hw.hw_addr, frame_size) !=
			HPI_SUCCESS)
			return -1;
	return 0;
}

int
hxge_vmac_promisc(struct hxge_adapter *hxgep, int enable)
{
       uint64_t        xconfig;
       hpi_handle_t    handle = hxgep->hw.hw_addr;
       config_op_t     cmd = DISABLE;

       xconfig = CFG_VMAC_RX_PROMISCUOUS_MODE;
       if (enable)
               cmd = ENABLE;

       if (hpi_vmac_rx_config(handle, cmd, xconfig, 0) != HPI_SUCCESS) {
               HXGE_ERR(hxgep, "hxge_vmac_promisc: hpi_vmac_rx_config failed");
               return -1;
       }

       return 0;
}


/* Enable TxVMAC */

int
hxge_tx_vmac_enable(struct hxge_adapter * hxgep)
{
	hpi_status_t	rv;
	int	status = 0;
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	int enable;


	rv = hxge_tx_vmac_init(hxgep);
	if (rv != 0)
		return (rv);

	rv = hpi_vmac_tx_config(handle, ENABLE, CFG_VMAC_TX_EN, 0);
	if (rv == HPI_SUCCESS) {
		if (hxge_get_option("enable_vmac_ints", &enable))
			return -1;
		rv = hpi_vmac_tx_ints(handle, enable);
	}

	status = (rv == HPI_SUCCESS) ? 0: -1;

	

	return (status);
}

/* Disable TxVMAC */

int
hxge_tx_vmac_disable(struct hxge_adapter * hxgep)
{
	hpi_status_t	rv;
	int	status = 0;
	hpi_handle_t	handle = hxgep->hw.hw_addr;


	rv = hpi_vmac_tx_config(handle, DISABLE, CFG_VMAC_TX_EN, 0);

	status = (rv == HPI_SUCCESS) ? 0 : -1;


	return (status);
}

/* Enable RxVMAC */

int
hxge_rx_vmac_enable(struct hxge_adapter * hxgep)
{
	hpi_status_t	rv;
	int	status = 0;
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	int enable;


	rv = hxge_rx_vmac_init(hxgep);
	if (rv != 0)
		return (rv);

	rv = hpi_vmac_rx_config(handle, ENABLE, CFG_VMAC_RX_EN, 0);
	if (rv == HPI_SUCCESS) {
		if (hxge_get_option("enable_vmac_ints", &enable))
			return -1;
		rv = hpi_vmac_rx_ints(handle, enable);
	}

	status = (rv == HPI_SUCCESS) ? 0 : -1;


	return (status);
}

/* Disable RxVMAC */

int
hxge_rx_vmac_disable(struct hxge_adapter * hxgep)
{
	hpi_status_t	rv;
	int	status = 0;
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	uint64_t	xconfig;

	xconfig = CFG_VMAC_RX_EN;
	rv = hpi_vmac_rx_config(handle, DISABLE, xconfig, 0);

	status = (rv == HPI_SUCCESS) ? 0 : -1;


	return (status);
}

/* Reset TxVMAC */

int
hxge_tx_vmac_reset(struct hxge_adapter * hxgep)
{
	hpi_handle_t	handle = hxgep->hw.hw_addr;

	hpi_tx_vmac_reset(handle);
	hpi_tx_vmac_clear_regs(handle);

	return  0;
}

/* Reset RxVMAC */

int
hxge_rx_vmac_reset(struct hxge_adapter * hxgep)
{
	hpi_handle_t	handle = hxgep->hw.hw_addr;

	hpi_rx_vmac_reset(handle);
	hpi_rx_vmac_clear_regs(handle);

	return  0;
}

/*ARGSUSED*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
irqreturn_t 
hxge_vmac_intr(int irq, void *data, struct pt_regs *regs)
#else
irqreturn_t 
hxge_vmac_intr(int irq, void *data)
#endif
{
	struct hxge_ldv *ldvp = (struct hxge_ldv *)data;
	struct hxge_ldg *ldgp = ldvp->ldgp;
	struct hxge_adapter * hxgep = ldgp->hxgep;
	hpi_handle_t handle = hxgep->hw.hw_addr;
	p_hxge_stats_t statsp;

	vmac_tx_stat_t		tx_stat;
	vmac_rx_stat_t		rx_stat;
	vmac_tx_frame_cnt_t	tx_frame_cnt;
	vmac_tx_byte_cnt_t	tx_byte_cnt;
	vmac_rx_frame_cnt_t	rx_frame_cnt;
	vmac_rx_byte_cnt_t	rx_byte_cnt;
	vmac_rx_drop_fr_cnt_t	rx_drop_fr_cnt;
	vmac_rx_drop_byte_cnt_t	rx_drop_byte_cnt;
	vmac_rx_crc_cnt_t	rx_crc_cnt;
	vmac_rx_pause_cnt_t	rx_pause_cnt;
	vmac_rx_bcast_fr_cnt_t	rx_bcast_fr_cnt;
	vmac_rx_mcast_fr_cnt_t	rx_mcast_fr_cnt;

	int got_ldf0, got_ldf1;

	get_ldf_flags(ldvp, &got_ldf0, &got_ldf1);
	if (!got_ldf0 && !got_ldf1)
		return IRQ_NONE;


	/*
	 * This interrupt handler is for a specific mac port.
	 */
	statsp = (p_hxge_stats_t)hxgep->statsp;

	HXGE_REG_RD64(handle, VMAC_TX_STAT, &tx_stat.value);
	HXGE_REG_RD64(handle, VMAC_TX_FRAME_CNT, &tx_frame_cnt.value);
	HXGE_REG_RD64(handle, VMAC_TX_BYTE_CNT, &tx_byte_cnt.value);

	HXGE_REG_RD64(handle, VMAC_RX_STAT, &rx_stat.value);
	HXGE_REG_RD64(handle, VMAC_RX_FRAME_CNT, &rx_frame_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_BYTE_CNT, &rx_byte_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_DROP_FR_CNT, &rx_drop_fr_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_DROP_BYTE_CNT, &rx_drop_byte_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_CRC_CNT, &rx_crc_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_PAUSE_CNT, &rx_pause_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_BCAST_FR_CNT, &rx_bcast_fr_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_MCAST_FR_CNT, &rx_mcast_fr_cnt.value);

	if (tx_stat.bits.tx_byte_cnt_overflow)
		statsp->vmac_stats.tx_byte_cnt_overflow++;
	if (tx_stat.bits.tx_frame_cnt_overflow)
		statsp->vmac_stats.tx_frame_cnt_overflow++;
	if (tx_stat.bits.frame_tx)
		statsp->vmac_stats.frame_tx++;

	if (rx_stat.bits.bcast_cnt_overflow)
		statsp->vmac_stats.bcast_cnt_overflow++;
	if (rx_stat.bits.mcast_cnt_overflow)
		statsp->vmac_stats.mcast_cnt_overflow++;
	if (rx_stat.bits.pause_cnt_overflow)
		statsp->vmac_stats.pause_cnt_overflow++;
	if (rx_stat.bits.crc_err_cnt_overflow)
		statsp->vmac_stats.crc_err_cnt_overflow++;
	if (rx_stat.bits.rx_drop_byte_cnt_overflow)
		statsp->vmac_stats.rx_drop_byte_cnt_overflow++;
	if (rx_stat.bits.rx_drop_frame_cnt_overflow)
		statsp->vmac_stats.rx_drop_frame_cnt_overflow++;
	if (rx_stat.bits.rx_byte_cnt_overflow)
		statsp->vmac_stats.rx_byte_cnt_overflow++;
	if (rx_stat.bits.rx_frame_cnt_overflow)
		statsp->vmac_stats.rx_frame_cnt_overflow++;
	if (rx_stat.bits.frame_rx)
		statsp->vmac_stats.frame_rx++;

	statsp->vmac_stats.tx_frame_cnt += tx_frame_cnt.bits.tx_frame_cnt;
	statsp->vmac_stats.tx_byte_cnt += tx_byte_cnt.bits.tx_byte_cnt;

	statsp->vmac_stats.rx_frame_cnt += rx_frame_cnt.bits.rx_frame_cnt;
	statsp->vmac_stats.rx_byte_cnt += rx_byte_cnt.bits.rx_byte_cnt;
	statsp->vmac_stats.rx_drop_frame_cnt +=
	    rx_drop_fr_cnt.bits.rx_drop_frame_cnt;
	statsp->vmac_stats.rx_drop_byte_cnt +=
	    rx_drop_byte_cnt.bits.rx_drop_byte_cnt;
	statsp->vmac_stats.rx_crc_cnt += rx_crc_cnt.bits.rx_crc_cnt;
	statsp->vmac_stats.rx_pause_cnt += rx_pause_cnt.bits.rx_pause_cnt;
	statsp->vmac_stats.rx_bcast_fr_cnt +=
	    rx_bcast_fr_cnt.bits.rx_bcast_fr_cnt;
	statsp->vmac_stats.rx_mcast_fr_cnt +=
	    rx_mcast_fr_cnt.bits.rx_mcast_fr_cnt;

	return IRQ_HANDLED;
}

/*
 * Set promiscous mode
 */

int
hxge_set_promisc(struct hxge_adapter * hxgep, boolean_t on)
{
	int status = 0;

	spin_lock(&hxgep->lock);	
	if ((status = hxge_rx_vmac_disable(hxgep)) != 0)
		goto fail;
	if ((status = hxge_rx_vmac_enable(hxgep)) != 0)
		goto fail;

	if (on)
		hxgep->vmac.promisc = TRUE;
	else
		hxgep->vmac.promisc = FALSE;

fail:
	spin_unlock(&hxgep->lock);

	return (status);
}


/*
 * Set in loopback mode
 */

int
hxge_set_loopback(struct hxge_adapter *hxgep, boolean_t enable)
{
	hpi_handle_t handle = hxgep->hw.hw_addr;
	config_op_t  cmd;

	spin_lock(&hxgep->lock);


	if (enable) 
		cmd = ENABLE;
	else
		cmd = DISABLE;

	if (hpi_vmac_rx_config(handle, CFG_VMAC_RX_LOOP_BACK, cmd, 0) != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hxge_set_loopback: hpi_vmac_rx_config failed");
		return -1;
	}

	hxgep->vmac.loopback = enable;
	spin_unlock(&hxgep->lock);

	return 0;
}
