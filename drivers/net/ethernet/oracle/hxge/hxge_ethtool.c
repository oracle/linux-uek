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
#include "hpi/hpi_txdma.h"
#include "hpi/hpi_rxdma.h"
#include "hxge.h"

/************************************************************************
* How to add new diagnostic (loopback) tests 
*
*
*   1. Add a new entry to the loopback_params array with new test parameters.
*   2. Add a corresponding new entry to hxge_gstrings_test array indicating 
*      a default of "NOTRUN"
*
*   Currently, the test will bail after the first failure. Also, the hydra
*   should be in loopback mode. I have been testing with the loopback module
*   plugged into the port. If there is no loopback module, then configure the 
*   VMAC RX in loopback mode
*
*************************************************************************/
	


extern const char hxge_driver_version[];
extern int hxge_reset_tx_channel(struct hxge_adapter *hxgep, int i);
extern int hxge_reset_rx_channel(struct hxge_adapter *hxgep, int i);
extern hpi_status_t hpi_txdma_desc_mem_get(hpi_handle_t handle, uint16_t index,
       	p_tx_desc_t desc_p);
extern hpi_status_t hpi_vmac_rx_config(hpi_handle_t handle, config_op_t op, 
	uint64_t config, uint16_t max_frame_length);
extern hpi_status_t hpi_txdma_desc_kick_reg_set(hpi_handle_t handle, 
	uint8_t channel, uint16_t tail_index, boolean_t wrap);
extern hpi_status_t hpi_rxdma_cfg_rdc_reset(hpi_handle_t handle, uint8_t rdc);
extern hpi_status_t hpi_txdma_channel_reset(hpi_handle_t handle, 
	uint8_t channel);
extern int hxge_process_packets(struct hxge_adapter *hxgep,
#ifdef CONFIG_HXGE_NAPI
						int work_to_do,
#endif
					int channel, struct sk_buff **skb);
#define PATT_LEN 8
uint8_t pattern[PATT_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xDE, 0xAD, 0xBE, 0xEF};

extern int hxge_alloc_tx(struct hxge_adapter *hxgep);
extern int hxge_alloc_rx(struct hxge_adapter *hxgep);
extern void hxge_enable_adapter(struct hxge_adapter *hxgep);
extern void hxge_disable_adapter(struct hxge_adapter *hxgep);
extern int hxge_free_tx(struct hxge_adapter *hxgep);
extern int hxge_free_rx(struct hxge_adapter *hxgep);
extern int hxge_set_option(const char *parm, int val);
extern int hxge_block_reset(struct hxge_adapter *hxgep, int device);
extern int hxge_start_xmit(struct sk_buff *skb, struct net_device *netdev);
extern int hxge_setup_interrupt(struct net_device *netdev);
extern int hxge_teardown_interrupt(struct hxge_adapter *hxgep);
extern int hxge_peu_get_link_status(struct hxge_adapter *hxgep);


typedef struct hxge_loopback_params {
	int intr_type;   /* interrupt type - INTx, MSI, MSIX, polling */
	int pkt_len; /* packet size in bytes */
	int num_pkts;    /* # of pkts to send */
	int tx_channels; /* # of tx channels */
	int rx_channels; /* # of rx channels */
	int tx_descs;    /* # of tx descriptors */
	int rcr_entries; /* # of RCR entries */
	int rbr_entries; /* # of RBR entries */
	int rcr_threshold;
	int rcr_timeout;
	int bad_len;     /* force a bad pkt_hdr formation */
} loopback_params_t;
	

loopback_params_t loopback_params[] = 
{ 
        /* 1 Packet sent from 1 channel */
       {
         INTx_TYPE,
         64,
         32,
         1,
         1,
         HXGE_TX_DESCS_MIN,
         HXGE_RCR_MIN,
         HXGE_RBR_RBB_MIN,
         1,
         0,
         1,
        },
       /* 1 Packet sent from 1 channel, using INTx */
       {
         INTx_TYPE,
         64,
         32,
         1,
         1,
         HXGE_TX_DESCS_MIN,
         HXGE_RCR_MIN,
         HXGE_RBR_RBB_MIN,
         1,
         0,
         1
       },
       /* 1 Packet sent from 1 channel, threshold but no timeout. Sending
 	* 2 packets because 1 packet with threshold does not work */
       {
         INTx_TYPE,
         64,
         2,
         1,
         1,
         HXGE_TX_DESCS_MIN,
         HXGE_RCR_MIN,
         HXGE_RBR_RBB_MIN,
         1,
         0,
         0
       },
	/* 1024-byte packet */
       { 
         INTx_TYPE, 
         1024, 
         2, 
         1, 
         1, 
         HXGE_TX_DESCS_MIN,
         HXGE_RCR_MIN,
         HXGE_RBR_RBB_MIN,
         1,
         0,
	 0
       },
        /* 1 Packet sent from 1 channel */
       { 
         POLLING_TYPE,
         64, 
         2, 
         1,
         1,
         HXGE_TX_DESCS_MIN,
         HXGE_RCR_MIN, 
         HXGE_RBR_RBB_MIN,
         1,
         0,
         0
        },
       /* 2 Tx channels, 2 Tx channels, 1 packet each */
       { POLLING_TYPE, 
         64, 
         1, 
         2,
         2,
         HXGE_TX_DESCS_MIN,
         HXGE_RCR_MIN, 
         HXGE_RBR_RBB_MIN,
         1,
         0,
         0
        },
       /* 1 Tx channel, Tx descriptor number of packets */
       { POLLING_TYPE,
         64,
         -1,
         1,
         1,
         HXGE_TX_DESCS_MIN,
         HXGE_RCR_MIN,
         HXGE_RBR_RBB_MIN,
         1,
         0,
         0
        },
};

#define HXGE_TEST_LEN sizeof(hxge_gstrings_test) / ETH_GSTRING_LEN

static char hxge_gstrings_test[][ETH_GSTRING_LEN] = {
        "Loopback Test 1 = NOTRUN", 
        "Loopback Test 2 = NOTRUN", 
        "Loopback Test 3 = NOTRUN", 
        "Loopback Test 4 = NOTRUN", 
        "Loopback Test 5 = NOTRUN", 
        "Loopback Test 6 = NOTRUN", 
        "Loopback Test 7 = NOTRUN", 
};

struct hxge_stats_struct {
	char name[ETH_GSTRING_LEN];
	uint64_t offset;
};

#define STAT_OFFSET(name) offsetof(hxge_stats_t, name)
#define RX_STAT_OFFSET(name) offsetof(struct rx_ring_stats_t, name)

static struct hxge_stats_struct hxge_rdc_stats[] = {
	{"Rx Channel #", 0},
	{"  Rx Packets", RX_STAT_OFFSET(ipackets)},
	{"  Rx Bytes", RX_STAT_OFFSET(ibytes)},
	{"  Rx Errors", RX_STAT_OFFSET(ierrors)},
	{"  Jumbo Packets", RX_STAT_OFFSET(jumbo_pkts)},
	{"  ECC Errors", RX_STAT_OFFSET(ecc_errors)},
	{"  RBR Completion Timeout", RX_STAT_OFFSET(rbr_cpl_tmout)},
	{"  PEU Response Error", RX_STAT_OFFSET(peu_resp_err)},
	{"  RCR Shadow Parity", RX_STAT_OFFSET(rcr_shadow_parity)},
	{"  RCR Prefetch Parity", RX_STAT_OFFSET(rcr_prefetch_parity)},
	{"  RCR Shadow Full", RX_STAT_OFFSET(rcr_shadow_full)},
	{"  RCR Full", RX_STAT_OFFSET(rcr_full)},
	{"  RBR Empty", RX_STAT_OFFSET(rbr_empty)},
        {"  RBR Empty Handled", RX_STAT_OFFSET(rbr_empty_handled)},
        {"  RBR Empty Buffers Posted", RX_STAT_OFFSET(rbr_empty_posted)},
	{"  RBR Full", RX_STAT_OFFSET(rbr_full)},
	{"  RCR Timeouts", RX_STAT_OFFSET(rcr_to)},
	{"  RCR Thresholds", RX_STAT_OFFSET(rcr_thres)},
	{"  Packet Too Long Errors", RX_STAT_OFFSET(pkt_too_long)},
	{"  No RBR available", RX_STAT_OFFSET(no_rbr_avail)},
	{"  No Memory Drops", RX_STAT_OFFSET(nomem_drop)},
	{"  RVM Errors", RX_STAT_OFFSET(rvm_errors)},
	{"  Frame Errors", RX_STAT_OFFSET(frame_errors)},
	{"  RAM Errors", RX_STAT_OFFSET(ram_errors)},
	{"  CRC Errors", RX_STAT_OFFSET(crc_errors)}
};
#define HXGE_RDC_STATS_CNT (sizeof(hxge_rdc_stats)/sizeof(struct hxge_stats_struct))


#define TX_STAT_OFFSET(name) offsetof(struct tx_ring_stats_t, name)
static struct hxge_stats_struct hxge_tdc_stats[] = {
	{"Tx Channel #", 0},
	{"  Tx Packets", TX_STAT_OFFSET(opackets)},
	{"  Tx Bytes", TX_STAT_OFFSET(obytes)},
	{"  Tx Errors", TX_STAT_OFFSET(oerrors)},
	{"  Tx Desc Used [0]", TX_STAT_OFFSET(descs_used[0])},
	{"  Tx Desc Used [1]", TX_STAT_OFFSET(descs_used[1])},
	{"  Tx Desc Used [2]", TX_STAT_OFFSET(descs_used[2])},
	{"  Tx Desc Used [3]", TX_STAT_OFFSET(descs_used[3])},
	{"  Tx Desc Used [4]", TX_STAT_OFFSET(descs_used[4])},
	{"  Tx Desc Used [5]", TX_STAT_OFFSET(descs_used[5])},
	{"  Tx Desc Used [6]", TX_STAT_OFFSET(descs_used[6])},
	{"  Tx Desc Used [7]", TX_STAT_OFFSET(descs_used[7])},
	{"  Tx Desc Used [8]", TX_STAT_OFFSET(descs_used[8])},
	{"  Tx Desc Used [9]", TX_STAT_OFFSET(descs_used[9])},
	{"  Tx Desc Used [10]", TX_STAT_OFFSET(descs_used[10])},
	{"  Tx Desc Used [11]", TX_STAT_OFFSET(descs_used[11])},
	{"  Tx Desc Used [12]", TX_STAT_OFFSET(descs_used[12])},
	{"  Tx Desc Used [13]", TX_STAT_OFFSET(descs_used[13])},
	{"  Tx Desc Used [14]", TX_STAT_OFFSET(descs_used[14])},
	{"  Tx Desc Used [15]", TX_STAT_OFFSET(descs_used[15])},
        {"  Tx Lock Failed", TX_STAT_OFFSET(txlock_acquire_failed)},
	{"  Marked Ints", TX_STAT_OFFSET(marked)},
	{"  PEU Response Error Ints", TX_STAT_OFFSET(peu_resp_err)},
	{"  Packet Hdr Size Err Ints", TX_STAT_OFFSET(pkt_size_hdr_err)},
	{"  Runt Packet Drop Ints", TX_STAT_OFFSET(runt_pkt_drop_err)},
	{"  Ring Overflow Ints", TX_STAT_OFFSET(tx_rng_oflow)},
	{"  Prefetch Parity Error Ints", TX_STAT_OFFSET(pref_par_err)},
	{"  Prefetch Compl Timeout Ints", TX_STAT_OFFSET(tdr_pref_cpl_to)},
	{"  Packet Completion Timeout Ints", TX_STAT_OFFSET(pkt_cpl_to)},
	{"  Invalid SOP Ints", TX_STAT_OFFSET(invalid_sop)},
	{"  Unexpected SOP Ints", TX_STAT_OFFSET(unexpected_sop)},
	{"  Header Error Count", TX_STAT_OFFSET(hdr_error_cnt)},
	{"  Abort Count", TX_STAT_OFFSET(abort_cnt)},
	{"  Runt Count", TX_STAT_OFFSET(runt_cnt)},
	{"  Descriptors Available", TX_STAT_OFFSET(descs_avail)}
};
#define HXGE_TDC_STATS_CNT (sizeof(hxge_tdc_stats)/sizeof(struct hxge_stats_struct))

#define PFC_STAT_OFFSET(name) offsetof(hxge_pfc_stats_t, name)
static struct hxge_stats_struct hxge_pfc_stats[] = {
	{"PFC ", 0},
	{"  Packets dropped", PFC_STAT_OFFSET(pkt_drop)},
	{"  TCAM Parity Errors", PFC_STAT_OFFSET(tcam_parity_err)},
	{"  VLAN Parity Errors", PFC_STAT_OFFSET(tcam_parity_err)},
	{"  Bad TCP/UDP Checksum Count ", PFC_STAT_OFFSET(bad_cs_count)},
	{"  Drop Counter ", PFC_STAT_OFFSET(drop_count)},
	{"  TCP Control Drop Cnt", PFC_STAT_OFFSET(errlog.tcp_ctrl_drop)},
	{"  L2 Addr Drop Cnt", PFC_STAT_OFFSET(errlog.l2_addr_drop)},
	{"  Class Code Drop Cnt", PFC_STAT_OFFSET(errlog.class_code_drop)},
	{"  TCAM Drop Cnt", PFC_STAT_OFFSET(errlog.tcam_drop)},
	{"  VLAN Drop Cnt", PFC_STAT_OFFSET(errlog.vlan_drop)},
	{"  VLAN Parity Error Address", PFC_STAT_OFFSET(errlog.vlan_par_err_log)},
	{"  TCAM Parity Error Address", PFC_STAT_OFFSET(errlog.tcam_par_err_log)},
};
#define HXGE_PFC_STATS_CNT (sizeof(hxge_pfc_stats)/sizeof(struct hxge_stats_struct))


#define VMAC_STAT_OFFSET(name) offsetof(hxge_vmac_stats_t, name)
static struct hxge_stats_struct hxge_vmac_stats[] = {
	{"VMAC", 0},
	{"  Tx Byte Cnt Overflow Ints", VMAC_STAT_OFFSET(tx_byte_cnt_overflow)},
	{"  Tx Frame Count Overflow Ints", VMAC_STAT_OFFSET(tx_frame_cnt_overflow)},
	{"  Tx Frame Ints", VMAC_STAT_OFFSET(frame_tx)},
	{"  Broadcast Cnt Overflowed", VMAC_STAT_OFFSET(bcast_cnt_overflow)},
	{"  Multicast Cnt Overflowed", VMAC_STAT_OFFSET(mcast_cnt_overflow)},
	{"  Pause Cnt Overflowed", VMAC_STAT_OFFSET(pause_cnt_overflow)},
	{"  CRC Error Cnt Overflowed", VMAC_STAT_OFFSET(pause_cnt_overflow)},
	{"  Rx Drop Byte Cnt Overflowed", VMAC_STAT_OFFSET(rx_drop_byte_cnt_overflow)},
	{"  Rx Drop Frame Cnt Overflowed", VMAC_STAT_OFFSET(rx_drop_frame_cnt_overflow)},
	{"  Rx Frame Ints ", VMAC_STAT_OFFSET(frame_rx)},
	{"  # Frames Transmitted", VMAC_STAT_OFFSET(tx_frame_cnt)},
	{"  # Bytes Transmitted", VMAC_STAT_OFFSET(tx_byte_cnt)},
	{"  # Frames Received", VMAC_STAT_OFFSET(rx_frame_cnt)},
	{"  # Bytes Received", VMAC_STAT_OFFSET(rx_byte_cnt)},
	{"  # Rx Frames Dropped", VMAC_STAT_OFFSET(rx_drop_frame_cnt)},
	{"  # Rx Bytes Dropped", VMAC_STAT_OFFSET(rx_drop_byte_cnt)},
	{"  # Rx CRC Error Frames", VMAC_STAT_OFFSET(rx_crc_cnt)},
	{"  # Rx Pause Frames", VMAC_STAT_OFFSET(rx_pause_cnt)},
	{"  # Rx Broadcast Frames", VMAC_STAT_OFFSET(rx_bcast_fr_cnt)},
	{"  # Rx Multicast Frames", VMAC_STAT_OFFSET(rx_mcast_fr_cnt)}
};
#define HXGE_VMAC_STATS_CNT (sizeof(hxge_vmac_stats)/sizeof(struct hxge_stats_struct))

wait_queue_head_t ethtool_evnt;
volatile int ethtool_cond = 0;
struct sk_buff *ethtool_skb;


static int 
hxge_get_settings(struct net_device *netdev, struct ethtool_cmd *cmd)
{
	cmd->supported	= SUPPORTED_FIBRE;
	cmd->advertising = ADVERTISED_FIBRE;
	cmd->port	= PORT_FIBRE;
	cmd->transceiver = XCVR_EXTERNAL;
	cmd->speed = SPEED_10000;
	cmd->duplex = DUPLEX_FULL;

	return 0;
}


static void
hxge_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *info)
{
	struct hxge_adapter *hxgep = netdev_priv(netdev);
	
	strncpy(info->driver, HXGE_DRIVER_NAME, strlen(HXGE_DRIVER_NAME));
	strncpy(info->version, hxge_driver_version, strlen(hxge_driver_version));
	strncpy(info->fw_version, "N/A", strlen("N/A"));
	strncpy(info->bus_info, pci_name(hxgep->pdev), strlen(pci_name(hxgep->pdev)));
	info->testinfo_len =  HXGE_TEST_LEN;
}


static struct sk_buff *create_lb_frame(loopback_params_t *p, int buffer_size)
{
	int i;
	struct sk_buff *skb;
	uint8_t *ptr;
	int pkt_len = p->pkt_len;

	skb = dev_alloc_skb(pkt_len);
	if (!skb) {
		HXGE_DBG_PRINT("Failed to allocate skb");
		return NULL;
	}

	/* Abusing the priority field for my own devious ends.. */
	skb->priority = p->bad_len;
	memset(skb_put(skb, pkt_len), 0xFF, pkt_len);

	ptr = skb->data;
	for (i = 0; i < PATT_LEN; i++)
		ptr[i] = pattern[i];

	return skb;
}

static int good_pkt(struct sk_buff *skb, int pkt_len)
{
	uint8_t *data = (uint8_t *)skb->data;
	int i;

	for (i = 0; i < PATT_LEN; i++)
		if (data[i] != pattern[i])
			return 0;

	while (i < pkt_len)
		if (data[i++] != 0xFF) {
			HXGE_DBG_PRINT("failed at byte %d",i);
			return 0;	
		}

	return 1;
}

static int hxge_send_lb_pkts(struct hxge_adapter *hxgep, 
			loopback_params_t *param)
{
	struct tx_ring_t *tx_ring;
	int i, j, buffer_size;
	int num_pkts_sent = 0;
	int pkts_to_send;
	struct sk_buff *skb;

	pkts_to_send = param->num_pkts;
	for (i = 0; i < hxgep->max_tdcs; i++)  {
		tx_ring = &hxgep->tx_ring[i];
		if (pkts_to_send <= 0)
			pkts_to_send = tx_ring->num_tdrs;	
		buffer_size = tx_ring->tx_buffer_size;
		for (j = 0; j < pkts_to_send; j++)  {
			skb = create_lb_frame(param, buffer_size);
			if (!skb) 
				return -1;
			hxge_start_xmit(skb, hxgep->netdev);
			num_pkts_sent++;
		}
	}
	HXGE_DBG(hxgep, "hxge_send_lb_pkts: %d Packets sent", num_pkts_sent);
	return num_pkts_sent;
		
}


/* Process packets that are received. Instead of sending them to the linux 
   network stack, hxge_process_packets link up the skb's and sends it to us.
   We free the skb's after validating the packet
*/
static int hxge_receive_and_validate_lb_pkts(struct hxge_adapter *hxgep,					loopback_params_t *param)
{
	int i;
	int pkts_rcvd, tot_pkts_rcvd = 0;
	struct sk_buff *ptr, *skb;
	int failed = 0;
	int pkts_freed=0;
	int retval;
	int mismatch = 0;


	/* If polling, then we have to explicity call the receive function
           to collect the packets. In interrupt case, we will get an event
	   signalling packets have arrived */

	if (param->intr_type != POLLING_TYPE) {
		HXGE_DBG(hxgep, "Waiting to receive packet..%d", ethtool_cond);
		retval = wait_event_interruptible_timeout(ethtool_evnt, 
					!ethtool_cond, 5000);
		if (!retval) {
			HXGE_DBG(hxgep, "Timeout out waiting for pkt");
		}
		else if (retval < 0) {
			HXGE_DBG(hxgep, "Got interrupted - failing");
		}
		else  {
			HXGE_DBG(hxgep, "Received all packet");
		}

		if (ethtool_cond)  {
			HXGE_DBG(hxgep, "Did not get all the pkts");
			failed = -1;
		}
	} else {
		for (i = 0; i < hxgep->max_rdcs; i++) {
			while ((pkts_rcvd = hxge_process_packets(hxgep,
#ifdef CONFIG_HXGE_NAPI
					param->tx_descs,
#endif
					i, &ethtool_skb)) > 0)
				tot_pkts_rcvd += pkts_rcvd;
			if (pkts_rcvd < 0) {
				HXGE_DBG(hxgep, "hxge_process_packets failed");
				return -1;
			}
			else if (!tot_pkts_rcvd)
			{
				HXGE_DBG(hxgep, "No packets received. Problem with sending?");
				return -1;
			}
			else 
				HXGE_DBG(hxgep, "%d packets received",tot_pkts_rcvd);
		}
	}

	skb = ethtool_skb;
	while (skb != NULL)  {
		if (!good_pkt(skb, param->pkt_len))
			mismatch = 1;
		ptr = skb;
		skb = skb->next;
		dev_kfree_skb_any(ptr);
		pkts_freed++;
	}

	HXGE_DBG(hxgep, "%d Packets Freed",pkts_freed);
	if (!param->bad_len && failed) {
		if (mismatch) {
			HXGE_DBG(hxgep, "Packet(s) did not match! Failing test");
		} else {
			HXGE_DBG(hxgep, "Receive failed");
		}
	} else if (param->bad_len)
		failed = 0;

	return failed;
}

static int hxge_setup_descs(struct hxge_adapter *hxgep, loopback_params_t *p)
{

	/* Allocate Tx and Rx descriptors */
	if (hxge_alloc_tx(hxgep)) {
		HXGE_DBG(hxgep, "hxge_setup_descs: Failed hxge_alloc_tx");
		return -1;
	}

	if (hxge_alloc_rx(hxgep)) {
		HXGE_DBG(hxgep, "hxge_setup_descs: Failed hxge_alloc_rx");
		return -1;
	}

	/* Setup interrupts if needed */
	if (hxge_setup_interrupt(hxgep->netdev)) {
		HXGE_DBG(hxgep, "hxge_setup_interrupt failed");
		return -1;
	}

	init_waitqueue_head(&ethtool_evnt);

	hxge_enable_adapter(hxgep);

	return 0;
}

int hxge_free_descs(struct hxge_adapter *hxgep, loopback_params_t *p)
{

	hxge_disable_adapter(hxgep);

	hxge_teardown_interrupt(hxgep);

	hxge_free_tx(hxgep);
	hxge_free_rx(hxgep);

	return 0;
}
		

static int hxge_run_loopback_test(struct hxge_adapter *hxgep, 
		loopback_params_t *param)
{
	int pkts_sent;

	ethtool_cond = param->num_pkts * param->tx_channels;
	ethtool_skb = NULL;	

	/* Setup the Tx descriptor packets */
	if ((pkts_sent = hxge_send_lb_pkts(hxgep, param)) <= 0) {
		HXGE_DBG(hxgep, "hxge_send_lb_pkts failed. Packets not sent.");
		return -1;
	}

	HXGE_DBG(hxgep, "Sleeping for 1 second  before processing RX...");
	msleep(1000); /* sleep for 2 ms before processing Rx */

	/* Receive the lb packets and validate them */
	if (hxge_receive_and_validate_lb_pkts(hxgep, param)) {
		HXGE_DBG(hxgep, "hxge_receive_and_validate_lb_pkts failed");
		return -1;
	}
		
	return 0;
}


/* Reset the adapter without involving any OS structures */
static void hxge_reset(struct hxge_adapter *hxgep)
{
	int i;
	hpi_handle_t handle = hxgep->hw.hw_addr;


	hxge_block_reset(hxgep, (LDV_RXDMA | LDV_TXDMA | LDV_VMAC));
	for ( i = 0; i < hxgep->max_rdcs; i++) 
		hpi_rxdma_cfg_rdc_reset(handle, i);
	for (i = 0; i < hxgep->max_tdcs; i++)
		hpi_txdma_channel_reset(handle, i);
	hpi_tx_vmac_reset(handle);
	hpi_rx_vmac_reset(handle);
}



int configure_driver_and_card(struct hxge_adapter *hxgep,
				loopback_params_t *param)
{
	uint64_t config = 0;
	hpi_handle_t handle = hxgep->hw.hw_addr;

        if ((hxge_set_option("intr_type", param->intr_type) < 0) ||
            (hxge_set_option("num_tx_descs", param->tx_descs) < 0) ||
            (hxge_set_option("tx_dma_channels", param->tx_channels) < 0) ||
            (hxge_set_option("rx_dma_channels", param->rx_channels) < 0) ||
            (hxge_set_option("rcr_entries", param->rcr_entries) < 0) ||
            (hxge_set_option("rbr_entries", param->rbr_entries) < 0) ||
	    (hxge_set_option("rcr_threshold", param->rcr_threshold) < 0) ||
            (hxge_set_option("rcr_timeout", param->rcr_timeout) < 0))
                return -1;

        hxge_reset(hxgep);

	/* Set up descriptors. Going to poll for Rx packets; no interrupts
           enabled here */
	if (hxge_setup_descs(hxgep,param)) {
		HXGE_DBG(hxgep, "configure_driver_and_card: Setting up descs failed");
		return -1;
	}

	/* Set the adapter in loopback mode now. Make sure that the STRIP_CRC
           is disabled due to a HW bug */
	 config = CFG_VMAC_RX_PROMISCUOUS_MODE | CFG_VMAC_RX_EN |
			CFG_VMAC_RX_PROMISCUOUS_GROUP | CFG_VMAC_RX_LOOP_BACK;
	if (hpi_vmac_rx_config(handle, INIT, config, 0) == HPI_FAILURE) {
		HXGE_DBG(hxgep, "configure_driver_and_card: Could not configure VMAC Rx");
		goto free_descs;
	}

       config = CFG_VMAC_TX_EN | CFG_VMAC_TX_CRC_INSERT;
       if (hpi_vmac_tx_config(handle, INIT, config, 0) == HPI_FAILURE) {
               HXGE_DBG(hxgep, "configure_driver_and_card: Could not configure VMAC Tx");
               goto free_descs;
       }

	return 0;

free_descs:
	hxge_free_descs(hxgep,param);
	return -1;
}

static int deconfigure_driver_and_card(struct hxge_adapter *hxgep,
			loopback_params_t *p)
{
	uint64_t config = 0;
	hpi_handle_t handle = hxgep->hw.hw_addr;

	flush_scheduled_work();

	config = 0;
	hpi_vmac_rx_config(handle, INIT, config, 0);

	hxge_free_descs(hxgep,p);

	return 0;
}

static int hxge_loopback_test(struct hxge_adapter *hxgep, loopback_params_t *p)
{
	int failed = 0;

	if (configure_driver_and_card(hxgep, p)) {
		HXGE_DBG(hxgep, "hxge_loopback_test: failed to configure device");			return -1;
	}

	if (hxge_run_loopback_test(hxgep, p)) {
		HXGE_DBG(hxgep, "hxge_loopback_test: Loopback Test failed");
		failed = -1;
	}

	deconfigure_driver_and_card(hxgep, p);

	return failed;
}

static void hxge_diag_test(struct net_device *netdev, 
		struct ethtool_test *eth_test, uint64_t *data)
{
	struct hxge_adapter *hxgep = netdev_priv(netdev);
	boolean_t if_running = netif_running(netdev);
	int link_up = hxge_peu_get_link_status(hxgep);
	int i;
	loopback_params_t *param;
	loopback_params_t orig_params;
	char *str;
	int num_tests;
			
	num_tests = sizeof(loopback_params)/sizeof(loopback_params_t);
	for (i = 0, param = loopback_params; i < num_tests; i++)
	{
		str = strstr(hxge_gstrings_test[i], "=");
		if (!str) {
			HXGE_ERR(hxgep, "Error in test strings construct");
			return;
		}
		str += 2; /* skip = and a space */
		strncpy(str, "NOTRUN", strlen("NOTRUN"));
	}

	for (i = 0; i < num_tests; i++) 
		data[i] = 0;

	/* These are offline tests */
	if (eth_test->flags == ETH_TEST_FL_OFFLINE) 
		HXGE_DBG(hxgep, "hxge_diag_test: Offline test starting");

	set_bit(HXGE_DEVICE_TESTING, &hxgep->state);

	/* Close the device before running this offline test */
	if (if_running) {
		HXGE_ERR(hxgep, "hxge_diag_test: Cannot run offline test on a running  interface. Bring interface down before attempting offline tests!");
		eth_test->flags |= ETH_TEST_FL_FAILED;
		return;
	}

	if (link_up) {
		HXGE_ERR(hxgep, "hxge_diag_test: Link should be down for offline tests");
		eth_test->flags |= ETH_TEST_FL_FAILED;
		return;
	}


	if ((hxge_get_option("intr_type", &orig_params.intr_type) < 0) ||
	    (hxge_get_option("num_tx_descs",&orig_params.tx_descs) < 0) ||
	    (hxge_get_option("tx_dma_channels", &orig_params.tx_channels) < 0) ||
	    (hxge_get_option("rx_dma_channels", &orig_params.rx_channels) < 0) ||
	    (hxge_get_option("rcr_entries", &orig_params.rcr_entries) < 0) ||
	    (hxge_get_option("rbr_entries", &orig_params.rbr_entries) < 0) ||
	    (hxge_get_option("rcr_threshold", &orig_params.rcr_threshold) < 0) ||
	    (hxge_get_option("rcr_timeout", &orig_params.rcr_timeout) < 0))
	{
		eth_test->flags |= ETH_TEST_FL_FAILED;
		return;
	}



	for (i = 0, param = loopback_params; i < num_tests; i++)
	{
		str = strstr(hxge_gstrings_test[i], "=");
		if (!str) {
			HXGE_ERR(hxgep, "Error in test strings construct");
			return;
		}
		str += 2; /* skip = and a space */
		HXGE_DBG(hxgep, "*** LOOPBACK TEST %d", i);
		if (hxge_loopback_test(hxgep, &param[i])) {
			eth_test->flags |= ETH_TEST_FL_FAILED;
			strncpy(str, "FAILED", strlen("FAILED"));
			break;
		}
		/* Replace FAILED with PASSED */
		strncpy(str, "PASSED", strlen("PASSED"));
		data[i] = 1;
	}

        /* restore parameters to original value */
        hxge_set_option("rbr_entries", orig_params.rbr_entries);
        hxge_set_option("rcr_entries", orig_params.rcr_entries);
        hxge_set_option("rx_dma_channels", orig_params.rx_channels);
        hxge_set_option("tx_dma_channels", orig_params.tx_channels);
        hxge_set_option("num_tx_descs", orig_params.tx_descs);
	hxge_set_option("intr_type", orig_params.intr_type);
	hxge_set_option("rcr_threshold", orig_params.rcr_threshold);
	hxge_set_option("rcr_timeout", orig_params.rcr_timeout);

	clear_bit(HXGE_DEVICE_TESTING, &hxgep->state);
}

static void
hxge_get_strings(struct net_device *netdev, uint32_t stringset, uint8_t *data)
{
	struct hxge_adapter *hxgep = netdev_priv(netdev);
	int i, j, offset = 0;

	switch (stringset) {
	case ETH_SS_TEST:
		memcpy(data, hxge_gstrings_test, 
			HXGE_TEST_LEN*ETH_GSTRING_LEN);
		break;
	case ETH_SS_STATS:
		for (i = 0; i < hxgep->max_rdcs; i++)
			for (j = 0; j < HXGE_RDC_STATS_CNT; j++)  {
				memcpy(&data[offset], 
				       hxge_rdc_stats[j].name, ETH_GSTRING_LEN);
				offset += ETH_GSTRING_LEN;
		}
		for (i = 0; i < hxgep->max_tdcs; i++)
			for (j = 0; j < HXGE_TDC_STATS_CNT; j++)  {
				memcpy(&data[offset], 
				       hxge_tdc_stats[j].name, ETH_GSTRING_LEN);
				offset += ETH_GSTRING_LEN;
		}
		for (j = 0; j < HXGE_PFC_STATS_CNT; j++) {
			memcpy(&data[offset], 
			       hxge_pfc_stats[j].name, ETH_GSTRING_LEN);
			offset += ETH_GSTRING_LEN;
		}
		for (j = 0; j < HXGE_VMAC_STATS_CNT; j++) {
			memcpy(&data[offset], 
			       hxge_vmac_stats[j].name, ETH_GSTRING_LEN);
			offset += ETH_GSTRING_LEN;
		}
		break;
	default: HXGE_DBG(hxgep, "hxge_get_strings: Unsupported type");
		 break;

	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
static int 
hxge_diag_test_count(struct net_device *netdev)
{
	return HXGE_TEST_LEN;
}

static int hxge_get_stats_count(struct net_device *netdev)
{
        struct hxge_adapter *hxgep = netdev_priv(netdev);
        int stats_count;

        stats_count = (hxgep->max_rdcs * HXGE_RDC_STATS_CNT);
        stats_count += (hxgep->max_tdcs * HXGE_TDC_STATS_CNT);
        stats_count += HXGE_PFC_STATS_CNT;
        stats_count += HXGE_VMAC_STATS_CNT;
        return (stats_count);
}
#else
static int hxge_get_sset_count(struct net_device *netdev, int sset)
{
        struct hxge_adapter *hxgep = netdev_priv(netdev);
	int stats_count;

	switch (sset) {
	case ETH_SS_TEST:
		return HXGE_TEST_LEN * ETH_GSTRING_LEN;
		break;
	case ETH_SS_STATS:
		stats_count = (hxgep->max_rdcs * HXGE_RDC_STATS_CNT);
		stats_count += (hxgep->max_tdcs * HXGE_TDC_STATS_CNT);
		stats_count += HXGE_PFC_STATS_CNT;
		stats_count += HXGE_VMAC_STATS_CNT;
		return (stats_count);
		break;
	default:
		HXGE_DBG(hxgep, "hxge_get_sset_count: Unsupported type");
		return -EOPNOTSUPP;
	}

}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 13)
static u32 hxge_get_tx_csum(struct net_device *netdev)
{
	struct hxge_adapter *hxgep = netdev_priv(netdev);
	return ((hxgep->flags & HXGE_TX_CHKSUM_ENABLED) != 0);
}

static int hxge_set_tx_csum (struct net_device *netdev, u32 data)
{
        struct hxge_adapter *hxgep = netdev_priv(netdev);
	int i;

        if (data) 
	{
		if (hxgep->flags & HXGE_TX_CHKSUM_ENABLED)
			return 0;

		hxgep->flags |= HXGE_TX_CHKSUM_ENABLED;
                netdev->features |= NETIF_F_IP_CSUM;
	} 
	else 
	{
		if (!(hxgep->flags & HXGE_TX_CHKSUM_ENABLED))
			return 0;
			
		hxgep->flags &= ~HXGE_TX_CHKSUM_ENABLED;
		/* Both chksum flags need to disabled for HW to be disabled */
		if (!(hxgep->flags & HXGE_CHKSUM_ENABLED))
                	netdev->features &= ~NETIF_F_IP_CSUM;
	}

	for (i = 0; i < hxgep->max_tdcs; i++)
        	hxge_reset_tx_channel(hxgep, i);
        return 0;
}

static u32 hxge_get_rx_csum(struct net_device *netdev)
{
        struct hxge_adapter *hxgep = netdev_priv(netdev);
	return ((hxgep->flags & HXGE_RX_CHKSUM_ENABLED) != 0);
}


static int hxge_set_rx_csum(struct net_device *netdev, u32 data)
{
        struct hxge_adapter *hxgep = netdev_priv(netdev);
	int i;

	if (data)
	{
		if (hxgep->flags & HXGE_RX_CHKSUM_ENABLED)
			return 0;

		hxgep->flags |= HXGE_RX_CHKSUM_ENABLED;
                netdev->features |= NETIF_F_IP_CSUM;
	}
	else 
	{
		if (!(hxgep->flags & HXGE_RX_CHKSUM_ENABLED))
			return 0;

		hxgep->flags &= ~HXGE_RX_CHKSUM_ENABLED;
		netdev->features &= ~NETIF_F_IP_CSUM;
	}

	for (i = 0; i < hxgep->max_rdcs; i++)
		hxge_reset_rx_channel(hxgep, i);

	return 0;
}
#endif

static void hxge_get_ethtool_stats(struct net_device *netdev, 
		struct ethtool_stats *stats, uint64_t *data)
{
        struct hxge_adapter *hxgep = netdev_priv(netdev);
	struct rx_ring_t *rx_ring;
	struct tx_ring_t *tx_ring;
	int i, j, offset = 0;
	uint32_t stat;
	p_hxge_stats_t	statsp = hxgep->statsp;
	p_hxge_pfc_stats_t pfc_statsp;
	p_hxge_vmac_stats_t vmac_statsp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
	int statssize = hxge_get_stats_count(netdev) * sizeof(uint64_t);
#else
	int statssize = hxge_get_sset_count(netdev, ETH_SS_STATS) * sizeof(uint64_t);
#endif
	/* None of the data structures are allocated yet; so, nothing to
	   show yet */
	if (!test_bit(HXGE_DEVICE_ALLOCATED, &hxgep->state)) {
		memset(data, 0, statssize);
		return;
	}

	for (i = 0; i < hxgep->max_rdcs;  i++) {
		rx_ring = &hxgep->rx_ring[i];
		data[offset++] = rx_ring->rdc;
		for (j = 1; j < HXGE_RDC_STATS_CNT; j++)
			data[offset++] = *(uint64_t *)((char *)&rx_ring->stats + hxge_rdc_stats[j].offset);
	}

	for (i = 0; i < hxgep->max_tdcs;  i++) {
		tx_ring = &hxgep->tx_ring[i];
		data[offset++] = tx_ring->tdc;
		for (j = 1; j < HXGE_TDC_STATS_CNT; j++)
			data[offset++] = *(uint64_t *)((char *)&tx_ring->stats + hxge_tdc_stats[j].offset);
	}

	pfc_statsp = &statsp->pfc_stats;
	data[offset++] = 0;
	for (j = 1; j < HXGE_PFC_STATS_CNT; j++) {
		stat = *(uint32_t *)((char *)pfc_statsp + hxge_pfc_stats[j].offset);
		data[offset++] = (uint64_t)stat;
	}

	vmac_statsp = &statsp->vmac_stats;
	data[offset++] = 0;
	for (j = 1; j < HXGE_VMAC_STATS_CNT; j++) 
		data[offset++]= *(uint64_t *)((char *)vmac_statsp + hxge_vmac_stats[j].offset);
}

static uint32_t hxge_get_msglevel(struct net_device *netdev)
{
	struct hxge_adapter *hxgep = netdev_priv(netdev);
	return (hxgep->msg_enable);
}

static void hxge_set_msglevel(struct net_device *netdev, uint32_t data)
{
	struct hxge_adapter *hxgep = netdev_priv(netdev);
	hxgep->msg_enable = data;
}

static int
hxge_get_coalesce_intr(struct net_device *dev,
                                           struct  ethtool_coalesce *intr_param)
{
        struct hxge_adapter *hxgep = netdev_priv(dev);

	/* 250MHz clock that is divided down by HXGE_RCR_CLK_RESO value. So,
	   1 tick = 0.004 usec */

        intr_param->rx_coalesce_usecs =	/* 32-bit safe integer expression */
		hxgep->rcr_timeout * ((4 * HXGE_RCR_CLK_RESO)/1000);
        intr_param->rx_max_coalesced_frames = hxgep->rcr_threshold;
        intr_param->rx_max_coalesced_frames_irq = hxgep->max_rx_pkts;
	intr_param->use_adaptive_rx_coalesce = hxgep->adaptive_rx;
        return 0;
}

static int
hxge_set_coalesce_intr(struct net_device *dev,
                                           struct  ethtool_coalesce *intr_param)
{
        struct hxge_adapter *hxgep = netdev_priv(dev);
	int i;

	/* Illegal to have both set to zero as this would disable both the
           threshold and timeout mechanisms resulting in no Rx interrupt
	   generation */
        if ((intr_param->rx_max_coalesced_frames == 0) &&
                (intr_param->rx_coalesce_usecs == 0)) {
                return (1);
        }
        if ((intr_param->rx_max_coalesced_frames_irq < HXGE_MAX_RX_PKTS_MIN) ||
	    (intr_param->rx_max_coalesced_frames_irq > HXGE_MAX_RX_PKTS_MAX))
                return (1);

	if (intr_param->rx_max_coalesced_frames > HXGE_RCR_THRESHOLD_MAX)
		return (1);

	spin_lock(&hxgep->lock);

	hxgep->adaptive_rx = intr_param->use_adaptive_rx_coalesce;
        if (intr_param->rx_coalesce_usecs) {
		hxgep->rcr_timeout =	/* 32-bit safe arithmetic */
			(uint32_t)(intr_param->rx_coalesce_usecs
				   / ((4 * HXGE_RCR_CLK_RESO)/1000));
                hxgep->rcr_cfgb_cpy = RCR_CFGB_ENABLE_TIMEOUT | hxgep->rcr_timeout;
        } else {
                hxgep->rcr_timeout= 0;
		hxgep->rcr_cfgb_cpy = 0;
        }

        hxgep->rcr_threshold =  intr_param->rx_max_coalesced_frames;
        hxgep->max_rx_pkts =  intr_param->rx_max_coalesced_frames_irq;

	for (i = 0; i < hxgep->max_rdcs; i++) {
		struct rx_ring_t *rx_ring = &hxgep->rx_ring[i];
		if (test_bit(RING_ENABLED, &rx_ring->state))
			RXDMA_REG_WRITE64(hxgep->hw.hw_addr, RDC_RCR_CFG_B, i, hxgep->rcr_threshold << 16 | hxgep->rcr_cfgb_cpy);
	}

	spin_unlock(&hxgep->lock);
        return 0;
}

static struct ethtool_ops hxge_ethtool_ops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
	.self_test_count	= hxge_diag_test_count,
	.get_stats_count	= hxge_get_stats_count,
#else
	.get_sset_count		= hxge_get_sset_count,
#endif
	.get_drvinfo		= hxge_get_drvinfo,
	.get_settings		= hxge_get_settings,
	.self_test		= hxge_diag_test,
	.get_strings		= hxge_get_strings,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 13)
        .get_tx_csum            = hxge_get_tx_csum,
        .set_tx_csum            = hxge_set_tx_csum,
	.get_rx_csum		= hxge_get_rx_csum,
	.set_rx_csum		= hxge_set_rx_csum,
	.get_tso		= ethtool_op_get_tso,
	.set_tso		= ethtool_op_set_tso,
#endif
	.get_ethtool_stats	= hxge_get_ethtool_stats,
	.get_msglevel		= hxge_get_msglevel,
	.set_msglevel		= hxge_set_msglevel,
        .get_coalesce           = hxge_get_coalesce_intr,
        .set_coalesce           = hxge_set_coalesce_intr,
	.get_link		= ethtool_op_get_link
};


void hxge_set_ethtool_ops(struct net_device *netdev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
		netdev->ethtool_ops = &hxge_ethtool_ops;
#else
		SET_ETHTOOL_OPS(netdev, &hxge_ethtool_ops);
#endif
}
