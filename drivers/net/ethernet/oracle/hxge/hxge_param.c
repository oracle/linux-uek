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


#include "hxge.h"

struct hxge_option {
	enum {range, boolean, range_mod} type;
	char 	*name;
	int 	val;
	int 	def;
	int	min;
	int 	max;
	int     mod;
};

typedef enum {
	param_enable_jumbo = 0,
	param_intr_type,
	param_rbr_entries,
	param_rcr_entries,
	param_rcr_timeout,
	param_rcr_threshold,
	param_rx_dma_channels,
	param_tx_dma_channels,
	param_num_tx_descs,
	param_tx_buffer_size,
	param_tx_mark_ints,
	param_max_rx_pkts,
	param_vlan_id,
	param_strip_crc,
	param_enable_vmac_ints,
	param_promiscuous,
	param_chksum,
	param_vlan,
	param_tcam,
	param_tcam_seed,
	param_tcam_ether_usr1,
	param_tcam_ether_usr2,
	param_tcam_tcp_ipv4,
	param_tcam_udp_ipv4,
	param_tcam_ipsec_ipv4,
	param_tcam_stcp_ipv4,
	param_tcam_tcp_ipv6,
	param_tcam_udp_ipv6,
	param_tcam_ipsec_ipv6,
	param_tcam_stcp_ipv6,
} hxge_param_t;

	


#define HXGE_PARAM(X, desc, default_val_addr) \
	module_param_named(X, default_val_addr, int, 0); \
	MODULE_PARM_DESC(X, desc);

#define PARAM(x) hxge_arr[x].val

struct hxge_option hxge_arr[] = {
{ boolean, "enable_jumbo", 1, 0},
{ range, "intr_type", MSIX_TYPE, MSI_TYPE, INTx_TYPE, POLLING_TYPE},
{ range_mod, "rbr_entries", HXGE_RBR_RBB_DEFAULT, HXGE_RBR_RBB_DEFAULT, HXGE_RBR_RBB_MIN, HXGE_RBR_RBB_MAX, 64},
{ range_mod, "rcr_entries", HXGE_RCR_DEFAULT, HXGE_RCR_DEFAULT, HXGE_RCR_MIN, HXGE_RCR_MAX, 32},
{ range, "rcr_timeout", HXGE_RCR_TIMEOUT, HXGE_RCR_TIMEOUT, HXGE_RCR_TIMEOUT_MIN, HXGE_RCR_TIMEOUT_MAX},
{ range, "rcr_threshold", HXGE_RCR_THRESHOLD, HXGE_RCR_THRESHOLD, HXGE_RCR_THRESHOLD_MIN, HXGE_RCR_THRESHOLD_MAX},
{ range, "rx_dma_channels", HXGE_MAX_RDCS, HXGE_MAX_RDCS, HXGE_MIN_RDCS, HXGE_MAX_RDCS},
{ range, "tx_dma_channels", HXGE_MAX_TDCS, HXGE_MAX_TDCS, HXGE_MIN_TDCS, HXGE_MAX_TDCS},
{ range_mod, "num_tx_descs", HXGE_TX_DESCS_DEFAULT, HXGE_TX_DESCS_DEFAULT, HXGE_TX_DESCS_MIN, HXGE_TX_DESCS_MAX, 32},
{ range, "tx_buffer_size", HXGE_TX_BUF_SZ_MIN, HXGE_TX_BUF_SZ_MIN, HXGE_TX_BUF_SZ_MIN, HXGE_TX_BUF_SZ_MAX},
{ range, "tx_mark_ints", 32, 16, 1, HXGE_TX_DESCS_DEFAULT/4},
{ range, "max_rx_pkts", HXGE_MAX_RX_PKTS, HXGE_MAX_RX_PKTS, 0, HXGE_MAX_RX_PKTS_MAX},
{ range, "vlan_id", VLAN_ID_MIN, VLAN_ID_IMPLICIT, VLAN_ID_MIN, VLAN_ID_MAX},
{ boolean, "strip_crc", 0, 0},
{ boolean, "enable_vmac_ints", 0, 0},
{ boolean, "promiscuous", 0, 0},
{ range, "chksum", HXGE_CHKSUM_ENABLED, HXGE_CHKSUM_ENABLED, 0, HXGE_CHKSUM_ENABLED },
{ boolean, "vlan", 1, 1},
{ boolean, "tcam", 1, 1},
{ range, "tcam_seed", 0x2323433, 0, 0, 0x7fffffff},
{ range, "tcam_ether_usr1", 0, 0x40000, 0, 0x4ffff},
{ range, "tcam_ether_usr2", 0, 0x40000, 0, 0x4ffff},
{ range, "tcam_tcp_ipv4", 1, 1, 0, 2},
{ range, "tcam_udp_ipv4", 1, 1, 0, 2},
{ range, "tcam_ipsec_ipv4", 0, 1, 0, 2},
{ range, "tcam_stcp_ipv4", 0, 1, 0, 2},
{ range, "tcam_tcp_ipv6", 0, 1, 0, 2},
{ range, "tcam_udp_ipv6", 0, 1, 0, 2},
{ range, "tcam_ipsec_ipv6", 0, 1, 0, 2},
{ range, "tcam_stcp_ipv6", 0, 1, 0, 2}
};

HXGE_PARAM(enable_jumbo, "enable jumbo packets", PARAM(param_enable_jumbo));
HXGE_PARAM(intr_type, "Interrupt type (INTx=0, MSI=1, MSIx=2, Polling=3)", PARAM(param_intr_type));
HXGE_PARAM(rbr_entries, "No. of RBR Entries", PARAM(param_rbr_entries));
HXGE_PARAM(rcr_entries, "No. of RCR Entries", PARAM(param_rcr_entries));
HXGE_PARAM(rcr_timeout, "RCR Timeout", PARAM(param_rcr_timeout));
HXGE_PARAM(rcr_threshold, "RCR Threshold", PARAM(param_rcr_threshold));
HXGE_PARAM(rx_dma_channels, "No. of Rx DMA Channels", PARAM(param_rx_dma_channels));
HXGE_PARAM(tx_dma_channels, "No. of Tx DMA Channels", PARAM(param_tx_dma_channels));
HXGE_PARAM(num_tx_descs, "No. of Tx Descriptors", PARAM(param_num_tx_descs));
HXGE_PARAM(tx_buffer_size, "No. of Tx Buffers", PARAM(param_tx_buffer_size));
HXGE_PARAM(tx_mark_ints, "Tx packets before getting marked interrupt", PARAM(param_tx_mark_ints));
HXGE_PARAM(max_rx_pkts, "Max Rx Packets", PARAM(param_max_rx_pkts));
HXGE_PARAM(vlan_id, "Implicit VLAN ID", PARAM(param_vlan_id));
HXGE_PARAM(strip_crc, "Strip CRC at VMAC (0=disable, 1=enable)", PARAM(param_strip_crc));
HXGE_PARAM(enable_vmac_ints, "Enable VMAC Interrupt Processing(0=disable, 1=enable)", PARAM(param_enable_vmac_ints));
HXGE_PARAM(promiscuous, "Enable promiscuous mode (0=disable, 1=enable)",PARAM(param_promiscuous));
HXGE_PARAM(chksum, "Enable HW Checksum(0=disable, 1=enable)",PARAM(param_chksum));
HXGE_PARAM(vlan, "Enable VLAN(0=disable, 1=enable)",PARAM(param_vlan));
HXGE_PARAM(tcam, "Enable TCAM(0=disable, 1=enable)",PARAM(param_tcam));
HXGE_PARAM(tcam_seed, "Source hash seed",PARAM(param_tcam_seed));
HXGE_PARAM(tcam_ether_usr1, "EtherType Class usr1",PARAM(param_tcam_ether_usr1));
HXGE_PARAM(tcam_ether_usr2, "EtherType Class usr2",PARAM(param_tcam_ether_usr2));
HXGE_PARAM(tcam_tcp_ipv4, "TCP over IPv4 class",PARAM(param_tcam_tcp_ipv4));
HXGE_PARAM(tcam_udp_ipv4, "UDP over IPv4 class",PARAM(param_tcam_udp_ipv4));
HXGE_PARAM(tcam_ipsec_ipv4, "IPSec over IPv4 class",PARAM(param_tcam_ipsec_ipv4));
HXGE_PARAM(tcam_stcp_ipv4, "STCP over IPv4 class",PARAM(param_tcam_stcp_ipv4));
HXGE_PARAM(tcam_tcp_ipv6, "TCP over IPv6 class",PARAM(param_tcam_tcp_ipv6));
HXGE_PARAM(tcam_udp_ipv6, "UDP over IPv6 class",PARAM(param_tcam_udp_ipv6));
HXGE_PARAM(tcam_ipsec_ipv6, "IPsec over IPv6 class",PARAM(param_tcam_ipsec_ipv6));
HXGE_PARAM(tcam_stcp_ipv6, "STCP over IPv6 class",PARAM(param_tcam_stcp_ipv6));

/* Find the value corresponding to the option name. Return -1 for 
 * failure */

static struct hxge_option *find_option(const char *option_name)
{
	int i;
	for (i = 0; i < (sizeof(hxge_arr)/sizeof(struct hxge_option)); i++)
		if (!strcmp(hxge_arr[i].name, option_name))
			return &hxge_arr[i];
	return NULL; 
}

int hxge_get_option(const char *option_name, int *value)
{
	struct hxge_option *option = find_option(option_name);	

	if (option)  {
		*value = option->val;
		return 0;
	}
	return -1;
}

int hxge_set_option(const char *option_name, int value)
{
	struct hxge_option *option = find_option(option_name);	
	int orig_value;
	
	if (!option) {
		HXGE_ERR_PRINT("Illegal option name");
		return -1;
	}

	orig_value = option->val;
	HXGE_DBG_PRINT("Setting %s to %d",option_name, value);
	switch (option->type) {
		case boolean :
			option->val = (value) ? 1 : 0;
			break;
		case range_mod:
			if (value % option->mod) {
				HXGE_ERR_PRINT("value %d for %s is not multiple of %d", value, option_name, option->mod);
				return -1;
			}
			/* fall through */
		case range :
			if ((value < option->min) || (value > option->max)) {
			   HXGE_ERR_PRINT("value %d for %s out of range; min=%d, max=%d",value,option->name,option->min, option->max);
			   return -1;
			}
			option->val = value;
			break;
		default:
			HXGE_ERR_PRINT("Illegal option type");
			return -1;
	}

	return orig_value;
}

				
int hxge_init_param (struct hxge_adapter *hxgep)
{
	int i;
	int entries = (sizeof(hxge_arr)/sizeof(struct hxge_option));
	int val;

	hxgep->param = hxge_arr;
	/* validate options; leverage set function to do validation */
	HXGE_DBG(hxgep, "hxge_init_param: %d parameters", entries);
	for (i = 0; i < entries; i++) {
		if (hxge_get_option(hxge_arr[i].name, &val)) {
			HXGE_ERR(hxgep, "hxge_init_param: failed param validation");
			return -1;
		}
		if (hxge_set_option(hxge_arr[i].name, val) < 0)
			return -1;
	}
	

	return 0;
}

/* Restore default values to all driver parameters */
void hxge_restore_defaults(struct hxge_adapter *hxgep)
{
	struct hxge_option *hxge_optp;
	int len = (sizeof(hxge_arr)/sizeof(struct hxge_option));
	int i;

	for (hxge_optp =  hxgep->param, i = 0; i < len; i++, hxge_optp++)
		hxge_optp->val = hxge_optp->def;
}
