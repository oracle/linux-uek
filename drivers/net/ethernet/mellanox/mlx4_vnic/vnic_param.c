/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "vnic.h"
#include "vnic_fip.h"

u32 vnic_lro_num = VNIC_MAX_LRO_DESCS;
u32 vnic_net_admin = 1;
u32 vnic_child_max = VNIC_CHILD_MAX;
u32 vnic_tx_rings_num = 0;
u32 vnic_rx_rings_num = 0;
u32 vnic_tx_rings_len = VNIC_TX_QUEUE_LEN;
u32 vnic_rx_rings_len = VNIC_RX_QUEUE_LEN;
u32 vnic_mgid_data_type = 0;
u32 vnic_encap_headroom = 1;
u32 vnic_tx_polling = 1;
u32 vnic_rx_linear = 0;
u32 vnic_change_mac = 0;
u32 vnic_learn_mac_enabled = 1;
u32 vnic_synd_backlog = 4;
u32 vnic_eport_state_enforce = 0;
u32 vnic_src_mac_enforce = 0;
u32 vnic_inline_tshold = 0;
u32 vnic_discovery_pkeys[MAX_NUM_PKEYS_DISCOVERY];
u32 vnic_discovery_pkeys_count = MAX_NUM_PKEYS_DISCOVERY;
u32 vnic_sa_query = 0;

/* these params are enbaled in debug mode */
u32 no_bxm = 0;
u32 vnic_msglvl = 0x80000000;
u32 vnic_max_tx_outs = VNIC_MAX_TX_OUTS;
u32 vnic_linear_small_pkt = 1;
u32 vnic_mcast_create = 0;
u32 vnic_napi_weight = VNIC_MAX_RX_CQE;

module_param_named(tx_rings_num, vnic_tx_rings_num, int, 0444);
MODULE_PARM_DESC(tx_rings_num, "Number of TX rings, use 0 for #cpus [default 0, max 32]");

module_param_named(tx_rings_len, vnic_tx_rings_len, int, 0444);
MODULE_PARM_DESC(tx_rings_len, "Length of TX rings, must be power of two [default 1024, max 8K]");

module_param_named(rx_rings_num, vnic_rx_rings_num, int, 0444);
MODULE_PARM_DESC(rx_rings_num, "Number of RX rings, use 0 for #cpus [default 0, max 32]");

module_param_named(rx_rings_len, vnic_rx_rings_len, int, 0444);
MODULE_PARM_DESC(rx_rings_len, "Length of RX rings, must be power of two [default 2048, max 8K]");

module_param_named(eport_state_enforce, vnic_eport_state_enforce, int, 0644);
MODULE_PARM_DESC(eport_state_enforce, "Bring interface up only when corresponding EPort is up [default 0]");

module_param_named(src_mac_enforce, vnic_src_mac_enforce, int, 0644);
MODULE_PARM_DESC(src_mac_enforce, "Enforce source MAC address [default 0]");

module_param_named(vnic_net_admin, vnic_net_admin, int, 0644);
MODULE_PARM_DESC(vnic_net_admin, "Enable Network Administration mode [default 1]");

module_param_named(vnic_child_max, vnic_child_max, int, 0644);
MODULE_PARM_DESC(vnic_child_max, "Max child vNics (per interface), use 0 to disable [default 128]");

module_param_named(mgid_data_type, vnic_mgid_data_type, int, 0444);
MODULE_PARM_DESC(mgid_data_type, "Set MGID data type for multicast traffic [default 0, max 1]");

module_param_named(encap_headroom, vnic_encap_headroom, int, 0444);
MODULE_PARM_DESC(encap_headroom, "Use SKB headroom for protocol encapsulation [default 1]");

module_param_named(inline_tshold, vnic_inline_tshold, int, 0444);
MODULE_PARM_DESC(inline_tshold, "Packets smaller than this threshold (in bytes) use inline & blue flame [default 0, max 512]");

module_param_named(tx_polling, vnic_tx_polling, int, 0444);
MODULE_PARM_DESC(tx_polling, "Enable TX polling mode [default 1]");

module_param_named(rx_linear, vnic_rx_linear, int, 0444);
MODULE_PARM_DESC(rx_linear, "Enable linear RX buffers [default 0]");

module_param_named(change_mac, vnic_change_mac, int, 0444);
MODULE_PARM_DESC(change_mac, "Enable MAC change using child vNics [default 0]");

module_param_named(learn_tx_mac, vnic_learn_mac_enabled, int, 0644);
MODULE_PARM_DESC(learn_tx_mac, "Enable TX MAC learning in promisc mode [default 1]");

module_param_named(synd_backlog, vnic_synd_backlog, int, 0644);
MODULE_PARM_DESC(synd_backlog, "Syndrome error reporting backlog limit [default 4]");

module_param_array_named(discovery_pkeys, vnic_discovery_pkeys, int, &vnic_discovery_pkeys_count, 0444);
MODULE_PARM_DESC(discovery_pkeys, "Vector of PKeys to be used for discovery [default 0xffff, max vector length 24]");

module_param_named(sa_query, vnic_sa_query, int, 0644);
MODULE_PARM_DESC(sa_query, "Query SA for each IB address and ignore gateway assigned SLs [default 0]");


#if !(defined(NETIF_F_GRO) && !defined(_BP_NO_GRO))
module_param_named(lro_num, vnic_lro_num, int, 0444);
MODULE_PARM_DESC(lro_num, "Number of LRO sessions per ring, use 0 to disable [default 32, max 32]");
#endif

#ifdef CONFIG_MLX4_VNIC_DEBUG
module_param_named(no_bxm, no_bxm, int, 0444);
MODULE_PARM_DESC(no_bxm, "Enable NO BXM mode [default 0]");

module_param_named(msglvl, vnic_msglvl, uint, 0644);
MODULE_PARM_DESC(msglvl, "Debug message level [default 0]");

module_param_named(max_tx_outs, vnic_max_tx_outs, int, 0644);
MODULE_PARM_DESC(max_tx_outs, "Max outstanding TX packets [default 16]");

module_param_named(linear_small_pkt, vnic_linear_small_pkt, int, 0644);
MODULE_PARM_DESC(linear_small_pkt, "Use linear buffer for small packets [default 1]");

module_param_named(mcast_create, vnic_mcast_create, int, 0444);
MODULE_PARM_DESC(mcast_create, "Create multicast group during join request [default 0]");

module_param_named(napi_weight, vnic_napi_weight, int, 0444);
MODULE_PARM_DESC(napi_weight, "NAPI weight [default 32]");
#endif /* CONFIG_MLX4_VNIC_DEBUG */

int vnic_param_check(void) {
#ifdef CONFIG_MLX4_VNIC_DEBUG
	vnic_info("VNIC_DEBUG flag is set\n");
#endif

	vnic_mcast_create = vnic_mcast_create ? 1 : 0;
	vnic_mcast_create = no_bxm ? 1 : vnic_mcast_create;
	no_bxm            = no_bxm ? 1 : 0;
	vnic_sa_query     = vnic_sa_query ? 1 : 0;

	vnic_mgid_data_type = max_t(u32, vnic_mgid_data_type, 0);
	vnic_mgid_data_type = min_t(u32, vnic_mgid_data_type, 1);

	vnic_rx_rings_num = max_t(u32, vnic_rx_rings_num, 0);
	vnic_rx_rings_num = min_t(u32, vnic_rx_rings_num, VNIC_MAX_NUM_CPUS);

	vnic_tx_rings_num = max_t(u32, vnic_tx_rings_num, 0);
	vnic_tx_rings_num = min_t(u32, vnic_tx_rings_num, VNIC_MAX_NUM_CPUS);

	vnic_tx_rings_len = rounddown_pow_of_two(vnic_tx_rings_len);
	vnic_tx_rings_len = max_t(u32, vnic_tx_rings_len, VNIC_TX_QUEUE_LEN_MIN);
	vnic_tx_rings_len = min_t(u32, vnic_tx_rings_len, VNIC_TX_QUEUE_LEN_MAX);

	vnic_rx_rings_len = rounddown_pow_of_two(vnic_rx_rings_len);
	vnic_rx_rings_len = max_t(u32, vnic_rx_rings_len, VNIC_RX_QUEUE_LEN_MIN);
	vnic_rx_rings_len = min_t(u32, vnic_rx_rings_len, VNIC_RX_QUEUE_LEN_MAX);

	vnic_max_tx_outs  = min_t(u32, vnic_tx_rings_len, vnic_max_tx_outs);

	vnic_napi_weight  = min_t(u32, vnic_napi_weight, VNIC_MAX_NUM_CPUS);

	vnic_lro_num      = max_t(u32, vnic_lro_num, 0);
	vnic_lro_num      = min_t(u32, vnic_lro_num, VNIC_MAX_LRO_DESCS);

	vnic_inline_tshold = max_t(u32, vnic_inline_tshold, 0);
	vnic_inline_tshold = min_t(u32, vnic_inline_tshold, VNIC_MAX_INLINE_TSHOLD);

	return 0;
}
