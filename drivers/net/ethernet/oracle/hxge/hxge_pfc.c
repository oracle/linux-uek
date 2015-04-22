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
#include "hpi/hpi_pfc.h"


/* Static prototypes */
static int hxge_pfc_set_mac_address(struct hxge_adapter *, uint32_t, 
		pfc_mac_addr_t ether_addr);
int hxge_vmac_promisc(struct hxge_adapter *, int);


int
hxge_get_tcam_properties(struct hxge_adapter *hxgep)
{
	tcam_class_t class;
	p_hxge_class_pt_cfg_t class_config = &hxgep->class_config;

	if (hxge_get_option("tcam_seed", &class_config->init_hash)) {
		HXGE_ERR(hxgep, "tcam_seed failed");
		return -1;
	}

	if (hxge_get_option("tcam_ether_usr1", &class_config->class_cfg[TCAM_CLASS_ETYPE_1]))
	{
		HXGE_ERR(hxgep, "tcam_ether_usr1 failed");
		return -1;
	}

	if (hxge_get_option("tcam_ether_usr2", &class_config->class_cfg[TCAM_CLASS_ETYPE_2]))
	{
		HXGE_ERR(hxgep, "tcam_ether_usr2 failed");
		return -1;
	}

	if (hxge_get_option("tcam_tcp_ipv4",&class_config->class_cfg[TCAM_CLASS_TCP_IPV4])) {

		HXGE_ERR(hxgep, "tcam_tcp_ipv4 failed");
		return -1;
	}

	if (hxge_get_option("tcam_udp_ipv4",&class_config->class_cfg[TCAM_CLASS_UDP_IPV4])) {

		HXGE_ERR(hxgep, "tcam_udp_ipv4 failed");
		return -1;
	}

	if (hxge_get_option("tcam_ipsec_ipv4",&class_config->class_cfg[TCAM_CLASS_AH_ESP_IPV4])) {

		HXGE_ERR(hxgep, "tcam_ipsec_ipv4 failed");
		return -1;
	}

	if (hxge_get_option("tcam_stcp_ipv4",&class_config->class_cfg[TCAM_CLASS_SCTP_IPV4])) {

		HXGE_ERR(hxgep, "tcam_stcp_ipv4 failed");
		return -1;
	}

	if (hxge_get_option("tcam_tcp_ipv6",&class_config->class_cfg[TCAM_CLASS_TCP_IPV6])) {

		HXGE_ERR(hxgep, "tcam_tcp_ipv6 failed");
		return -1;
	}
	
	if (hxge_get_option("tcam_udp_ipv6",&class_config->class_cfg[TCAM_CLASS_UDP_IPV6])) {

		HXGE_ERR(hxgep, "tcam_udp_ipv6 failed");
		return -1;
	}

	if (hxge_get_option("tcam_ipsec_ipv6",&class_config->class_cfg[TCAM_CLASS_AH_ESP_IPV6])) {

		HXGE_ERR(hxgep, "tcam_ipsec_ipv6 failed");
		return -1;
	}

	if (hxge_get_option("tcam_stcp_ipv6",&class_config->class_cfg[TCAM_CLASS_SCTP_IPV6])) {

		HXGE_ERR(hxgep, "tcam_stcp_ipv6 failed");
		return -1;
	}

	for (class = TCAM_CLASS_TCP_IPV4; class < TCAM_CLASS_SCTP_IPV6; class++)
	{
		switch (class_config->class_cfg[class])  {
			case 0 : /* do nothing */
				 break;
			case 1 : class_config->class_cfg[class] = HXGE_CLASS_TCAM_LOOKUP;
				 break;
			case 2  : class_config->class_cfg[class] = HXGE_CLASS_DISCARD;
				break;
			default: HXGE_ERR(hxgep, "Bad class value");
				 return -1;
		}
	}

	return 0;

}
int
hxge_pfc_config_tcam_enable(struct hxge_adapter *  hxgep)
{
        void 			*handle;	
	boolean_t		enable = TRUE;
	hpi_status_t		hpi_status;

	if (!(hxgep->flags & HXGE_TCAM_ENABLED)) {
		HXGE_DBG(hxgep, "TCAM not enabled");
		return 0;
	}

	handle = hxgep->hw.hw_addr;
	hpi_status = hpi_pfc_set_tcam_enable(handle, enable);
	if (hpi_status != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "enable tcam failed");
		return  -1;
	}

	HXGE_DBG(hxgep, "TCAM enabled");

	return  0;
}

int
hxge_pfc_config_tcam_disable(struct hxge_adapter *  hxgep)
{
	void * 		handle;
	boolean_t		enable = FALSE;
	hpi_status_t		hpi_status;

	handle = hxgep->hw.hw_addr;
	hpi_status = hpi_pfc_set_tcam_enable(handle, enable);
	if (hpi_status != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "disable tcam failed");
		return  -1;
	}

	return  0;
}
int
hxge_pfc_set_hash(struct hxge_adapter *hxgep, uint32_t seed)
{
        hpi_status_t            rs = HPI_SUCCESS;
        hpi_handle_t            handle = hxgep->hw.hw_addr;
        p_hxge_class_pt_cfg_t   p_class_cfgp;

        HXGE_DBG(hxgep, " ==> hxge_pfc_set_hash");

        p_class_cfgp = (p_hxge_class_pt_cfg_t)&hxgep->class_config;
        p_class_cfgp->init_hash = seed;

        rs = hpi_pfc_set_hash_seed_value(handle, seed);
        if (rs & HPI_PFC_ERROR) {
                HXGE_ERR(hxgep, " hxge_pfc_set_hash %x failed ", seed);
                return -1;
        }

        HXGE_DBG(hxgep, " <== hxge_pfc_set_hash");

        return 0;
}

static int 
hxge_cfg_tcam_ip_class_get(struct hxge_adapter *hxgep, tcam_class_t class,
    uint32_t *class_config)
{
        hpi_status_t    rs = HPI_SUCCESS;
        tcam_key_cfg_t  cfg;
        hpi_handle_t    handle = hxgep->hw.hw_addr;
        uint32_t        ccfg = 0;

        HXGE_DBG(hxgep, "==> hxge_cfg_tcam_ip_class_get");

        memset(&cfg, 0, sizeof (tcam_key_cfg_t));

        rs = hpi_pfc_get_l3_class_config(handle, class, &cfg);
        if (rs & HPI_PFC_ERROR) {
                HXGE_ERR(hxgep, "hxge_cfg_tcam_ip_class opt %x for class %d failed ", *class_config, class);
                return -1;
        }
        if (cfg.discard)
                ccfg |=  HXGE_CLASS_DISCARD;

        if (cfg.lookup_enable)
                ccfg |= HXGE_CLASS_TCAM_LOOKUP;

        *class_config = ccfg;

        HXGE_DBG(hxgep, " ==> hxge_cfg_tcam_ip_class_get %x", ccfg);

        return 0;
} 


int
hxge_pfc_ip_class_config_get(struct hxge_adapter *hxgep, tcam_class_t class,
    uint32_t *config)
{
        uint32_t        t_class_config;

        HXGE_DBG(hxgep, " ==> hxge_pfc_ip_class_config_get");
        t_class_config = 0;
        if (hxge_cfg_tcam_ip_class_get(hxgep, class, &t_class_config)) {
                HXGE_ERR(hxgep, " hxge_pfc_ip_class_config_get for class %d tcam failed", class);
                return -1;
        }

        HXGE_DBG(hxgep, " hxge_pfc_ip_class_config tcam %x", t_class_config);

        *config = t_class_config;

        HXGE_DBG(hxgep, "<== hxge_pfc_ip_class_config_get");
        return 0;
}

static int
hxge_pfc_ip_class_config(struct hxge_adapter *hxgep, tcam_class_t class, 
			uint32_t config)
{
        uint32_t                class_config;
        p_hxge_class_pt_cfg_t   p_class_cfgp;
        tcam_key_cfg_t          cfg;
        hpi_handle_t            handle = hxgep->hw.hw_addr;
        hpi_status_t            rs = HPI_SUCCESS;

        HXGE_DBG(hxgep, " ==> hxge_pfc_ip_class_config");
        p_class_cfgp = (p_hxge_class_pt_cfg_t)&hxgep->class_config;
        class_config = p_class_cfgp->class_cfg[class];

        if (class_config != config) {
                p_class_cfgp->class_cfg[class] = config;
                class_config = config;
        }

        if (class == TCAM_CLASS_ETYPE_1 || class == TCAM_CLASS_ETYPE_2) {
                rs = hpi_pfc_set_l2_class_slot(handle,
                    class_config & HXGE_CLASS_ETHER_TYPE_MASK,
                    class_config & HXGE_CLASS_VALID,
                    class - TCAM_CLASS_ETYPE_1);
        } else {
                if (class_config & HXGE_CLASS_DISCARD)
                        cfg.discard = 1;
                else
                        cfg.discard = 0;
                if (class_config & HXGE_CLASS_TCAM_LOOKUP)
                        cfg.lookup_enable = 1;
                else
                        cfg.lookup_enable = 0;

                rs = hpi_pfc_set_l3_class_config(handle, class, cfg);
        }

        if (rs & HPI_PFC_ERROR) {
                HXGE_DBG(hxgep, "hxge_pfc_ip_class_config %x for class %d tcam failed", config, class);
                return -1;
        }

        HXGE_DBG(hxgep, "<== hxge_pfc_ip_class_config");
        return 0;
}

static int
hxge_pfc_ip_class_config_all(struct hxge_adapter *hxgep)
{
        uint32_t        class_config;
        tcam_class_t    cl;

        HXGE_DBG(hxgep, "==> hxge_pfc_ip_class_config_all");

        for (cl = TCAM_CLASS_ETYPE_1; cl <= TCAM_CLASS_SCTP_IPV6; cl++) {
                if (cl == TCAM_CLASS_RESERVED_4 ||
                    cl == TCAM_CLASS_RESERVED_5 ||
                    cl == TCAM_CLASS_RESERVED_6 ||
                    cl == TCAM_CLASS_RESERVED_7)
                        continue;

                class_config = hxgep->class_config.class_cfg[cl];
                if (hxge_pfc_ip_class_config(hxgep, cl, class_config)) {
                        HXGE_ERR(hxgep, "hxge_pfc_ip_class_config failed, class %d config %x ", cl, class_config);
			return -1;
                }
        }

        HXGE_DBG(hxgep, "<== hxge_pfc_ip_class_config_all");
        return 0;
}

static int
hxge_pfc_update_hw(struct hxge_adapter *hxgep)
{
        p_hxge_class_pt_cfg_t   p_class_cfgp;

        HXGE_DBG(hxgep, "==> hxge_pfc_update_hw");
        p_class_cfgp = (p_hxge_class_pt_cfg_t)&hxgep->class_config;

        if (hxge_pfc_set_hash(hxgep, p_class_cfgp->init_hash)) {
                HXGE_DBG(hxgep, "hxge_pfc_set_hash Failed");
                return -1;
        }

	/*TODO: Setup VLAN */

        /* Configure hash value and classes */
        if (hxge_pfc_ip_class_config_all(hxgep)) {
                HXGE_ERR(hxgep, "hxge_pfc_ip_class_config_all Failed");
                return -1;
        }

        return 0;
}

static  uint32_t
hxge_get_blade_id(struct hxge_adapter *hxgep)
{
        phy_debug_training_vec_t        blade_id;

        HXGE_DBG(hxgep, "==> hxge_get_blade_id");
        HXGE_REG_RD32(hxgep->hw.hw_addr, PHY_DEBUG_TRAINING_VEC,
            &blade_id.value);
        HXGE_DBG(hxgep, "<== hxge_get_blade_id: id = %d",blade_id.bits.bld_num);

        return (blade_id.bits.bld_num);
}



static int 
hxge_tcam_default_add_entry(struct hxge_adapter *hxgep, tcam_class_t class)
{
        hpi_status_t            rs = HPI_SUCCESS;
        uint32_t                location;
        hxge_tcam_entry_t       entry;
        hxge_tcam_spread_t      *key = NULL;
        hxge_tcam_spread_t      *mask = NULL;
        hpi_handle_t            handle = hxgep->hw.hw_addr;

        memset(&entry, 0, sizeof (hxge_tcam_entry_t));

        /*
         * The class id and blade id are common for all classes
         * Only use the blade id for matching and the rest are wild cards.
         * This will allow one TCAM entry to match all traffic in order
         * to spread the traffic using source hash.
         */
        key = &entry.key.spread;
        mask = &entry.mask.spread;

        key->blade_id = hxge_get_blade_id(hxgep);

        mask->class_code = 0xf;
        mask->class_code_l = 0x1;
        mask->blade_id = 0;
        mask->wild1 = 0x7ffffff;
        mask->wild = 0xffffffff;
        mask->wild_l = 0xffffffff;

        location = class;

        spin_lock(&hxgep->tcam_lock);
        rs = hpi_pfc_tcam_entry_write(handle, location, &entry);
        if (rs & HPI_PFC_ERROR) {
                spin_unlock(&hxgep->tcam_lock);
                HXGE_ERR(hxgep, " hxge_tcam_default_add_entry tcam entry write failed for location %d", location);
                return -1;
        }

        /* Add the associative portion */
        entry.match_action.value = 0;

        /* Use source hash to spread traffic */
        entry.match_action.bits.channel_d = 0;
        entry.match_action.bits.channel_c = 1;
        entry.match_action.bits.channel_b = 2;
        entry.match_action.bits.channel_a = 3;
        entry.match_action.bits.source_hash = 1;
        entry.match_action.bits.discard = 0;

        rs = hpi_pfc_tcam_asc_ram_entry_write(handle,
            location, entry.match_action.value);
        if (rs & HPI_PFC_ERROR) {
                spin_lock(&hxgep->tcam_lock);
                HXGE_DBG(hxgep, " hxge_tcam_default_add_entry tcam entry write failed for ASC RAM location %d", location);
                return -1;
        }

        memcpy((void *) &entry,
            (void *) &hxgep->classifier.tcam_entries[location].tce,
            sizeof (hxge_tcam_entry_t));

        spin_unlock(&hxgep->tcam_lock);
        return 0;
}



/*
 * Configure one TCAM entry for each class and make it match
 * everything within the class in order to spread the traffic
 * among the DMA channels based on the source hash.
 *
 * This is the default for now. This may change when Crossbow is
 * available for configuring TCAM.
 */
static int
hxge_tcam_default_config(struct hxge_adapter *hxgep)
{
        uint8_t         class;
        uint32_t        class_config;

        HXGE_DBG(hxgep, "==> hxge_tcam_default_config");

        /*
         * Add TCAM and its associative ram entries
         * A wild card will be used for the class code in order to match
         * any classes.
         */
        class = 0;
        if (hxge_tcam_default_add_entry(hxgep, class)) {
                HXGE_ERR(hxgep, "hxge_tcam_default_add_entry failed class %d ", class);
                return -1;
        }

        /* Enable the classes */
        for (class = TCAM_CLASS_TCP_IPV4;
            class <= TCAM_CLASS_SCTP_IPV6; class++) {
                /*
                 * By default, it is set to HXGE_CLASS_TCAM_LOOKUP in
                 * hxge_ndd.c. It may be overwritten in hxge.conf.
                 */
                class_config = hxgep->class_config.class_cfg[class];

                if (hxge_pfc_ip_class_config(hxgep, class, class_config)) {
                        HXGE_ERR(hxgep, "hxge_pfc_ip_class_config failed. class %d config %x ", class, class_config);
                        return -1;
                }
        }

        if (hxge_pfc_config_tcam_enable(hxgep)) {
		HXGE_ERR(hxgep, "hxge_pfc_config_tcam_enable failed");
		return -1;
	}

        HXGE_DBG(hxgep, "hxge_tcam_default_config done");

        return 0;
}


int 
hxge_classify_init_sw(struct hxge_adapter *hxgep)
{
        int             alloc_size;
        hxge_classify_t *classify_ptr;

        HXGE_DBG(hxgep, "==> hxge_classify_init_sw");
        classify_ptr = &hxgep->classifier;

        if (classify_ptr->state & HXGE_PFC_SW_INIT) {
                HXGE_DBG(hxgep, "hxge_classify_init_sw already init");
                return 0;
        }

        /* Init SW structures */
        classify_ptr->tcam_size = TCAM_HXGE_TCAM_MAX_ENTRY;

        alloc_size = sizeof (tcam_flow_spec_t) * classify_ptr->tcam_size;
        classify_ptr->tcam_entries = kzalloc(alloc_size, GFP_KERNEL);
        memset(classify_ptr->class_usage, 0, sizeof (classify_ptr->class_usage));

        /* Start from the beginning of TCAM */
        hxgep->classifier.tcam_location = 0;
        classify_ptr->state |= HXGE_PFC_SW_INIT;

        HXGE_DBG(hxgep, "<== hxge_classify_init_sw");

        return 0;
}


int
hxge_classify_init_hw(struct hxge_adapter *hxgep)
{
        HXGE_DBG(hxgep, "==> hxge_classify_init_hw");

        if (hxgep->classifier.state & HXGE_PFC_HW_INIT) {
                HXGE_DBG(hxgep, "hxge_classify_init_hw already init");
                return 0;
        }

        /* Now do a real configuration */
        if (hxge_pfc_update_hw(hxgep)) {
                HXGE_ERR(hxgep, "hxge_pfc_update_hw failed");
                return -1;
        }

        if (hxge_tcam_default_config(hxgep)) {
                HXGE_ERR(hxgep, "hxge_tcam_default_config failed"); 
                return -1;
        }

        hxgep->classifier.state |= HXGE_PFC_HW_INIT;

        HXGE_DBG(hxgep, "<== hxge_classify_init_hw");
        return 0;
}

int
hxge_classify_exit_sw(struct hxge_adapter *hxgep)
{
        hxge_classify_t *classify_ptr;

        HXGE_DBG(hxgep, "==> hxge_classify_exit_sw");
        classify_ptr = &hxgep->classifier;

        if (classify_ptr->tcam_entries) {
                kfree(classify_ptr->tcam_entries);
        }
        hxgep->classifier.state = HXGE_PFC_HW_UNINIT;

        HXGE_DBG(hxgep, "<== hxge_classify_exit_sw");

        return 0;
}


int
hxge_classify_init(struct hxge_adapter *hxgep)
{
        HXGE_DBG(hxgep, "==> hxge_classify_init");

        if (hxge_classify_init_sw(hxgep)) {
		HXGE_ERR(hxgep, "SW init failed");	
                return -1;
		}

        if (hxge_classify_init_hw(hxgep)) {
		HXGE_ERR(hxgep, "hxge_classify_init_hw failed");
                hxge_classify_exit_sw(hxgep);
                return -1;
        }

        HXGE_DBG(hxgep, "<== hxge_classify_init");
        return 0;
}

int
hxge_classify_uninit(struct hxge_adapter *hxgep)
{
        return (hxge_classify_exit_sw(hxgep));
}

void
hxge_vlan_rx_register(struct net_device *netdev, struct vlan_group *grp)
{
	struct hxge_adapter *hxgep = netdev_priv(netdev);
	hpi_handle_t handle = hxgep->hw.hw_addr;
	hpi_status_t status;
	int enable_vlan_id;

	enable_vlan_id = (grp ? (hxgep->vlan_id > 0) : 0);
	status = hpi_pfc_cfg_vlan_control_set(handle, 0, enable_vlan_id, 
				hxgep->vlan_id);
	HXGE_DBG(hxgep, "Implicit VLAN ID %d",hxgep->vlan_id);
	if (status != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_pfc_cfg_vlan_control_set failed to enable VLAN");
		return;
	}
	if (grp) {
		HXGE_DBG(hxgep, "Adding vlan group");
		/* Initialize the entire vlan table to avoid parity err */
		hpi_pfc_cfg_vlan_table_clear(handle);
	}
	else {
		HXGE_DBG(hxgep, "Removing vlan group");
	}
	hxgep->vlangrp = grp;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
int
hxge_vlan_rx_add_vid(struct net_device *netdev, __be16 proto, uint16_t vid)
#else
void
hxge_vlan_rx_add_vid(struct net_device *netdev, uint16_t vid)
#endif
{
        struct hxge_adapter *hxgep = netdev_priv(netdev);
	hpi_handle_t handle = hxgep->hw.hw_addr;
	hpi_status_t status;

	HXGE_DBG(hxgep, "Adding VID %d", vid);
	status = hpi_pfc_cfg_vlan_table_entry_set(handle, vid);
	if (status != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_pfc_cfg_vlan_table_entry_set failed, status = %d", status);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
		return -1;
#else
		return;
#endif
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
		return 0;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
int
hxge_vlan_rx_kill_vid(struct net_device *netdev, __be16 proto, uint16_t vid)
#else
void
hxge_vlan_rx_kill_vid(struct net_device *netdev, uint16_t vid)
#endif
{
        struct hxge_adapter *hxgep = netdev_priv(netdev);
	hpi_handle_t handle = hxgep->hw.hw_addr;
	hpi_status_t status;
	
	HXGE_DBG(hxgep, "Removing VID %d", vid);
	status = hpi_pfc_cfg_vlan_table_entry_clear(handle, vid);
	if (status != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_pfc_cfg_vlan_table_entry_clear failed");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
		return -1;
#else
		return;
#endif
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
		return 0;
#endif
}


int
hxge_set_mac_address(struct net_device *netdev, void *p)
{
	struct sockaddr	*addr = (struct sockaddr *)p;
	struct hxge_adapter *hxgep = netdev_priv(netdev);
	pfc_mac_addr_t	mac_addr;
	int status = 0;
	int i;


	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	MUTEX_ENTER(&hxgep->lock);

	/* Hydra expects the MAC address to be in little endian (PCI device).
         * So, we byte swap from network order (big endian) to little endian 
	 */

	for (i = 0; i < ETH_ALEN; i++)
		mac_addr.byte[i] = addr->sa_data[ETH_ALEN-1-i];

	status = hxge_pfc_set_mac_address(hxgep, HXGE_MAC_DEFAULT_ADDR_SLOT,
				mac_addr);

	memcpy(netdev->dev_addr, addr->sa_data, ETH_ALEN);
	memcpy(&mac_addr.value, addr->sa_data, ETH_ALEN);

	MUTEX_EXIT(&hxgep->lock);

	if (status)
		HXGE_ERR(hxgep, "Unable to set mac address");

	return (status);
}

int
hxge_add_mcast_addr(struct hxge_adapter *  hxgep, uint8_t *addrp)
{
	return  0;
}

int
hxge_del_mcast_addr(struct hxge_adapter *  hxgep, uint8_t *addrp)
{
	return  0;
}

static int
hxge_pfc_set_mac_address(struct hxge_adapter *  hxgep, uint32_t slot, 
		pfc_mac_addr_t address)
{
	void * 			handle = hxgep->hw.hw_addr;
	hpi_status_t		hpi_status;

	hpi_status = hpi_pfc_set_mac_address(handle, slot, address.value);
	if (hpi_status != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "failed to set PFC slot %d to MAC address %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
			 slot, address.byte[5], address.byte[4],
			 address.byte[3], address.byte[2],
			 address.byte[1], address.byte[0]);
		hpi_pfc_mac_addr_disable(handle, slot);	/* Might as well try */
		return  -1;
	}

	/* A MAC address of 00:00:00:00:00:00 is a call to disable
	 * that PFC MAC slot; all other addresses assumed valid and
	 * the PFC is enabled to match incoming traffic against that
	 * MAC address slot.
	 */

	if (address.bits.addr) { /* Enable PFC MAC addr match */
		hpi_status = hpi_pfc_mac_addr_enable(handle, slot);
		if (hpi_status != HPI_SUCCESS) {
			HXGE_ERR(hxgep, "Failed to enable PFC slot %d for MAC address %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
				 slot, address.byte[5], address.byte[4],
				 address.byte[3], address.byte[2],
				 address.byte[1], address.byte[0]);
			return  -1;
		}
	} else {		/* Disable PFC MAC==0 slot */
		hpi_status = hpi_pfc_mac_addr_disable(handle, slot);
		if (hpi_status != HPI_SUCCESS) {
			HXGE_ERR(hxgep, "Failed to disable PFC slot %d for MAC address 00:00:00:00:00:00",
				 slot);
			return  -1;
		}
	}

	return  0;
}

int
hxge_pfc_num_macs_get(struct hxge_adapter *  hxgep, uint32_t *nmacs)
{
	*nmacs = PFC_N_MAC_ADDRESSES;
	return  0;
}


static int
hxge_pfc_config_init(struct hxge_adapter *  hxgep)
{
	void *  handle;
	handle = hxgep->hw.hw_addr;

	MUTEX_ENTER(&hxgep->lock);

	(void) hpi_pfc_set_tcam_enable(handle, FALSE);
	(void) hpi_pfc_set_l2_hash(handle, TRUE);

	if (hxgep->flags & (HXGE_RX_CHKSUM_ENABLED | HXGE_TX_CHKSUM_ENABLED))
		(void) hpi_pfc_set_tcp_cksum(handle, TRUE);
	else
		(void) hpi_pfc_set_tcp_cksum(handle, FALSE);

	(void) hpi_pfc_set_default_dma(handle, 0);
	(void) hpi_pfc_mac_addr_enable(handle, 0);
	(void) hpi_pfc_set_force_csum(handle, FALSE);

	/* Clear the interrupt masks */
	hpi_pfc_set_interrupt_mask(handle, 0, 0, 0);
        hpi_pfc_set_drop_log_mask(handle, 1, 1, 1, 1, 1);

	MUTEX_EXIT(&hxgep->lock);
	return  0;
}

int
hxge_pfc_hw_reset(struct hxge_adapter *  hxgep)
{
	int status = 0;

	HXGE_DBG(hxgep, "==> hxge_pfc_hw_reset");

	status = hxge_pfc_config_init(hxgep);
	if (status != 0) {
		HXGE_ERR(hxgep, "failed PFC config init.");
		return (status);
	}

	return  0;
}


static int hxge_pfc_load_hash_table(struct hxge_adapter *hxgep)
{
	hpi_handle_t handle = hxgep->hw.hw_addr;
	int i;


	hpi_pfc_set_l2_hash(handle, FALSE);

	for (i = 0; i < MAC_MAX_HASH_ENTRY; i++) 
		if (hpi_pfc_set_multicast_hash_table(handle, i, 
						hxgep->mcast_hash_tbl[i])) {
			HXGE_ERR(hxgep, "hpi_pfc_set_multicast_hash_table failed");
			return -1;
	}

	hpi_pfc_set_l2_hash(handle, TRUE);
	return 0;

}

/* Took this routine from ether_crc_le in linux/crc32.h and modified the 
 * way that the ethernet address is passed. Hydra computes the 
 * address backwards i.e pass the highest octet first and work backwards
 * to the lowest octet
 */
static 
uint32_t crc32_le(unsigned char const *addr, size_t len)
{
        int i;
	uint32_t crc = 0xffffffff;

        while (len--) {
                crc ^= addr[len];
                for (i = 0; i < 8; i++)
                        crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
        }
        return ((~crc) >> 24);
}

void hxge_set_multi (struct net_device *dev)
{
	struct hxge_adapter *hxgep = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
	struct dev_mc_list *dmi = dev->mc_list;
#else
	struct netdev_hw_addr *dmi;
#endif
	uint16_t *filter_tbl= &hxgep->mcast_hash_tbl[0];
	uint32_t crc;
	uint8_t byte = 0;
	
	spin_lock(&hxgep->lock);

       if (dev->flags & IFF_PROMISC)
       {
               HXGE_DBG(hxgep, "PROMISC enabled");
               hxge_vmac_promisc(hxgep, 1);
       }
       else {
               HXGE_DBG(hxgep, "PROMSC disabled");
               hxge_vmac_promisc(hxgep, 0);
       }

	if (dev->flags & IFF_ALLMULTI) 
	{
		HXGE_DBG(hxgep, "Setting allmulti");
		byte = 0xff;
	}

	memset(filter_tbl, byte, sizeof(uint16_t)*MAC_MAX_HASH_ENTRY);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
	while (dmi) {
		HXGE_DBG(hxgep, "Adding %x:%x:%x:%x:%x:%x", dmi->dmi_addr[0],dmi->dmi_addr[1],dmi->dmi_addr[2],dmi->dmi_addr[3],dmi->dmi_addr[4],dmi->dmi_addr[5]);
		crc = crc32_le(dmi->dmi_addr, ETH_ALEN);
		filter_tbl[crc/MAC_MAX_HASH_ENTRY] |= 
				1 << (crc%MAC_MAX_HASH_ENTRY);
		dmi = dmi->next;
	}
#else
	netdev_for_each_mc_addr(dmi, dev) {
		crc = crc32_le(dmi->addr, ETH_ALEN);
		filter_tbl[crc/MAC_MAX_HASH_ENTRY] |= 
				1 << (crc%MAC_MAX_HASH_ENTRY);
	}
#endif
	hxge_pfc_load_hash_table(hxgep);
	spin_unlock(&hxgep->lock);
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
irqreturn_t 
hxge_pfc_intr(int irq, void *data, struct pt_regs *regs)
#else
irqreturn_t 
hxge_pfc_intr(int irq, void *data)
#endif
{
	struct hxge_ldv *ldvp	= (struct hxge_ldv *)data;
        struct hxge_ldg *ldgp = ldvp->ldgp;
	struct hxge_adapter *hxgep = ldgp->hxgep;
	void * 		handle;
	p_hxge_pfc_stats_t	statsp;
	pfc_int_status_t	int_status;
	pfc_bad_cs_counter_t	bad_cs_count;
	pfc_drop_counter_t	drop_count;
	pfc_drop_log_t		drop_log;
	pfc_vlan_par_err_log_t	vlan_par_err_log;
	pfc_tcam_par_err_log_t	tcam_par_err_log;

	handle = hxgep->hw.hw_addr;
	statsp = (p_hxge_pfc_stats_t)&hxgep->statsp->pfc_stats;

	/*
	 * need to read the pfc interrupt status register to figure out
	 * what is happenning
	 */
	hpi_pfc_get_interrupt_status(handle, &int_status);

	if (int_status.bits.pkt_drop) {
		statsp->pkt_drop++;

		/* Collect each individual drops */
		hpi_pfc_get_drop_log(handle, &drop_log);

		if (drop_log.bits.l2_addr_drop) {
			statsp->errlog.l2_addr_drop++;
			HXGE_DBG(hxgep, "dropped => l2_addr");
		}
		if (drop_log.bits.class_code_drop) {
			statsp->errlog.class_code_drop++;
			HXGE_DBG(hxgep, "dropped => class_code");
		}
		if (drop_log.bits.tcam_drop) {
			statsp->errlog.tcam_drop++;
			HXGE_DBG(hxgep, "dropped => tcam_drop");
		}
		if (drop_log.bits.tcp_ctrl_drop) {
			statsp->errlog.tcp_ctrl_drop++;
			HXGE_DBG(hxgep, "dropped => tcp_ctrl");
		}

		/* Collect the total drops for all kinds */
		(void) hpi_pfc_get_drop_counter(handle, &drop_count.value);
		statsp->drop_count += drop_count.bits.drop_count;
	}

	if (int_status.bits.tcam_parity_err) {
		statsp->tcam_parity_err++;

		(void) hpi_pfc_get_tcam_parity_log(handle, &tcam_par_err_log);
		statsp->errlog.tcam_par_err_log = tcam_par_err_log.bits.addr;
		HXGE_DBG(hxgep, "hxge_pfc_intr: TCAM parity error addr: 0x%x",tcam_par_err_log.bits.addr);
	}

	if (int_status.bits.vlan_parity_err) {
		statsp->vlan_parity_err++;

		(void) hpi_pfc_get_vlan_parity_log(handle, &vlan_par_err_log);
		statsp->errlog.vlan_par_err_log = vlan_par_err_log.bits.addr;

		HXGE_DBG(hxgep, "hxge_pfc_intr: vlan table parity error addr: 0x%x", vlan_par_err_log.bits.addr);
	}

	(void) hpi_pfc_get_bad_csum_counter(handle, &bad_cs_count.value);
	statsp->bad_cs_count += bad_cs_count.bits.bad_cs_count;

	(void) hpi_pfc_clear_interrupt_status(handle);
	return (IRQ_HANDLED);
}

int
hxge_pfc_mac_addr_get(struct hxge_adapter *  hxgep, int slot, uint8_t *mac_addr)
{
	hpi_status_t	hpi_status = HPI_SUCCESS;
	hpi_handle_t handle = hxgep->hw.hw_addr;

	/* MAC is in big-endian format now because callers require it that
 	 * way
 	 */
	hpi_status = hpi_pfc_get_mac_address(handle, slot, mac_addr);
	if (hpi_status != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "slot %d failed", slot);
		return (-1 | hpi_status);
	}

        if (!is_valid_ether_addr(mac_addr)) {
                return -1;
	}

	return (0);
}


/* Look for MAC address from the 16 that are available. We program the
   net_device with the first valid mac address that we find. This routine
   only fails if we have not found any valid mac addressess.
*/

int
hxge_pfc_mac_addrs_get(struct hxge_adapter *hxgep)
{
	int i, num_found = 0, nmacs;
	uint8_t        mac_addr[ETH_ALEN];

	hxge_pfc_num_macs_get(hxgep, &nmacs);
	for (i = 0; i < nmacs; i++) {
		if (hxge_pfc_mac_addr_get(hxgep, i, mac_addr)) {
			HXGE_DBG(hxgep, "Slot %d No valid MAC address",i);
			continue;
		} else {
			if (num_found==0) { /* Primary MAC */
//				HXGE_ERR(hxgep,
//				"Setting Net Device MAC address %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
//					mac_addr[0], mac_addr[1], mac_addr[2],
//					mac_addr[3], mac_addr[4], mac_addr[5]);

				/* Copy the MAC address into net_device struct */
				memcpy(hxgep->netdev->dev_addr, mac_addr, ETH_ALEN);
				/* Used by ethtool */
				memcpy(hxgep->netdev->perm_addr, mac_addr, ETH_ALEN);
			num_found++;
			}
		} 

//		memcpy(&hxgep->vmac.mac_addr[i], mac_addr, ETH_ALEN);
	}

	if (!num_found)
		return -1;	/* FAIL if not at least one valid MAC address */

	return 0;
}

/* This routine is called from the probe function. It reads the MAC addresses
 * from the HCR register space and writes them to the PFC MAC address
 * registers which are used by the interface to filter MAC addresses
 */
int 
hxge_pfc_init_mac_addrs(struct hxge_adapter *hxgep)
{
	int nmacs,i;
	pfc_mac_addr_t mac_addr;
	hpi_handle_t handle = hxgep->hw.hw_addr;

	uint32_t addr_hi, addr_lo;
	peu_debug_training_vec_t blade;
	int offset;
	int hcr_mac_count;
	peu_intr_stat_t peusts;

	hxge_pfc_num_macs_get(hxgep, &nmacs);

	/* CR 6687755 Skewed SPROM vs HCR offsets */

	HXGE_REG_RD32(handle, PEU_DEBUG_TRAINING_VEC, &blade.value);
	HXGE_DBG(hxgep, "Base address 0x%p", handle);
	HXGE_DBG(hxgep, "...   PEU_DEBUG_TRAINING_VEC 0x%8.8x", blade.value);
	HXGE_DBG(hxgep, "...   Blade number (U/L) %d/%d",
		 blade.bits.bld_num_upper, blade.bits.bld_num_lower);

	if (blade.bits.bld_num_upper) {
		offset = 0x08;	/* Hydra blade/ports 1-5 MAC count at 8 */
	} else {
		offset = 0x04;	/* Hydra blade/port 0 MAC count at 4 */
	}

	/* Get count of SPROM/HCR-resident static MAC addresses */

	HXGE_REG_RD32(handle, HCR_REG + offset, &addr_lo);
	hcr_mac_count = (addr_lo >> 8) & 0xffffff; /* MAC count in [31:08] */
	if (hcr_mac_count > 4) {
		HXGE_ERR(hxgep, "HCR MAC count %d too large",
			 hcr_mac_count);
		hcr_mac_count = 1; /* Only use first entry */
	}

	HXGE_DBG(hxgep, "...   HCR_REG_CNT 0x%8.8x (= %d)", addr_lo, hcr_mac_count);

	offset += 4;		/* Step to first HCR MAC address */

	/* Initialize ("fill") PFC with MAC addresses; copy all static
	 * MAC addresses from SPROM (HCR registers) into PFC, zero-filling
	 * the rest of the PFC
	 */

	for (i = 0; i < nmacs; i++, hcr_mac_count--) {
		if (hcr_mac_count > 0) {
			HXGE_REG_RD32(handle, HCR_REG + offset, &addr_lo);
			HXGE_REG_RD32(handle, HCR_REG + offset+4, &addr_hi);
			offset += 8;
			/* Device error interrupt not yet enabled so must
			 * poll PEU_INTR_STAT to get a timely HCR parity
			 * error report
			 */
			HXGE_REG_RD32(handle, PEU_INTR_STAT, &peusts.value);
			if (peusts.bits.hcr_parerr) {
				HXGE_ERR(hxgep, "HCR Parity Error (PEU_INTR_STAT=0x%8.8x) reading MAC %d",
					 peusts.value, i);
				return (-1); /* Init failed */
			}
		} else {
			addr_lo = 0; /* No more SPROM MAC addresses, so */
			addr_hi = 0; /*   fill rest of PFC with zeros */
		}

		mac_addr.byte[5] = ((addr_lo)) & 0xff; /* First 4 MAC octets */
		mac_addr.byte[4] = ((addr_lo) >>  8) & 0xff;
		mac_addr.byte[3] = ((addr_lo) >> 16) & 0xff;
		mac_addr.byte[2] = ((addr_lo) >> 24) & 0xff;
		mac_addr.byte[1] = ((addr_hi)) & 0xff; /* Final 2 MAC octets */
		mac_addr.byte[0] = ((addr_hi) >>  8) & 0xff;

		if (hcr_mac_count > 0) {
			HXGE_ERR(hxgep, "Initializing static MAC address %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
				 mac_addr.byte[5], mac_addr.byte[4],
				 mac_addr.byte[3], mac_addr.byte[2],
				 mac_addr.byte[1], mac_addr.byte[0]);
		}

		hxge_pfc_set_mac_address(hxgep, i, mac_addr);
	}

	if (hxge_pfc_mac_addrs_get(hxgep))
		return -1;

	return 0;
}
