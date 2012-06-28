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

static const char hxge_driver_string[] = "Sun Microsystems(R) 10 Gigabit  Network Driver";
#ifndef CONFIG_HXGE_NAPI
#define DRIVERNAPI
#else
#define DRIVERNAPI "-NAPI"
#endif
#define DRV_VERSION "1.3.4"
const char hxge_driver_version[] = DRV_VERSION;
static const char hxge_copyright[] = "Copyright (c) 2009, 2011 Oracle America.";


lb_property_t lb_properties[] = {
        {normal, "normal", hxge_lb_normal},
        {external, "external10g", hxge_lb_ext10g}
};


/* hxge_pci_tbl - PCI Device ID Table
 *
 * Last entry must be all 0s
 *
 * Macro expands to...
 *   {PCI_DEVICE(PCI_VENDOR_ID_INTEL, device_id)}
 */
static struct pci_device_id hxge_pci_tbl[] = {
	SUN_ETHERNET_DEVICE(PCI_DEVICE_ID_SUN_HYDRA),
	/* required last entry */
	{0,}
};
MODULE_DEVICE_TABLE(pci, hxge_pci_tbl);

/* External Functions */
extern int hxge_pfc_init_mac_addrs(struct hxge_adapter *hxgep);
extern int hxge_pfc_hw_reset(struct hxge_adapter *hxgep);
extern int hxge_init_param(struct hxge_adapter *hxgep);
extern void hxge_init_stats(struct hxge_adapter *hxgep);
extern void hxge_free_stats(struct hxge_adapter *hxgep);
extern int hxge_set_mac_address(struct net_device *netdev, void *p);
extern int hxge_vmac_init(struct hxge_adapter *hxgep);
extern void hxge_vmac_uninit(struct hxge_adapter *hxgep);
extern int hxge_link_intr(struct hxge_adapter *hxgep, int cmd);
extern int hxge_get_option(const char *str, int *val);
extern void hxge_enable_interrupts(struct hxge_adapter *hxgep);
extern int hxge_enable_rx(struct hxge_adapter *hxgep);
extern int hxge_enable_tx(struct hxge_adapter *hxgep);
extern int hxge_disable_rx(struct hxge_adapter *hxgep);
extern int hxge_disable_tx(struct hxge_adapter *hxgep);
extern void hxge_disable_interrupts(struct hxge_adapter *hxgep);
extern int hxge_alloc_rx(struct hxge_adapter *hxgep);
extern int hxge_alloc_tx(struct hxge_adapter *hxgep);
extern int hxge_setup_interrupt (struct net_device *netdev);
extern void hxge_teardown_interrupt(struct hxge_adapter *hxgep);
extern int hxge_peu_get_link_status(struct hxge_adapter *hxgep);
extern int hxge_free_rx(struct hxge_adapter *hxgep);
extern int hxge_ok_to_continue(struct hxge_adapter *hxgep);
extern int hxge_block_reset(struct hxge_adapter *hxgep, int device);
extern int hxge_peu_deverr_init(struct hxge_adapter *hxgep);
extern void hxge_free_tx(struct hxge_adapter *hxgep);
extern void hxge_reset_tx_channel(struct hxge_adapter *hxgep, int channel);
extern void hxge_reset_rx_channel(struct hxge_adapter *hxgep, int channel);
extern int hxge_reset_tdc(struct hxge_adapter *hxgep);
extern int hxge_reset_rdc(struct hxge_adapter *hxgep);
#ifdef CONFIG_HXGE_NAPI
extern int hxge_poll(struct net_device *poll_dev, int *budget);
#endif
extern int hxge_start_xmit(struct sk_buff *skb, struct net_device *netdev);
extern struct net_device_stats *hxge_get_stats(struct net_device *netdev);
extern int hxge_classify_init(struct hxge_adapter *hxgep);
extern int hxge_classify_uninit(struct hxge_adapter *hxgep);
extern void hxge_vlan_rx_register(struct net_device *netdev, struct vlan_group *grp);
extern void hxge_vlan_rx_add_vid(struct net_device *netdev, uint16_t vid);
extern void hxge_vlan_rx_kill_vid(struct net_device *netdev, uint16_t vid);
extern void hxge_set_multi(struct net_device *netdev);
extern int hxge_get_tcam_properties(struct hxge_adapter *hxgep);
extern int hxge_set_loopback(struct hxge_adapter *hxgep, boolean_t enable);

#ifdef CONFIG_ERRINJECT
extern int hxge_create_sysfs(struct net_device *netdev);
extern void hxge_remove_sysfs(struct net_device *netdev);
#endif


/* Local Function Prototypes */

static int hxge_init_module(void);
static void hxge_exit_module(void);
static int hxge_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void __devexit hxge_remove(struct pci_dev *pdev);
static int hxge_open(struct net_device *netdev);
static int hxge_close(struct net_device *netdev);
static int hxge_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd);
static int hxge_change_mtu(struct net_device *netdev, int new_mtu);
static int hxge_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd);
static void hxge_tx_timeout(struct net_device *dev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static void hxge_work_to_do(struct hxge_adapter *hxgep);
#else
static void hxge_work_to_do(struct work_struct *work);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
#define DMA_MASK	DMA_BIT_MASK(32)
#else
#define DMA_MASK	DMA_32BIT_MASK
#endif


static int hxge_sw_init(struct hxge_adapter *adapter);
static int hxge_link_monitor(struct hxge_adapter *hxgep, int cmd);
#ifdef CONFIG_NET_POLL_CONTROLLER
/* for netdump / net console */
static void hxge_netpoll (struct net_device *netdev);
#endif

static struct pci_driver hxge_driver = {
	.name     = HXGE_DRIVER_NAME,
	.id_table = hxge_pci_tbl,
	.probe    = hxge_probe,
	.remove   = __devexit_p(hxge_remove),
};

MODULE_AUTHOR("Oracle Corporation, <james.puthukattukaran@oracle.com>");
MODULE_DESCRIPTION("Oracle Corporation(R) 10 Gigabit Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

static int debug = NETIF_MSG_HW | NETIF_MSG_PROBE;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "Debug level (0=none,...,16=all)");

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
spinlock_t hxge_lock = SPIN_LOCK_UNLOCKED; /* HXGE PIO global lock */
#else
DEFINE_SPINLOCK(hxge_lock);
#endif

/**
 * hxge_init_module - Driver Registration Routine
 *
 * hxge_init_module is called when the driver is loaded. It registers
 * the driver with the PCI subsystem 
 **/

static int __init
hxge_init_module(void)
{
	int ret;
	printk(KERN_INFO "%s - version %s\n",
	       hxge_driver_string, hxge_driver_version);

	printk(KERN_INFO "%s\n", hxge_copyright);

	ret = pci_register_driver(&hxge_driver);

	return ret;
}
module_init(hxge_init_module);

/**
 * hxge_exit_module - Driver Exit Routine
 *
 * hxge_exit_module is called when driver is unloaded via rmmod. It 
 * unregisters itself from the PCI subsystem
 *
 **/

static void __exit
hxge_exit_module(void)
{
	pci_unregister_driver(&hxge_driver);
}
module_exit(hxge_exit_module);

/**
 * hxge_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/

static void
hxge_irq_disable(struct hxge_adapter *adapter)
{
	atomic_inc(&adapter->irq_sem);
	hxge_disable_interrupts(adapter);
	synchronize_irq(adapter->pdev->irq);
}

/**
 * hxge_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 **/

static void
hxge_irq_enable(struct hxge_adapter *adapter)
{
	if (likely(atomic_dec_and_test(&adapter->irq_sem))) {
		hxge_enable_interrupts(adapter);
	}
}

/* Ignores linux network stack niceties and brings down the adapter */
void
hxge_disable_adapter(struct hxge_adapter *hxgep)
{
	/* Disable interrupts */
	hxge_disable_interrupts(hxgep);

	/* Disable TCAM */
	hxge_classify_uninit(hxgep);	

	/* Disable VMAC interface  */
        hxge_vmac_uninit(hxgep);

        /* Disable all Tx channels */
        hxge_disable_tx(hxgep);

        /* Disable all Rx channels */
        hxge_disable_rx(hxgep);

	/* Do a PEU reset to take care of CR 6668282 in the event that 
 	 * the PCI links are not left in the proper state 
 	 */
	hxge_block_reset(hxgep, (LDV_RXDMA | LDV_TXDMA | LDV_VMAC));
}

int
hxge_enable_adapter(struct hxge_adapter *hxgep)
{
	/* Do reset of all the major blocks, especially those that
           are shared across channels and potentially blades. This is done
	   via the PEU space */
	hxge_block_reset(hxgep, (LDV_RXDMA | LDV_TXDMA | LDV_VMAC));

        /* Enable Tx DMA channels */
        if (hxge_enable_tx(hxgep)) 
	{	
		if (!test_bit(HXGE_DEVICE_UP, &hxgep->state)) {
			HXGE_ERR(hxgep, "hxge_enable_adapter: hxge_enable_tx failed");
			hxge_disable_adapter(hxgep);
			return -1;
		}
	}

        /* Enable the Rx DMA channels */
        hxge_enable_rx(hxgep);

	/* Allocate and enable TCAM */
	hxge_classify_init(hxgep);

        hxge_vmac_init(hxgep);

	/* Now that all the feeds into Device Error (PEU, TDC, etc.)
	 * have been cleared/initialized, enable the Device Error
	 * [logical] device/function */

	if (hxge_peu_deverr_init(hxgep))
		return -1;

	/* Enable interrupts for all devices */
	hxge_enable_interrupts(hxgep);

	return 0;
}

static int
hxge_lif_up(struct hxge_adapter *hxgep)
{
	struct net_device *netdev = hxgep->netdev;

	/* Start link monitoring */
	hxgep->prev_link_status = -1;
	hxge_link_monitor(hxgep, LINK_MONITOR_START);

#ifdef CONFIG_HXGE_NAPI
	netif_poll_enable(netdev);
#endif

	if (hxge_enable_adapter(hxgep))
		return -1;

	hxge_irq_enable(hxgep);

	/* Enable Linux network stack */
	netif_carrier_on(netdev);
	netif_start_queue(netdev);

	set_bit(HXGE_DEVICE_UP, &hxgep->state);
	return 0;
}

static int
hxge_up(struct hxge_adapter *hxgep)
{
	/* If we were in error shutdown state, this constitutes a
         * manual intervention to bring it back up again. */

	clear_bit(HXGE_DEVICE_SHUTTINGDOWN, &hxgep->state);

	hxgep->statsp->accum_hard_errors += hxgep->statsp->hard_errors;
	hxgep->statsp->accum_soft_errors += hxgep->statsp->soft_errors;
	hxgep->statsp->accum_line_errors += hxgep->statsp->line_errors;
	hxgep->statsp->hard_errors = 0;	/* Reset all error rate counters */
	hxgep->statsp->soft_errors = 0;
	hxgep->statsp->line_errors = 0;
	hxgep->ifup_time = jiffies; /* "t = 0" for error rate calc */

	return(hxge_lif_up (hxgep)); /* local interface "up" work */
}

static void
hxge_down(struct hxge_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	clear_bit(HXGE_DEVICE_UP, &adapter->state);

	hxge_link_monitor(adapter, LINK_MONITOR_STOP);
	netif_carrier_off(netdev); /* avoids Tx timeouts */
	netif_stop_queue(netdev);

#ifdef CONFIG_HXGE_NAPI
	netif_poll_disable(netdev);
#endif
	hxge_irq_disable(adapter);

	/* Reset the adapter */
	hxge_disable_adapter(adapter);
}


/* This routine memory maps the Hydra register (PIO/BAR0) */
static int hxge_map_registers(struct net_device *netdev)
{
	unsigned long pio_base, pio_len;
	struct hxge_adapter *adapter= netdev_priv(netdev);
	struct pci_dev *pdev = adapter->pdev;
	int err;
	u32 vendorid;

        pio_base = pci_resource_start(pdev, BAR_0);
        pio_len = pci_resource_len(pdev, BAR_0);

        err = -EIO;
        adapter->hw.hw_addr = ioremap(pio_base, pio_len);
        if (!adapter->hw.hw_addr)
		return err;

	/* There is a bug in the HW (we think) where the link retrain, which is
	   as part of the ASPM common clock configuration code, fails.
	   Consequently, the device is left in a completely initialized state
           i.e. the BARs are reset and inaccessible by the time the driver is
	   loaded. We have verified that bypassing the common clock
	   configuration code works around the problem (pcie_aspm=off). This 
	   is a warning/informative message to the customer to check if the 
	   boot argument is passed
	*/
	vendorid= readl(adapter->hw.hw_addr + PCI_VENDOR_ID);
	if (vendorid== 0xffffffff) {
		HXGE_ERR(adapter,"Device probe failed. The PCI BAR space is inaccessible! You may want to set the boot argument pcie_aspm=off");
	}

        netdev->mem_start = pio_base;
        netdev->mem_end = pio_base + pio_len;

	return 0;
}

/* This function runs periodically trigger off the one-shot timer and 
   periodically monitors the link status (if monitoring is enabled). 
   It notifies the kernel (linux network stack) of change in link status
   so that the traffic control subsystem can take appropriate action */

static void hxge_watchdog_timer(unsigned long data)
{
	struct hxge_adapter *hxgep = (struct hxge_adapter *)data;
	int link_up = hxge_peu_get_link_status(hxgep);

	/* Calling either netif_carrier_on if link is already up does nothing.
	   Similarly, calling netif_carrier_down if link is down does nothing
           either */

	if (link_up)
		netif_carrier_on(hxgep->netdev);
	else
		netif_carrier_off(hxgep->netdev);

	/* Log a change in link status */
	if (hxgep->prev_link_status != link_up) {
		HXGE_ERR(hxgep, "hxge_watchdog_timer: link is %s", (link_up) ? "up":"down");	
		hxgep->prev_link_status = link_up;
	}
	mod_timer (&hxgep->wd_timer, jiffies + HXGE_LINK_TIMEOUT);
}


/* Initialize link management */
static void hxge_init_link(struct hxge_adapter *hxgep)
{
	hxgep->link_monitor_state = LINK_MONITOR_DISABLED;
	hxgep->link_mode = LINK_MODE_POLL;
	setup_timer(&hxgep->wd_timer,hxge_watchdog_timer,(unsigned long)hxgep);
}

/* Start or stop link monitoring. If we want to be interrupted for a link 
   state change, then we call this routine just once when turning on 
   interrupt monitoring. For polling, this routine is called periodically
   every HX_LINK_TIMEOUT seconds and the one-shot timer is set for the next
   period. */
static int hxge_link_monitor(struct hxge_adapter *hxgep, int cmd)
{
	if (netif_msg_link(hxgep)) {
		HXGE_DBG(hxgep, "hxge_link_monitor: cmd = %d",cmd);
		if (hxgep->link_monitor_state == LINK_MONITOR_DISABLED) {
			HXGE_DBG(hxgep, "hxge_link_monitor: Link monitoring disabled");
		}
		else {
			HXGE_DBG(hxgep, "hxge_link_monitor: Link monitoring enabled");
		}
	}

	hxgep->statsp->link_monitor_cnt++;
	switch (cmd) {
		case LINK_MONITOR_START:
		   /* Assert an interrupt when link state changes. */
		   if (hxgep->link_mode == LINK_MODE_INTR) {
			if (hxge_link_intr(hxgep, cmd))
				goto fail;
		    /* Periodically poll for for state change */
		    } else if (hxgep->link_monitor_state == LINK_MONITOR_DISABLED) {
			hxgep->link_monitor_state = LINK_MONITOR_ENABLED;
			mod_timer (&hxgep->wd_timer, jiffies + HXGE_LINK_TIMEOUT);
		    }
		    HXGE_DBG(hxgep, "hxge_link_monitor: Link monitoring started");
		    break;
		case LINK_MONITOR_STOP: 
		   if (hxgep->link_mode == LINK_MODE_INTR) {
			if (hxge_link_intr(hxgep, cmd))
				goto fail;
		   } else if (hxgep->link_monitor_state == LINK_MONITOR_ENABLED)
		   {   
			hxgep->link_monitor_state = LINK_MONITOR_DISABLED;
			del_timer_sync(&hxgep->wd_timer);
		   }
		    HXGE_DBG(hxgep, "hxge_link_monitor: Link monitoring stopped");
		   break;
		default:
		   HXGE_ERR(hxgep, "hxge_link_monitor: Unknown command");
		   break;
	}
	return 0;

fail:
	HXGE_ERR(hxgep, "hxge_link_monitor: failed");
	return -1;
}

	

static void hxge_init_locks(struct hxge_adapter *hxgep)
{
	spin_lock_init(&hxgep->lock);
	spin_lock_init(&hxgep->stats_lock);
	spin_lock_init(&hxgep->tcam_lock);
	rwlock_init(&hxgep->wtd_lock);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
static const struct net_device_ops hxge_netdev_ops = {
        .ndo_open               = hxge_open,
        .ndo_stop               = hxge_close,
        .ndo_start_xmit         = hxge_start_xmit,
        .ndo_get_stats          = hxge_get_stats,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
        .ndo_set_multicast_list = hxge_set_multi,
#else
	.ndo_set_rx_mode	= hxge_set_multi,
#endif
        .ndo_validate_addr      = eth_validate_addr,
        .ndo_set_mac_address    = hxge_set_mac_address,
        .ndo_do_ioctl           = hxge_ioctl,
        .ndo_tx_timeout         = hxge_tx_timeout,
        .ndo_change_mtu         = hxge_change_mtu,
       .ndo_vlan_rx_register   = hxge_vlan_rx_register,
       .ndo_vlan_rx_add_vid    = hxge_vlan_rx_add_vid,
       .ndo_vlan_rx_kill_vid   = hxge_vlan_rx_kill_vid,
#ifdef CONFIG_NET_POLL_CONTROLLER
       .ndo_poll_controller    = hxge_netpoll,
#endif
};
#endif



/**
 * hxge_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in hxge_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * hxge_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/

static int __devinit
hxge_probe(struct pci_dev *pdev,
            const struct pci_device_id *ent)
{
	struct net_device *netdev;
	struct hxge_adapter *adapter;
	static int cards_found = 0;
	int err, pci_using_dac;

	if ((err = pci_enable_device(pdev)))
	{
		HXGE_ERR_PRINT("hxge_probe: Failed to (PCI) enable device");
		return err;
	}

	/* Hydra can address up to 44-bits of physical memory. Let the 
           kernel know */
	if (!(err = pci_set_dma_mask(pdev, HXGE_MAX_ADDRESS_BITS_MASK)) &&
	    !(err = pci_set_consistent_dma_mask(pdev, HXGE_MAX_ADDRESS_BITS_MASK))) {
		pci_using_dac = 1;
	} else {
		if ((err = pci_set_dma_mask(pdev, DMA_MASK)) &&
		    (err = pci_set_consistent_dma_mask(pdev, DMA_MASK))) {
			HXGE_ERR_PRINT("No usable DMA configuration, aborting");
			goto err_dma;
		}
		pci_using_dac = 0;
	}

	if ((err = pci_request_regions(pdev, HXGE_DRIVER_NAME)))
		goto err_pci_reg;

	pci_set_master(pdev);

	err = -ENOMEM;
	netdev = alloc_etherdev(sizeof(struct hxge_adapter));
	if (!netdev)
		goto err_alloc_etherdev;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	SET_MODULE_OWNER(netdev);
#endif

	SET_NETDEV_DEV(netdev, &pdev->dev);

	pci_set_drvdata(pdev, netdev);
	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	adapter->msg_enable = debug;

	if (hxge_map_registers(netdev) < 0)
		goto err_mapfailed;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
	netdev->open = &hxge_open;
	netdev->stop = &hxge_close;
	netdev->hard_start_xmit = &hxge_start_xmit;
	netdev->get_stats = &hxge_get_stats;
	netdev->set_multicast_list = &hxge_set_multi;
	netdev->set_mac_address = &hxge_set_mac_address;
	netdev->change_mtu = &hxge_change_mtu;
	netdev->do_ioctl = &hxge_ioctl;
	netdev->tx_timeout = &hxge_tx_timeout;
	netdev->vlan_rx_register = hxge_vlan_rx_register;
	netdev->vlan_rx_add_vid = hxge_vlan_rx_add_vid;
	netdev->vlan_rx_kill_vid = hxge_vlan_rx_kill_vid;
#ifdef CONFIG_NET_POLL_CONTROLLER
	netdev->poll_controller = hxge_netpoll;
#endif
#else
	netdev->netdev_ops = &hxge_netdev_ops;
#endif

	hxge_set_ethtool_ops(netdev);
#ifdef CONFIG_HXGE_NAPI
	netdev->poll = &hxge_poll;
	netdev->weight = 64;
#endif
	netdev->watchdog_timeo = HXGE_TX_TIMEOUT;
	strncpy(netdev->name, pci_name(pdev), strlen(pci_name(pdev)));

	adapter->bd_number = cards_found;

	HXGE_DBG(adapter, "Allocated adapter");

	/* Initialize locks */
	hxge_init_locks(adapter);
	HXGE_DBG(adapter, "Got Locks");

	/* Get the driver parameters */
	if (hxge_init_param(adapter))
		goto err_register;
	HXGE_DBG(adapter, "Initialized parameter list");

	/* setup the private structure */
	if ((err = hxge_sw_init(adapter)))
		goto err_sw_init;
	HXGE_DBG(adapter, "Initialized hxgep with parameters");

        if (hxge_pfc_hw_reset(adapter))
        {
                HXGE_ERR(adapter, "hxge_probe: Failed hxge_pfc_hw_reset");
                goto err_register;
        }
	HXGE_DBG(adapter, "Reset the HW");

	/* Initialize link management */
	hxge_init_link(adapter);
	HXGE_DBG(adapter, "Initialized the link");

	/* Initialize and set up statistics for the device */
	hxge_init_stats(adapter);
	HXGE_DBG(adapter, "Initialized stats");

	err = -EIO;

	if (pci_using_dac)
		netdev->features |= NETIF_F_HIGHDMA;

	/* We have to provide our own locking for transmit */
	netdev->features |= NETIF_F_LLTX;
	netdev->features |= NETIF_F_SG;


	if (adapter->flags & HXGE_TX_CHKSUM_ENABLED)
		netdev->features |= (NETIF_F_IP_CSUM 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
				| NETIF_F_IPV6_CSUM
#endif
				);


	if (adapter->flags & HXGE_VLAN_ENABLED)
		netdev->features |= NETIF_F_HW_VLAN_RX | NETIF_F_HW_VLAN_FILTER;
					
	
	/* copy the MAC address from the PFC block; all 16 of them */
	if (hxge_pfc_init_mac_addrs(adapter)) {
		HXGE_ERR(adapter, "EEPROM Read Error");
		goto err_sw_init;
	}
	HXGE_DBG(adapter, "Initialized MAC addresses");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	INIT_WORK(&adapter->work_to_do,
		(void (*)(void *))hxge_work_to_do, adapter);
#else
	INIT_WORK(&adapter->work_to_do, hxge_work_to_do);
#endif

	/* we're going to reset the device because we have no clue what
           state we find it in */
	netif_carrier_off(netdev);
	netif_stop_queue(netdev);

	strcpy(netdev->name, "eth%d");
	if ((err = register_netdev(netdev)))
		goto err_register;

	HXGE_DBG(adapter, "hxge_probe: SMI(R) 10 Gb Ethernet Network Connection");

#ifdef CONFIG_ERRINJECT
	hxge_create_sysfs(netdev);
#endif
	cards_found++;
	set_bit (HXGE_DEVICE_INITIALIZED, &adapter->state);
	return 0;

err_register:
err_sw_init:
	iounmap(adapter->hw.hw_addr);
err_mapfailed:
	free_netdev(netdev);
err_alloc_etherdev:
	pci_release_regions(pdev);
err_pci_reg:
err_dma:
	pci_disable_device(pdev);
	return err;
}

/**
 * hxge_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * hxge_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/

static void __devexit
hxge_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct hxge_adapter *adapter = netdev_priv(netdev);

	if (!netdev)
		return;

	set_bit(HXGE_DRIVER_REMOVING, &adapter->state);
#ifdef CONFIG_ERRINJECT
	hxge_remove_sysfs(netdev);
#endif

	/* 
 	 * grab the wtd lock before calling flush_scheduled work. Also called
 	 * in hxge_down. However, if we are calling hxge_down via hxge_close
 	 * from hxge_remove (when we do a rmmod without ifconfig down), we 
 	 * could have a nasty deadlock situation. See hxge_down for details.
 	 * 
 	 */
	write_lock(&adapter->wtd_lock);
	
	flush_scheduled_work();
	unregister_netdev(netdev);

	write_unlock(&adapter->wtd_lock);

	hxge_free_stats(adapter);

	iounmap(adapter->hw.hw_addr);
	pci_release_regions(pdev);

	free_netdev(netdev);

	pci_disable_device(pdev);
}

/**
 * hxge_sw_init - Initialize general software structures (struct hxge_adapter)
 * @adapter: board private structure to initialize
 *
 * hxge_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/

static int __devinit
hxge_sw_init(struct hxge_adapter *adapter)
{
	int flags;
	int tcam;

	adapter->max_tdcs = HXGE_MAX_TDCS; /* max Tx DMA channels per blade */
	adapter->max_rdcs = HXGE_MAX_RDCS; /* max Rx DMA channels per blade */

	adapter->default_block_size = PAGE_SIZE;
	adapter->num_openers = 0;
	if (hxge_get_option("intr_type", &adapter->intr_type)) {
		HXGE_ERR(adapter, "hxge_sw_init: intr_type failed");
		return -1;
	}

	/* Hydra supports IP (L4) checksumming in hardware */
	if (hxge_get_option("chksum", &flags)) {
		HXGE_ERR(adapter, "hxge_probe: chksum invalid");
		return -1;
	}

	/* When Hydra enables HW TCP/UDP checksumming, it's for both Rx and
         * Tx. There is no finer knob than that. So, when one of them is 
         * disabled via the sw flag, it's still done in HW but ignored and
	 * redone by Linux 
	 */

	if (flags) {
		adapter->flags |= flags;
		if (adapter->flags & HXGE_TX_CHKSUM_ENABLED)
			HXGE_DBG(adapter, "hxge_sw_init: HW TCP/UDP TX Chksum Enabled");
		if (adapter->flags & HXGE_RX_CHKSUM_ENABLED)
			HXGE_DBG(adapter, "hxge_sw_init: HW TCP/UDP RX Chksum Enabled");
	}

	/* Get number of Rx dma channels */
        if (hxge_get_option("rx_dma_channels", &adapter->max_rdcs)) {
                HXGE_ERR(adapter, "Invalid rx_dma_channels option");
                return -1;
        }


	/* Check for TCAM enablement */
        if (hxge_get_option("tcam", &tcam)) {
                HXGE_ERR(adapter, "tcam failed");
                return -1;
        }

	if (!tcam && (adapter->max_rdcs > 1))
	{
		HXGE_ERR(adapter, "running with only 1 rx channel; other channels unused if tcam is disabled");
		adapter->max_rdcs = 1;
	}

	if (tcam && (adapter->max_rdcs < HXGE_MAX_RDCS)) {
		HXGE_ERR(adapter,"cannot have tcam enabled and have less than four channels; tcam needs all four channels enabled to work!");
		return -1;
	}
	
	if (tcam) {
		HXGE_DBG(adapter, "hxge_sw_init: TCAM enabled");
		adapter->flags |= HXGE_TCAM_ENABLED;
	}

	if (hxge_get_option("vlan_id", &adapter->vlan_id)) {
		HXGE_ERR(adapter, "hxge_sw_init: vlan_id failed");
		return -1;
	}

	if (hxge_get_option("vlan", &flags)) {
		HXGE_ERR(adapter, "hxge_sw_init: vlan failed");
		return -1;
	}

	if (flags) {
		HXGE_DBG(adapter, "hxge_sw_init: VLAN enabled");
		adapter->flags |= HXGE_VLAN_ENABLED;
	}

	if (hxge_get_option("tx_mark_ints", &adapter->tx_mark_ints)) {
		HXGE_ERR(adapter, "hxge_sw_init: tx_mark_ints invalid");
		return -1;
	}

	hxge_get_tcam_properties(adapter);

        /* Throughput/latency tuning parameters. Can be changed via eththool */

	if (hxge_get_option("rcr_timeout", &adapter->rcr_timeout)) {
		HXGE_ERR(adapter, "rcr_timeout invalid");
		return -1;
	}

	if (hxge_get_option("rcr_threshold", &flags)) {
		HXGE_ERR(adapter, "rcr_threshold invalid");
		return -1;
	}
	adapter->rcr_threshold = (uint16_t)flags;

	if (hxge_get_option("max_rx_pkts", &flags)) {
		HXGE_ERR(adapter, "max_rx_pkts invalid");
		return -1;
	}
	adapter->max_rx_pkts = (uint16_t)flags;

	return 0;
}


/**
 * hxge_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog timer is started,
 * and the stack is notified that the interface is ready.
 **/

static int
hxge_open (struct net_device *netdev)
{
	struct hxge_adapter *hxgep= netdev_priv(netdev);
	int retval;

	set_bit(HXGE_DEVICE_OPENING, &hxgep->state);
	clear_bit(HXGE_DEVICE_FATAL, &hxgep->state);

	/* Allocate hxge data structures only if first opener */
	if (!hxgep->num_openers) {
		HXGE_DBG(hxgep, "hxge: Allocating I/O buffers and resources");

		if (hxge_alloc_rx (hxgep)) {
			HXGE_ERR(hxgep, "hxge_open: hxge_alloc_rx failed");
			return -1;
		}
	
		if (hxge_alloc_tx (hxgep)) {
			HXGE_ERR(hxgep, "hxge_open: hxge_alloc_tx failed");
			return -1;
		}

		if (hxge_setup_interrupt(netdev)) {
			HXGE_ERR(hxgep, "hxge_open: hxge_setup_interrupt failed");
			return -1;
		}

		set_bit(HXGE_DEVICE_ALLOCATED, &hxgep->state);
	}

	/* Bring up the interface */
	write_lock(&hxgep->wtd_lock);
	spin_lock(&hxgep->lock);
	retval = hxge_up(hxgep);
	spin_unlock(&hxgep->lock);
	write_unlock(&hxgep->wtd_lock);

	hxgep->num_openers++;
	if (retval || test_bit(HXGE_DEVICE_FATAL, &hxgep->state))
	{
		HXGE_ERR(hxgep, "hxge_open: Fatal error bringing hxge up");
		hxge_close(netdev);
		retval = -1;
	}

	/* We're either 'UP' or quiescent (dead) now */

	clear_bit (HXGE_DEVICE_OPENING, &hxgep->state);

	return retval;
}


/**
 * hxge_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 **/

static int
hxge_close(struct net_device *netdev)
{
	struct hxge_adapter *adapter = netdev_priv(netdev);
        int already_locked = test_bit(HXGE_DRIVER_REMOVING, &adapter->state);

	set_bit (HXGE_DEVICE_CLOSING, &adapter->state);
	clear_bit (HXGE_DEVICE_OPENING, &adapter->state);

	/* Bring down the interface */
	if (!already_locked) 
		write_lock(&adapter->wtd_lock);

	/* Force any work queue functions to just run. It will do nothing,
 	 * of course, because the wtd_lock is held by this routine. We just
 	 * want to make sure that nothing is outstanding which could run
 	 * after the driver is removed. That would be very bad. Also, by
 	 * this point, nothing new ever gets scheduled. Need "removing" to
	 * avoid nasty race with linkwatch_event under workqueue thread
         * attempting to get the rtnl_lock (this is really a bug in Linux
  	 * network layer)
 	 */
	if (already_locked)
		flush_scheduled_work();


	spin_lock(&adapter->lock);
	hxge_down(adapter);
	spin_unlock(&adapter->lock);

	if (!already_locked)
		write_unlock(&adapter->wtd_lock);

	/* Free hxge data structures only if last closer */

	adapter->num_openers--;
	if (!adapter->num_openers) {
		HXGE_DBG(adapter, "hxge: Freeing I/O buffers and resources");

		/* Free up allocated resouces */
		hxge_teardown_interrupt(adapter);

		hxge_free_rx(adapter);

		/* Free all Tx data structures */
		hxge_free_tx(adapter);

		clear_bit(HXGE_DEVICE_ALLOCATED, &adapter->state);
	}

	/* Back to quiescent (not UP) state */

	clear_bit (HXGE_DEVICE_CLOSING, &adapter->state);

	return 0;
}


/* Reinitialize the device and driver structures. This is a big hammer 
   that will bring down the interface and bring it back up */
static void hxge_reset_adapter(struct hxge_adapter *hxgep)
{
	HXGE_DBG(hxgep, "hxge_reset_adapter called");
	WARN_ON(in_interrupt());

	/* We are currently being reset. This could happen if there is a
           separate thread of execution, say, from a user command line like 
	   ethtool. Wait till that completes */
	if (test_and_set_bit(HXGE_DEVICE_RESETTING, &hxgep->state)) {
		while (test_bit(HXGE_DEVICE_RESETTING, &hxgep->state))
			msleep(1);
		return;
	}

	/* Shutting down adapter trumps resetting the adapter */
	if (!(test_bit(HXGE_DEVICE_SHUTTINGDOWN, &hxgep->state))) {
		spin_lock(&hxgep->lock);
		hxge_down(hxgep);
		hxge_lif_up (hxgep);	/* Maintain hard_errors/etc. counters */
		spin_unlock(&hxgep->lock);
	}

	clear_bit(HXGE_DEVICE_RESETTING, &hxgep->state);
	HXGE_DBG(hxgep, "hxge_reset_adapter done");
}


/* Take down the hxge device. This is a big hammer that will bring down
   the interface and leave it down until manually brought back up. */
static void hxge_shutdown_adapter(struct hxge_adapter *hxgep)
{
	HXGE_DBG(hxgep, "hxge_shutdown_adapter called");
	WARN_ON(in_interrupt());
	set_bit(HXGE_DEVICE_SHUTTINGDOWN, &hxgep->state);

	/* If an hxge_reset_adapter() is in progress, wait for it to
	   complete. This could happen if there is a separate thread
	   of execution, say, from a user command line like ethtool. */
	while (test_bit(HXGE_DEVICE_RESETTING, &hxgep->state))
		msleep(1);

	spin_lock(&hxgep->lock);
	hxge_down(hxgep);
	spin_unlock(&hxgep->lock);

	/* HXGE_DEVICE_SHUTTINGDOWN only cleared in up/open */

	HXGE_DBG(hxgep, "hxge_shutdown_adapter done");
}


/**
 * hxge_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 **/

static void
hxge_tx_timeout(struct net_device *netdev)
{
	struct hxge_adapter *hxgep= netdev_priv(netdev);

	/* Do the reset outside of interrupt context */
	hxgep->statsp->tx_timeout_cnt++;

	if (netif_queue_stopped(netdev))
		netif_wake_queue(netdev);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static void
hxge_work_to_do(struct hxge_adapter *hxgep)
#else
static void
hxge_work_to_do(struct work_struct *work)
#endif
{
	int i;
	int channel;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	struct hxge_adapter *hxgep = container_of(work, struct hxge_adapter, work_to_do);
#endif

	HXGE_ERR(hxgep, "hxge_work_to_do called on cpu %d",smp_processor_id());
	if (!read_trylock(&hxgep->wtd_lock)) {
		return;
	}

	for (i = 0; i < MAX_CMD; i++) 
		if (test_and_clear_bit(i, &hxgep->work_q.command)) {
			switch (i) {
			   case RESET_TX_CHANNEL_0 : 
			   case RESET_TX_CHANNEL_1 :
			   case RESET_TX_CHANNEL_2 :
			   case RESET_TX_CHANNEL_3 :
				channel =  i - RESET_TX_CHANNEL_0;
				HXGE_ERR(hxgep, "hxge_work_to_do: Resetting Tx channel %d", channel);
				hxge_reset_tx_channel(hxgep, channel);
				break;
			   case RESET_RX_CHANNEL_0 :
			   case RESET_RX_CHANNEL_1 :
			   case RESET_RX_CHANNEL_2 :
			   case RESET_RX_CHANNEL_3 :
				channel =  i - RESET_RX_CHANNEL_0;
				HXGE_ERR(hxgep, "hxge_work_to_do: Resetting Rx channel %d", channel);
				hxge_reset_rx_channel(hxgep, channel);
				break;
			   case RESET_ADAPTER:
				HXGE_ERR(hxgep, "hxge_work_to_do: Resetting adapter");
				hxge_reset_adapter(hxgep);
				break;
			   case RESET_TDC:
				HXGE_ERR(hxgep, "hxge_work_to_do: Resetting TDC core");
				hxge_reset_tdc(hxgep);
				break;
			   case RESET_RDC:
				HXGE_ERR(hxgep, "hxge_work_to_do: Resetting RDC core");
				hxge_reset_rdc(hxgep);
				break;
			   case RESET_PFC:
				/* For now, just reset the whole hxge */
				HXGE_ERR(hxgep, "hxge_work_to_do: Resetting PFC; resetting whole hxge");
				hxge_reset_adapter(hxgep);
				break;
			   case RESET_VMAC:
				/* For now, just reset the whole hxge */
				HXGE_ERR(hxgep, "hxge_work_to_do: Resetting VMAC; resetting whole hxge");
				hxge_reset_adapter(hxgep);
				break;
			   case SHUTDOWN_ADAPTER:
				HXGE_ERR(hxgep, "hxge_work_to_do: Shutting down adapter");
				hxge_shutdown_adapter(hxgep);
				break;
			   default:
				HXGE_ERR(hxgep, "hxge_work_to_do: Uh? unknown command");
				break;
			}
		}
	read_unlock(&hxgep->wtd_lock);
}


/* Bypasses the OS structures and linux network stack niceties and directly
   wacks the adapter. Currently used by ethtool for diagnostic tests where
   the card might not be "up" but could be in an unknown state  */
void hxge_reset (struct hxge_adapter *hxgep)
{
	spin_lock(&hxgep->lock);
	hxge_disable_adapter(hxgep);
	hxge_enable_adapter(hxgep);
	spin_unlock(&hxgep->lock);
}

/**
 * hxge_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/

static int
hxge_change_mtu(struct net_device *dev, int new_mtu)
{
	struct hxge_adapter *hxgep= netdev_priv(dev);
	int old_mtu = dev->mtu;
	int is_jumbo;
	int err = 0;

	HXGE_DBG(hxgep, "hxge_change_mtu : old_mtu=%d, new mtu = %d",old_mtu,new_mtu);
	if (hxge_get_option("enable_jumbo", &is_jumbo)) {
		HXGE_ERR(hxgep, "hxge_change_mtu: Could not read enable_jumbo");
		return -1;
	}

	if ((new_mtu < ETH_ZLEN) || (new_mtu > MAX_JUMBO_FRAME_SIZE))
		return -EINVAL;
	if ((new_mtu > ETH_DATA_LEN) && !is_jumbo)
		return -EINVAL;

	dev->mtu = new_mtu;

	/* The device is not up or the device is not present. In
	   either case, we set the MTU and just return. The MTU
	   for the hardware interface will be set when the 
	   VMAC is initialized */
  	   
        if (!netif_running(dev) || !netif_device_present(dev)) {
		HXGE_DBG(hxgep, "hxge_change_mtu: interface not up");
		return 0;
        }


	/* It is now a jumbo packet. So, we have to reset the adapter. We
         * really want to only reset the Tx but we also change the size of the
         * Rx frame size. So, reset the whole adapter for safety */
	if (old_mtu > new_mtu) {
		hxge_reset_adapter(hxgep);
	}
	else {
		netif_stop_queue(dev);
		hxge_vmac_uninit(hxgep);
		err = hxge_vmac_init(hxgep);
		/* If new mtu failed, then revert to old mtu and reinit vmac.
		 * Return failure to the caller
		 */
		if (err) {
			HXGE_DBG(hxgep, "hxge_change_mtu: Bad MTU size, returning %d",err);
			dev->mtu = old_mtu;
			hxge_vmac_init(hxgep);
		}
		netif_wake_queue(dev);
	}

	if (!err) {
		if (new_mtu > ETH_DATA_LEN)
			hxgep->vmac.is_jumbo = TRUE;
		else
			hxgep->vmac.is_jumbo = FALSE;
	}

	return err; 
} 


static int 
hxge_lb_ioctl(struct hxge_adapter *hxgep, void *data)
{
	struct lb_size_info *lb_size = (struct lb_size_info *)data;
	int cmd = *(int *)data;

	switch (cmd)
	{
		case GET_INFO_SIZE:
			lb_size->size = sizeof(lb_properties);
			HXGE_ERR(hxgep, "hxge_lb_ioctl: lb_size is  %d",lb_size->size);
			break;
		case GET_INFO:
			memcpy((char *)data+sizeof(int),lb_properties,
				sizeof(lb_properties));
			break;
		case GET_LB_MODE:
		       lb_size->size = (uint32_t)hxgep->vmac.loopback;
		       break;
		case SET_LB_MODE:
			hxge_set_loopback(hxgep, (lb_size->size) ?TRUE : FALSE);
		default:
			HXGE_ERR(hxgep, "hxge_lb_ioctl: Unsupported ioctl 0x%x",cmd);
			return -1;
	}

	return 0;
}


/**
 * hxge_ioctl-
 * @netdev:
 * @ifreq:
 * @cmd:
 **/

static int
hxge_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct hxge_adapter *hxgep = netdev_priv(netdev);

	switch (cmd) {
	case LB_IOC:
		if  (!test_bit(HXGE_DEVICE_UP, &hxgep->state)) {
			HXGE_ERR(hxgep, "hxge_ioctl: interface is not up");
			return -1;
		}
		hxge_lb_ioctl(hxgep, ifr->ifr_data); 
		break;

	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
/*
 * Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 */
static void
hxge_netpoll(struct net_device *netdev)
{

}
#endif
