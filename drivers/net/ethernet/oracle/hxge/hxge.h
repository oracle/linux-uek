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

/* Linux Hydra 10GBe Driver main header file */

#ifndef _HXGE_H_
#define _HXGE_H_

#include <linux/version.h>
#include <linux/stddef.h>
#include <linux/module.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/dma-mapping.h>
#include <linux/bitops.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <linux/capability.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/pkt_sched.h>
#include <linux/list.h>
#include <linux/reboot.h>
#ifdef NETIF_F_TSO
#include <net/checksum.h>
#endif
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/version.h>

#include "hxge_defs.h"
#include "hxge_pfc_hw.h"
#include "hxge_peu_hw.h"
#include "hxge_rxdma.h"
#include "hxge_txdma.h"
#include "hxge_vmac.h"
#include "hxge_pfc.h"
#include "hxge_classify.h"

#define BAR_0		0
#define BAR_1		1
#define BAR_5		5

#define ETHERADDRL ETH_ALEN
#define PCI_DEVICE_ID_SUN_HYDRA 0xAAAA

#define SUN_ETHERNET_DEVICE(device_id) {\
	PCI_DEVICE(PCI_VENDOR_ID_SUN, device_id)}

#define MUTEX_INIT(lock, nm, tp, arg)   spin_lock_init((lock))
#define MUTEX_ENTER(lock)               spin_lock((lock))
#define MUTEX_TRY_ENTER(lock)           spin_trylock((lock))
#define MUTEX_EXIT(lock)                spin_unlock((lock))
#define MUTEX_ENTER_INT(lock, flags)    spin_lock_irqsave(lock, flags)
#define MUTEX_EXIT_INT(lock, flags)     spin_unlock_irqrestore(lock, flags)
#define MUTEX_DESTROY(lock)

/* forward declaration of hxge_adapter structure */
struct hxge_adapter;
/* declarations required for debug */
#define HXGE_DRIVER_NAME "hxge"
#define PFX "hxge: "
#define DPRINTK(adapter, nlevel, klevel, fmt, args...) \
	do{\
	(void)((adapter) &&\
	(NETIF_MSG_##nlevel & ((struct hxge_adapter *)adapter)->msg_enable)&&\
	printk(KERN_##klevel PFX "%s: %s: " fmt "\n",\
	((struct hxge_adapter *)adapter)->netdev->name, __FUNCTION__ , ##args));\
	} while (0)
/* Only two functions defined, can be extended */
#define HXGE_ERR(adapter, fmt, args...) DPRINTK(adapter, HW, ERR, fmt, ##args)
#define HXGE_DBG(adapter, fmt, args...) DPRINTK(adapter, DRV, DEBUG, fmt, ##args)

/* This is for where the adapter is not defined in context */
#define HPRINTK(klevel, fmt, args...) \
	do{\
	printk(KERN_##klevel PFX "%s: " fmt "\n", __FUNCTION__ , ##args);\
	} while (0)
#define HXGE_ERR_PRINT(fmt, args...) HPRINTK(ERR, fmt, ##args)
#define HXGE_DBG_PRINT(fmt, args...) HPRINTK(DEBUG, fmt, ##args)

/* Hydra can address up to 44-bits of DMA memory */
#define HXGE_MAX_ADDRESS_BITS_MASK 0x00000FFFFFFFFFFFULL
#define HXGE_MAX_ADDRESS_BITS 44

/* Timeout for Transmit before declaring it hung */
#define HXGE_TX_TIMEOUT (5*HZ)

/* Periodic timeout for monitoring link state */
#define HXGE_LINK_TIMEOUT (2*HZ)

/* Device hardware error threshold/limits before taking hxge down
 *  THRESHOLD   Initial count before invoking rate limit
 *  RATELIMIT   Event count per day ("rate") before taking device "down".
 *
 * Example:  THRESHOLD 4 & RATELIMIT 1 says allow 3 errors; on fourth
 *           error, impose the rate/limit of 1 per day.  In other words,
 *           allow a burst of up to three errors "immediately", but if
 *           the long term average exceeds one per day (after any initial
 *           burst), take the hxge down; 300 errors would be OK if you've
 *           been up for a year.
 */
	
#define HARD_ERROR_THRESHOLD	4
#define HARD_ERROR_RATELIMIT	1
#define SOFT_ERROR_THRESHOLD	100
#define SOFT_ERROR_RATELIMIT	20
#define LINE_ERROR_THRESHOLD	1000
#define LINE_ERROR_RATELIMIT	500

typedef enum {
        HXGE_DEVICE_TESTING = 0,
        HXGE_DEVICE_RESETTING,
	HXGE_DEVICE_INITIALIZED, /* Device available; hxge_probe() complete */
	HXGE_DEVICE_OPENING,	/* Opening ('UP'ing) device; hxge_open() */
	HXGE_DEVICE_ALLOCATED,	/* I/O Buffers allocated; hxge_open() */
	HXGE_DEVICE_UP,		/* In 'UP' state, active & running */
	HXGE_DEVICE_CLOSING,	/* Closing/shutting down; hxge_close() */
	HXGE_DRIVER_REMOVING,
	HXGE_DEVICE_SHUTTINGDOWN, /* Shutting down (on fatal error) */
	HXGE_DEVICE_FATAL	/* Fatal error in open, close & abort */
} hxge_state_t;

typedef enum {
        LINK_MONITOR_DISABLED = 0,
        LINK_MONITOR_ENABLED,
}link_monitor_state_t;

typedef enum {
	LINK_MONITOR_START,
	LINK_MONITOR_STOP
} link_monitor_t;

typedef enum {
	LINK_MODE_INTR,
	LINK_MODE_POLL
} link_monitor_mode_t;


struct hxge_hw {
	uint8_t		*hw_addr;
};


typedef struct _hxge_stats_t {
	hxge_vmac_stats_t	vmac_stats;
	hxge_pfc_stats_t	pfc_stats;
	uint32_t		link_monitor_cnt;
	uint32_t		hard_errors; /* Hard device errors */
	uint32_t		soft_errors; /* Soft device errors */
	uint32_t		line_errors; /* Line (non-device) errors */
	uint32_t		accum_hard_errors; /* Accumulated ... */
	uint32_t		accum_soft_errors; /* Accumulated ... */
	uint32_t		accum_line_errors; /* Accumulated ... */
	/* Device Error status/statistics
	 * PEU_INTR_STAT Generic/other/high-level device errors */
	uint32_t		peu_errors; /* Accumulated non-"i/o" errors */
	uint32_t		peu_spc_acc_err; /* PEU_INTR_STAT[20] */
	uint32_t		peu_pioacc_err;	/* PEU_INTR_STAT[19:16] */
	uint32_t		peu_pcie_parerr; /* PEU_INTR_STAT[9:2] */
	uint32_t		peu_hcr_msix_parerr; /* PEU_INTR_STAT[1:0] */
	/* Device Error status/statistics
	 * RDC_FIFO_ERR_STAT Receive subsystem device errors */
	uint32_t		rx_ierrors; /* Generic/accumulated "i" errors */
	uint32_t		rx_ctrl_sec; /* RX Ctrl RAM SEC */
	uint32_t		rx_ctrl_ded; /* RX Ctrl RAM DED */
	uint32_t		rx_data_sec; /* RX Data RAM SEC */
	uint32_t		rx_data_ded; /* RX Data RAM DED */
	/* Device Error status/statistics
	 * TDC_FIFO_ERR_STAT Transmit subsystem device errors */
	uint32_t		tx_oerrors; /* Generic/accumulated "o" errors */
	uint32_t 		tx_timeout_cnt;
	uint32_t		tx_reorder_sec;	/* TX Reorder buffer SEC */
	uint32_t		tx_reorder_ded;	/* TX Reorder buffer DED */
	uint32_t		tx_rtab_parerr;	/* TX Reorder table parity */
} hxge_stats_t, *p_hxge_stats_t;

#define LDV_RXDMA	1	
#define LDV_TXDMA 	2
#define LDV_VMAC	4
#define LDV_PFC		8
#define LDV_DEVERR	16
#define LDV_ALL		0xFF

#define INTx_TYPE 	0
#define MSI_TYPE  	1
#define MSIX_TYPE	2
#define POLLING_TYPE	3

struct ldv_array {
	uint16_t	type;
	uint16_t	dev_no;
};
struct hxge_ldv {        
	uint16_t         	ldv; /* logical device number */ 
	uint16_t		dev_type; /* rxdma,txdma,vmac,syserr,pfc */ 
	boolean_t       	use_timer; 
	uint16_t                ldv_flags; 
	uint8_t                 ldf_masks; 

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	irqreturn_t		(*intr_handler)(int, void *, struct pt_regs *);
#else
	irqreturn_t		(*intr_handler)(int, void *);
#endif

	struct hxge_ldg		*ldgp;
	uint64_t		data;  /* device specific data */
	struct list_head 	ldg_list;
	struct list_head	list; 
}; 

#define HXGE_MAX_IRQNAME	16
struct hxge_ldg { 
	uint16_t              	ldg;/* logical group number */ 
        uint16_t               	vldg_index; 
        uint16_t               	vector; 
        uint16_t               	nldvs; 
        struct hxge_adapter	*hxgep; 
	uint32_t		timer;
	boolean_t		arm;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
        irqreturn_t 	    	(*intr_handler)(int, void *, struct pt_regs *);
#else
        irqreturn_t 	    	(*intr_handler)(int, void *);
#endif

	char			irq_name[HXGE_MAX_IRQNAME]; /* dyn. allocated */
        struct list_head 	ldv_list; 
	struct list_head	list; 
}; 


struct hxge_ldgv { 
	uint8_t			nldvs; 
	uint8_t 		nldgs;
	uint8_t                 max_ldgs; 
	uint8_t                 max_ldvs; 
	uint32_t                tmres; 
	struct list_head	ldgp; 
	struct list_head 	ldvp;   
};


typedef enum {
	RESET_TX_CHANNEL_0,
	RESET_TX_CHANNEL_1,
	RESET_TX_CHANNEL_2,
	RESET_TX_CHANNEL_3,
	RESET_RX_CHANNEL_0 = HXGE_MAX_TDCS,
	RESET_RX_CHANNEL_1,
	RESET_RX_CHANNEL_2,
	RESET_RX_CHANNEL_3,
	RESET_ADAPTER = HXGE_MAX_RDCS + HXGE_MAX_TDCS,
	RESET_TDC,
	RESET_RDC,
	RESET_PFC,
	RESET_VMAC,
	SHUTDOWN_ADAPTER,
	MAX_CMD
} hxge_command_t;


/*
 *  * VLAN table configuration
 *   */
typedef struct hxge_mv_cfg {
        uint8_t         flag;                   /* 0:unconfigure 1:configured */
} hxge_mv_cfg_t, *p_hxge_mv_cfg_t;



/* classification configuration */
typedef struct hxge_class_pt_cfg {
        /* VLAN table */
        hxge_mv_cfg_t   vlan_tbl[VLAN_ID_MAX + 1];
        /* class config value */
        uint32_t        init_hash;
        uint32_t        class_cfg[TCAM_CLASS_MAX];
} hxge_class_pt_cfg_t, *p_hxge_class_pt_cfg_t;


/* Adapter flags */
#define HXGE_RX_CHKSUM_ENABLED 0x1
#define HXGE_TX_CHKSUM_ENABLED 0x2
#define HXGE_VLAN_ENABLED   0x4
#define HXGE_TCAM_ENABLED   0x8

#define HXGE_CHKSUM_ENABLED (HXGE_RX_CHKSUM_ENABLED | HXGE_TX_CHKSUM_ENABLED)

/* board specific private data structure */

struct hxge_adapter {
#ifdef CONFIG_HXGE_NAPI
	struct net_device 	*polling_netdev;  /* One per active queue */
#endif
	/* OS defined structs */
	struct net_device 	*netdev;
	struct pci_dev 		*pdev;
	struct net_device_stats net_stats;
	unsigned long		state;
	int 			num_openers;
	int			rbrs_to_kick; /* workaround for CR 6671220 */
	unsigned int		tx_mark_ints;
	unsigned long 		ifup_time; /* "ifconfig up" time */
	/* Flags */
	uint32_t		flags;
	unsigned long 		err_flags;

	/* Used during suspend and resume to save and restore PCI configuration
           space */
	uint32_t 		*config_space;
	uint32_t		msg_enable;
	uint32_t  		bd_number;
        struct hxge_hw 		hw;
	struct hxge_work_queue_t {
		unsigned long command;
	} work_q;
        struct work_struct	work_to_do;
	uint32_t 		rx_buffer_len;
	
	/* Locks */
	spinlock_t		lock;
	spinlock_t		stats_lock;
	spinlock_t		tcam_lock;
	rwlock_t		wtd_lock;

	/* Interrupt */
	unsigned int		intr_type;
#ifdef CONFIG_PCI_MSI
	struct msix_entry       *msix;
#endif
        atomic_t 		irq_sem;
	struct hxge_ldgv	*ldgvp;

	/* link management */
	link_monitor_t 		link_monitor_state;
	link_monitor_mode_t	link_mode;
	int			prev_link_status;
	struct timer_list	wd_timer;

	/* Transmit and Receive */
	uint32_t		max_tdcs;
	uint32_t		max_rdcs;
	uint32_t		default_block_size;

        /* threshold of packets when queued up will force an interrupt */
	uint16_t		rcr_threshold;
        /* Max number of packets that are processed before giving the 
           interrupt handling a breather */
	uint16_t		max_rx_pkts;
        /* Timeout value after which interrupt will be forced (if timeout is 
           enabled and interrupt is armed */
	uint32_t		rcr_timeout;
	uint64_t		rcr_cfgb_cpy;
	/* Enable adaptive tuning of Rx interrupt rate */
	uint32_t		adaptive_rx;

	/* Transmit */
	struct tx_ring_t	*tx_ring;

	/* Receive */
	struct rx_ring_t	*rx_ring;

	/* Statistics */
	p_hxge_stats_t	statsp;

	/* Parameter array */
	void 		*param;	

	/* VMAC block */
	hxge_vmac_t	vmac;

	/* VLAN/TCAM/PFC */
	hxge_classify_t         classifier;
	hxge_class_pt_cfg_t     class_config;
	pfc_vlan_table_t	vlan_table[VLAN_MAX_ENTRIES];
	struct vlan_group	*vlangrp;
	int			vlan_id;

	/* Multicast Filter Table */
	uint16_t		mcast_hash_tbl[MAC_MAX_HASH_ENTRY];
};

#define LB_IOC	(SIOCDEVPRIVATE + 15)
#define GET_INFO_SIZE 1
#define GET_INFO      2
#define GET_LB_MODE   3
#define SET_LB_MODE   4

struct lb_size_info {
	int	 cmd;
	uint32_t size;
};

typedef enum {
	normal,
	internal,
	external
} lb_type_t;

typedef enum {
        hxge_lb_normal,
        hxge_lb_ext10g,
} hxge_lb_t;


typedef struct lb_property_s {
        lb_type_t lb_type;
        char key[16];
        uint32_t value;
} lb_property_t;

/* Error injection flags */

#define KMEM_FAILURE		0x1
#define SKB_FAILURE		0x2
#define ALLOC_PAGES_FAILURE	0x4
#define CHKSUM_FAILURE		0x8
#define PCIMAP_FAILURE		0x10

/*  hxge_ethtool.c  */
extern void hxge_set_ethtool_ops(struct net_device *netdev);

/*  hxge_param.c  */
extern void hxge_check_options(struct hxge_adapter *adapter);
extern int hxge_get_option(const char *str, int *val);

/* hxge_intr.c */
extern void hxge_disable_rx_ints(struct hxge_adapter *hxgep, struct hxge_ldg *ldgp, int channel);
extern void hxge_enable_rx_ints(struct hxge_adapter *hxgep, struct hxge_ldg *ldgp, int channel);
extern void hxge_enable_tx_ints(struct hxge_adapter *hxgep, struct hxge_ldg *ldgp);
extern void hxge_disable_tx_ints(struct hxge_adapter *hxgep);
extern void get_ldf_flags(struct hxge_ldv *ldvp, int *ldf0, int *ldf1);
extern int valid_alignment(uint64_t addr, uint64_t size, int);
extern int hxge_debug;


#endif /* _HXGE_H_ */
