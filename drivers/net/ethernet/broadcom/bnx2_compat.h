/* bnx2_compat.h: Broadcom NX2 network driver.
 *
 * Copyright (c) 2012 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Michael Chan  (mchan@broadcom.com)
 */


#ifndef BNX2_COMPAT_H
#define BNX2_COMPAT_H

#if defined(__VMKLNX__) && (VMWARE_ESX_DDK_VERSION >= 41000)
#define VMWARE_ISCSI
#endif

#if defined(__VMKLNX__) && \
    (VMWARE_ESX_DDK_VERSION >= 40000)
#define BNX2_VMWARE_BMAPILNX
#endif

#if defined(__VMKLNX__)
#define HAVE_LE32	1
#define HAVE_IP_HDR	1
#define NEW_SKB		1
#define BNX2_NEW_NAPI	1
#endif

#ifndef ADVERTISE_10HALF
#define ADVERTISE_10HALF	0x0020
#endif

#ifndef ADVERTISE_10FULL
#define ADVERTISE_10FULL	0x0040
#endif

#ifndef ADVERTISE_100HALF
#define ADVERTISE_100HALF	0x0080
#endif

#ifndef ADVERTISE_100FULL
#define ADVERTISE_100FULL	0x0100
#endif

#ifndef ADVERTISE_1000XFULL
#define ADVERTISE_1000XFULL	0x0020
#define ADVERTISE_1000XHALF	0x0040
#define ADVERTISE_1000XPAUSE	0x0080
#define ADVERTISE_1000XPSE_ASYM	0x0100
#endif

#ifndef ADVERTISE_PAUSE_CAP
#define ADVERTISE_PAUSE_CAP	0x0400
#define ADVERTISE_PAUSE_ASYM	0x0800
#endif

#ifndef MII_CTRL1000
#define MII_CTRL1000		0x9
#define MII_STAT1000		0xa
#endif

#ifndef BMCR_SPEED1000
#define BMCR_SPEED1000		0x0040
#endif

#ifndef ADVERTISE_1000FULL
#define ADVERTISE_1000FULL	0x0200
#define ADVERTISE_1000HALF	0x0100
#endif

#ifndef SPEED_2500
#define SPEED_2500		2500
#endif

#ifndef SUPPORTED_2500baseX_Full
#define SUPPORTED_2500baseX_Full	(1 << 15)
#define ADVERTISED_2500baseX_Full	(1 << 15)
#endif

#if (LINUX_VERSION_CODE < 0x02061b)
static inline void ethtool_cmd_speed_set(struct ethtool_cmd *ep,
					 __u32 speed)
{
	ep->speed = (__u16)speed;
}

static inline __u32 ethtool_cmd_speed(struct ethtool_cmd *ep)
{
	return ep->speed;
}
#endif

#ifndef ETH_FCS_LEN
#define ETH_FCS_LEN	4
#endif

#ifndef PCI_DEVICE_ID_NX2_5706
#define PCI_DEVICE_ID_NX2_5706	0x164a
#define PCI_DEVICE_ID_NX2_5706S	0x16aa
#endif

#ifndef PCI_DEVICE_ID_NX2_5708
#define PCI_DEVICE_ID_NX2_5708	0x164c
#define PCI_DEVICE_ID_NX2_5708S	0x16ac
#endif

#ifndef PCI_DEVICE_ID_NX2_5709
#define PCI_DEVICE_ID_NX2_5709	0x1639
#endif

#ifndef PCI_DEVICE_ID_NX2_5709S
#define PCI_DEVICE_ID_NX2_5709S	0x163a
#endif

#ifndef PCI_DEVICE_ID_AMD_8132_BRIDGE
#define PCI_DEVICE_ID_AMD_8132_BRIDGE	0x7458
#endif

#ifndef IRQ_RETVAL
typedef void irqreturn_t;
#define IRQ_RETVAL(x)
#define IRQ_HANDLED
#define IRQ_NONE
#endif

#ifndef IRQF_SHARED
#define IRQF_SHARED SA_SHIRQ
#endif

#ifndef NETDEV_TX_OK
#define NETDEV_TX_OK 0
#endif

#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY 1
#endif

#if (LINUX_VERSION_CODE < 0x020620)
typedef int netdev_tx_t;
#endif

#ifndef HAVE_NETDEV_FEATURES
typedef u32 netdev_features_t;
#endif

#if (LINUX_VERSION_CODE < 0x020547)
#define pci_set_consistent_dma_mask(pdev, mask) (0)
#endif

#ifndef PCI_CAP_ID_EXP
#define PCI_CAP_ID_EXP 0x10
#endif

#ifndef PCI_MSIX_FLAGS
#define PCI_MSIX_FLAGS		2
#endif

#ifndef PCI_MSIX_FLAGS_ENABLE
#define PCI_MSIX_FLAGS_ENABLE	(1 << 15)
#endif

#ifndef DEFINE_PCI_DEVICE_TABLE
#define DEFINE_PCI_DEVICE_TABLE(_table) \
	struct pci_device_id _table[]
#endif

#ifndef HAVE_AER
static inline int pci_disable_pcie_error_reporting(struct pci_dev *pdev)
{
	return 0;
}
static inline int pci_enable_pcie_error_reporting(struct pci_dev *pdev)
{
	return 0;
}

static inline int pci_cleanup_aer_uncorrect_error_status(struct pci_dev *pdev)
{
	return 0;
}
#endif

#ifndef HAVE_BOOL
typedef int bool;
#define false 0
#define true  1
#endif

#ifndef HAVE_IS_PCIE
static inline bool pci_is_pcie(struct pci_dev *dev)
{
	if (pci_find_capability(dev, PCI_CAP_ID_EXP) == 0)
		return false;

	return true;
}
#endif

#ifndef DEFINE_DMA_UNMAP_ADDR
#define DEFINE_DMA_UNMAP_ADDR(mapping) DECLARE_PCI_UNMAP_ADDR(mapping)
#endif

#ifndef dma_unmap_addr_set
#define dma_unmap_addr_set pci_unmap_addr_set
#endif

#ifndef dma_unmap_addr
#define dma_unmap_addr pci_unmap_addr
#endif

#if (LINUX_VERSION_CODE < 0x020604)
#define MODULE_VERSION(version)
#endif

#ifndef SET_MODULE_OWNER
#define SET_MODULE_OWNER(dev) do { } while (0)
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

#ifndef mmiowb
#define mmiowb()
#endif

#if !defined(__iomem)
#define __iomem
#endif

/*
 *  On ESX the wmb() instruction is defined to only a compiler barrier
 *  The macro wmb() need to be overrode to properly synchronize memory
 */
#if defined(__VMKLNX__)
#undef wmb
#define wmb()   asm volatile("sfence" ::: "memory")
#endif

#if !defined(__rcquires)
#define __acquires(x)
#define __releases(x)
#endif

#ifndef HAVE_LE32
typedef u32 __le32;
typedef u32 __be32;
#endif

#ifndef USEC_PER_SEC
#define USEC_PER_SEC	1000000L
#endif

#ifndef __maybe_unused
#define __maybe_unused
#endif

#ifndef __devinit
#define __devinit
#endif

#ifndef __devinitdata
#define __devinitdata
#endif

#ifndef __devexit
#define __devexit
#endif

#ifndef __devexit_p
#define __devexit_p(x) (x)
#endif

#ifndef uninitialized_var
#define uninitialized_var(x) x
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) 0
#endif

#if (LINUX_VERSION_CODE < 0x2060b)
typedef u32 pm_message_t;
typedef u32 pci_power_t;
#define PCI_D0		0
#define PCI_D3hot	3
#endif

#ifndef HAVE_DEVICE_SET_WAKEUP_CAP
#define device_set_wakeup_capable(dev, val)
#endif

#ifndef HAVE_PCI_WAKE_FROM_D3
#ifndef HAVE_PCI_PME_CAPABLE
static bool pci_pme_capable(struct pci_dev *dev, pci_power_t state)
{
	int pm_cap;
	u16 caps;
	bool ret = false;

	pm_cap = pci_find_capability(dev, PCI_CAP_ID_PM);
	if (pm_cap == 0)
		goto done;

	pci_read_config_word(dev, pm_cap + PCI_PM_PMC, &caps);

	if (state == PCI_D3cold &&
		(caps & PCI_PM_CAP_PME_D3cold))
			ret = true;

done:
	return ret;
}
#endif /* HAVE_PCI_PME_CAPABLE */

static int pci_wake_from_d3(struct pci_dev *dev, bool enable)
{
	return pci_pme_capable(dev, PCI_D3cold) ?
			pci_enable_wake(dev, PCI_D3cold, enable) :
			pci_enable_wake(dev, PCI_D3hot, enable);
}
#endif /* HAVE_PCI_WAKE_FROM_D3 */

#if defined(__VMKLNX__)
#ifndef SYSTEM_POWER_OFF
#define SYSTEM_POWER_OFF	(3)
#endif
#define system_state	SYSTEM_POWER_OFF
#endif /* defined (__VMKLNX__) */

#if (LINUX_VERSION_CODE < 0x020605)
#define pci_dma_sync_single_for_cpu(pdev, map, len, dir)	\
	pci_dma_sync_single(pdev, map, len, dir)

#define pci_dma_sync_single_for_device(pdev, map, len, dir)
#endif

#if (LINUX_VERSION_CODE < 0x020612)
#ifndef HAVE_GFP
typedef unsigned gfp_t;
#endif

static inline struct sk_buff *__netdev_alloc_skb(struct net_device *dev,
		unsigned int length, gfp_t gfp_mask)
{
	struct sk_buff *skb = __dev_alloc_skb(length, gfp_mask);
	if (skb)
		skb->dev = dev;
	return skb;
}

static inline struct sk_buff *netdev_alloc_skb(struct net_device *dev,
		unsigned int length)
{
	return __netdev_alloc_skb(dev, length, GFP_ATOMIC);
}

#endif

static inline void bnx2_skb_fill_page_desc(struct sk_buff *skb, int i,
					   struct page *page, int off, int size)
{
#if (LINUX_VERSION_CODE < 0x020600)
	skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

	frag->page		  = page;
	frag->page_offset	  = off;
	frag->size		  = size;
	skb_shinfo(skb)->nr_frags = i + 1;
#else
	skb_fill_page_desc(skb, i, page, off, size);
#endif
}

#ifndef NETIF_F_GSO
static inline void netif_tx_lock(struct net_device *dev)
{
	spin_lock(&dev->xmit_lock);
	dev->xmit_lock_owner = smp_processor_id();
}

static inline void netif_tx_unlock(struct net_device *dev)
{
	dev->xmit_lock_owner = -1;
	spin_unlock(&dev->xmit_lock);
}
#endif

#if !defined(HAVE_NETDEV_PRIV) && (LINUX_VERSION_CODE != 0x020603) && (LINUX_VERSION_CODE != 0x020604) && (LINUX_VERSION_CODE != 0x20605) && (LINUX_VERSION_CODE < 0x30000)
static inline void *netdev_priv(struct net_device *dev)
{
	return dev->priv;
}
#endif

#ifdef OLD_NETIF
static inline void netif_poll_disable(struct net_device *dev)
{
	while (test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state)) {
		/* No hurry. */
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
	}
}

static inline void netif_poll_enable(struct net_device *dev)
{
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

static inline void netif_tx_disable(struct net_device *dev)
{
	spin_lock_bh(&dev->xmit_lock);
	netif_stop_queue(dev);
	spin_unlock_bh(&dev->xmit_lock);
}

#endif

#if (LINUX_VERSION_CODE >= 0x20418) && (LINUX_VERSION_CODE < 0x2060c)
static inline int bnx2_set_tx_hw_csum(struct net_device *dev, u32 data)
{
	if (data)
		dev->features |= NETIF_F_HW_CSUM;
	else
		dev->features &= ~NETIF_F_HW_CSUM;

	return 0;
}
#endif

#if !defined(VLAN_GROUP_ARRAY_SPLIT_PARTS) && !defined(VLAN_CFI_MASK)
static inline void vlan_group_set_device(struct vlan_group *vg, int vlan_id,
					 struct net_device *dev)
{
	if (vg)
		vg->vlan_devices[vlan_id] = dev;
}
#endif

#ifndef NETIF_F_HW_VLAN_CTAG_TX
#define NETIF_F_HW_VLAN_CTAG_TX NETIF_F_HW_VLAN_TX
#define NETIF_F_HW_VLAN_CTAG_RX NETIF_F_HW_VLAN_RX
#ifdef NEW_VLAN
#define __vlan_hwaccel_put_tag(skb, proto, tag) \
	__vlan_hwaccel_put_tag(skb, tag)
#endif
#endif

#ifdef NETIF_F_TSO
#ifndef NETIF_F_GSO
static inline int skb_is_gso(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->tso_size;
}
#define gso_size tso_size
#define gso_segs tso_segs
#endif
#ifndef NETIF_F_TSO6
#define NETIF_F_TSO6	0
#define BCM_NO_TSO6	1
#endif
#ifndef NETIF_F_TSO_ECN
#define NETIF_F_TSO_ECN	0
#endif

#ifndef HAVE_IP_HDR
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return skb->nh.iph;
}
#endif

#ifndef NEW_SKB
static inline int skb_transport_offset(const struct sk_buff *skb)
{
	return (int) (skb->h.raw - skb->data);
}

static inline unsigned int ip_hdrlen(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl * 4;
}

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return skb->h.th;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

#endif
#endif /* #ifdef NETIF_F_TSO */

#ifndef VMWARE_ESX_40_DDK
#if ((LINUX_VERSION_CODE >= 0x20617) && !defined(NETIF_F_MULTI_QUEUE)) || defined(__VMKLNX__)

#define BCM_HAVE_MULTI_QUEUE

#else

static inline void netif_tx_wake_all_queues(struct net_device *dev)
{
	netif_wake_queue(dev);
}

static inline void netif_tx_start_all_queues(struct net_device *dev)
{
	netif_start_queue(dev);
}

#endif
#else
#define BCM_HAVE_MULTI_QUEUE
#endif


#ifndef NET_SKB_PAD
#define NET_SKB_PAD	16
#endif

#if (LINUX_VERSION_CODE < 0x02061e)
static inline void skb_record_rx_queue(struct sk_buff *skb, u16 rx_queue)
{
}
#endif

#if defined(HAVE_SET_RX_MODE) || (LINUX_VERSION_CODE > 0x20621)
#define BCM_HAVE_SET_RX_MODE	1
#endif

#ifdef NETDEV_HW_ADDR_T_MULTICAST
#define BCM_NEW_NETDEV_HW_ADDR
#endif

#ifndef netdev_uc_count
#if (LINUX_VERSION_CODE < 0x2061f)
#define netdev_uc_count(dev)	((dev)->uc_count)
#else
#define netdev_uc_count(dev)	((dev)->uc.count)
#endif
#endif

#ifndef netdev_for_each_uc_addr
#define netdev_for_each_uc_addr(ha, dev) \
	list_for_each_entry(ha, &dev->uc.list, list)
#endif

#ifndef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(mclist, dev) \
	for (mclist = dev->mc_list; mclist; mclist = mclist->next)
#endif

#if (LINUX_VERSION_CODE < 0x020600)
#define dev_err(unused, format, arg...)		\
	printk(KERN_ERR "bnx2: " format , ## arg)
#else
#ifndef HAVE_DEV_ERR
#ifndef HAVE_DEV_PRINTK
#define dev_printk(level, dev, format, arg...)	\
	printk(level "bnx2 %s: " format , (dev)->bus_id , ## arg)
#endif
#define dev_err(dev, format, arg...)		\
	dev_printk(KERN_ERR , dev , format , ## arg)
#endif
#endif

#if (LINUX_VERSION_CODE < 0x020606)
#undef netdev_printk
#undef netdev_err
#undef netdev_info
#endif

#if !defined(netdev_printk) && (LINUX_VERSION_CODE < 0x020624)

#if (LINUX_VERSION_CODE < 0x020615)
#define NET_PARENT_DEV(netdev)  ((netdev)->class_dev.dev)
#else
#define NET_PARENT_DEV(netdev)  ((netdev)->dev.parent)
#endif

#if !defined(__VMKLNX__)
#define netdev_printk(level, netdev, format, args...)		\
	dev_printk(level, NET_PARENT_DEV(netdev),	\
		   "%s: " format,				\
		   netdev_name(netdev), ##args)
#else /*(__VMKLNX__)*/
#define netdev_printk(level, netdev, format, args...)           \
	printk("%s" \
	       "%s %s: %s: " format, level,                     \
               DRV_MODULE_NAME, pci_name(netdev->pdev),         \
               netdev_name(netdev), ##args)
#endif

static inline const char *netdev_name(const struct net_device *dev)
{
	if (dev->reg_state != NETREG_REGISTERED)
		return "(unregistered net_device)";
	return dev->name;
}

#endif

#ifndef KERN_CONT
#define KERN_CONT     "<c>"
#endif

#ifndef netdev_err
#define netdev_err(dev, format, args...)			\
	netdev_printk(KERN_ERR, dev, format, ##args)
#endif

#ifndef netdev_info
#define netdev_info(dev, format, args...)			\
	netdev_printk(KERN_INFO, dev, format, ##args)
#endif

#ifndef netdev_warn
#define netdev_warn(dev, format, args...)			\
	netdev_printk(KERN_WARNING, dev, format, ##args)
#endif

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#ifndef pr_cont
#define pr_cont(fmt, ...) \
	printk(KERN_CONT fmt, ##__VA_ARGS__)
#endif

#ifndef pr_alert
#define pr_alert(fmt, ...) \
        printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#endif

#ifndef pr_warning
#define pr_warning(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#endif

#ifndef pr_warn
#define pr_warn pr_warning
#endif

#ifndef pr_err
#define pr_err(fmt, ...) \
        printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#endif

#ifndef pr_info
#define pr_info(fmt, ...) \
        printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#endif

#if !defined(DECLARE_MAC_BUF) || (LINUX_VERSION_CODE >= 0x020621)
#ifndef MAC_FMT
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

static inline char *print_mac(char *buf, const u8 *addr)
{
	sprintf(buf, MAC_FMT,
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}
#endif

#ifndef DECLARE_MAC_BUF
#define DECLARE_MAC_BUF(var) char var[18]
#endif


#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#if (LINUX_VERSION_CODE >= 0x020618)

#if (LINUX_VERSION_CODE < 0x02061b)

static inline void netif_napi_del(struct napi_struct *napi)
{
#ifdef CONFIG_NETPOLL
	list_del(&napi->dev_list);
#endif
}

#endif
#endif

#ifndef HAVE_REAL_RX
static inline int netif_set_real_num_rx_queues(struct net_device *dev,
						unsigned int rxq)
{
	return 0;
}
#endif

#ifdef BCM_HAVE_MULTI_QUEUE
#ifndef HAVE_REAL_TX
static inline void netif_set_real_num_tx_queues(struct net_device *dev,
						unsigned int txq)
{
	dev->real_num_tx_queues = txq;
}
#endif
#endif

#ifndef HAVE_SKB_FRAG
static inline unsigned int skb_frag_size(const skb_frag_t *frag)
{
	return frag->size;
}

static inline void skb_frag_size_sub(skb_frag_t *frag, int delta)
{
	frag->size -= delta;
}

#endif

#ifndef HAVE_SKB_FRAG_PAGE
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}

static inline void __skb_frag_set_page(skb_frag_t *frag, struct page *page)
{
	frag->page = page;
}

#define skb_frag_dma_map(x, frag, y, len, z) \
	pci_map_page(bp->pdev, (frag)->page, \
		     (frag)->page_offset, (len), PCI_DMA_TODEVICE)
#endif

#ifndef HAVE_ETHTOOL_TO_MII
static inline u32 ethtool_adv_to_mii_adv_t(u32 ethadv)
{
	u32 result = 0;

	if (ethadv & ADVERTISED_10baseT_Half)
		result |= ADVERTISE_10HALF;
	if (ethadv & ADVERTISED_10baseT_Full)
		result |= ADVERTISE_10FULL;
	if (ethadv & ADVERTISED_100baseT_Half)
		result |= ADVERTISE_100HALF;
	if (ethadv & ADVERTISED_100baseT_Full)
		result |= ADVERTISE_100FULL;
	if (ethadv & ADVERTISED_Pause)
		result |= ADVERTISE_PAUSE_CAP;
	if (ethadv & ADVERTISED_Asym_Pause)
		result |= ADVERTISE_PAUSE_ASYM;

	return result;
}

static inline u32 ethtool_adv_to_mii_ctrl1000_t(u32 ethadv)
{
	u32 result = 0;

	if (ethadv & ADVERTISED_1000baseT_Half)
		result |= ADVERTISE_1000HALF;
	if (ethadv & ADVERTISED_1000baseT_Full)
		result |= ADVERTISE_1000FULL;

	return result;
}
#endif

static inline void bnx2_msleep(unsigned int msecs)
{
#if (LINUX_VERSION_CODE < 0x20607)
	current->state = TASK_UNINTERRUPTIBLE;
	schedule_timeout((msecs * HZ / 1000) + 1);
#else
	msleep(msecs);
#endif
}

static inline unsigned long bnx2_msleep_interruptible(unsigned int msecs)
{
#if (LINUX_VERSION_CODE < 0x20609)
	current->state = TASK_INTERRUPTIBLE;
	return schedule_timeout((msecs * HZ / 1000) + 1);
#else
	return msleep_interruptible(msecs);
#endif
}

#ifndef rcu_dereference_protected

#define rcu_dereference_protected(p, c) \
	rcu_dereference((p))

#endif

#ifndef __rcu
#define __rcu
#endif

#ifndef RCU_INIT_POINTER
#define RCU_INIT_POINTER(p, v) \
		p = (typeof(*v) __force __rcu *)(v)
#endif

#if defined (__VMKLNX__)
/**
 * THIS FUNCTION SHOULD BE REMOVED ONCE PR 379263 IS RESOLVED
 */
static inline void *bcm_memmove(void *dest, const void *src, size_t count)
{
	char *tmp;
	const char *s;

	if (dest <= src) {
		tmp = dest;
		s = src;
		while (count--)
			*tmp++ = *s++;
	} else {
		tmp = dest;
		tmp += count;
		s = src;
		s += count;
		while (count--)
			*--tmp = *--s;
	}
	return dest;
}
#else /* !defined (__VMKLNX__) */
#define bcm_memmove	memmove
#endif /* defined (__VMKLNX__) */

#endif
