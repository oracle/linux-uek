/* Copyright (C) 2009-2013 Broadcom Corporation. */

#ifndef BCM_HAS_PCI_PCIE_CAP
static inline int pci_pcie_cap(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct tg3 *tp = netdev_priv(dev);

	return tp->pcie_cap;
}
#endif

#ifndef BCM_HAS_PCI_IS_PCIE
static inline bool pci_is_pcie(struct pci_dev *dev)
{
	return !!pci_pcie_cap(dev);
}
#endif

#ifndef BCM_HAS_SKB_FRAG_DMA_MAP
#define skb_frag_dma_map(x, frag, y, len, z) \
	pci_map_page(tp->pdev, (frag)->page, \
		     (frag)->page_offset, (len), PCI_DMA_TODEVICE)
#endif

#ifdef SIMPLE_DEV_PM_OPS

#define tg3_invalid_pci_state(tp, state)	false
#define tg3_pci_save_state(tp)
#define tg3_pci_restore_state(tp)

#else /* SIMPLE_DEV_PM_OPS */

#if (LINUX_VERSION_CODE < 0x2060b)
static bool tg3_invalid_pci_state(struct tg3 *tp, u32 state)
{
	bool ret = true;
	pci_power_t target_state;

	target_state = pci_choose_state(tp->pdev, state);
	if (target_state != PCI_D3hot || target_state != PCI_D3cold)
		ret = false;

	return ret;
}
#else
static bool tg3_invalid_pci_state(struct tg3 *tp, pm_message_t state)
{
	bool ret = true;
	pci_power_t target_state;

#ifdef BCM_HAS_PCI_TARGET_STATE
	target_state = tp->pdev->pm_cap ? pci_target_state(tp->pdev) : PCI_D3hot;
#else
	target_state = pci_choose_state(tp->pdev, state);
#endif
	if (target_state != PCI_D3hot || target_state != PCI_D3cold)
		ret = false;

	return ret;
}
#endif

#if (LINUX_VERSION_CODE < 0x2060a)
#define tg3_pci_save_state(tp)		pci_save_state(tp->pdev, tp->pci_cfg_state)
#define tg3_pci_restore_state(tp)	pci_restore_state(tp->pdev, tp->pci_cfg_state)
#else
#define tg3_pci_save_state(tp)		pci_save_state(tp->pdev)
#define tg3_pci_restore_state(tp)	pci_restore_state(tp->pdev)
#endif

#endif /* SIMPLE_DEV_PM_OPS */


#ifdef BCM_HAS_NEW_PCI_DMA_MAPPING_ERROR
#define tg3_pci_dma_mapping_error(pdev, mapping)  pci_dma_mapping_error((pdev), (mapping))
#elif defined(BCM_HAS_PCI_DMA_MAPPING_ERROR)
#define tg3_pci_dma_mapping_error(pdev, mapping)  pci_dma_mapping_error((mapping))
#else
#define tg3_pci_dma_mapping_error(pdev, mapping)  0
#endif

#ifndef BCM_HAS_HW_FEATURES
#define hw_features		features
#endif

#ifndef BCM_HAS_VLAN_FEATURES
#define vlan_features		features
#endif

#ifdef HAVE_POLL_CONTROLLER
#define CONFIG_NET_POLL_CONTROLLER
#endif

static inline void tg3_5780_class_intx_workaround(struct tg3 *tp)
{
#ifndef BCM_HAS_INTX_MSI_WORKAROUND
	if (tg3_flag(tp, 5780_CLASS) &&
	    tg3_flag(tp, USING_MSI))
		tg3_enable_intx(tp->pdev);
#endif
}

#ifdef BCM_HAS_TXQ_TRANS_UPDATE
#define tg3_update_trans_start(dev)
#else
#define tg3_update_trans_start(dev)		((dev)->trans_start = jiffies)
#endif

#ifndef BCM_HAS_NEW_VLAN_INTERFACE
#define TG3_TO_INT(Y)       ((int)((ptrdiff_t)(Y) & (SMP_CACHE_BYTES - 1)))
#define TG3_COMPAT_VLAN_ALLOC_LEN		(SMP_CACHE_BYTES + VLAN_HLEN)
#define TG3_COMPAT_VLAN_RESERVE(addr)	(SKB_DATA_ALIGN((addr) + VLAN_HLEN) - (addr))
#else
#define TG3_COMPAT_VLAN_ALLOC_LEN		0
#define TG3_COMPAT_VLAN_RESERVE(addr)	0
#endif

#ifdef BCM_KERNEL_SUPPORTS_8021Q

#ifndef BCM_HAS_NEW_VLAN_INTERFACE
#undef  TG3_RAW_IP_ALIGN
#define TG3_RAW_IP_ALIGN (2 + VLAN_HLEN)
#endif /* BCM_HAS_NEW_VLAN_INTERFACE */

#ifndef BCM_HAS_NEW_VLAN_INTERFACE
static void __tg3_set_rx_mode(struct net_device *);
static inline void tg3_netif_start(struct tg3 *tp);
static inline void tg3_netif_stop(struct tg3 *tp);
static inline void tg3_full_lock(struct tg3 *tp, int irq_sync);
static inline void tg3_full_unlock(struct tg3 *tp);

static void tg3_vlan_rx_register(struct net_device *dev, struct vlan_group *grp)
{
	struct tg3 *tp = netdev_priv(dev);

	if (!netif_running(dev)) {
		tp->vlgrp = grp;
		return;
	}

	tg3_netif_stop(tp);

	tg3_full_lock(tp, 0);

	tp->vlgrp = grp;

	/* Update RX_MODE_KEEP_VLAN_TAG bit in RX_MODE register. */
	__tg3_set_rx_mode(dev);

	tg3_netif_start(tp);

	tg3_full_unlock(tp);
}

#ifndef BCM_HAS_NET_DEVICE_OPS
#ifndef BCM_HAS_VLAN_GROUP_SET_DEVICE
static inline void vlan_group_set_device(struct vlan_group *vg, int vlan_id,
					 struct net_device *dev)
{
	if (vg)
		vg->vlan_devices[vlan_id] = dev;
}
#endif

static void tg3_vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
{
	struct tg3 *tp = netdev_priv(dev);

	if (netif_running(dev))
		tg3_netif_stop(tp);

	tg3_full_lock(tp, 0);
	vlan_group_set_device(tp->vlgrp, vid, NULL);
	tg3_full_unlock(tp);

	if (netif_running(dev))
		tg3_netif_start(tp);
}
#endif /* BCM_HAS_NET_DEVICE_OPS */
#endif /* BCM_USE_OLD_VLAN_INTERFACE */
#endif /* BCM_KERNEL_SUPPORTS_8021Q */


#ifndef BCM_HAS_NETDEV_UPDATE_FEATURES
static u32 tg3_get_rx_csum(struct net_device *dev)
{
	return (dev->features & NETIF_F_RXCSUM) != 0;
}

static int tg3_set_rx_csum(struct net_device *dev, u32 data)
{
	struct tg3 *tp = netdev_priv(dev);

	/* BROKEN_CHECKSUMS */
	if (tp->pci_chip_rev_id == CHIPREV_ID_5700_B0) {
		if (data != 0)
			return -EINVAL;
		return 0;
	}

	spin_lock_bh(&tp->lock);
	if (data)
		dev->features |= NETIF_F_RXCSUM;
	else
		dev->features &= ~NETIF_F_RXCSUM;
	spin_unlock_bh(&tp->lock);

	return 0;
}

#ifdef BCM_HAS_SET_TX_CSUM
static int tg3_set_tx_csum(struct net_device *dev, u32 data)
{
	struct tg3 *tp = netdev_priv(dev);

	/* BROKEN_CHECKSUMS */
	if (tp->pci_chip_rev_id == CHIPREV_ID_5700_B0) {
		if (data != 0)
			return -EINVAL;
		return 0;
	}

	if (tg3_flag(tp, 5755_PLUS))
#if defined(BCM_HAS_ETHTOOL_OP_SET_TX_IPV6_CSUM)
		ethtool_op_set_tx_ipv6_csum(dev, data);
#elif defined(BCM_HAS_ETHTOOL_OP_SET_TX_HW_CSUM)
		ethtool_op_set_tx_hw_csum(dev, data);
#else
		tg3_set_tx_hw_csum(dev, data);
#endif
	else
		ethtool_op_set_tx_csum(dev, data);

	return 0;
}
#endif

#if TG3_TSO_SUPPORT != 0
static int tg3_set_tso(struct net_device *dev, u32 value)
{
	struct tg3 *tp = netdev_priv(dev);

	if (!tg3_flag(tp, TSO_CAPABLE)) {
		if (value)
			return -EINVAL;
		return 0;
	}
	if ((dev->features & NETIF_F_IPV6_CSUM) &&
	    (tg3_flag(tp, HW_TSO_2) ||
	     tg3_flag(tp, HW_TSO_3))) {
		if (value) {
			dev->features |= NETIF_F_TSO6;
			if (tg3_flag(tp, HW_TSO_3) ||
			    tg3_asic_rev(tp) == ASIC_REV_5761 ||
			    (tg3_asic_rev(tp) == ASIC_REV_5784 &&
			     tg3_chip_rev(tp) != CHIPREV_5784_AX) ||
			    tg3_asic_rev(tp) == ASIC_REV_5785 ||
			    tg3_asic_rev(tp) == ASIC_REV_57780)
				dev->features |= NETIF_F_TSO_ECN;
		} else
			dev->features &= ~(NETIF_F_TSO6 | NETIF_F_TSO_ECN);
	}
	return ethtool_op_set_tso(dev, value);
}
#endif

static void netdev_update_features(struct net_device *dev)
{
	struct tg3 *tp = netdev_priv(dev);

	if (dev->mtu > ETH_DATA_LEN) {
		if (tg3_flag(tp, 5780_CLASS)) {
#if TG3_TSO_SUPPORT != 0
			ethtool_op_set_tso(dev, 0);
#endif
		}
	}
}
#endif /* BCM_HAS_NETDEV_UPDATE_FEATURES */

#if !defined(BCM_HAS_SET_PHYS_ID) || defined(GET_ETHTOOL_OP_EXT)

#if !defined(BCM_HAS_SET_PHYS_ID)
enum ethtool_phys_id_state {
	ETHTOOL_ID_INACTIVE,
	ETHTOOL_ID_ACTIVE,
	ETHTOOL_ID_ON,
	ETHTOOL_ID_OFF
};
#endif

static int tg3_set_phys_id(struct net_device *dev,
			    enum ethtool_phys_id_state state);
static int tg3_phys_id(struct net_device *dev, u32 data)
{
	struct tg3 *tp = netdev_priv(dev);
	int i;

	if (!netif_running(tp->dev))
		return -EAGAIN;

	if (data == 0)
		data = UINT_MAX / 2;

	for (i = 0; i < (data * 2); i++) {
		if ((i % 2) == 0)
			tg3_set_phys_id(dev, ETHTOOL_ID_ON);
		else
			tg3_set_phys_id(dev, ETHTOOL_ID_OFF);

		if (msleep_interruptible(500))
			break;
	}
	tg3_set_phys_id(dev, ETHTOOL_ID_INACTIVE);
	return 0;
}
#endif /* BCM_HAS_SET_PHYS_ID */

#ifndef BCM_HAS_GET_STATS64
static struct rtnl_link_stats64 *tg3_get_stats64(struct net_device *dev,
						struct rtnl_link_stats64 *stats);
static struct rtnl_link_stats64 *tg3_get_stats(struct net_device *dev)
{
	struct tg3 *tp = netdev_priv(dev);
	return tg3_get_stats64(dev, &tp->net_stats);
}
#endif /* BCM_HAS_GET_STATS64 */

#ifdef BCM_HAS_GET_RXFH_INDIR
#ifndef BCM_HAS_GET_RXFH_INDIR_SIZE
static int tg3_get_rxfh_indir(struct net_device *dev,
			      struct ethtool_rxfh_indir *indir)
{
	struct tg3 *tp = netdev_priv(dev);
	int i;

	if (!tg3_flag(tp, SUPPORT_MSIX))
		return -EINVAL;

	if (!indir->size) {
		indir->size = TG3_RSS_INDIR_TBL_SIZE;
		return 0;
	}

	if (indir->size != TG3_RSS_INDIR_TBL_SIZE)
		return -EINVAL;

	for (i = 0; i < TG3_RSS_INDIR_TBL_SIZE; i++)
		indir->ring_index[i] = tp->rss_ind_tbl[i];

	return 0;
}

static void tg3_rss_init_dflt_indir_tbl(struct tg3 *tp, u32 qcnt);
static void tg3_rss_write_indir_tbl(struct tg3 *tp);
static inline void tg3_full_lock(struct tg3 *tp, int irq_sync);
static inline void tg3_full_unlock(struct tg3 *tp);

static int tg3_set_rxfh_indir(struct net_device *dev,
			      const struct ethtool_rxfh_indir *indir)
{
	struct tg3 *tp = netdev_priv(dev);
	size_t i;

	if (!tg3_flag(tp, SUPPORT_MSIX))
		return -EINVAL;

	if (!indir->size) {
		tg3_flag_clear(tp, USER_INDIR_TBL);
		tg3_rss_init_dflt_indir_tbl(tp, tp->rxq_cnt);
	} else {
		int limit;

		/* Validate size and indices */
		if (indir->size != TG3_RSS_INDIR_TBL_SIZE)
			return -EINVAL;

		if (netif_running(dev))
			limit = tp->irq_cnt;
		else {
			limit = num_online_cpus();
			if (limit > TG3_IRQ_MAX_VECS_RSS)
				limit = TG3_IRQ_MAX_VECS_RSS;
		}

		/* The first interrupt vector only
		 * handles link interrupts.
		 */
		limit -= 1;

		/* Check the indices in the table.
		 * Leave the existing table unmodified
		 * if an error is detected.
		 */
		for (i = 0; i < TG3_RSS_INDIR_TBL_SIZE; i++)
			if (indir->ring_index[i] >= limit)
				return -EINVAL;

		tg3_flag_set(tp, USER_INDIR_TBL);

		for (i = 0; i < TG3_RSS_INDIR_TBL_SIZE; i++)
			tp->rss_ind_tbl[i] = indir->ring_index[i];
	}

	if (!netif_running(dev) || !tg3_flag(tp, ENABLE_RSS))
		return 0;

	/* It is legal to write the indirection
	 * table while the device is running.
	 */
	tg3_full_lock(tp, 0);
	tg3_rss_write_indir_tbl(tp);
	tg3_full_unlock(tp);

	return 0;
}
#endif /* !BCM_HAS_GET_RXFH_INDIR_SIZE */
#endif /* BCM_HAS_GET_RXFH_INDIR */

#ifdef __VMKLNX__

/**
 *      skb_copy_expand -       copy and expand sk_buff
 *      @skb: buffer to copy
 *      @newheadroom: new free bytes at head
 *      @newtailroom: new free bytes at tail
 *      @gfp_mask: allocation priority
 *
 *      Make a copy of both an &sk_buff and its data and while doing so
 *      allocate additional space.
 *
 *      This is used when the caller wishes to modify the data and needs a
 *      private copy of the data to alter as well as more space for new fields.
 *      Returns %NULL on failure or the pointer to the buffer
 *      on success. The returned buffer has a reference count of 1.
 *
 *      You must pass %GFP_ATOMIC as the allocation priority if this function
 *      is called from an interrupt.
 */
struct sk_buff *skb_copy_expand(const struct sk_buff *skb,
                                int newheadroom, int newtailroom,
                                gfp_t gfp_mask)
{
	int rc;
	struct sk_buff *new_skb = skb_copy((struct sk_buff *) skb, gfp_mask);

	if(new_skb == NULL)
		return NULL;

	rc = pskb_expand_head(new_skb, newheadroom, newtailroom, gfp_mask);

	if(rc != 0)
		return NULL;

	return new_skb;
}

void *memmove(void *dest, const void *src, size_t count)
{
	if (dest < src) {
		return memcpy(dest, src, count);
	} else {
		char *p = dest + count;
		const char *s = src + count;
		while (count--)
			*--p = *--s;
	}
	return dest;
}
#endif
