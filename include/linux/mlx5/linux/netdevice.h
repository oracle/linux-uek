#ifndef _COMPAT_LINUX_NETDEVICE_H
#define _COMPAT_LINUX_NETDEVICE_H 1

#include <linux/mlx5/compat/config.h>
#include <linux/kconfig.h>
#include <generated/uapi/linux/version.h>

#include_next <linux/netdevice.h>

/* supports eipoib flags */
#ifndef IFF_EIPOIB_VIF
#define IFF_EIPOIB_VIF  0x800       /* IPoIB VIF intf(eg ib0.x, ib1.x etc.), using IFF_DONT_BRIDGE */
#endif

#ifndef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev,ops) \
    ( (netdev)->ethtool_ops = (ops) )
#endif

#if !defined(HAVE_NETDEV_EXTENDED_HW_FEATURES)     && \
    !defined(HAVE_NETDEV_OPS_EXT_NDO_FIX_FEATURES) && \
    !defined(HAVE_NETDEV_OPS_EXT_NDO_SET_FEATURES) && \
    !defined(HAVE_NDO_SET_FEATURES)
#define LEGACY_ETHTOOL_OPS
#endif

#ifndef NETDEV_BONDING_INFO
#define NETDEV_BONDING_INFO     0x0019
#endif


#ifndef HAVE_NETDEV_MASTER_UPPER_DEV_GET_RCU
#define netdev_master_upper_dev_get_rcu(x) (x)->master
#define netdev_master_upper_dev_get(x) \
	netdev_master_upper_dev_get_rcu(x)
#else
static inline int netdev_set_master(struct net_device *dev,
				    struct net_device *master)
{
	int rc = 0;

	if (master) {
#if defined(NETDEV_MASTER_UPPER_DEV_LINK_4_PARAMS)
		rc = netdev_master_upper_dev_link(dev, master, NULL, NULL);
#elif defined(NETDEV_MASTER_UPPER_DEV_LINK_5_PARAMS)
		rc = netdev_master_upper_dev_link(dev, master,
						  NULL, NULL, NULL);
#else
		rc = netdev_master_upper_dev_link(dev, master);
#endif
	} else {
		master = netdev_master_upper_dev_get_rcu(dev);
		netdev_upper_dev_unlink(dev, master);
	}
	return rc;
}
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
#ifdef HAVE_ALLOC_ETHERDEV_MQ
#ifndef HAVE_NETIF_SET_REAL_NUM_TX_QUEUES
static inline void netif_set_real_num_tx_queues(struct net_device *netdev,
						unsigned int txq)
{
	netdev->real_num_tx_queues = txq;
}
#endif
#endif
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18) */

#ifndef HAVE_NETDEV_RSS_KEY_FILL
static inline void netdev_rss_key_fill(void *addr, size_t len)
{
	__be32 *hkey;

	hkey = (__be32 *)addr;
	hkey[0] = cpu_to_be32(0xD181C62C);
	hkey[1] = cpu_to_be32(0xF7F4DB5B);
	hkey[2] = cpu_to_be32(0x1983A2FC);
	hkey[3] = cpu_to_be32(0x943E1ADB);
	hkey[4] = cpu_to_be32(0xD9389E6B);
	hkey[5] = cpu_to_be32(0xD1039C2C);
	hkey[6] = cpu_to_be32(0xA74499AD);
	hkey[7] = cpu_to_be32(0x593D56D9);
	hkey[8] = cpu_to_be32(0xF3253C06);
	hkey[9] = cpu_to_be32(0x2ADC1FFC);
}
#endif

#ifndef HAVE_NETIF_TRANS_UPDATE
static inline void netif_trans_update(struct net_device *dev)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);

	if (txq->trans_start != jiffies)
		txq->trans_start = jiffies;
}
#endif

#ifndef NAPI_POLL_WEIGHT
/* Default NAPI poll() weight
 * Device drivers are strongly advised to not use bigger value
 */
#define NAPI_POLL_WEIGHT 64
#endif

#ifndef NETDEV_JOIN
#define NETDEV_JOIN           0x0014
#endif

#ifdef HAVE_ALLOC_NETDEV_MQS_5_PARAMS
#define alloc_netdev_mqs(p1, p2, p3, p4, p5, p6) alloc_netdev_mqs(p1, p2, p4, p5, p6)
#elif defined(HAVE_ALLOC_NETDEV_MQ_4_PARAMS)
#define alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, txqs, rxqs)	\
	alloc_netdev_mq(sizeof_priv, name, setup,					\
			max_t(unsigned int, txqs, rxqs))
#endif


#ifndef HAVE_NETIF_IS_BOND_MASTER
#define netif_is_bond_master LINUX_BACKPORT(netif_is_bond_master)
static inline bool netif_is_bond_master(struct net_device *dev)
{
	return dev->flags & IFF_MASTER && dev->priv_flags & IFF_BONDING;
}
#endif

#ifndef HAVE_SELECT_QUEUE_FALLBACK_T
#define fallback(dev, skb) __netdev_pick_tx(dev, skb)
#endif

#ifndef HAVE_NAPI_SCHEDULE_IRQOFF
#define napi_schedule_irqoff(napi) napi_schedule(napi)
#endif

#ifndef HAVE_DEV_UC_DEL
#define dev_uc_del(netdev, mac) dev_unicast_delete(netdev, mac)
#endif
#ifndef HAVE_DEV_MC_DEL
#define dev_mc_del(netdev, mac) dev_mc_delete(netdev, mac, netdev->addr_len, true)
#endif

#ifdef HAVE_REGISTER_NETDEVICE_NOTIFIER_RH
#define register_netdevice_notifier register_netdevice_notifier_rh
#define unregister_netdevice_notifier unregister_netdevice_notifier_rh
#endif

#ifndef HAVE_NETDEV_NOTIFIER_INFO_TO_DEV
#define netdev_notifier_info_to_dev LINUX_BACKPORT(netdev_notifier_info_to_dev)
static inline struct net_device *
netdev_notifier_info_to_dev(void *ptr)
{
	return (struct net_device *)ptr;
}
#endif

/* This is geared toward old kernels that have Bonding.h and don't have TX type.
 * It's tested on RHEL 6.9, 7.2 and 7.3 in addition to Ubuntu 16.04.
 */

#if defined(HAVE_BONDING_H) && !defined(HAVE_LAG_TX_TYPE)
#define MLX_USE_LAG_COMPAT
#define NETDEV_CHANGELOWERSTATE			0x101B
#undef NETDEV_CHANGEUPPER
#define NETDEV_CHANGEUPPER			0x1015

#ifndef HAVE_NETDEV_NOTIFIER_INFO
#define netdev_notifier_info LINUX_BACKPORT(netdev_notifier_info)
struct netdev_notifier_info {
	struct net_device *dev;
};
#endif

static inline struct net_device *
netdev_notifier_info_to_dev_v2(void *ptr)
{
	return (((struct netdev_notifier_info *)ptr)->dev);
}

enum netdev_lag_tx_type {
	NETDEV_LAG_TX_TYPE_UNKNOWN,
	NETDEV_LAG_TX_TYPE_RANDOM,
	NETDEV_LAG_TX_TYPE_BROADCAST,
	NETDEV_LAG_TX_TYPE_ROUNDROBIN,
	NETDEV_LAG_TX_TYPE_ACTIVEBACKUP,
	NETDEV_LAG_TX_TYPE_HASH,
};

struct netdev_notifier_changelowerstate_info {
	struct netdev_notifier_info info; /* must be first */
	void *lower_state_info; /* is lower dev state */
};

struct netdev_lag_lower_state_info {
	u8 link_up : 1,
	   tx_enabled : 1;
};

#ifndef HAVE_NETIF_IS_LAG_MASTER
#define netif_is_lag_master LINUX_BACKPORT(netif_is_lag_master)
static inline bool netif_is_lag_master(struct net_device *dev)
{
	return netif_is_bond_master(dev);
}
#endif

#ifndef HAVE_NETIF_IS_LAG_PORT
#define netif_is_lag_port LINUX_BACKPORT(netif_is_lag_port)
static inline bool netif_is_lag_port(struct net_device *dev)
{
	return netif_is_bond_slave(dev);
}
#endif

#if !defined(HAVE_NETDEV_NOTIFIER_CHANGEUPPER_INFO_UPPER_INFO)

#define netdev_notifier_changeupper_info LINUX_BACKPORT(netdev_notifier_changeupper_info)
struct netdev_notifier_changeupper_info {
	struct netdev_notifier_info info; /* must be first */
	struct net_device *upper_dev; /* new upper dev */
	bool master; /* is upper dev master */
	bool linking; /* is the notification for link or unlink */
	void *upper_info; /* upper dev info */
};

#define netdev_lag_upper_info LINUX_BACKPORT(netdev_lag_upper_info)
struct netdev_lag_upper_info {
	enum netdev_lag_tx_type tx_type;
};
#endif
#endif

#ifndef NET_NAME_UNKNOWN
#define NET_NAME_UNKNOWN        0       /*  unknown origin (not exposed to userspace) */
#endif


#if IS_ENABLED(CONFIG_VXLAN) && (defined(HAVE_NDO_ADD_VXLAN_PORT) || defined(HAVE_NDO_UDP_TUNNEL_ADD))
#define HAVE_KERNEL_WITH_VXLAN_SUPPORT_ON
#endif

#if (defined(HAVE_NDO_GET_STATS64) && !defined(HAVE_NETDEV_STATS_TO_STATS64))
static inline void netdev_stats_to_stats64(struct rtnl_link_stats64 *stats64,
					   const struct net_device_stats *netdev_stats)
{
#if BITS_PER_LONG == 64
	BUILD_BUG_ON(sizeof(*stats64) != sizeof(*netdev_stats));
	memcpy(stats64, netdev_stats, sizeof(*stats64));
#else
	size_t i, n = sizeof(*stats64) / sizeof(u64);
	const unsigned long *src = (const unsigned long *)netdev_stats;
	u64 *dst = (u64 *)stats64;

	BUILD_BUG_ON(sizeof(*netdev_stats) / sizeof(unsigned long) !=
		     sizeof(*stats64) / sizeof(u64));
	for (i = 0; i < n; i++)
		dst[i] = src[i];
#endif
}
#endif

#ifdef HAVE_NETDEV_XDP
#define HAVE_NETDEV_BPF 1
#define netdev_bpf	netdev_xdp
#define ndo_bpf		ndo_xdp
#endif

#ifndef HAVE_TC_SETUP_QDISC_MQPRIO
#define TC_SETUP_QDISC_MQPRIO TC_SETUP_MQPRIO
#endif

#ifndef netdev_WARN_ONCE

#define netdev_level_once(level, dev, fmt, ...)			\
do {								\
	static bool __print_once __read_mostly;			\
								\
	if (!__print_once) {					\
		__print_once = true;				\
		netdev_printk(level, dev, fmt, ##__VA_ARGS__);	\
	}							\
} while (0)

#define netdev_emerg_once(dev, fmt, ...) \
	netdev_level_once(KERN_EMERG, dev, fmt, ##__VA_ARGS__)
#define netdev_alert_once(dev, fmt, ...) \
	netdev_level_once(KERN_ALERT, dev, fmt, ##__VA_ARGS__)
#define netdev_crit_once(dev, fmt, ...) \
	netdev_level_once(KERN_CRIT, dev, fmt, ##__VA_ARGS__)
#define netdev_err_once(dev, fmt, ...) \
	netdev_level_once(KERN_ERR, dev, fmt, ##__VA_ARGS__)
#define netdev_warn_once(dev, fmt, ...) \
	netdev_level_once(KERN_WARNING, dev, fmt, ##__VA_ARGS__)
#define netdev_notice_once(dev, fmt, ...) \
	netdev_level_once(KERN_NOTICE, dev, fmt, ##__VA_ARGS__)
#define netdev_info_once(dev, fmt, ...) \
	netdev_level_once(KERN_INFO, dev, fmt, ##__VA_ARGS__)

#endif /* netdev_WARN_ONCE */

#ifndef HAVE_NETDEV_REG_STATE
static inline const char *netdev_reg_state(const struct net_device *dev)
{
	switch (dev->reg_state) {
	case NETREG_UNINITIALIZED: return " (uninitialized)";
	case NETREG_REGISTERED: return "";
	case NETREG_UNREGISTERING: return " (unregistering)";
	case NETREG_UNREGISTERED: return " (unregistered)";
	case NETREG_RELEASED: return " (released)";
	case NETREG_DUMMY: return " (dummy)";
	}

	WARN_ONCE(1, "%s: unknown reg_state %d\n", dev->name, dev->reg_state);
	return " (unknown)";
}
#endif

/* WA for broken netdev_WARN_ONCE in some kernels */
#ifdef netdev_WARN_ONCE
#undef netdev_WARN_ONCE
#endif
#define netdev_WARN_ONCE(dev, format, args...)				\
	WARN_ONCE(1, "netdevice: %s%s: " format, netdev_name(dev),	\
		  netdev_reg_state(dev), ##args)

#ifndef HAVE_NAPI_COMPLETE_DONE
#define napi_complete_done(p1, p2) napi_complete(p1)
#endif


#ifndef HAVE_NETDEV_PHYS_ITEM_ID
#ifndef MAX_PHYS_ITEM_ID_LEN
#define MAX_PHYS_ITEM_ID_LEN 32
#endif
/* This structure holds a unique identifier to identify some
 * physical item (port for example) used by a netdevice.
 */
struct netdev_phys_item_id {
    unsigned char id[MAX_PHYS_ITEM_ID_LEN];
    unsigned char id_len;
};
#endif

#if defined(CONFIG_COMPAT_CLS_FLOWER_MOD) && !defined(CONFIG_COMPAT_KERNEL_4_9)
enum {
	TC_SETUP_MQPRIO,
	TC_SETUP_CLSU32,
	TC_SETUP_CLSFLOWER,
};

struct tc_cls_u32_offload;

struct tc_to_netdev {
	unsigned int type;
	union {
		u8 tc;
		struct tc_cls_u32_offload *cls_u32;
		struct tc_cls_flower_offload *cls_flower;
	};
};
#endif

#endif	/* _COMPAT_LINUX_NETDEVICE_H */
