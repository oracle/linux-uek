
#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/mii.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>

#endif

#ifdef CONFIG_XPS
extern int __kc_netif_set_xps_queue(struct net_device *, struct cpumask *, u16);
#define netif_set_xps_queue(_dev, _mask, _idx) __kc_netif_set_xps_queue((_dev), (_mask), (_idx))
#else /* CONFIG_XPS */
#define netif_set_xps_queue(_dev, _mask, _idx) do {} while (0)
#endif /* CONFIG_XPS */

/* hardware time stamping: parameters in linux/net_tstamp.h */
#define SIOCGHWTSTAMP	0x89b1		/* get config */

#undef hlist_entry
#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#undef hlist_entry_safe
#define hlist_entry_safe(ptr, type, member) \
	(ptr) ? hlist_entry(ptr, type, member) : NULL

#undef hlist_for_each_entry
#define hlist_for_each_entry(pos, head, member)                             \
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member); \
	     pos;                                                           \
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#undef hlist_for_each_entry_safe
#define hlist_for_each_entry_safe(pos, n, head, member) 		    \
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);   \
	     pos && ({ n = pos->member.next; 1; });			    \
	     pos = hlist_entry_safe(n, typeof(*pos), member))

#ifndef ether_addr_copy
#define ether_addr_copy __kc_ether_addr_copy
static inline void __kc_ether_addr_copy(u8 *dst, const u8 *src)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	*(u32 *)dst = *(const u32 *)src;
	*(u16 *)(dst + 4) = *(const u16 *)(src + 4);
#else
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
#endif
}
#endif /* ether_addr_copy */
