
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

static inline void csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
	*sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

struct udp_tunnel_info {
	unsigned short type;
	sa_family_t sa_family;
	__be16 port;
};

enum udp_parsable_tunnel_type {
        UDP_TUNNEL_TYPE_VXLAN,          /* RFC 7348 */
        UDP_TUNNEL_TYPE_GENEVE,         /* draft-ietf-nvo3-geneve */
        UDP_TUNNEL_TYPE_VXLAN_GPE,      /* draft-ietf-nvo3-vxlan-gpe */
};

#define NETDEV_UDP_TUNNEL_PUSH_INFO	0x001C
static inline void udp_tunnel_get_rx_info(struct net_device *dev)
{
	ASSERT_RTNL();
	call_netdevice_notifiers(NETDEV_UDP_TUNNEL_PUSH_INFO, dev);
}

