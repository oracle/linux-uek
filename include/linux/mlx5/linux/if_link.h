#ifndef LINUX_IF_LINK_H
#define LINUX_IF_LINK_H

#include <linux/mlx5/compat/config.h>

#include_next <linux/if_link.h>

#ifndef HAVE_IFLA_VF_STATS
struct ifla_vf_stats {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 broadcast;
	__u64 multicast;
};
#endif

#endif /* LINUX_IF_LINK_H */
