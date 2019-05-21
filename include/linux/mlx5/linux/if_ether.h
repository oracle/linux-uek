#ifndef _COMPAT_LINUX_IF_ETHER_H
#define _COMPAT_LINUX_IF_ETHER_H

#include "linux/mlx5/compat/config.h"

#include_next <linux/if_ether.h>

#ifndef HAVE_ETH_MIN_MTU
#define ETH_MIN_MTU  68 /* Min IPv4 MTU per RFC791 */
#endif

#endif /* _COMPAT_LINUX_IF_ETHER_H */
