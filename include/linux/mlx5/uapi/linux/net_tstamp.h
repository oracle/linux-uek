#ifndef _COMPAT_LINUX_NET_TSTAMP_H
#define _COMPAT_LINUX_NET_TSTAMP_H

#include "linux/mlx5/compat/config.h"

#include_next <linux/net_tstamp.h>

#ifndef HAVE_HWTSTAMP_FILTER_NTP_ALL
#define HWTSTAMP_FILTER_NTP_ALL	15
#endif

#endif /* _COMPAT_LINUX_NET_TSTAMP_H */
