/*
 * Copyright (c) 2019, Oracle and/or its affilicates.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef _RDMAIP_H
#define _RDMAIP_H

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <linux/pci.h>
#include <linux/slab.h>

#define	RDMAIP_IPv4_SOCK_CREATED	0x1
#define	RDMAIP_IPv6_SOCK_CREATED	0x2
#define	RDMAIP_REG_NET_SYSCTL		0x4
#define	RDMAIP_IB_REG			0x8
#define	RDMAIP_IP_WQ_CREATED		0x10
#define	RDMAIP_IP_CONFIG_INIT_DONE	0x20
#define	RDMAIP_REG_NETDEV_NOTIFIER	0x40
#define	RDMAIP_REG_INETADDR_NOTIFIER	0x80
#define	RDMAIP_REG_INET6ADDR_NOTIFIER	0x100

#define RDMAIP_DEFAULT_GIDTBL_LEN	64
#define	RDMAIP_MAX_NAME_LEN		32

#define RDMAIP_DEV_TYPE_IB		0x1
#define RDMAIP_DEV_TYPE_ETHER		0x2

static int rdmaip_init_flag;

struct list_head rdmaip_devlist_head;
DECLARE_RWSEM(rdmaip_devlist_lock);

#define RDMAIP_FLAG_BUSY		1
#define RDMAIP_FLAG_EVENT_PENDING	2
#define RDMAIP_FLAG_TEARDOWN		3

unsigned long rdmaip_global_flag;
DEFINE_MUTEX(rdmaip_global_flag_lock);

struct port_info {
	int	gid_tbl_len;
	struct net_device *real_netdev;
};

#define RDMAIP_MAX_PHYS_PORTS 4

struct rdmaip_device {
	struct list_head	list;
	struct ib_device	*ibdev;
	struct ib_event_handler	event_handler;
	struct port_info	pinfo[RDMAIP_MAX_PHYS_PORTS];
};

#define RDMAIP_DEFAULT_NUM_ARPS		50
#define RDMAIP_MAX_NUM_ARPS		100
#define RDMAIP_DEFAULT_NUM_ARPS_GAP_MS	100

#define RDMAIP_MAX_ALIASES		50
#define RDMAIP_MAX_PORTS		50
#define RDMAIP_MAX_EXCL_IPS		20

#define	RDMAIP_PORT_ADDR_SET(idx)	\
	(ip_config[idx].ip_addr || ip_config[idx].ip6_addrs_cnt)

#define RDMAIP_IPV4_ADDR_SET(port)	\
	(ip_config[port].ip_addr != 0)

#define RDMAIP_IPV6_ADDR_SET(port)	\
	(ip_config[port].ip6_addrs_cnt > 0)
/*
 * Resilient RDMA IP Module parameters
 *
 * rdmaip_active_bonding_enabled
 *	0 - Active bonding is disabled
 *     >0 - Active Bonding is enabled
 *          If active bonding is enabled, then
 *          active bonding groups are created
 *          across ports of the same RDMA device
 */
unsigned int rdmaip_active_bonding_enabled;
module_param(rdmaip_active_bonding_enabled, int, 0444);
MODULE_PARM_DESC(rdmaip_active_bonding_enabled,
		 " Enables/Disables Active Bonding");

/*
 * rdmaip_exclude_ips_list
 *     Contains list of IP 's to excluded when creating
 *     default active bond grops
 *     Exclude IPv4 link local addresses
 */
static char *rdmaip_ipv4_exclude_ips_list = "169.254/16";
module_param(rdmaip_ipv4_exclude_ips_list, charp, 0444);
MODULE_PARM_DESC(rdmaip_ipv4_exclude_ips_list,
	"[<IP>/<prefix>][,<IP>/<prefix>]*");

/*
 *
 * rdmaip_active_bonding_failover_groups
 *     Contains user specified bonding groups information
 *     If active bonding is enabled, then RDMAIP module
 *     creates active bodning groups specified in this
 *     parameter. Default active bonding groups will not be
 *     created when this variable is set
 *
 */

unsigned int rdmaip_active_bonding_failback = 1;
module_param(rdmaip_active_bonding_failback, int, 0444);
MODULE_PARM_DESC(rdmaip_active_bonding_failback,
		 " Active Bonding failback Enabled");

/*
 * This is upper bound on time between when
 * RDMAIP module is loaded (and its init script
 * run including this code!) in rdma (openibd in OL5)
 * script and the network init script *after* all
 * the interfaces are initialized with their setup
 * scripts (ifcfg-ibN etc).
 *
 * This is a max time which should normally not be
 * hit. Normally the network startup script
 * will set rdmaip_sysctl_trigger_active_bonding
 * (initialized to 0) and we will not hit the
 * max time.
 *
 * Based on some empirical experiments, we put
 * upper bound to be 75secs(60000msecs) and up.
 * And we put min to be 20secs (20000msecs).
 */
unsigned int rdmaip_trigger_delay_max_msecs = 75000;
module_param(rdmaip_trigger_delay_max_msecs, int, 0444);
MODULE_PARM_DESC(rdmaip_trigger_delay_max_msecs,
		" Maximum delay in msec before failover during boot is triggered");

unsigned int rdmaip_trigger_delay_min_msecs = 20000;
module_param(rdmaip_trigger_delay_min_msecs, int, 0444);
MODULE_PARM_DESC(rdmaip_trigger_delay_min_msecs,
		" Minimum delay in msec before failover during boot is triggered");

/*
 * rdmaip_active_bonding_failover_groups allows
 * user to create active bonding groups by specifying
 * interfaces in this variables.
 */
static char *rdmaip_active_bonding_failover_groups;
module_param(rdmaip_active_bonding_failover_groups, charp, 0444);
MODULE_PARM_DESC(rdmaip_active_bonding_failover_groups,
		 "<ifname>[,<ifname>]*[;<ifname>[,<ifname>]*]*");

/*
 * Number of ARP request to send when IP is moved from one port
 * another port in the active bonding group
 */
unsigned int rdmaip_active_bonding_arps = RDMAIP_DEFAULT_NUM_ARPS;
unsigned int rdmaip_active_bonding_arps_gap_ms = RDMAIP_DEFAULT_NUM_ARPS_GAP_MS;
module_param(rdmaip_active_bonding_arps, int, 0644);
MODULE_PARM_DESC(rdmaip_active_bonding_arps,
		 " Number of gratuitous ARP requests to send when IP moved");
module_param(rdmaip_active_bonding_arps_gap_ms, int, 0644);
MODULE_PARM_DESC(rdmaip_active_bonding_arps_gap_ms,
		 " Number of msecs between gARPs sent");

struct socket	*rdmaip_inet_socket;
struct socket	*rdmaip_inet6_socket;

static struct	rdmaip_port *ip_config;
static u8	ip_port_cnt;
static u8	ip_port_max = RDMAIP_MAX_PORTS;

/* Check if a given ip_config[] port is set. */
#define	IP_PORT_ADDR_SET(idx)   \
	(ip_config[idx].ip_addr || ip_config[idx].ip6_addrs_cnt)

#define RDMAIP_MAX_EXCLUDE_IPS     20
struct rdmaip_exclude_ips {
	__be32                  ip;
	__be32                  prefix;
	__be32                  mask;
};

static struct	rdmaip_exclude_ips exclude_ips_tbl[RDMAIP_MAX_EXCLUDE_IPS];
static u8	exclude_ips_cnt;

static int initial_failovers_iterations; /* = 0 */

static void rdmaip_initial_failovers(struct work_struct *workarg);
static int timeout_until_initial_failovers;

struct rdmaip_alias {
	char	if_name[IFNAMSIZ];
	__be32	ip_addr;
	__be32	ip_bcast;
	__be32	ip_mask;
};

enum {
	RDMAIP_PORT_INIT = 0,
	RDMAIP_PORT_UP,
	RDMAIP_PORT_DOWN,
};

/*
 * Bit flags to keep track of status of different layers
 * in field "port_layerflags" of "struct rdmaip_port"
 * data structure declared below.
 *
 * The structure also uses field "port_state" as
 * a composite UP/DOWN state derived from the
 * setting of the "port_layerflags" field bits.
 *
 * Layer 1: HWPORTUP - HCA port UP
 * Layer 2: LINKUP - Link UP
 * Layer 3: NETDEVUP - netdev layer UP
 *
 *  +-----------------------------------------------------------------+
 *  | ALL THREE Flags need to be UP(set) for a port_state to be UP for|
 *  | failback.                                                       |
 *  | ANY ONE  Flag being DOWN (clear) triggers failover.             |
 *  +-----------------------------------------------------------------+
 */
#define RDMAIP_PORT_STATUS_HWPORTUP	0x0001U /* HCA port UP */
#define RDMAIP_PORT_STATUS_LINKUP	0x0002U /* Link layer UP */
#define RDMAIP_PORT_STATUS_NETDEVUP	0x0004U /* NETDEV layer UP */
#define RDMAIP_PORT_STATUS_IP_CONFIGURED 0x0008U /* IP's Configured */
#define RDMAIP_PORT_STATUS_ALLUP	(RDMAIP_PORT_STATUS_HWPORTUP \
					| RDMAIP_PORT_STATUS_LINKUP \
					| RDMAIP_PORT_STATUS_NETDEVUP\
					| RDMAIP_PORT_STATUS_IP_CONFIGURED)

/*
 * Design notes for failover/failback processing:
 *
 * Opportunity for checking and setting status of above
 * "port_layerflags: bits done at:
 *
 *  (1) module load time:
 *         rdmaip_ip_config_init()
 *  (2) HW port status changes:
 *         rdmaip_event_handler()
 *  (3) link layer status changes: NETDEV_CHANGE handling in
 *         rdmaip_netdev_callback()
 *  (4) netdevice layer status changes: NETDEV_UP/NETDEV_DOWN handling in
 *         rdmaip_netdev_callback()
 *
 * Caveats:
 *    (a) A link-layer LINKUP detection can be used to mark HW port HWPORTUP
 *        also. Used because VM guests rebooting do not get the HW port UP
 *        events during boot (presumably) because the VM server has the
 *        HW ports up and no real transitions are happening.[module init
 *        code will show link layer up on VM reboots but not for bare metal,
 *        also on module load (after an unload)]
 *
 *    (b) The HW port down/up usually causes the link layer NETDEV_CHANGE
 *        trigger but NOT always! If due to any hardware issues if HW ports
 *        momentarily bounce, but such "port-bounces" do not generate
 *        corresponding link layer NETDEV_CHANGE events!
 *
 *    (c) Event processing in (2)-(4) above triggers failover/failback
 *        processing but initialization in (1) does detection but not
 *        processing as resilient_rdmaip module load processing happens
 *	  before devices have come up.
 *
 *        For initial/boot time failover processing, a separate delayed
 *        processing is launched to run after link layer and netdev is UP!
 *
 */

#define RDMAIP_MAX_ALIASES	50
#define RDMAIP_MAX_PORTS	50

/* Maximum number of IPv6 addresses for each rdmaip_ip6_port. */
#define RDMAIP_MAX_ADDRS        10

/*
 * This struct is used for storing IPv6 addresses in a rdmaip_port.
 * Note that address alias is obsolete and does not apply to IPv6 address.
 * Broadcast is also not applicable.
 *
 * IPv6 addresses are separated from IPv4 addresses to minimize code changes.
 * The alias address list should probably be removed in future.
 */
struct rdmaip_ip6_port_addr {
	struct in6_addr		addr;
	u32			prefix_len;
};

struct rdmaip_port {
	struct rdmaip_device	*rdmaip_dev;
	u32			device_type;
	unsigned int		failover_group;
	struct net_device	*netdev;
	unsigned int            port_state;
	u32                     port_layerflags;
	u8			port_num;
	union ib_gid            gid;
	char			port_label[4];
	char                    if_name[IFNAMSIZ];
	__be32                  ip_addr;
	__be32			ip_bcast;
	__be32			ip_mask;
	unsigned int            ip_active_port;
	uint16_t		pkey_vlan;
	unsigned int            alias_cnt;
	struct rdmaip_alias	aliases[RDMAIP_MAX_ALIASES];
	int			ifindex;
	u32			ip6_addrs_cnt; /* No. of IPv6 addresses */
	struct rdmaip_ip6_port_addr ip6_addrs[RDMAIP_MAX_ADDRS];
};

enum {
	RDMAIP_PORT_TRANSITION_NOOP,
	RDMAIP_PORT_TRANSITION_UP,
	RDMAIP_PORT_TRANSITION_DOWN
};

/*
 * Work queues private data
 *
 * if event_type == RDMAIP_EVENT_IB, following fields are valid
 *     rdmaip_dev
 *     ib_port
 *     ib_event
 *
 * if event_type == RDMAIP_EVENT_NET, following fields are valid
 *     netdev
 *     net_event
 */

struct rdmaip_dly_work_req {
	struct delayed_work	work;
	struct net_device	*netdev;
	unsigned int		port;
	int			timeout;
	struct rdmaip_device	*rdmaip_dev;
	unsigned int		ib_port;
	int			event_type;
	int			ib_event;
	int			net_event;
	unsigned char		*dev_addr;
	unsigned long		delay;
	__be32			ip_addr;
	int			garps_left;
	bool			queued;
	struct list_head	list;
};

enum {
	RDMAIP_EVENT_NONE,
	RDMAIP_EVENT_IB,
	RDMAIP_EVENT_NET,
	RDMAIP_EVENT_INETADDR,
	RDMAIP_EVENT_GARP
};

#define ibdev_to_rdmaipdev(ibdev) dev_to_node((ibdev)->dev.parent)

enum {
	RDMAIP_DEBUG_L1		= 1 << 0,	/* 0x1    */
	RDMAIP_DEBUG_L2		= 1 << 1,	/* 0x2    */
	RDMAIP_DEBUG_L3		= 1 << 2,	/* 0x4    */
};

/*
 * Debugging
 */
u32 rdmaip_sysctl_debug_flag	= RDMAIP_DEBUG_L1 |
				  RDMAIP_DEBUG_L2;

#define rdmaip_printk(format, arg...)		\
	trace_printk("%d: " format, __LINE__, ## arg)

#define RDMAIP_DBG1_PTR(format, arg...)				\
	do { if (rdmaip_sysctl_debug_flag & RDMAIP_DEBUG_L1)	\
		__trace_printk(_THIS_IP_, "%d: " format, __LINE__, ## arg); \
	} while (0)

#define RDMAIP_DBG1(format, arg...)				\
	do { if (rdmaip_sysctl_debug_flag & RDMAIP_DEBUG_L1)	\
		 rdmaip_printk(format, ## arg);			\
	} while (0)

#define RDMAIP_DBG2_PTR(format, arg...)				\
	do { if (rdmaip_sysctl_debug_flag & RDMAIP_DEBUG_L2)	\
		__trace_printk(_THIS_IP_, "%d: " format, __LINE__, ## arg); \
	} while (0)

#define RDMAIP_DBG2(format, arg...)				\
	do { if (rdmaip_sysctl_debug_flag & RDMAIP_DEBUG_L2)	\
		 rdmaip_printk(format, ## arg);			\
	} while (0)

#define RDMAIP_DBG3(format, arg...)				\
	do { if (rdmaip_sysctl_debug_flag & RDMAIP_DEBUG_L3)	\
		 rdmaip_printk(format, ## arg);			\
	} while (0)

/*
 * Sysctl variable that allows to enable or disable active
 * bonding on a running system.
 *
 * Network service uses this varialbe to enable active_bonding
 * as part of the "start" operation and disables active_bonding
 * as part of the "stop" operation.
 */
unsigned int rdmaip_sysctl_active_bonding = 1;

/*
 * sysctl to trigger active bonding when set to 1
 * by the network startup script *after* all IB
 * devices have been configured to trigger asap
 * the active bonding.
 * If not triggered by this sysctl, a max timeout
 * will trigger it!
 */
unsigned int rdmaip_sysctl_trigger_active_bonding; /* = 0 */

unsigned long rdmaip_active_bonding_failback_min_jiffies = HZ;
unsigned long rdmaip_active_bonding_failback_max_jiffies = HZ * 100;
unsigned long rdmaip_sysctl_active_bonding_failback_ms = 10000;

unsigned long rdmaip_roce_active_bonding_failback_min_ms = 1000;
unsigned long rdmaip_roce_active_bonding_failback_max_ms = 60000;
unsigned long rdmaip_sysctl_roce_active_bonding_failback_ms = 20000;

static struct ctl_table_header *rdmaip_sysctl_hdr;

static struct ctl_table rdmaip_sysctl_table[] = {
	{
		.procname       = "active_bonding",
		.data           = &rdmaip_sysctl_active_bonding,
		.maxlen         = sizeof(rdmaip_sysctl_active_bonding),
		.mode           = 0644,
		.proc_handler   = &proc_dointvec,
	},
	{
		.procname       = "trigger_active_bonding",
		.data           = &rdmaip_sysctl_trigger_active_bonding,
		.maxlen         = sizeof(rdmaip_sysctl_trigger_active_bonding),
		.mode           = 0644,
		.proc_handler   = &proc_dointvec,
	},
	{
		.procname       = "active_bonding_failback_ms",
		.data           = &rdmaip_sysctl_active_bonding_failback_ms,
		.maxlen         = sizeof(rdmaip_sysctl_active_bonding_failback_ms),
		.mode           = 0644,
		.proc_handler   = proc_doulongvec_ms_jiffies_minmax,
		.extra1		= &rdmaip_active_bonding_failback_min_jiffies,
		.extra2		= &rdmaip_active_bonding_failback_max_jiffies,
	},
	{
		.procname       = "debug_flag",
		.data           = &rdmaip_sysctl_debug_flag,
		.maxlen         = sizeof(rdmaip_sysctl_active_bonding),
		.mode           = 0644,
		.proc_handler   = &proc_dointvec,
	},
	{
		.procname       = "roce_active_bonding_failback_ms",
		.data           = &rdmaip_sysctl_roce_active_bonding_failback_ms,
		.maxlen         = sizeof(rdmaip_sysctl_roce_active_bonding_failback_ms),
		.mode           = 0644,
		.proc_handler   = proc_doulongvec_ms_jiffies_minmax,
		.extra1		= &rdmaip_roce_active_bonding_failback_min_ms,
		.extra2		= &rdmaip_roce_active_bonding_failback_max_ms,
	},
	{ }
};
#endif
