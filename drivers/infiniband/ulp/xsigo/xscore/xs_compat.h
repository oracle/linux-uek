/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
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
#ifndef	_XS_COMPAT_H
#define	_XS_COMPAT_H
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/scatterlist.h>
#include <linux/io.h>
#include <linux/in.h>
#include <linux/log2.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/idr.h>
#include <linux/netdevice.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>
#include <rdma/ib_verbs.h>

/*
 * Workqueue changes backport for kernel < linux 2.6.20
 * ESX 4.0 has these changes and hence no need of this
 */

typedef void *xsmp_cookie_t;

#if defined(XSIGOPSEUDOFLAG)
/*
 * ESX-5.1 pseudo device registration.
 */
static inline void xg_preregister_pseudo_device(struct net_device *netdev)
{
	if (netdev->pdev) {
		netdev->pdev->netdev = NULL;
		netdev->pdev_pseudo = netdev->pdev;
		netdev->pdev = NULL;
	}
}

static inline void xg_setup_pseudo_device(struct net_device *netdev,
					  struct ib_device *hca)
{
	netdev->features |= NETIF_F_PSEUDO_REG;
	SET_NETDEV_DEV(netdev, hca->dma_device);
}
#else
static inline void xg_preregister_pseudo_device(struct net_device *netdev)
{
}

static inline void xg_setup_pseudo_device(struct net_device *netdev,
					  struct ib_device *hca)
{
}
#endif

static inline void xg_set_netdev_dev(struct net_device *netdev,
				     struct ib_device *hca)
{
}

#ifndef BACKPORT_LINUX_WORKQUEUE_TO_2_6_19

#endif


#if !defined(XG_FRAG_SIZE_PRESENT)

static inline unsigned int skb_frag_size(const skb_frag_t *frag)
{
	return frag->size;
}

#endif

#if !defined(XG_FRAG_PAGE_PRESENT)

static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}

#endif


#include <scsi/scsi_cmnd.h>

#if defined(SCSI_STRUCT_CHANGES)

static inline void scsi_set_buffer(struct scsi_cmnd *cmd, void *buffer)
{
	cmd->sdb.table.sgl = buffer;
}

static inline void set_scsi_sg_count(struct scsi_cmnd *cmd, int cnt)
{
	cmd->sdb.table.nents = cnt;
}

#else /* ! defined(SCSI_STRUCT_CHANGES) */

static inline void scsi_set_buffer(struct scsi_cmnd *cmd, void *buffer)
{
	cmd->request_buffer = buffer;
}

#define set_scsi_sg_count(cmd, cnt)	((cmd)->use_sg = (cnt))

#ifndef	scsi_sg_count

#define scsi_sg_count(cmd) ((cmd)->use_sg)
#define scsi_sglist(cmd) ((struct scatterlist *)(cmd)->request_buffer)
#define scsi_bufflen(cmd) ((cmd)->request_bufflen)

static inline void scsi_set_resid(struct scsi_cmnd *cmd, int resid)
{
	cmd->resid = resid;
}

static inline int scsi_get_resid(struct scsi_cmnd *cmd)
{
	return cmd->resid;
}

#define scsi_for_each_sg(cmd, sg, nseg, __i)                    \
	for_each_sg(scsi_sglist(cmd), sg, nseg, __i)

#endif

#ifndef	sg_page
#define sg_page(x) ((x)->page)
#endif

#endif /* ! defined(SCSI_STRUCT_CHANGES) */

#if defined(SCSI_TIMEOUT_CHANGES)
#define timeout_per_command(cmd)	((cmd)->request->timeout)
#define vhba_reset_scsi_timeout(cmd, jiffies)	/* NOTHING */
#else /* ! defined(SCSI_TIMEOUT_CHANGES) */
#define timeout_per_command(cmd)	((cmd)->timeout_per_command)
#define vhba_reset_scsi_timeout(cmd, jiffies)			\
do {								\
	if ((cmd)->eh_timeout.function)				\
		mod_timer(&(cmd)->eh_timeout, jiffies)		\
} while (0)
#endif /* ! defined(SCSI_TIMEOUT_CHANGES) */


#define	SET_OWNER(file)	do { } while (0)

/*
 * In 2.6.31 added new netdev_ops in netdev
 */
#define SET_NETDEV_OPS(netdev, ops) \
	((netdev)->netdev_ops = (ops))


#if !defined(HAS_SKB_ACCESS_FUNCTIONS)

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return skb->h.th->doff << 2;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (skb->h.th->doff - 5) * 4;
}

static inline void skb_reset_network_header(struct sk_buff *skb)
{
	skb->nh.raw = skb->data;
}
#endif



/*
 * Backported NAPI changes  ESX 4.0 already supports it
 */

static inline void napi_update_budget(struct napi_struct *n, int cnt)
{
}


#ifndef	NETIF_F_GRO
#define	NETIF_F_GRO	0
#endif

#ifndef	NETIF_F_GSO
#define	NETIF_F_GSO	0
#endif

#ifndef	IFF_SLAVE_INACTIVE
#define	IFF_SLAVE_INACTIVE	0x4
#endif

#ifndef	CHECKSUM_PARTIAL
#define	CHECKSUM_PARTIAL	CHECKSUM_HW
#endif

#if !defined(LLE) && defined(IB_VERBS_H)
#if defined(NATIVE_IB_STACK_CHECK)
enum rdma_link_layer {
	IB_LINK_LAYER_UNSPECIFIED,
	IB_LINK_LAYER_INFINIBAND,
	IB_LINK_LAYER_ETHERNET,
};

static inline void iboe_mac_vlan_to_ll(union ib_gid *gid, u8 *mac, u16 vid)
{
	memset(gid->raw, 0, 16);
	*((u32 *) gid->raw) = cpu_to_be32(0xfe800000);
	if (vid) {
		gid->raw[12] = vid & 0xff;
		gid->raw[11] = vid >> 8;
	} else {
		gid->raw[12] = 0xfe;
		gid->raw[11] = 0xff;
	}

	memcpy(gid->raw + 13, mac + 3, 3);
	memcpy(gid->raw + 8, mac, 3);
	gid->raw[8] ^= 2;
}
#endif /*IB_REV_106_CHECK */

static inline enum rdma_link_layer rdma_port_link_layer(struct ib_device
							*device, u8 port_num)
{
	return IB_LINK_LAYER_INFINIBAND;
}

#endif /* ! defined(LLE) */

#if defined(LLE) && defined(RDMA_PORT_LINK_LAYER_CHANGES)
#define	rdma_port_link_layer rdma_port_get_link_layer
#endif

#define PROC_ROOT       0

extern int xscore_uadm_init(void);
extern void xscore_uadm_destroy(void);
extern void xscore_uadm_receive(xsmp_cookie_t xsmp_hndl, u8 *data, int len);

/* required for IB_REV_106 */
#if !defined(IB_REV_106_CHECK) || !defined(IB_REV_110_CHECK)
#define xg_vmk_kompat_init() do {} while (0)
#define xg_vmk_kompat_cleanup() do {} while (0)
#else
extern int xg_vmk_kompat_init(void);
extern void xg_vmk_kompat_cleanup(void);
#endif

#define VMWARE_RESERVED_KEYS ""
#define SG_OFFSET(sg) (sg->offset)
#define SG_LENGTH(sg) (sg->length)
#define	SG_NEXT(sg) (sg++)
#define	SG_RESET(sg) {}
#define ib_sa_force_update(client, dev, attr, value, mode)  do {} while (0)

#define	GET_NLINK(file)		((file)->nlink)
#define SET_NLINK(file, value)	((file)->nlink = (value))

/*
 * 8k IBMTU support
 */
enum xg_ib_mtu {
	IB_MTU_8192 = 6
};

static inline int xg_ib_mtu_enum_to_int(enum ib_mtu _mtu)
{
	int mtu = (int)_mtu;

	switch (mtu) {
	case IB_MTU_256:
		return 256;
	case IB_MTU_512:
		return 512;
	case IB_MTU_1024:
		return 1024;
	case IB_MTU_2048:
		return 2048;
	case IB_MTU_4096:
		return 4096;
	case IB_MTU_8192:
		return 8192;
	default:
		return -1;
	}
}
#endif /* _XS_COMPAT_H */
