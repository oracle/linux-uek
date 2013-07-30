/*
 * Copyright (c) 2011-2012 Xsigo Systems. All rights reserved
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
 */
#ifndef _XVE_COMPAT_H
#define _XVE_COMPAT_H
#include "xve.h"
#define	XVE_OP_CM     (1ul << 30)

#include <net/icmp.h>
static inline void skb_pkt_type(struct sk_buff *skb, unsigned char type)
{
	skb->pkt_type = type;
}

static inline void xve_dev_set_mtu(struct net_device *dev, int mtu)
{
	rtnl_lock();
	dev_set_mtu(dev, mtu);
	rtnl_unlock();
}

static inline void xg_skb_push(struct sk_buff *skb, unsigned int len)
{
	skb_push(skb, len);
}

static inline unsigned xve_random32(struct xve_dev_priv *priv)
{
	return random32() & 0xffffff;
}


static inline struct proc_dir_entry *xg_create_proc_entry(const char *name,
							  mode_t mode,
							  struct proc_dir_entry
							  *parent, char root)
{
	return create_proc_entry(name, mode, parent);
}

static inline void xg_remove_proc_entry(const char *name,
					struct proc_dir_entry *parent)
{
	return remove_proc_entry(name, parent);
}

#endif /* _XVE_COMPAT_H */
