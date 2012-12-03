/*
 * Copyright (c) 2012 Mellanox Technologies. All rights reserved
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * openfabric.org BSD license below:
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

#ifndef _LINUX_ETH_IB_IPOIB_H
#define _LINUX_ETH_IB_IPOIB_H
#include <net/sch_generic.h>

struct eipoib_cb_data {
	/*
	* extra care taken not to collide with the usage done
	* by the qdisc layer in struct skb cb data.
	*/
	struct qdisc_skb_cb     qdisc_cb;
	struct { /* must be <= 20 bytes */
		u32 sqpn;
		struct napi_struct *napi;
		u16 slid;
		u8 data[6];
	} __packed rx;
};

#define IPOIB_HANDLER_CB(skb) ((struct eipoib_cb_data *)(skb)->cb)

#endif /* _LINUX_ETH_IB_IPOIB_H */
