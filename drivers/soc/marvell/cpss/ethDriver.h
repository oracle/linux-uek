/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

This software file (the "File") is owned and distributed by Marvell
International Ltd. and/or its affiliates ("Marvell") under the following
alternative licensing terms.  Once you have made an election to distribute the
File under one of the following license alternatives, please (i) delete this
introductory statement regarding license alternatives, (ii) delete the two
license alternatives that you have not elected to use and (iii) preserve the
Marvell copyright notice above.

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.
*******************************************************************************/

#ifndef __ethDriver_h__
#define __ethDriver_h__

#include <linux/types.h>
#include <linux/netdevice.h>

#define MAX_FRAGS 8
#define NUM_OF_RX_QUEUES 8
#define DSA_SIZE 16

struct mvppnd_dma_sg_buf {
	unsigned char *virt;
	dma_addr_t mappings[MAX_FRAGS + 1]; /* 1 for head */
	size_t sizes[MAX_FRAGS + 1];
};

extern int mvppnd_emulate_rx(struct net_device *ndev, u8 *dsa, char *data,
			     size_t data_len, u8 queue);

struct mvppnd_ops {
	/* May return NF_ACCEPT, NF_DROP, NF_STOLEN and NF_QUEUE (route to TX) */
	int (*process_rx)(struct net_device *ndev, unsigned char *data,
			  int *sz, int max_sz);
	/* May return NF_ACCEPT, NF_DROP, NF_STOLEN and NF_QUEUE (route to RX) */
	int (*process_tx)(struct net_device *ndev, struct sk_buff *skb);
};

extern int mvppnd_register_hooks(struct net_device *ndev,
				 struct mvppnd_ops *ops);

#endif
