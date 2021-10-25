/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

This software file (the "File") is owned and distributed by Marvell
International Ltd. and/or its affiliates ("Marvell") under the following
alternative licensing terms.  Once you have made an election to distribute the
File under one of the following license alternatives, please (i) delete this
introductory statement regarding license alternatives, (ii) delete the
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

*******************************************************************************
Marvell BSD License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File under the following licensing terms.
Redistribution and use in source and binary forms, with or without modification,

are permitted provided that the following conditions are met:

*   Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

*   Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

*   Neither the name of Marvell nor the names of its contributors may be
    used to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*******************************************************************************/

/*******************************************************************************
* ethOpsDriver.c
*
* DESCRIPTION:
* The example separate driver (ethOpsDriver.c / mvEthOpsDrv.ko) can be
* configured from user-space to modify receive packets in various ways,
* and return any of the four possible actions for the packet.
* For the transmission path, it can delay packet transmission and
* additionally it can capture a packet scheduled for transmission
* and artificially loop it back into the driver as if the was
* received from the network.
*
*
* DEPENDENCIES:
*       ethDriver.c .
*
* FILE REVISION NUMBER:
*
*       $Revision: 1 $
*
*******************************************************************************/

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/kthread.h>
#include <uapi/linux/sched/types.h>
#include "ethDriver.h"

MODULE_LICENSE("GPL");

/*!
  \def DRV_NAME
  Defines the name of the kernel driver
*/
#define DRV_NAME "ethOpsDriver"
static const char *ifname = "mvpp0";
static struct net_device *ndev;

struct rx_context {
	struct task_struct *tg;
	struct net_device *ndev;
	char *data;
	size_t data_len;
};

enum {
	TX_OP_MODE_NOP = 0, /*!< No special operation for TX */
	TX_OP_MODE_TG = 1, /*!< Traffic Generator mode for TX */
};
enum {
	RX_OP_MODE_NOP = 0, /*!< No special operation for RX */
	RX_OP_MODE_PRINT = 1, /*!< print operation for RX */
	RX_OP_MODE_REPLACE = 2, /*!< replace operation for RX */
	RX_OP_MODE_INSERT = 3, /*!< insert operation for RX */
	RX_OP_MODE_DROP = 4, /*!< drop operation for RX */
	RX_OP_MODE_PRINT_COUNT = 5, /*!< print count operation for RX */
	RX_OP_MODE_STOLEN = 6, /*!< stolen buffer by callee operation for RX */
	RX_OP_MODE_REDIRECT_TO_TX = 7, /*!< redirect to TX operation for RX */
};

static unsigned int tx_mode = TX_OP_MODE_NOP;
module_param(tx_mode, uint, 0644);
MODULE_PARM_DESC(tx_mode, "TX Operation mode:\n\t\t1. Fork traffic generator");

static unsigned int tx_delay_msecs = 0;
module_param(tx_delay_msecs, uint, 0644);
MODULE_PARM_DESC(tx_delay_msecs, "Simulate slow TX");

static unsigned int tg_delay_msecs = 1;
module_param(tg_delay_msecs, uint, 0644);
MODULE_PARM_DESC(tg_delay_msecs, "traffic generator, msecs delay between packets");

static unsigned int tg_packet_to_dup = 0x0806;
module_param(tg_packet_to_dup, uint, 0644);
MODULE_PARM_DESC(tg_packet_to_dup, "traffic generator, packet to capture from TX to be used for RX emulation");

static unsigned int tg_mon_sent = 0;
module_param(tg_mon_sent, uint, 0444);
MODULE_PARM_DESC(tg_mon_sent, "traffic generator, sent packets counter");

static unsigned int tg_mon_drops = 0;
module_param(tg_mon_drops, uint, 0444);
MODULE_PARM_DESC(tg_mon_drops, "traffic generator, droped packets counter");

static unsigned int rx_mode = RX_OP_MODE_NOP;
module_param(rx_mode, uint, 0644);
MODULE_PARM_DESC(rx_mode,
		 "RX Operation mode:\n\t\t1. print buf\n\t\t2. Replace some bytes\n\t\t3. Insert some bytes\n\t\t4. Drop\n\t\t5. Count\n\t\t6. Stolen\n\t\t7. Redirect to TX");

static char *rx_data = "Yuval";
module_param(rx_data, charp, 0644);
MODULE_PARM_DESC(rx_data, "String to be used for RX mode 1 and 2");

static unsigned int rx_data_pos = 0;
module_param(rx_data_pos, uint, 0644);
MODULE_PARM_DESC(rx_data_pos, "Possition to place the string (max page_size) for RX mode 1 and 2");

static unsigned int rx_counter_dump = 10000;
module_param(rx_counter_dump, uint, 0644);
MODULE_PARM_DESC(rx_counter_dump, "Counter, when exceeds print message");

struct rx_context rx_ctx = {};

/**
* @internal print_buf function
* @endinternal
*
* @brief  prints the given binary buffer as text string
*
* @param[in] title                   - title to print
* @param[in] data                    - binary data to print
* @param[in] len                     - length of binary data to print, in bytes
*
* @retval void
*/
static void print_buf(const char *title, const unsigned char *data, size_t len)
{
	size_t sz;
	char *b;
	int i;

	sz = (len * 3) + 4 + strlen(title) + 1 + 1;

	b = kmalloc(sz, GFP_KERNEL);
	if (!b)
		return;

	sprintf(b, "len %ld:", len);
	for (i = 0; i < len; i++)
		sprintf(b, "%s %.2x", b, data[i]);
	pr_info("%s: %s\n", title, b);

	/*
	sprintf(b, "len %ld:", len);
	for (i = 0; i < len; i++)
		sprintf(b, "%s %c", b, data[i]);

	printk("%s: %s\n", title, b);
	*/

	kfree(b);
}

/**
* @internal process_rx function
* @endinternal
*
* @brief  RX hook callback processing function
*         Modifies the packet according to the rx_mode configured:
* 	  RX_OP_MODE_NOP: No special operation for RX
* 	  RX_OP_MODE_PRINT: print operation for RX
* 	  RX_OP_MODE_REPLACE: replace operation for RX
* 	  RX_OP_MODE_INSERT: insert operation for RX
* 	  RX_OP_MODE_DROP: drop operation for RX
* 	  RX_OP_MODE_PRINT_COUNT:  print count operation for RX
* 	  RX_OP_MODE_STOLEN: stolen buffer by callee operation for RX
* 	  RX_OP_MODE_REDIRECT_TO_TX: redirect to TX operation for RX
*
* @param[in] ndev               - Linux Kernel network device structure pointer
* @param[in] data               - data of received buffer to process
* @param[in,out] sz             - pointer to size of received buffer to process
*                                 Can be updated by this function
* @param[in] data               - maximum size of received buffer for expansion
*                                 purposes (when updating sz above)
*
* @retval NF_DROP               - When requesting to drop the packet
* @retval NF_ACCEPT             - When requesting to pass onwards the packet
* @retval NF_STOLEN             - When the packet is handled by this function
* @retval NF_QUEUE              - When requesting to redirect the packet to TX
*/
int process_rx(struct net_device *ndev, unsigned char *data, int *sz,
	       int max_sz)
{
	static int counter = 0;
	char *tmp_data, *p;
	int new_size;

	switch (rx_mode) {
	case RX_OP_MODE_PRINT:
		/* Just print */
		print_buf("rx", data, *sz);
		break;
	case RX_OP_MODE_REPLACE:
		/* Modify the buffer content, without changing the size */
		print_buf("nf1-before", data, *sz);
		if (rx_data_pos + strlen(rx_data) <= *sz)
			memcpy(data + rx_data_pos, rx_data, strlen(rx_data));
		print_buf("nf1-after ", data, *sz);
		break;
	case RX_OP_MODE_INSERT:
		/* Add some bytes to buffer, will increase the buffer size.*/
		print_buf("nf2-before", data, *sz);
		new_size = *sz + strlen(rx_data);
		if ((rx_data_pos < *sz) && (new_size < max_sz)) {
			p = tmp_data = kmalloc(new_size + 1, GFP_KERNEL);
			memcpy(p, data, rx_data_pos);
			p += rx_data_pos;
			memcpy(p, rx_data, strlen(rx_data));
			p += strlen(rx_data);
			memcpy(p, data + rx_data_pos, *sz - rx_data_pos);

			memcpy(data, tmp_data, new_size);
			*sz = new_size;

			kfree(tmp_data);
		}
		print_buf("nf2-after ", data, *sz);
		break;
	case RX_OP_MODE_DROP:
		/* Drop packet */
		return NF_DROP;
	case RX_OP_MODE_PRINT_COUNT:
		/* Print message after every $rx_counter_dump messages */
		if (++counter == rx_counter_dump) {
			dev_info(&ndev->dev, "%s: Got %d packets\n", DRV_NAME,
				 counter);
			counter = 0;
		}
		break;
	case RX_OP_MODE_STOLEN:
		return NF_STOLEN;
	case RX_OP_MODE_REDIRECT_TO_TX:
		return NF_QUEUE; /* Utilize as redirect to TX */
	default:
		/* Ignore */
		break;
	};

	return NF_ACCEPT;
}

/**
* @internal rx_traffic_generator function
* @endinternal
*
* @brief  Simulates reception of frames into the RX path of the ethDriver
*
* @param[in] data                  - pointer to RX simulation context structure
*
* @retval always zero
*/
static int rx_traffic_generator(void *data)
{
	struct rx_context *ctx = (struct rx_context *)data;
	u8 dsa[DSA_SIZE] = {};
	int rc, queue = 0;

	while (!kthread_should_stop()) {
		if (tx_mode != 1) {
			msleep(500);
			continue;
		}

		/* Push while we can */
		rc = mvppnd_emulate_rx(ctx->ndev, &dsa[0], ctx->data,
				       ctx->data_len, queue);
		if (rc > 0)
			mdelay(tg_delay_msecs);
		else
			tg_mon_drops++;

		tg_mon_sent++;

		if (++queue >= NUM_OF_RX_QUEUES)
			queue = 0;
	};

	return 0;
}

/**
* @internal free_rx_context function
* @endinternal
*
* @brief  Stops RX simulation and free the RX simulation context structure
*
* @param[in] void
*
* @retval void
*/
static void free_rx_context(void)
{
	if (!rx_ctx.data)
		return;

	kthread_stop(rx_ctx.tg);
	mdelay(tg_delay_msecs * 2);

	kfree(rx_ctx.data);
}

/**
* @internal process_tx function
* @endinternal
*
* @brief  TX hook callback processing function:
*         if configured so, and the packet matches
*	  the configured protocol number, simulates
*	  loop reception of this specific packet into
*	  the RX path of the ethDriver.
*	  In any case, delays the packet before
*	  transmitting it.
*
* @param[in] ndev               - Linux Kernel network device structure pointer
* @param[in] data               - data of received buffer to process
* @param[in,out] sz             - pointer to size of received buffer to process
*                                 Can be updated by this function
* @param[in] data               - maximum size of received buffer for expansion
*                                 purposes (when updating sz above)
*
* @retval NF_DROP               - When requesting to drop the packet
* @retval NF_ACCEPT             - When requesting to pass onwards the packet
* @retval NF_STOLEN             - When the packet is handled by this function
*/
int process_tx(struct net_device *ndev, struct sk_buff *skb)
{
	struct ethhdr *eth_hdr = (struct ethhdr *)skb->data;

	switch (tx_mode) {
	case TX_OP_MODE_TG:
		if ((!rx_ctx.data) && ((be16_to_cpu(eth_hdr->h_proto)) ==
		    tg_packet_to_dup)) {
			/* No support for frags */
			rx_ctx.data_len = skb_headlen(skb);
			rx_ctx.data = kmalloc(rx_ctx.data_len, GFP_KERNEL);
			if (!rx_ctx.data) {
				dev_err(&ndev->dev,
					"%s: Fail to allocate memory for data\n",
					DRV_NAME);
				return NF_ACCEPT;
			}

			memcpy(rx_ctx.data, skb->data, rx_ctx.data_len);
			rx_ctx.ndev = ndev;
			rx_ctx.tg = kthread_run(rx_traffic_generator,
						(void *)&rx_ctx, DRV_NAME);
		}
	}

	/* Simulate slow TX */
	mdelay(tx_delay_msecs);

	return NF_ACCEPT;
}

static struct mvppnd_ops ops = {
	.process_rx = process_rx,
	.process_tx = process_tx,
};

/**
* @internal ethopsdrv_init function
* @endinternal
*
* @brief  Module's initialization function
*	  Registers RX/TX hooks callback
*	  function in ethDriver.
*
* @param[in] void
*
* @retval EIO                         - on error
* @retval zero                        - on success
*/
static int __init ethopsdrv_init(void)
{
	int rc;

	ndev = dev_get_by_name(&init_net, ifname);
	if (!ndev) {
		pr_err("Fail to find netdev %s\n", ifname);
		return -EIO;
	}

	rc = mvppnd_register_hooks(ndev, &ops);
	if (rc) {
		dev_put(ndev);
		dev_err(&ndev->dev, "Fail to register to mvppnd\n");
		return -EIO;
	}

	pr_info("%s: driver hooked\n", DRV_NAME);

	return 0;
}

/**
* @internal ethopsdrv_exit function
* @endinternal
*
* @brief  Module's De-initialization function
*	  Un-Registers RX/TX hooks callback
*	  function in ethDriver, and frees
*	  RX simulation RX.
*
* @param[in] void
*
* @retval void
*/
static void __exit ethopsdrv_exit(void)
{
	mvppnd_register_hooks(ndev, NULL);

	free_rx_context();

	dev_put(ndev);

	pr_info("%s: driver un-hooked\n", DRV_NAME);
}

module_init(ethopsdrv_init);
module_exit(ethopsdrv_exit);

MODULE_AUTHOR("Yuval Shaia <yshaia@marvell.com>");
MODULE_DESCRIPTION("rx hook example");
MODULE_LICENSE("Dual BSD/GPL");
