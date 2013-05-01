/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
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

#include <linux/cpumask.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/slab.h>

#include <linux/mlx4/driver.h>
#include <linux/mlx4/device.h>
#include <linux/mlx4/cmd.h>

#include "mlx4_en.h"

MODULE_AUTHOR("Liran Liss, Yevgeny Petrilin");
MODULE_DESCRIPTION("Mellanox ConnectX HCA Ethernet driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION " ("DRV_RELDATE")");

static const char mlx4_en_version[] =
	DRV_NAME ": Mellanox ConnectX HCA Ethernet driver v"
	DRV_VERSION " (" DRV_RELDATE ")\n";

#define MLX4_EN_PARM_INT(X, def_val, desc) \
	static unsigned int X = def_val;\
	module_param(X , uint, 0444); \
	MODULE_PARM_DESC(X, desc);

#define MLX4_EN_PARM_BOOL(X, def_val, desc) \
	static unsigned int X = def_val;\
	module_param(X , bool, 0444); \
	MODULE_PARM_DESC(X, desc);
/*
 * Device scope module parameters
 */


/* Total number of RX Rings */
MLX4_EN_PARM_INT(num_rx_rings, MAX_RX_RINGS,
		 "Total number of RX Rings (default 16, range 1-16, power of 2)");

/* Enable RSS UDP traffic */
MLX4_EN_PARM_BOOL(udp_rss, true,
		 "Enable RSS for incomming UDP traffic or disabled (0)");

MLX4_EN_PARM_BOOL(enable_sys_tune, false, "Tune the cpu's for better performance (default 0)");

MLX4_EN_PARM_INT(mem_node, -1,
		 "Default Node for memory allocation (default -1)");

static int mlx4_en_get_profile(struct mlx4_en_dev *mdev)
{
	struct mlx4_en_profile *params = &mdev->profile;
	int i;
	u8 pfctx, pfcrx;

	params->udp_rss = udp_rss;
	if (params->udp_rss && !mdev->dev->caps.udp_rss) {
		mlx4_warn(mdev, "UDP RSS is not supported on this device.\n");
		params->udp_rss = 0;
	}
	for (i = 1; i <= MLX4_MAX_PORTS; i++) {
		mlx4_get_port_pfc(mdev->dev, i, &pfctx, &pfcrx);
		params->prof[i].rx_pause = 1;
		params->prof[i].tx_pause = 1;
		params->prof[i].tx_ring_size = MLX4_EN_DEF_TX_RING_SIZE;
		params->prof[i].rx_ring_size = MLX4_EN_DEF_RX_RING_SIZE;
		params->prof[i].tx_ring_num = MLX4_EN_NUM_HASH_RINGS +
			(!!pfcrx) * MLX4_EN_NUM_PPP_RINGS;
		params->prof[i].rx_ppp = pfcrx;
	}
	/* validate mem_node parameter */
	if (mem_node != -1 && !node_online(mem_node)) {
		mlx4_warn(mdev, "Illegal value for Memory node: %d,"
				" reseting to default\n", mem_node);
		mem_node = -1;
	}
	params->mem_node = mem_node;

	return 0;
}

static void *get_netdev(struct mlx4_dev *dev, void *ctx, u8 port)
{
	struct mlx4_en_dev *endev = ctx;

	return endev->pndev[port];
}

static void mlx4_en_event(struct mlx4_dev *dev, void *endev_ptr,
			  enum mlx4_dev_event event, unsigned long port)
{
	struct mlx4_en_dev *mdev = (struct mlx4_en_dev *) endev_ptr;
	struct mlx4_en_priv *priv;
	int i;

	switch (event) {
	case MLX4_DEV_EVENT_PORT_UP:
	case MLX4_DEV_EVENT_PORT_DOWN:
		 if (!mdev->pndev[port])
            return;
        priv = netdev_priv(mdev->pndev[port]);

		/* To prevent races, we poll the link state in a separate
		  task rather than changing it here */
		priv->link_state = event;
		queue_work(mdev->workqueue, &priv->linkstate_task);
		break;

	case MLX4_EVENT_TYPE_MAC_UPDATE:
		 if (!mdev->pndev[port])
            return;
        priv = netdev_priv(mdev->pndev[port]);

		priv->mac = dev->caps.def_mac[port];
		for (i = 0; i < ETH_ALEN; i++) {
			priv->dev->dev_addr[ETH_ALEN - 1 - i] = (u8) (priv->mac >> (8 * i));
			priv->dev->perm_addr[ETH_ALEN - 1 - i] = (u8) (priv->mac >> (8 * i));
		}
		queue_work(mdev->workqueue, &priv->mac_task);
		break;

	case MLX4_DEV_EVENT_CATASTROPHIC_ERROR:
		mlx4_err(mdev, "Internal error detected, restarting device\n");
		break;

	default:
		mlx4_warn(mdev, "Unhandled event: %d\n", event);
	}
}

static void mlx4_en_remove(struct mlx4_dev *dev, void *endev_ptr)
{
	struct mlx4_en_dev *mdev = endev_ptr;
	int i;

	mutex_lock(&mdev->state_lock);
	mdev->device_up = false;
	mutex_unlock(&mdev->state_lock);

	mlx4_foreach_port(i, dev, MLX4_PORT_TYPE_ETH)
		if (mdev->pndev[i])
			mlx4_en_destroy_netdev(mdev->pndev[i]);

	flush_workqueue(mdev->workqueue);
	destroy_workqueue(mdev->workqueue);
	mlx4_mr_free(dev, &mdev->mr);
	iounmap(mdev->uar_map);
	mlx4_uar_free(dev, &mdev->priv_uar);
	mlx4_pd_free(dev, mdev->priv_pdn);
	kfree(mdev);
}

static struct mlx4_interface mlx4_en_interface;

static void *mlx4_en_add(struct mlx4_dev *dev)
{
	static int mlx4_en_version_printed;
	struct mlx4_en_dev *mdev;
	int i;
	int err;

	if (!mlx4_en_version_printed) {
		printk(KERN_INFO "%s", mlx4_en_version);
		mlx4_en_version_printed++;
	}

	mdev = kzalloc(sizeof *mdev, GFP_KERNEL);
	if (!mdev) {
		dev_err(&dev->pdev->dev, "Device struct alloc failed, "
			"aborting.\n");
		err = -ENOMEM;
		goto err_free_res;
	}

	if (mlx4_pd_alloc(dev, &mdev->priv_pdn))
		goto err_free_dev;

	if (mlx4_uar_alloc(dev, &mdev->priv_uar))
		goto err_pd;

	mdev->uar_map = ioremap(mdev->priv_uar.pfn << PAGE_SHIFT, PAGE_SIZE);
	if (!mdev->uar_map)
		goto err_uar;
	spin_lock_init(&mdev->uar_lock);

	mdev->dev = dev;
	mdev->dma_device = &(dev->pdev->dev);
	mdev->pdev = dev->pdev;
	mdev->device_up = false;
	mdev->mlx4_intf = &mlx4_en_interface;

	mdev->LSO_support = !!(dev->caps.flags & (1 << 15));
	if (!mdev->LSO_support)
		mlx4_warn(mdev, "LSO not supported, please upgrade to later "
				"FW version to enable LSO\n");

	if (mlx4_mr_alloc(mdev->dev, mdev->priv_pdn, 0, ~0ull,
			 MLX4_PERM_LOCAL_WRITE |  MLX4_PERM_LOCAL_READ,
			 0, 0, &mdev->mr)) {
		mlx4_err(mdev, "Failed allocating memory region\n");
		goto err_map;
	}
	if (mlx4_mr_enable(mdev->dev, &mdev->mr)) {
		mlx4_err(mdev, "Failed enabling memory region\n");
		goto err_mr;
	}

	/* Build device profile according to supplied module parameters */
	err = mlx4_en_get_profile(mdev);
	if (err) {
		mlx4_err(mdev, "Bad module parameters, aborting.\n");
		goto err_mr;
	}

	/* Configure wich ports to start according to module parameters */
	mdev->port_cnt = 0;
	mlx4_foreach_port(i, dev, MLX4_PORT_TYPE_ETH)
		mdev->port_cnt++;

	/* Number of RX rings is between (MIN_RX_RINGS, MAX_RX_RINGS) + 1
	 * and depends on number of completion vectors */
	mlx4_foreach_port(i, dev, MLX4_PORT_TYPE_ETH) {
			if (!dev->caps.poolsz) {
				int def_rings = max_t(int, dev->caps.num_comp_vectors,
						      MIN_DEF_RX_RINGS);
				mdev->profile.prof[i].rx_ring_num =
					rounddown_pow_of_two(min_t(int, def_rings,
								   min_t(int, MAX_RX_RINGS, num_rx_rings)));
			} else {
				mdev->profile.prof[i].rx_ring_num =
					rounddown_pow_of_two(min_t(int, dev->caps.poolsz/
					      dev->caps.num_ports - 1,
					      min_t(int, MAX_RX_RINGS, num_rx_rings)));			}
	}

	/* Create our own workqueue for reset/multicast tasks
	 * Note: we cannot use the shared workqueue because of deadlocks caused
	 *       by the rtnl lock */
	mdev->workqueue = create_singlethread_workqueue("mlx4_en");
	if (!mdev->workqueue) {
		err = -ENOMEM;
		goto err_mr;
	}

	/* At this stage all non-port specific tasks are complete:
	 * mark the card state as up */
	mutex_init(&mdev->state_lock);
	mdev->device_up = true;

	/* Setup ports */

	/* Create a netdev for each port */
	mlx4_foreach_port(i, dev, MLX4_PORT_TYPE_ETH) {
		mlx4_info(mdev, "Activating port:%d\n", i);
		if (mlx4_en_init_netdev(mdev, i, &mdev->profile.prof[i])) {
			mdev->pndev[i] = NULL;
			goto err_free_netdev;
		}
	}
	return mdev;


err_free_netdev:
	mlx4_foreach_port(i, dev, MLX4_PORT_TYPE_ETH) {
		if (mdev->pndev[i])
			mlx4_en_destroy_netdev(mdev->pndev[i]);
	}

	mutex_lock(&mdev->state_lock);
	mdev->device_up = false;
	mutex_unlock(&mdev->state_lock);
	flush_workqueue(mdev->workqueue);

	/* Stop event queue before we drop down to release shared SW state */
	destroy_workqueue(mdev->workqueue);

err_mr:
	mlx4_mr_free(dev, &mdev->mr);
err_map:
	if (mdev->uar_map)
		iounmap(mdev->uar_map);
err_uar:
	mlx4_uar_free(dev, &mdev->priv_uar);
err_pd:
	mlx4_pd_free(dev, mdev->priv_pdn);
err_free_dev:
	kfree(mdev);
err_free_res:
	return NULL;
}

enum mlx4_query_reply mlx4_en_query(void *endev_ptr, void *int_dev)
{
	struct mlx4_en_dev *mdev = endev_ptr;
	struct net_device *netdev = int_dev;
	int p;
	
	for (p = 1; p <= MLX4_MAX_PORTS; ++p)
		if (mdev->pndev[p] == netdev)
			return p;

	return MLX4_QUERY_NOT_MINE;
}

static struct pci_device_id mlx4_en_pci_table[] = {
	{ PCI_VDEVICE(MELLANOX, 0x6340) }, /* MT25408 "Hermon" SDR */
	{ PCI_VDEVICE(MELLANOX, 0x634a) }, /* MT25408 "Hermon" DDR */
	{ PCI_VDEVICE(MELLANOX, 0x6354) }, /* MT25408 "Hermon" QDR */
	{ PCI_VDEVICE(MELLANOX, 0x6732) }, /* MT25408 "Hermon" DDR PCIe gen2 */
	{ PCI_VDEVICE(MELLANOX, 0x673c) }, /* MT25408 "Hermon" QDR PCIe gen2 */
	{ PCI_VDEVICE(MELLANOX, 0x6368) }, /* MT25408 "Hermon" EN 10GigE */
	{ PCI_VDEVICE(MELLANOX, 0x6750) }, /* MT25408 "Hermon" EN 10GigE PCIe gen2 */
	{ PCI_VDEVICE(MELLANOX, 0x6372) }, /* MT25458 ConnectX EN 10GBASE-T 10GigE */
	{ PCI_VDEVICE(MELLANOX, 0x675a) }, /* MT25458 ConnectX EN 10GBASE-T+Gen2 10GigE */
	{ PCI_VDEVICE(MELLANOX, 0x6764) }, /* MT26468 ConnectX EN 10GigE PCIe gen2 */
	{ PCI_VDEVICE(MELLANOX, 0x6746) }, /* MT26438 ConnectX VPI PCIe 2.0 5GT/s - IB QDR / 10GigE Virt+ */
	{ PCI_VDEVICE(MELLANOX, 0x676e) }, /* MT26478 ConnectX EN 40GigE PCIe 2.0 5GT/s */
	{ PCI_VDEVICE(MELLANOX, 0x6778) }, /* MT26488 ConnectX VPI PCIe 2.0 5GT/s - IB DDR / 10GigE Virt+ */
	{ PCI_VDEVICE(MELLANOX, 0x1000) },
	{ PCI_VDEVICE(MELLANOX, 0x1001) },
	{ PCI_VDEVICE(MELLANOX, 0x1002) },
	{ PCI_VDEVICE(MELLANOX, 0x1003) },
	{ PCI_VDEVICE(MELLANOX, 0x1004) },
	{ PCI_VDEVICE(MELLANOX, 0x1005) },
	{ PCI_VDEVICE(MELLANOX, 0x1006) },
	{ PCI_VDEVICE(MELLANOX, 0x1007) },
	{ PCI_VDEVICE(MELLANOX, 0x1008) },
	{ PCI_VDEVICE(MELLANOX, 0x1009) },
	{ PCI_VDEVICE(MELLANOX, 0x100a) },
	{ PCI_VDEVICE(MELLANOX, 0x100b) },
	{ PCI_VDEVICE(MELLANOX, 0x100c) },
	{ PCI_VDEVICE(MELLANOX, 0x100d) },
	{ PCI_VDEVICE(MELLANOX, 0x100e) },
	{ PCI_VDEVICE(MELLANOX, 0x100f) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, mlx4_en_pci_table);

static struct mlx4_interface mlx4_en_interface = {
	.add		= mlx4_en_add,
	.remove		= mlx4_en_remove,
	.event		= mlx4_en_event,
	.query		= mlx4_en_query,
	.get_prot_dev	= get_netdev,
	.protocol	= MLX4_PROT_EN,
};

void mlx4_en_verify_params(void)
{
	if (num_rx_rings < MIN_RX_RINGS || num_rx_rings > MAX_RX_RINGS) {
		printk(KERN_WARNING "mlx4_en: WARNING: illegal module parameter num_rx_rings %d - "
		       "should be in range %d-%d, will be changed to %d\n",
		       num_rx_rings, MIN_RX_RINGS, MAX_RX_RINGS, MAX_RX_RINGS);
		num_rx_rings = MAX_RX_RINGS;
	} else if (rounddown_pow_of_two(num_rx_rings) != num_rx_rings) {
		printk(KERN_WARNING "mlx4_en: WARNING: illegal module parameter num_rx_rings %d - "
		       "should be power of 2, will be changed to %lu\n",
		       num_rx_rings, rounddown_pow_of_two(num_rx_rings));
		num_rx_rings = rounddown_pow_of_two(num_rx_rings);
	}
}

static int __init mlx4_en_init(void)
{
	int err;

	mlx4_en_verify_params();
	if (enable_sys_tune)
		sys_tune_init();

	 err = mlx4_register_interface(&mlx4_en_interface);
	 if (err && enable_sys_tune)
		 sys_tune_fini();
	 return err;
		 
}

static void __exit mlx4_en_cleanup(void)
{
	if (enable_sys_tune)
		sys_tune_fini();
	mlx4_unregister_interface(&mlx4_en_interface);
}

module_init(mlx4_en_init);
module_exit(mlx4_en_cleanup);

