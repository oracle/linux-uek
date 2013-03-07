/*
 * Copyright (c) 2012, Mellanox Technologies inc.  All rights reserved.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/cmd.h>
#include "mlx5_core.h"

MLX5_MOD_DBG_MASK(MLX5_MOD_HEALTH);

enum {
	MLX5_HEALTH_POLL_INTERVAL	= 2 * HZ,
	MAX_MISSES			= 3,
};

static DEFINE_SPINLOCK(health_lock);

static LIST_HEAD(health_list);
static struct work_struct health_work;

static void health_care(struct work_struct *work)
{
	LIST_HEAD(tlist);
	struct mlx5_core_health *health;
	struct mlx5_priv *priv;
	struct mlx5_core_dev *dev;

	spin_lock_irq(&health_lock);
	list_splice_init(&health_list, &tlist);
	spin_unlock_irq(&health_lock);

	list_for_each_entry(health, &tlist, list) {
		priv = container_of(health, struct mlx5_priv, health);
		dev = container_of(priv, struct mlx5_core_dev, priv);
		mlx5_core_warn(dev, "handling bad device here\n");
		/* nothing yet */
	}
}

static void print_health_info(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;
	struct health_buffer __iomem *h = health->health;
	int i;

	for (i = 0; i < ARRAY_SIZE(h->assert_var); ++i)
		pr_info("assert_var[%d] 0x%08x\n", i, be32_to_cpu(h->assert_var[i]));

	pr_info("assert_exit_ptr 0x%08x\n", be32_to_cpu(h->assert_exit_ptr));
	pr_info("assert_callra 0x%08x\n", be32_to_cpu(h->assert_callra));
	pr_info("fw_ver 0x%08x\n", be32_to_cpu(h->fw_ver));
	pr_info("hw_id 0x%08x\n", be32_to_cpu(h->hw_id));
	pr_info("irisc_index %d\n", h->irisc_index);
	pr_info("synd 0x%x\n", h->synd);
	pr_info("ext_sync 0x%04x\n", be16_to_cpu(h->ext_sync));
}

static void poll_health(unsigned long data)
{
	struct mlx5_core_dev *dev = (struct mlx5_core_dev *)data;
	struct mlx5_core_health *health = &dev->priv.health;
	u32 count;
	unsigned long next;

	count = ioread32be(health->health_counter);
	if (count == health->prev)
		++health->miss_counter;
	else
		health->miss_counter = 0;

	health->prev = count;
	if (health->miss_counter == MAX_MISSES) {
		mlx5_core_err(dev, "device's health compromised\n");
		print_health_info(dev);
		spin_lock_irq(&health_lock);
		list_add(&health->list, &health_list);
		spin_unlock_irq(&health_lock);

		queue_work(mlx5_core_wq, &health_work);
	} else {
		spin_lock_irq(&health_lock);
		if (health->active) {
			get_random_bytes(&next, sizeof(next));
			next %= HZ;
			next += jiffies + MLX5_HEALTH_POLL_INTERVAL;
			mod_timer(&health->timer, next);
		}
		spin_unlock_irq(&health_lock);
	}
}

void mlx5_start_health_poll(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;

	INIT_LIST_HEAD(&health->list);
	init_timer(&health->timer);
	health->health = &dev->iseg->health;
	health->health_counter = &dev->iseg->health_counter;

	health->timer.data = (unsigned long)dev;
	health->timer.function = poll_health;
	health->timer.expires = round_jiffies(jiffies + MLX5_HEALTH_POLL_INTERVAL);
	health->active = 1;
	add_timer(&health->timer);
}

void mlx5_stop_health_poll(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;

	spin_lock_irq(&health_lock);
	health->active = 0;
	spin_unlock_irq(&health_lock);
	del_timer_sync(&health->timer);

	spin_lock_irq(&health_lock);
	if (!list_empty(&health->list))
		list_del_init(&health->list);
	spin_unlock_irq(&health_lock);
}

void mlx5_health_cleanup(void)
{
}

void  __init mlx5_health_init(void)
{
	INIT_WORK(&health_work, health_care);
}
