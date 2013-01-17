/*
 * Copyright (c) 2011, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
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
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/random.h>
#include "mlx4.h"

#if 0
enum test_mode {
	RANDOM_MTT,
	TEST_CQS,
	MAX_MODES
};

static struct workqueue_struct *wq[MAX_MODES];

static int allow_tests;
static int num_pending;

struct mtt_item {
	struct list_head        list;
	struct mlx4_mtt         mtt;
};

struct test_work {
	struct work_struct      work;
	struct mlx4_dev        *dev;
	int                     slave;
};

enum {
	MAX_PENDING = 128
};

static int get_npages(int max)
{
	return random32() % max;
}

static void run_random_mtt(struct work_struct *work)
{
	struct test_work *tw = container_of(work, struct test_work, work);
	int n = 1000;
	int max_order = 7;
	int page_shift = PAGE_SHIFT;
	int err;
	LIST_HEAD(mtts);
	struct mtt_item *item;
	struct mtt_item *tmp;
	int i;
	struct mlx4_dev *dev = tw->dev;
	int goods = 0;

	if (!allow_tests) {
		--num_pending;
		kfree(tw);
		return;
	}

	for (i = 0; i < n; ++i) {
		item = kmalloc(sizeof *item, GFP_KERNEL);
		if (!item)
			break;

		err = mlx4_mtt_init(dev,
				    get_npages(1 << max_order),
				    page_shift,
				    &item->mtt);
		if (!err) {
			list_add_tail(&item->list, &mtts);
			++goods;
		} else
			kfree(item);
	}

	list_for_each_entry_safe(item, tmp, &mtts, list) {
		mlx4_mtt_cleanup(dev, &item->mtt);
		list_del(&item->list);
		kfree(item);
	}

	kfree(tw);
	if (goods != n)
		printk(KERN_INFO "%s, failed: ran %d cases but only %d succeeded\n",
		       __func__, n, goods);
	else
		printk(KERN_INFO "%s: test finished successfully\n", __func__);

	--num_pending;
}


static void fill_random(void *arg, int size)
{
	u32 *p = arg;
	int i;
	int n = size / 4;

	for (i = 0; i < n; ++i)
		p[i] = random32();
}

static int cq_bad(struct mlx4_dev *dev, int slave)
{
	int err;
	struct mlx4_mtt mtt;
	int nent = random32();
	struct mlx4_uar uar;
	struct mlx4_cq cq;

	fill_random(&mtt, sizeof mtt);
	fill_random(&uar, sizeof uar);
        err = mlx4_cq_alloc(dev, nent, &mtt, &uar, 0, &cq, 0, 0);
	SASSERT(err);

	return err;
}

static void run_cqs(struct work_struct *work)
{
	struct test_work *tw = container_of(work, struct test_work, work);
	int slave = tw->slave;
	int i;
	int n = 1000;
	int err;
	int bads = 0;

	if (!allow_tests) {
		--num_pending;
		kfree(tw);
		return;
	}

	for (i = 0; i < n; ++i) {
		err = cq_bad(tw->dev, slave);
		if (err)
			++bads;
	}

	kfree(tw);

	if (bads != n)
		printk(KERN_INFO "%s, failed: Ran %d bad cases but only %d failed\n",
		       __func__, n, bads);

	printk(KERN_INFO "%s: test finished successfully\n", __func__);
	--num_pending;
}

static void run_test(struct mlx4_dev *dev, int slave, enum test_mode mode)
{
	struct test_work *tw;

	tw = kmalloc(sizeof *tw, GFP_KERNEL);
	if (!tw) {
		mlx4_swarn("kmalloc failed\n");
		return;
	}
	tw->slave = slave;
	tw->dev = dev;

	switch (mode) {
	case RANDOM_MTT:
		++num_pending;
		INIT_WORK(&tw->work, run_random_mtt);
		queue_work(wq[mode], &tw->work);
		break;

	case TEST_CQS:
		++num_pending;
		INIT_WORK(&tw->work, run_cqs);
		queue_work(wq[mode], &tw->work);
		break;


	default:
		kfree(tw);
		mlx4_swarn("test mode %d not supported\n", mode);
	}
}

static ssize_t show_test(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct mlx4_priv *priv = container_of(attr, struct mlx4_priv, test_attr);
	int slave = priv->dev.caps.function;

	mlx4_sdbg("\n");

	return -ENOSYS;
}

static ssize_t store_test(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct mlx4_priv *priv = container_of(attr, struct mlx4_priv, test_attr);
	int slave = priv->dev.caps.function;
	int err;
	int mode;

	if (!allow_tests)
		return -EINVAL;

	if (num_pending > MAX_PENDING)
		return -ENOMEM;

	err = sscanf(buf, "%d", &mode);
	if (err == 1)
		run_test(&priv->dev, slave, mode);

	 return count;
}

int mlx4_rtt_init(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int slave = dev->caps.function;
	int err;
	int i;

	for (i = 0; i < MAX_MODES; ++i) {
		wq[i] = create_singlethread_workqueue("rt_torture_wq");
		if (!wq[i]) {
			mlx4_swarn("failed to create work queue\n");
			err = -ENOMEM;
			goto ex_wq;
		}
	}

	priv->test_attr.attr.name = "test";
	priv->test_attr.attr.mode = S_IRUGO | S_IWUSR;
	priv->test_attr.show      = show_test;
	priv->test_attr.store     = store_test;

	allow_tests = 0;
	num_pending = 0;
	err = device_create_file(&dev->pdev->dev, &priv->test_attr);
	if (err) {
		mlx4_swarn("Failed to create sysfs file\n");
		goto ex_wq;
	}
	allow_tests = 1;

	return 0;

ex_wq:
	for (--i; i >= 0; --i)
		destroy_workqueue(wq[i]);

	return err;
}

void mlx4_rtt_cleanup(struct mlx4_dev *dev)
{
       struct mlx4_priv *priv = mlx4_priv(dev);
       int i;

       allow_tests = 0;
       for (i = 0; i < MAX_MODES; ++i)
               flush_workqueue(wq[i]);

       device_remove_file(&dev->pdev->dev, &priv->test_attr);
       for (i = 0; i < MAX_MODES; ++i)
               destroy_workqueue(wq[i]);
}
#else

int mlx4_rtt_init(struct mlx4_dev *dev)
{
	return 0;
}

void mlx4_rtt_cleanup(struct mlx4_dev *dev)
{
}

#endif
