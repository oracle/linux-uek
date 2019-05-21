/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
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
#include <linux/hardirq.h>
#include <linux/delay.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/cmd.h>
#include "mlx5_core.h"

enum {
	MLX5_HEALTH_POLL_INTERVAL	= 2 * HZ,
	MAX_MISSES			= 3,
};

enum {
	MLX5_HEALTH_SYNDR_FW_ERR		= 0x1,
	MLX5_HEALTH_SYNDR_IRISC_ERR		= 0x7,
	MLX5_HEALTH_SYNDR_HW_UNRECOVERABLE_ERR	= 0x8,
	MLX5_HEALTH_SYNDR_CRC_ERR		= 0x9,
	MLX5_HEALTH_SYNDR_FETCH_PCI_ERR		= 0xa,
	MLX5_HEALTH_SYNDR_HW_FTL_ERR		= 0xb,
	MLX5_HEALTH_SYNDR_ASYNC_EQ_OVERRUN_ERR	= 0xc,
	MLX5_HEALTH_SYNDR_EQ_ERR		= 0xd,
	MLX5_HEALTH_SYNDR_EQ_INV		= 0xe,
	MLX5_HEALTH_SYNDR_FFSER_ERR		= 0xf,
	MLX5_HEALTH_SYNDR_HIGH_TEMP		= 0x10
};

enum {
	MLX5_DROP_NEW_HEALTH_WORK,
	MLX5_DROP_NEW_RECOVERY_WORK,
};

enum  {
	MLX5_SENSOR_NO_ERR		= 0,
	MLX5_SENSOR_PCI_COMM_ERR	= 1,
	MLX5_SENSOR_PCI_ERR		= 2,
	MLX5_SENSOR_NIC_DISABLED	= 3,
	MLX5_SENSOR_NIC_SW_RESET	= 4,
	MLX5_SENSOR_FW_SYND_RFR		= 5,
};

static int lock_sem_sw_reset(struct mlx5_core_dev *dev, int state)
{
	int ret;

	/* Lock GW access */
	ret = mlx5_pciconf_cap9_sem(dev, LOCK);
	if (ret == -EBUSY)
		return -EINVAL;
	if (ret)
		return ret;

	ret = mlx5_pciconf_set_sem_addr_space(dev, MLX5_SEMAPHORE_SW_RESET, state);
	if (!ret && state == LOCK)
		mlx5_core_warn(dev, "SW reset semaphore locked\n");

	/* Unlock GW access */
	mlx5_pciconf_cap9_sem(dev, UNLOCK);
	return ret;
}

u8 mlx5_get_nic_mode(struct mlx5_core_dev *dev)
{
	return (ioread32be(&dev->iseg->cmdq_addr_l_sz) >> 8) & 7;
}

void mlx5_set_nic_mode(struct mlx5_core_dev *dev, u8 state)
{
	u32 cur_cmdq_addr_l_sz;

	cur_cmdq_addr_l_sz = ioread32be(&dev->iseg->cmdq_addr_l_sz);
	iowrite32be((cur_cmdq_addr_l_sz & 0xFFFFF000) |
		    state << MLX5_NIC_IFC_OFFSET,
		    &dev->iseg->cmdq_addr_l_sz);
}

static bool sensor_pci_not_working(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;
	struct health_buffer __iomem *h = health->health;
	bool err = ioread32be(&h->fw_ver) == 0xffffffff;

	return err;
}

static bool sensor_nic_disabled(struct mlx5_core_dev *dev)
{
	return mlx5_get_nic_mode(dev) == MLX5_NIC_IFC_DISABLED;
}

static bool sensor_nic_sw_reset(struct mlx5_core_dev *dev)
{
	return mlx5_get_nic_mode(dev) == MLX5_NIC_IFC_SW_RESET;
}

static bool sensor_fw_synd_rfr(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;
	struct health_buffer __iomem *h = health->health;
	u32 rfr = ioread32be(&h->rfr) >> MLX5_RFR_OFFSET;
	u8 synd = ioread8(&h->synd);

	if (rfr && synd)
		mlx5_core_dbg(dev, "FW requests reset, synd: %d\n", synd);
	return rfr && synd;
}

static u32 check_fatal_sensors(struct mlx5_core_dev *dev)
{
	if (sensor_pci_not_working(dev))
		return MLX5_SENSOR_PCI_COMM_ERR;
	if (pci_channel_offline(dev->pdev))
		return MLX5_SENSOR_PCI_ERR;
	if (sensor_nic_disabled(dev))
		return MLX5_SENSOR_NIC_DISABLED;
	if (sensor_nic_sw_reset(dev))
		return MLX5_SENSOR_NIC_SW_RESET;
	if (sensor_fw_synd_rfr(dev))
		return MLX5_SENSOR_FW_SYND_RFR;

	return MLX5_SENSOR_NO_ERR;
}

static bool reset_fw_if_needed(struct mlx5_core_dev *dev)
{
	bool supported = (ioread32be(&dev->iseg->initializing) >>
			  MLX5_FW_RESET_SUPPORTED_OFFSET) & 1;
	u32 fatal_error;

	if (!supported)
		return false;

	/* The reset only needs to be issued by one PF. The health buffer is
	 * shared between all functions, and will be cleared during a reset.
	 * Check again to avoid a redundant 2nd reset. If the fatal erros was
	 * PCI related a reset won't help.
	 */
	fatal_error = check_fatal_sensors(dev);
	if (fatal_error == MLX5_SENSOR_PCI_COMM_ERR ||
	    fatal_error == MLX5_SENSOR_NIC_DISABLED ||
	    fatal_error == MLX5_SENSOR_NIC_SW_RESET) {
		mlx5_core_warn(dev, "Not issuing FW reset. Either it's already done or won't help.");
		return false;
	}

	mlx5_core_warn(dev, "Issuing FW Reset\n");
	/* Write the NIC interface field to initiate the reset, the command
	 * interface address also resides here, don't overwrite it.
	 */
	mlx5_set_nic_mode(dev, MLX5_NIC_IFC_SW_RESET);

	return true;
}

#define MLX5_CRDUMP_WAIT_MS	60000
#define MLX5_FW_RESET_WAIT_MS	1000
#define MLX5_NIC_STATE_POLL_MS	5
void mlx5_enter_error_state(struct mlx5_core_dev *dev, bool force)
{
	unsigned long end, delay_ms = MLX5_FW_RESET_WAIT_MS;
	u32 fatal_error, err;
	int lock = -EBUSY;

	mutex_lock(&dev->intf_state_mutex);
	if (dev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR)
		goto unlock;
	if (dev->state == MLX5_DEVICE_STATE_UNINITIALIZED) {
		dev->state = MLX5_DEVICE_STATE_INTERNAL_ERROR;
		goto unlock;
	}

	if (force)
		mlx5_core_dbg(dev, "start\n");
	else
		mlx5_core_err(dev, "start\n");

	fatal_error = check_fatal_sensors(dev);

	if (fatal_error || force) {
		dev->state = MLX5_DEVICE_STATE_INTERNAL_ERROR;
		mlx5_lock_and_flush_cmdif(dev);
		mlx5_unlock_cmdif(dev);
	}

	mlx5_core_event(dev, MLX5_DEV_EVENT_SYS_ERROR, 1);

	if (force)
		goto err_state_done;

	if (fatal_error == MLX5_SENSOR_FW_SYND_RFR) {
		/* Get cr-dump and reset FW semaphore */
		if (mlx5_core_is_pf(dev))
			lock = lock_sem_sw_reset(dev, LOCK);

		/* Execute cr-dump and SW reset */
		if (lock != -EBUSY) {
			err = mlx5_fill_cr_dump(dev);
			if (err)
				mlx5_core_err(dev, "Failed to collect crdump area err %d\n", err);
			reset_fw_if_needed(dev);
		} else {
			delay_ms = MLX5_CRDUMP_WAIT_MS;
		}
	}

	/* Recover from SW reset */
	end = jiffies + msecs_to_jiffies(delay_ms);
	do {
		if (sensor_nic_disabled(dev))
			break;

		msleep(MLX5_NIC_STATE_POLL_MS);
	} while (!time_after(jiffies, end));

	if (!sensor_nic_disabled(dev)) {
		dev_err(&dev->pdev->dev, "NIC IFC still %d after %lums.\n",
			mlx5_get_nic_mode(dev), delay_ms);
	}

	/* Release FW semaphore if you are the lock owner */
	if (!lock)
		lock_sem_sw_reset(dev, UNLOCK);

err_state_done:
	if (force)
		mlx5_core_dbg(dev, "end\n");
	else
		mlx5_core_err(dev, "end\n");

unlock:
	mutex_unlock(&dev->intf_state_mutex);
}

static void mlx5_handle_bad_state(struct mlx5_core_dev *dev)
{
	u8 nic_mode = mlx5_get_nic_mode(dev);

	mlx5_core_warn(dev, "NIC mode: %d\n", nic_mode);
	/* The IFC mode field is 3 bits, so it will read 0x7 in 2 cases:
	 * 1. PCI has been disabled (ie. PCI-AER, PF driver unloaded
	 *    and this is a VF), this is not recoverable by SW reset.
	 *    Logging of this is handled elsewhere.
	 * 2. FW reset has been issued by another function, driver can
	 *    be reloaded to recover after the mode switches to
	 *    MLX5_NIC_IFC_DISABLED.
	 */
	if (nic_mode == MLX5_NIC_IFC_SW_RESET &&
	    dev->priv.health.fatal_error != MLX5_SENSOR_PCI_COMM_ERR)
		mlx5_core_warn(dev, "NIC SW reset in progress\n");

	switch (nic_mode) {
	case MLX5_NIC_IFC_FULL:
		mlx5_core_warn(dev, "Expected to see disabled NIC but it is full driver\n");
		break;

	case MLX5_NIC_IFC_DISABLED:
		mlx5_core_warn(dev, "starting teardown\n");
		break;

	case MLX5_NIC_IFC_NO_DRAM_NIC:
		mlx5_core_warn(dev, "Expected to see disabled NIC but it is no dram nic\n");
		break;
	default:
		mlx5_core_warn(dev, "Expected to see disabled NIC but it is has invalid value %d\n",nic_mode);
	}

	mlx5_disable_device(dev);
}

static void health_recover(struct work_struct *work)
{
	struct mlx5_core_health *health;
	struct delayed_work *dwork;
	struct mlx5_core_dev *dev;
	struct mlx5_priv *priv;

	dwork = container_of(work, struct delayed_work, work);
	health = container_of(dwork, struct mlx5_core_health, recover_work);
	priv = container_of(health, struct mlx5_priv, health);
	dev = container_of(priv, struct mlx5_core_dev, priv);

	if (sensor_pci_not_working(dev)) {
		dev_err(&dev->pdev->dev, "health recovery flow aborted, PCI reads still not working\n");
		return;
	}

	dev_err(&dev->pdev->dev, "starting health recovery flow\n");
	mlx5_recover_device(dev);
}

/* How much time to wait until health resetting the driver (in msecs) */
#define MLX5_RECOVERY_DELAY_MSECS 60000
#define MLX5_RECOVERY_NO_DELAY 0
static unsigned long get_recovery_delay(struct mlx5_core_dev *dev)
{
	return dev->priv.health.fatal_error == MLX5_SENSOR_PCI_ERR ||
	       dev->priv.health.fatal_error == MLX5_SENSOR_PCI_COMM_ERR	?
	       MLX5_RECOVERY_DELAY_MSECS : MLX5_RECOVERY_NO_DELAY;
}

static void health_care(struct work_struct *work)
{
	struct mlx5_core_health *health;
	unsigned long recover_delay;
	struct mlx5_core_dev *dev;
	struct mlx5_priv *priv;
	unsigned long flags;

	health = container_of(work, struct mlx5_core_health, work);
	priv = container_of(health, struct mlx5_priv, health);
	dev = container_of(priv, struct mlx5_core_dev, priv);

	mlx5_core_warn(dev, "handling bad device here\n");
	mlx5_handle_bad_state(dev);
	recover_delay = msecs_to_jiffies(get_recovery_delay(dev));

	spin_lock_irqsave(&health->wq_lock, flags);
	if (!test_bit(MLX5_DROP_NEW_RECOVERY_WORK, &health->flags)) {
		mlx5_core_warn(dev, "Scheduling recovery work with %lums delay\n",
			       recover_delay);
		schedule_delayed_work(&health->recover_work, recover_delay);
	} else {
		dev_err(&dev->pdev->dev,
			"new health works are not permitted at this stage\n");
	}
	spin_unlock_irqrestore(&health->wq_lock, flags);
}

static const char *hsynd_str(u8 synd)
{
	switch (synd) {
	case MLX5_HEALTH_SYNDR_FW_ERR:
		return "firmware internal error";
	case MLX5_HEALTH_SYNDR_IRISC_ERR:
		return "irisc not responding";
	case MLX5_HEALTH_SYNDR_HW_UNRECOVERABLE_ERR:
		return "unrecoverable hardware error";
	case MLX5_HEALTH_SYNDR_CRC_ERR:
		return "firmware CRC error";
	case MLX5_HEALTH_SYNDR_FETCH_PCI_ERR:
		return "ICM fetch PCI error";
	case MLX5_HEALTH_SYNDR_HW_FTL_ERR:
		return "HW fatal error\n";
	case MLX5_HEALTH_SYNDR_ASYNC_EQ_OVERRUN_ERR:
		return "async EQ buffer overrun";
	case MLX5_HEALTH_SYNDR_EQ_ERR:
		return "EQ error";
	case MLX5_HEALTH_SYNDR_EQ_INV:
		return "Invalid EQ referenced";
	case MLX5_HEALTH_SYNDR_FFSER_ERR:
		return "FFSER error";
	case MLX5_HEALTH_SYNDR_HIGH_TEMP:
		return "High temperature";
	default:
		return "unrecognized error";
	}
}

static void print_health_info(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;
	struct health_buffer __iomem *h = health->health;
	char fw_str[18];
	u32 fw;
	int i;

	/* If the syndrome is 0, the device is OK and no need to print buffer */
	if (!ioread8(&h->synd))
		return;

	for (i = 0; i < ARRAY_SIZE(h->assert_var); i++)
		dev_err(&dev->pdev->dev, "assert_var[%d] 0x%08x\n", i, ioread32be(h->assert_var + i));

	dev_err(&dev->pdev->dev, "assert_exit_ptr 0x%08x\n", ioread32be(&h->assert_exit_ptr));
	dev_err(&dev->pdev->dev, "assert_callra 0x%08x\n", ioread32be(&h->assert_callra));
	sprintf(fw_str, "%d.%d.%d", fw_rev_maj(dev), fw_rev_min(dev), fw_rev_sub(dev));
	dev_err(&dev->pdev->dev, "fw_ver %s\n", fw_str);
	dev_err(&dev->pdev->dev, "hw_id 0x%08x\n", ioread32be(&h->hw_id));
	dev_err(&dev->pdev->dev, "irisc_index %d\n", ioread8(&h->irisc_index));
	dev_err(&dev->pdev->dev, "synd 0x%x: %s\n", ioread8(&h->synd), hsynd_str(ioread8(&h->synd)));
	dev_err(&dev->pdev->dev, "ext_synd 0x%04x\n", ioread16be(&h->ext_synd));
	fw = ioread32be(&h->fw_ver);
	dev_err(&dev->pdev->dev, "raw fw_ver 0x%08x\n", fw);
}

static unsigned long get_next_poll_jiffies(void)
{
	unsigned long next;

	get_random_bytes(&next, sizeof(next));
	next %= HZ;
	next += jiffies + MLX5_HEALTH_POLL_INTERVAL;

	return next;
}

void mlx5_trigger_health_work(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;
	unsigned long flags;

	spin_lock_irqsave(&health->wq_lock, flags);
	if (!test_bit(MLX5_DROP_NEW_HEALTH_WORK, &health->flags))
		queue_work(health->wq, &health->work);
	else
		dev_err(&dev->pdev->dev,
			"new health works are not permitted at this stage\n");
	spin_unlock_irqrestore(&health->wq_lock, flags);
}

#ifdef HAVE_TIMER_SETUP
static void poll_health(struct timer_list *t)
#else
static void poll_health(unsigned long data)
#endif
{
#ifdef HAVE_TIMER_SETUP
	struct mlx5_core_dev *dev = from_timer(dev, t, priv.health.timer);
#else
	struct mlx5_core_dev *dev = (struct mlx5_core_dev *)data;
#endif
	struct mlx5_core_health *health = &dev->priv.health;
	u32 fatal_error;
	u32 count;

	if (dev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR)
		goto out;

	count = ioread32be(health->health_counter);
	if (count == health->prev)
		++health->miss_counter;
	else
		health->miss_counter = 0;

	health->prev = count;
	if (health->miss_counter == MAX_MISSES) {
		dev_err(&dev->pdev->dev, "device's health compromised - reached miss count\n");
		print_health_info(dev);
	}

	fatal_error = check_fatal_sensors(dev);

	if (fatal_error && !health->fatal_error) {
		mlx5_core_err(dev, "Fatal error %u detected\n", fatal_error);
		dev->priv.health.fatal_error = fatal_error;
		print_health_info(dev);
		mlx5_trigger_health_work(dev);
	}

out:
	mod_timer(&health->timer, get_next_poll_jiffies());
}

void mlx5_start_health_poll(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;

#ifdef HAVE_TIMER_SETUP
	timer_setup(&health->timer, poll_health, 0);
#else
	init_timer(&health->timer);
	health->timer.data = (unsigned long)dev;
	health->timer.function = poll_health;
#endif
	health->fatal_error = MLX5_SENSOR_NO_ERR;
	clear_bit(MLX5_DROP_NEW_HEALTH_WORK, &health->flags);
	clear_bit(MLX5_DROP_NEW_RECOVERY_WORK, &health->flags);
	health->health = &dev->iseg->health;
	health->health_counter = &dev->iseg->health_counter;

	health->timer.expires = round_jiffies(jiffies + MLX5_HEALTH_POLL_INTERVAL);
	add_timer(&health->timer);
}

void mlx5_stop_health_poll(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;

	del_timer_sync(&health->timer);
}

void mlx5_drain_health_wq(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;
	unsigned long flags;

	spin_lock_irqsave(&health->wq_lock, flags);
	set_bit(MLX5_DROP_NEW_HEALTH_WORK, &health->flags);
	set_bit(MLX5_DROP_NEW_RECOVERY_WORK, &health->flags);
	spin_unlock_irqrestore(&health->wq_lock, flags);
	cancel_delayed_work_sync(&health->recover_work);
	cancel_work_sync(&health->work);
}

void mlx5_drain_health_recovery(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;
	unsigned long flags;

	spin_lock_irqsave(&health->wq_lock, flags);
	set_bit(MLX5_DROP_NEW_RECOVERY_WORK, &health->flags);
	spin_unlock_irqrestore(&health->wq_lock, flags);
	cancel_delayed_work_sync(&dev->priv.health.recover_work);
}

void mlx5_health_cleanup(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;

	destroy_workqueue(health->wq);
}

int mlx5_health_init(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health;
	char *name;

	health = &dev->priv.health;
	name = kmalloc(64, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	strcpy(name, "mlx5_health");
	strcat(name, dev_name(&dev->pdev->dev));
	health->wq = create_singlethread_workqueue(name);
	kfree(name);
	if (!health->wq)
		return -ENOMEM;
	spin_lock_init(&health->wq_lock);
	INIT_WORK(&health->work, health_care);
	INIT_DELAYED_WORK(&health->recover_work, health_recover);

	return 0;
}
