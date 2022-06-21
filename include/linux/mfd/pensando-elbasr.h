/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2022 Pensando Systems, Inc.
 *
 * Declarations for Pensando Elba System Resource Chip
 *
 */

#ifndef __MFD_PENSANDO_ELBA_H
#define __MFD_PENSANDO_ELBA_H

#include <linux/mfd/core.h>
#include <linux/regmap.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#define ELBASR_MAX_REG			0x80
#define ELBASR_NR_RESETS		1

#define ELBASR_ASIC_CONTROL_REG0	0x10
#define EMMC_HW_RESET			BIT(6)

/*
 * Pensando Elba System Resource MFD device private data structure
 */
struct elbasr_data {
	dev_t devt;
	spinlock_t spi_lock;
	struct spi_device *spi;
	struct list_head device_entry;

	/* TX/RX buffers are NULL unless this device is open (users > 0) */
	struct mutex buf_lock;
	unsigned int users;
	u8 *tx_buffer;
	u8 *rx_buffer;
	u32 speed_hz;

	/* System Resource Chip CS0 register access */
	struct regmap *elbasr_regs;
};

#endif /* __MFD_PENSANDO_ELBA_H */
