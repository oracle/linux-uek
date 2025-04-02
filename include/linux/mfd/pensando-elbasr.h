/* SPDX-License-Identifier: (GPL-2.0+ OR MIT) */
/*
 * Copyright (c) 2022 Advanced Micro Devices, Inc.
 *
 * Declarations for AMD Pensando Elba System Resource Chip
 */

#ifndef __MFD_AMD_PENSANDO_ELBA_H
#define __MFD_AMD_PENSANDO_ELBA_H

#include <linux/cdev.h>
#include <linux/regmap.h>

#define ELBASR_CTRL0_REG	0x10
#define ELBASR_MAX_REG		0xff
#define ELBASR_NR_RESETS	1

/*
 * Pensando Elba System Resource MFD device private data structure
 */
struct elbasr_data {
	dev_t devt;
	int minor;
	struct device *dev;
	struct cdev *cdev;
	struct spi_device *spi;
	struct list_head device_entry;
	spinlock_t spi_lock;

	/* TX/RX buffers are NULL unless this device is open (users > 0) */
	struct mutex buf_lock;
	unsigned int users;
	u8 *tx_buffer;
	u8 *rx_buffer;
	u32 speed_hz;

	/* System Resource Chip CS0 register access */
	struct regmap *elbasr_regs;
};

#endif /* __MFD_AMD_PENSANDO_ELBA_H */
