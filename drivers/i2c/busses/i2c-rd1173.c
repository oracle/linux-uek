// SPDX-License-Identifier: GPL-2.0
/*
 * Lattice RD1173 SPI to I2C bus interface driver
 *
 * Copyright (C) 2020 Pensando Systems, Inc.
 */

#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <linux/spi/spi.h>
#include <linux/delay.h>
#include <linux/sysfs.h>

/* SoC is assigned I2C bus 0 */
#define PORT1_I2C_BUS_NUM    1
#define PORT2_I2C_BUS_NUM    2

/* SPI command bits 7:4 */
#define RD1173_CMD_REG_WR         0x00    /* write internal reg */
#define RD1173_CMD_REG_RD         0x10    /* read internal reg */
#define RD1173_CMD_INT_CHECK      0x20    /* interrupt check */
#define RD1173_CMD_I2C_WR_N       0x30    /* write N bytes */
#define RD1173_CMD_I2C_RD_N       0x40    /* read N bytes */
#define RD1173_CMD_RD_RX_FIFO     0x50    /* read rx fifo */

/* Register address bits 3:0 */
#define RD1173_FIFO_STATUS_REG    0x01
#define RD1173_I2C0_CONFIG_REG    0x04
#define RD1173_I2C0_MODE_REG      0x05
#define RD1173_I2C0_CMD_STAT_REG  0x06
#define RD1173_I2C1_CONFIG_REG    0x0a
#define RD1173_I2C1_MODE_REG      0x0b
#define RD1173_I2C1_CMD_STAT_REG  0x0c

/* Register offset from master regbase */
#define RD1173_CONFIG_REG         0x00
#define RD1173_MODE_REG           0x01
#define RD1173_CMD_STAT_REG       0x02

/* FIFO register definitions */
#define RD1173_FIFO_RX0_FULL      0x80
#define RD1173_FIFO_RX0_EMPTY     0x40
#define RD1173_FIFO_TX0_FULL      0x20
#define RD1173_FIFO_TX0_EMPTY     0x10
#define RD1173_FIFO_RX1_FULL      0x08
#define RD1173_FIFO_RX1_EMPTY     0x04
#define RD1173_FIFO_TX1_FULL      0x02
#define RD1173_FIFO_TX1_EMPTY     0x01

/* Configuration register definitions */
#define RD1173_CONFIG_RESET       0x80
#define RD1173_CONFIG_RXFIFO_CLR  0x40
#define RD1173_CONFIG_TXFIFO_CLR  0x20
#define RD1173_CONFIG_ABORT       0x10
#define RD1173_CONFIG_RXREAD_CLR  0x08
#define RD1173_CONFIG_TXREAD_CLR  0x04
#define RD1173_CONFIG_INT_CLR     0x02
#define RD1173_CONFIG_START       0x01

/* Mode register definitions */
#define RD1173_MODE_BPS1          0x80
#define RD1173_MODE_BPS0          0x40
#define RD1173_MODE_TX_IE         0x20
#define RD1173_MODE_ACK_POL       0x10
#define RD1173_MODE_RX_IE         0x08

/* Command status register definitions */
#define RD1173_STAT_I2C_BUSY      0x80
#define RD1173_STAT_NO_ANS        0x40
#define RD1173_STAT_NO_ACK        0x20
#define RD1173_STAT_TX_ERR        0x10
#define RD1173_STAT_RX_ERR        0x08
#define RD1173_STAT_ABORT_ACK     0x04
#define RD1173_STAT_TS            0x02

struct i2c_stats {
	u32 i2c0_tx_complete;
	u32 i2c0_rx_complete;
	u32 i2c0_busy;
	u32 i2c0_no_answer;
	u32 i2c0_no_ack;
	u32 i2c0_tx_error;
	u32 i2c0_rx_error;
	u32 i2c0_abort_ack;

	u32 i2c1_tx_complete;
	u32 i2c1_rx_complete;
	u32 i2c1_busy;
	u32 i2c1_no_answer;
	u32 i2c1_no_ack;
	u32 i2c1_tx_error;
	u32 i2c1_rx_error;
	u32 i2c1_abort_ack;
};

struct rd1173_i2c_adapter {
	struct rd1173dev *rd1173dev;
	struct i2c_adapter i2c_adap;
	int i2c_master;
	int state;
	u32 offset;
};

struct rd1173dev {
	struct spi_device *spi;
	const struct chipdesc *chip;
	struct regmap *regmap;
	struct rd1173_i2c_adapter i2c_adap[2];
	struct i2c_stats stats;
	struct mutex xfer_active;
	struct completion completion;
};

enum chiptype {
	SPI2I2C_PENCPLD,
};

struct chipdesc {
	u8  type;
	u32 buffer_size;
	const struct regmap_config *regmap_cfg;
};

#define i2c_show_simple(field, name, format_string, cast)                  \
static ssize_t                                                             \
show_##name(struct device *dev, struct device_attribute *attr, char *buf)  \
{                                                                          \
	struct spi_device *spi = to_spi_device(dev);                       \
	struct rd1173dev *rd1173dev = spi_get_drvdata(spi);                \
	struct i2c_stats *i2c_stats = &rd1173dev->stats;                   \
									   \
	return snprintf(buf, 20, format_string, cast i2c_stats->field);    \
}

#define i2c_attr_show(field, name, format_string, type)         \
	i2c_show_simple(field, name, format_string, (type))     \
static DEVICE_ATTR(name, 0444, show_##name, NULL)

i2c_attr_show(i2c0_tx_complete, i2c0_tx_complete, "%d\n", u32);
i2c_attr_show(i2c0_rx_complete, i2c0_rx_complete, "%d\n", u32);
i2c_attr_show(i2c0_busy, i2c0_busy, "%d\n", u32);
i2c_attr_show(i2c0_no_answer, i2c0_no_answer, "%d\n", u32);
i2c_attr_show(i2c0_no_ack, i2c0_no_ack, "%d\n", u32);
i2c_attr_show(i2c0_tx_error, i2c0_tx_error, "%d\n", u32);
i2c_attr_show(i2c0_rx_error, i2c0_rx_error, "%d\n", u32);
i2c_attr_show(i2c0_abort_ack, i2c0_abort_ack, "%d\n", u32);

i2c_attr_show(i2c1_tx_complete, i2c1_tx_complete, "%d\n", u32);
i2c_attr_show(i2c1_rx_complete, i2c1_rx_complete, "%d\n", u32);
i2c_attr_show(i2c1_busy, i2c1_busy, "%d\n", u32);
i2c_attr_show(i2c1_no_answer, i2c1_no_answer, "%d\n", u32);
i2c_attr_show(i2c1_no_ack, i2c1_no_ack, "%d\n", u32);
i2c_attr_show(i2c1_tx_error, i2c1_tx_error, "%d\n", u32);
i2c_attr_show(i2c1_rx_error, i2c1_rx_error, "%d\n", u32);
i2c_attr_show(i2c1_abort_ack, i2c1_abort_ack, "%d\n", u32);

static struct attribute *i2c_attrs[] = {
	&dev_attr_i2c0_tx_complete.attr,
	&dev_attr_i2c0_rx_complete.attr,
	&dev_attr_i2c0_busy.attr,
	&dev_attr_i2c0_no_answer.attr,
	&dev_attr_i2c0_no_ack.attr,
	&dev_attr_i2c0_tx_error.attr,
	&dev_attr_i2c0_rx_error.attr,
	&dev_attr_i2c0_abort_ack.attr,

	&dev_attr_i2c1_tx_complete.attr,
	&dev_attr_i2c1_rx_complete.attr,
	&dev_attr_i2c1_busy.attr,
	&dev_attr_i2c1_no_answer.attr,
	&dev_attr_i2c1_no_ack.attr,
	&dev_attr_i2c1_tx_error.attr,
	&dev_attr_i2c1_rx_error.attr,
	&dev_attr_i2c1_abort_ack.attr,
	NULL,
};

static const struct attribute_group i2c_attr_group = {
	.attrs = i2c_attrs,
};

static bool rd1173_writeable_reg(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case RD1173_FIFO_STATUS_REG:
	case RD1173_I2C0_CMD_STAT_REG:
	case RD1173_I2C1_CMD_STAT_REG:
		return false;
	default:
		return true;
	}
}

static const struct regmap_config rd1173_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = RD1173_I2C1_CMD_STAT_REG,
	.writeable_reg = rd1173_writeable_reg,
};

static const struct chipdesc chip_rd1173 = {
	.type = SPI2I2C_PENCPLD,
	.buffer_size = 8,
	.regmap_cfg = &rd1173_regmap_config,
};

static irqreturn_t rd1173_irq_handler(int this_irq, void *data)
{
	struct rd1173dev *rd1173dev = data;
	struct rd1173_i2c_adapter *i2c0 = &rd1173dev->i2c_adap[0];
	struct rd1173_i2c_adapter *i2c1 = &rd1173dev->i2c_adap[1];
	struct rd1173_i2c_adapter *i2c;
	int state;
	int rc;

	/* Check both masters */
	rc = regmap_read(rd1173dev->regmap,
			 i2c0->offset + RD1173_CMD_STAT_REG,
			 &i2c0->state);
	if (rc)
		return IRQ_NONE;

	rc = regmap_read(rd1173dev->regmap,
			 i2c1->offset + RD1173_CMD_STAT_REG,
			 &i2c1->state);
	if (rc)
		return IRQ_NONE;

	if (i2c0->state) {
		i2c = i2c0;
		state = i2c0->state;
	} else if (i2c1->state) {
		i2c = i2c1;
		state = i2c1->state;
	} else {
		return IRQ_NONE;
	}

	if (state == RD1173_STAT_TS) {
		complete(&i2c->rd1173dev->completion);
		return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

/**
 * reg_read - RD1173 internal register read
 * @context: Pointer to rd1173 device
 * @reg: Internal register address
 * @val: Read data
 *
 * Return: zero on success, else a negative error code.
 */
static int reg_read(void *context, unsigned int reg, unsigned int *val)
{
	struct device *dev = context;
	struct spi_device *spi = to_spi_device(dev);
	u8 txbuffer[1] = { RD1173_CMD_REG_RD | (reg & 0xf) };
	u8 rxbuffer[1];
	int rc;

	rc = spi_write_then_read(spi, txbuffer, sizeof(txbuffer),
				 rxbuffer, sizeof(rxbuffer));
	if (rc) {
		dev_dbg(&spi->dev, "reg read error %d\n", rc);
		return rc;
	}
	*val = rxbuffer[0];

	return 0;
}

/**
 * reg_write - RD1173 internal register write
 * @context: Pointer to rd1173 device
 * @reg: Internal register address
 * @val: Write data
 *
 * Return: zero on success, else a negative error code.
 */
static int reg_write(void *context, unsigned int reg, unsigned int val)
{
	struct device *dev = context;
	struct spi_device *spi = to_spi_device(dev);
	u8 txbuffer[2] = { RD1173_CMD_REG_WR | (reg & 0xf), val & 0xff };

	return spi_write(spi, txbuffer, sizeof(txbuffer));
}

static struct regmap_bus regmap_rd1173_bus = {
	.reg_write = reg_write,
	.reg_read = reg_read,
	.reg_format_endian_default = REGMAP_ENDIAN_BIG,
	.val_format_endian_default = REGMAP_ENDIAN_BIG,
};

/**
 * rd1173_reset - Reset i2c master
 * @i2c: Pointer to rd1173 i2c master device
 *
 * Return: zero on success, else a negative error code.
 */
static int rd1173_reset(struct rd1173_i2c_adapter *i2c)
{
	struct device *dev = &i2c->rd1173dev->spi->dev;
	int reset = RD1173_CONFIG_RESET | RD1173_CONFIG_INT_CLR |
		    RD1173_CONFIG_ABORT;
	int enable = RD1173_MODE_TX_IE | RD1173_MODE_RX_IE;
	int rc;

	/* Assert reset */
	rc = regmap_update_bits(i2c->rd1173dev->regmap,
				i2c->offset + RD1173_CONFIG_REG,
				reset, reset);
	if (rc)
		dev_dbg(dev, "assert reset error %d\n", rc);

	/* Remove reset */
	rc = regmap_update_bits(i2c->rd1173dev->regmap,
				i2c->offset + RD1173_CONFIG_REG,
				reset, 0);
	if (rc)
		dev_dbg(dev, "deassert reset error %d\n", rc);

	/* Enable TX/RX interrupts, standard I2C speed */
	rc = regmap_update_bits(i2c->rd1173dev->regmap,
				i2c->offset + RD1173_MODE_REG,
				enable, enable);
	if (rc)
		dev_dbg(dev, "enable int error %d\n", rc);

	return rc;
}

/**
 * rd1173_fifo_clear - Clear TX and RX FIFOs
 * @i2c: Pointer to rd1173 i2c master device
 *
 * Return: zero on success, else a negative error code.
 */
static int rd1173_fifo_clear(struct rd1173_i2c_adapter *i2c)
{
	struct device *dev = &i2c->rd1173dev->spi->dev;
	int clr = RD1173_CONFIG_RXFIFO_CLR | RD1173_CONFIG_TXFIFO_CLR |
		  RD1173_CONFIG_RXREAD_CLR | RD1173_CONFIG_TXREAD_CLR;
	int rc;

	/* Assert fifo clear */
	rc = regmap_update_bits(i2c->rd1173dev->regmap,
				i2c->offset + RD1173_CONFIG_REG,
				clr, clr);
	if (rc)
		dev_dbg(dev, "fifo clear error %d\n", rc);

	/* Deassert fifo clear */
	rc = regmap_update_bits(i2c->rd1173dev->regmap,
				i2c->offset + RD1173_CONFIG_REG,
				clr, 0);
	if (rc)
		dev_dbg(dev, "fifo clear error %d\n", rc);

	return rc;
}

/**
 * rd1173_read - Initiate a read from rd1173 i2c master
 * @i2c: Pointer to rd1173 i2c master device
 * @msg: Pointer to i2c message structure
 * @cnt: Number of bytes to read (max 8)
 *
 * Return: Return: zero on success, else a negative error code.
 */
static int rd1173_read(struct rd1173_i2c_adapter *i2c, struct i2c_msg *msg, u8 cnt)
{
	u8 hdr[] = { RD1173_CMD_I2C_RD_N | (i2c->i2c_master << 1),
		     cnt, msg->addr };
	u8 start[] = { RD1173_CMD_REG_WR | (i2c->offset + RD1173_CONFIG_REG),
		       RD1173_CONFIG_START };
	int rc;

	rc = spi_write(i2c->rd1173dev->spi, hdr, sizeof(hdr));
	if (rc)
		return rc;

	return spi_write(i2c->rd1173dev->spi, start, sizeof(start));
}

/**
 * rd1173_write - Initiate a write to rd1173 i2c master
 * @i2c: Pointer to rd1173 i2c master device
 * @msg: Pointer to i2c message structure
 * @cnt: Number of bytes to write (max 8)
 *
 * Return: Return: zero on success, else a negative error code.
 */
static int rd1173_write(struct rd1173_i2c_adapter *i2c, struct i2c_msg *msg, u8 cnt)
{
	u8 hdr[] = { RD1173_CMD_I2C_WR_N | (i2c->i2c_master << 1),
		     cnt, msg->addr };
	u8 start[] = { RD1173_CMD_REG_WR | (i2c->offset + RD1173_CONFIG_REG),
		       RD1173_CONFIG_START };
	struct spi_transfer xfer[2] = { 0 };
	int rc;

	xfer[0].tx_buf = hdr;
	xfer[0].len = sizeof(hdr);

	xfer[1].tx_buf = msg->buf;
	xfer[1].len = msg->len;

	rc = spi_sync_transfer(i2c->rd1173dev->spi, xfer, 2);
	if (rc)
		return rc;

	return spi_write(i2c->rd1173dev->spi, start, sizeof(start));
}

/**
 * rd1173_read_buffer - Read rd1173 i2c master receive fifo
 * @i2c: Pointer to rd1173 i2c master device
 * @buf: Pointer to receive buffer address
 * @cnt: Number of bytes to read from rx fifo (max 8)
 *
 * Return: zero on success, else a negative error code.
 */
static int rd1173_read_buffer(struct rd1173_i2c_adapter *i2c, u8 *buf, u8 cnt)
{
	u8 txbuffer[1] = { RD1173_CMD_RD_RX_FIFO | (i2c->i2c_master << 1) };

	return spi_write_then_read(i2c->rd1173dev->spi,
				   txbuffer, sizeof(txbuffer),
				   buf, cnt + 1);
}

/**
 * rd1173_clear_cmdstat - Clear rd1173 command/status register
 * @i2c: Pointer to rd1173 i2c master device
 *
 * Return: zero on success, else a negative error code.
 */
static int rd1173_clear_cmdstat(struct rd1173_i2c_adapter *i2c)
{
	struct device *dev = &i2c->rd1173dev->spi->dev;
	int rc;

	rc = regmap_update_bits(i2c->rd1173dev->regmap,
				i2c->offset + RD1173_CONFIG_REG,
				RD1173_CONFIG_INT_CLR, RD1173_CONFIG_INT_CLR);
	if (rc)
		dev_dbg(dev, "clear cmdstat err %d\n", rc);

	rc = regmap_update_bits(i2c->rd1173dev->regmap,
				i2c->offset + RD1173_CONFIG_REG,
				RD1173_CONFIG_INT_CLR, 0);
	if (rc)
		dev_dbg(dev, "clear cmdstat err %d\n", rc);

	return rc;
}

/**
 * update_i2c_stats - Update the i2c transfer state counters
 * @i2c: Pointer to rd1173 i2c master device
 * @readop: I2C readop or writeop
 *
 */
static void update_i2c_stats(struct rd1173_i2c_adapter *i2c, int readop)
{
	struct i2c_stats *stats = &i2c->rd1173dev->stats;

	regmap_read(i2c->rd1173dev->regmap,
		    i2c->offset + RD1173_CMD_STAT_REG,
		    &i2c->state);

	switch (i2c->state) {
	case RD1173_STAT_TS:
		if (i2c->i2c_master) {
			if (readop)
				stats->i2c1_rx_complete++;
			else
				stats->i2c1_tx_complete++;
		} else {
			if (readop)
				stats->i2c0_rx_complete++;
			else
				stats->i2c0_tx_complete++;
		}
		break;
	case RD1173_STAT_I2C_BUSY:
		if (i2c->i2c_master)
			stats->i2c1_busy++;
		else
			stats->i2c0_busy++;
		break;
	case RD1173_STAT_NO_ANS:
		if (i2c->i2c_master)
			stats->i2c1_no_answer++;
		else
			stats->i2c0_no_answer++;
		break;
	case RD1173_STAT_NO_ACK:
		if (i2c->i2c_master)
			stats->i2c1_no_ack++;
		else
			stats->i2c0_no_ack++;
		break;
	case RD1173_STAT_TX_ERR:
		if (i2c->i2c_master)
			stats->i2c1_tx_error++;
		else
			stats->i2c0_tx_error++;
		break;
	case RD1173_STAT_RX_ERR:
		if (i2c->i2c_master)
			stats->i2c1_rx_error++;
		else
			stats->i2c0_rx_error++;
		break;
	case RD1173_STAT_ABORT_ACK:
		if (i2c->i2c_master)
			stats->i2c1_abort_ack++;
		else
			stats->i2c0_abort_ack++;
		break;
	}
}

/**
 * rd1173_xfer - The master spi to i2c transfer function
 * @adap: Pointer to the i2c_adapter structure
 * @msgs: Pointer to the messages to be processed
 * @num: Length of the MSGS array
 *
 * Returns the number of messages processed, or a negative errno on failure.
 */
static int rd1173_xfer(struct i2c_adapter *i2c_adap, struct i2c_msg *msgs, int num)
{
	struct rd1173_i2c_adapter *i2c = i2c_get_adapdata(i2c_adap);
	struct device *dev = &i2c->rd1173dev->spi->dev;
	u8 max_len = i2c->rd1173dev->chip->buffer_size;
	int read_operation = 0;
	u16 bytes_remaining;
	u16 bytes_transferred;
	u8 num_transfers;
	u8 rx_fifo[9];
	u8 cnt;
	int rc = 0;
	int i, j;

	if (num > 2)
		return -EOPNOTSUPP;

	for (i = 0; i < num; i++) {
		if (msgs[i].flags & I2C_M_RD) {
			if (msgs[i].len > 256)
				return -EOPNOTSUPP;
			read_operation++;
		} else {
			/* Writes limited buffer size */
			if (msgs[i].len > max_len)
				return -EOPNOTSUPP;
		}
		dev_dbg(dev, "msgs[%d]: addr 0x%x flags 0x%x len %d\n",
			i, msgs[i].addr, msgs[i].flags, msgs[i].len);
	}

	if (mutex_lock_interruptible(&i2c->rd1173dev->xfer_active))
		return -ERESTARTSYS;

	reinit_completion(&i2c->rd1173dev->completion);

	for (i = 0; i < num; i++) {
		rd1173_fifo_clear(i2c);
		rd1173_clear_cmdstat(i2c);

		bytes_transferred = 0;
		bytes_remaining = msgs[i].len;
		num_transfers = (bytes_remaining + max_len - 1) / max_len;

		for (j = 0; j < num_transfers; j++) {
			rd1173_fifo_clear(i2c);
			rd1173_clear_cmdstat(i2c);

			if (bytes_remaining > max_len)
				cnt = max_len;
			else
				cnt = bytes_remaining;

			if (msgs[i].flags & I2C_M_RD)
				rc = rd1173_read(i2c, &msgs[i], cnt);
			else
				rc = rd1173_write(i2c, &msgs[i], cnt);

			rc = wait_for_completion_timeout(&i2c->rd1173dev->completion,
				i2c->i2c_adap.timeout);

			update_i2c_stats(i2c, msgs[i].flags & I2C_M_RD);

			if (!rc || i2c->state != RD1173_STAT_TS)
				goto done;

			if (msgs[i].flags & I2C_M_RD) {
				rc = rd1173_read_buffer(i2c, rx_fifo, cnt);
				if (rc)
					goto done;

				memcpy((u8 *)(msgs[i].buf + bytes_transferred),
				       &rx_fifo[1], cnt);

				bytes_remaining -= cnt;
				bytes_transferred += cnt;
			}
		}
	}

done:
	rd1173_clear_cmdstat(i2c);
	switch (i2c->state) {
	case RD1173_STAT_TS:
		rc = num;        /* transfer complete */
		break;
	case RD1173_STAT_I2C_BUSY:
		rc = -EAGAIN;
		break;
	case RD1173_STAT_NO_ANS:
		rc = -ENXIO;
		break;
	case RD1173_STAT_NO_ACK:
		rc = -EREMOTEIO;
		break;
	case RD1173_STAT_TX_ERR:
	case RD1173_STAT_RX_ERR:
	case RD1173_STAT_ABORT_ACK:
		rd1173_reset(i2c);
		rc = -EAGAIN;
	default:
		rc = -EAGAIN;
	}

	mutex_unlock(&i2c->rd1173dev->xfer_active);
	return rc;
}

static u32 rd1173_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm rd1173_algo = {
	.master_xfer   = rd1173_xfer,
	.functionality = rd1173_func,
};

static int rd1173_probe(struct spi_device *spi)
{
	struct rd1173dev *rd1173dev;
	struct rd1173_i2c_adapter *i2c;
	int i, rc;

	rd1173dev = devm_kzalloc(&spi->dev, sizeof(*rd1173dev), GFP_KERNEL);
	if (!rd1173dev)
		return -ENOMEM;

	spi_set_drvdata(spi, rd1173dev);
	init_completion(&rd1173dev->completion);
	rd1173dev->spi = spi;
	spi->bits_per_word = 8;
	spi->mode = SPI_MODE_0;

	for (i = 0; i < 2; i++) {
		i2c = &rd1173dev->i2c_adap[i];
		i2c_set_adapdata(&i2c->i2c_adap, i2c);
		i2c->rd1173dev = rd1173dev;
		i2c->i2c_master = i;
		i2c->i2c_adap.algo = &rd1173_algo;
		i2c->i2c_adap.algo_data = NULL;
		i2c->i2c_adap.dev.parent = &spi->dev;
		i2c->i2c_adap.owner = THIS_MODULE;
		i2c->i2c_adap.class = I2C_CLASS_DEPRECATED;
		i2c->i2c_adap.timeout = msecs_to_jiffies(100);
		i2c->i2c_adap.nr = PORT1_I2C_BUS_NUM + i;

		if (i == 0)
			i2c->offset = RD1173_I2C0_CONFIG_REG;
		else
			i2c->offset = RD1173_I2C1_CONFIG_REG;

		snprintf(i2c->i2c_adap.name, sizeof(i2c->i2c_adap.name),
			 "CPLD Lattice RD1173 I2C%d", i);

		dev_info(&spi->dev, "%s mode %d irq %d\n", i2c->i2c_adap.name,
			 spi->mode, spi->irq);
	}

	rd1173dev->chip = of_device_get_match_data(&spi->dev);
	if (!rd1173dev->chip) {
		dev_info(&spi->dev, "No matching chip %d\n", -ENODEV);
		return -ENODEV;
	}

	rd1173dev->regmap = devm_regmap_init(&spi->dev, &regmap_rd1173_bus,
					     &spi->dev,
					     rd1173dev->chip->regmap_cfg);
	if (IS_ERR(rd1173dev->regmap)) {
		rc = PTR_ERR(rd1173dev->regmap);
		dev_err(&spi->dev, "Failed to init regmap, %d\n", rc);
		return rc;
	}


	mutex_init(&rd1173dev->xfer_active);

	rc = devm_request_threaded_irq(&spi->dev, spi->irq, NULL,
				       rd1173_irq_handler,
				       IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
				       "cpld-rd1173", rd1173dev);
	if (rc) {
		dev_err(&spi->dev, "Failed to request irq, err %d\n", rc);
		return rc;
	}

	rc = spi_setup(spi);
	if (rc) {
		dev_info(&spi->dev, "spi setup error %d\n", rc);
		return rc;
	}

	for (i = 0; i < 2; i++) {
		i2c = &rd1173dev->i2c_adap[i];
		rd1173_reset(i2c);
		rd1173_fifo_clear(i2c);

		rc = i2c_add_numbered_adapter(&i2c->i2c_adap);
		if (rc) {
			dev_err(&spi->dev, "error adding i2c adapter: %d\n", rc);
			return rc;
		}
		dev_info(&spi->dev, "registered I2C bus number %d\n",
			 i2c->i2c_adap.nr);
	}

	rc = sysfs_create_group(&spi->dev.kobj, &i2c_attr_group);
	if (rc)
		dev_warn(&spi->dev, "failed to create sysfs files\n");

	return 0;
}

static int rd1173_remove(struct spi_device *spi)
{
	struct rd1173dev *rd1173dev = spi_get_drvdata(spi);

	i2c_del_adapter(&rd1173dev->i2c_adap[0].i2c_adap);
	i2c_del_adapter(&rd1173dev->i2c_adap[1].i2c_adap);

	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id rd1173_of_match[] = {
	{ .compatible = "pensando,cpld-rd1173", .data = &chip_rd1173 },
	{},
};
MODULE_DEVICE_TABLE(of, rd1173_of_match);
#endif

static struct spi_driver rd1173_driver = {
	.probe  = rd1173_probe,
	.remove = rd1173_remove,
	.driver = {
		.name  = "i2c-rd1173",
		.of_match_table = of_match_ptr(rd1173_of_match),
	},
};
module_spi_driver(rd1173_driver);

MODULE_AUTHOR("Brad Larson <brad@pensando.io>");
MODULE_DESCRIPTION("Pensando CPLD Lattice RD1173 SPI to I2C bus adapter");
MODULE_LICENSE("GPL");
