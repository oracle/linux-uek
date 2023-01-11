// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * AMD Pensando Elba System Resource MFD Driver
 *
 * Userspace interface and reset driver support for SPI connected
 * Pensando Elba System Resource Chip.
 *
 * Adapted from spidev.c
 *
 * Copyright (C) 2006 SWAPP
 *	Andrea Paterniani <a.paterniani@swapp-eng.it>
 * Copyright (C) 2007 David Brownell (simplification, cleanup)
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 */

#include <linux/mfd/pensando-elbasr.h>
#include <linux/mfd/core.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/regmap.h>
#include <linux/spi/spi.h>
#include <linux/spi/spidev.h>
#include <linux/delay.h>

#define ELBASR_SPI_CMD_REGRD	0x0b
#define ELBASR_SPI_CMD_REGWR	0x02
#define ELBASR_MAX_DEVS		4

/* The main reason to have this class is to make mdev/udev create the
 * /dev/spidevB.C character device nodes exposing our userspace API.
 * It also simplifies memory management.  The device nodes
 * /dev/spidevB.C are used for backward compatibility.
 */
static struct class *elbasr_class;

static dev_t elbasr_devt;
static DECLARE_BITMAP(minors, ELBASR_MAX_DEVS);
static unsigned int bufsiz = 4096;

static LIST_HEAD(device_list);
static DEFINE_MUTEX(device_list_lock);

static const struct mfd_cell pensando_elbasr_subdev_info[] = {
	{
		.name = "pensando_elbasr_reset",
		.of_compatible = "amd,pensando-elbasr-reset",
	},
};

/* Bit masks for spi_device.mode management.  Note that incorrect
 * settings for some settings can cause *lots* of trouble for other
 * devices on a shared bus:
 *
 *  - CS_HIGH ... this device will be active when it shouldn't be
 *  - 3WIRE ... when active, it won't behave as it should
 *  - NO_CS ... there will be no explicit message boundaries; this
 *	is completely incompatible with the shared bus model
 *  - READY ... transfers may proceed when they shouldn't.
 */
#define SPI_MODE_MASK		(SPI_CPHA | SPI_CPOL | SPI_CS_HIGH \
				| SPI_LSB_FIRST | SPI_3WIRE | SPI_LOOP \
				| SPI_NO_CS | SPI_READY | SPI_TX_DUAL \
				| SPI_TX_QUAD | SPI_TX_OCTAL | SPI_RX_DUAL \
				| SPI_RX_QUAD | SPI_RX_OCTAL)

static ssize_t
elbasr_spi_sync(struct elbasr_data *elbasr_spi, struct spi_message *message)
{
	int status;
	struct spi_device *spi;

	spin_lock_irq(&elbasr_spi->spi_lock);
	spi = elbasr_spi->spi;
	spin_unlock_irq(&elbasr_spi->spi_lock);

	if (spi == NULL)
		status = -ESHUTDOWN;
	else
		status = spi_sync(spi, message);

	if (status == 0)
		status = message->actual_length;

	return status;
}

static inline ssize_t
elbasr_spi_sync_write(struct elbasr_data *elbasr, size_t len)
{
	struct spi_transfer	t = {
			.tx_buf		= elbasr->tx_buffer,
			.len		= len,
			.speed_hz	= elbasr->speed_hz,
		};
	struct spi_message	m;

	spi_message_init(&m);
	spi_message_add_tail(&t, &m);
	return elbasr_spi_sync(elbasr, &m);
}

static inline ssize_t
elbasr_spi_sync_read(struct elbasr_data *elbasr, size_t len)
{
	struct spi_transfer	t = {
			.rx_buf		= elbasr->rx_buffer,
			.len		= len,
			.speed_hz	= elbasr->speed_hz,
		};
	struct spi_message	m;

	spi_message_init(&m);
	spi_message_add_tail(&t, &m);
	return elbasr_spi_sync(elbasr, &m);
}

/* Read-only message with current device setup */
static ssize_t
elbasr_spi_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	struct elbasr_data *elbasr;
	ssize_t status;

	/* chipselect only toggles at start or end of operation */
	if (count > bufsiz)
		return -EMSGSIZE;

	elbasr = filp->private_data;

	mutex_lock(&elbasr->buf_lock);
	status = elbasr_spi_sync_read(elbasr, count);
	if (status > 0) {
		unsigned long missing;

		missing = copy_to_user(buf, elbasr->rx_buffer, status);
		if (missing == status)
			status = -EFAULT;
		else
			status = status - missing;
	}
	mutex_unlock(&elbasr->buf_lock);

	return status;
}

/* Write-only message with current device setup */
static ssize_t
elbasr_spi_write(struct file *filp, const char __user *buf,
		 size_t count, loff_t *f_pos)
{
	struct elbasr_data *elbasr;
	ssize_t status;
	unsigned long missing;

	/* chipselect only toggles at start or end of operation */
	if (count > bufsiz)
		return -EMSGSIZE;

	elbasr = filp->private_data;

	mutex_lock(&elbasr->buf_lock);
	missing = copy_from_user(elbasr->tx_buffer, buf, count);
	if (missing == 0)
		status = elbasr_spi_sync_write(elbasr, count);
	else
		status = -EFAULT;
	mutex_unlock(&elbasr->buf_lock);

	return status;
}

static int elbasr_spi_message(struct elbasr_data *elbasr,
			      struct spi_ioc_transfer *u_xfers,
			      unsigned int n_xfers)
{
	struct spi_message msg;
	struct spi_transfer *k_xfers;
	struct spi_transfer *k_tmp;
	struct spi_ioc_transfer *u_tmp;
	unsigned int n, total, tx_total, rx_total;
	u8 *tx_buf, *rx_buf;
	int status = -EFAULT;

	spi_message_init(&msg);
	k_xfers = kcalloc(n_xfers, sizeof(*k_tmp), GFP_KERNEL);
	if (k_xfers == NULL)
		return -ENOMEM;

	/* Construct spi_message, copying any tx data to bounce buffer.
	 * We walk the array of user-provided transfers, using each one
	 * to initialize a kernel version of the same transfer.
	 */
	tx_buf = elbasr->tx_buffer;
	rx_buf = elbasr->rx_buffer;
	total = 0;
	tx_total = 0;
	rx_total = 0;
	for (n = n_xfers, k_tmp = k_xfers, u_tmp = u_xfers;
			n;
			n--, k_tmp++, u_tmp++) {
		/* Ensure that also following allocations from rx_buf/tx_buf will meet
		 * DMA alignment requirements.
		 */
		unsigned int len_aligned = ALIGN(u_tmp->len,
						 ARCH_KMALLOC_MINALIGN);

		k_tmp->len = u_tmp->len;

		total += k_tmp->len;
		/* Since the function returns the total length of transfers
		 * on success, restrict the total to positive int values to
		 * avoid the return value looking like an error.  Also check
		 * each transfer length to avoid arithmetic overflow.
		 */
		if (total > INT_MAX || k_tmp->len > INT_MAX) {
			status = -EMSGSIZE;
			goto done;
		}

		if (u_tmp->rx_buf) {
			/* this transfer needs space in RX bounce buffer */
			rx_total += len_aligned;
			if (rx_total > bufsiz) {
				status = -EMSGSIZE;
				goto done;
			}
			k_tmp->rx_buf = rx_buf;
			rx_buf += len_aligned;
		}
		if (u_tmp->tx_buf) {
			/* this transfer needs space in TX bounce buffer */
			tx_total += len_aligned;
			if (tx_total > bufsiz) {
				status = -EMSGSIZE;
				goto done;
			}
			k_tmp->tx_buf = tx_buf;
			if (copy_from_user(tx_buf, (const u8 __user *)
						(uintptr_t) u_tmp->tx_buf,
					u_tmp->len))
				goto done;
			tx_buf += len_aligned;
		}

		k_tmp->cs_change = !!u_tmp->cs_change;
		k_tmp->tx_nbits = u_tmp->tx_nbits;
		k_tmp->rx_nbits = u_tmp->rx_nbits;
		k_tmp->bits_per_word = u_tmp->bits_per_word;
		k_tmp->delay_usecs = u_tmp->delay_usecs;
		k_tmp->speed_hz = u_tmp->speed_hz;
		k_tmp->word_delay_usecs = u_tmp->word_delay_usecs;
		if (!k_tmp->speed_hz)
			k_tmp->speed_hz = elbasr->speed_hz;
#ifdef VERBOSE
		dev_dbg(&elbasr->spi->dev,
			" xfer len %u %s%s%s%dbits %u usec %u usec %uHz (%u)\n",
			k_tmp->len,
			k_tmp->rx_buf ? "rx " : "",
			k_tmp->tx_buf ? "tx " : "",
			k_tmp->cs_change ? "cs " : "",
			k_tmp->bits_per_word ? : elbasr->spi->bits_per_word,
			k_tmp->delay.value,
			k_tmp->word_delay.value,
			k_tmp->speed_hz ? : elbasr->spi->max_speed_hz);
#endif
		spi_message_add_tail(k_tmp, &msg);
	}

	status = elbasr_spi_sync(elbasr, &msg);
	if (status < 0)
		goto done;

	/* copy any rx data out of bounce buffer */
	for (n = n_xfers, k_tmp = k_xfers, u_tmp = u_xfers;
			n;
			n--, k_tmp++, u_tmp++) {
		if (u_tmp->rx_buf) {
			if (copy_to_user((u8 __user *)
					(uintptr_t) u_tmp->rx_buf, k_tmp->rx_buf,
					u_tmp->len)) {
				status = -EFAULT;
				goto done;
			}
		}
	}
	status = total;

done:
	kfree(k_xfers);
	return status;
}

static struct spi_ioc_transfer *
elbasr_spi_get_ioc_message(unsigned int cmd,
			   struct spi_ioc_transfer __user *u_ioc,
			   unsigned int *n_ioc)
{
	u32 tmp;

	/* Check type, command number and direction */
	if (_IOC_TYPE(cmd) != SPI_IOC_MAGIC
			|| _IOC_NR(cmd) != _IOC_NR(SPI_IOC_MESSAGE(0))
			|| _IOC_DIR(cmd) != _IOC_WRITE)
		return ERR_PTR(-ENOTTY);

	tmp = _IOC_SIZE(cmd);
	if ((tmp % sizeof(struct spi_ioc_transfer)) != 0)
		return ERR_PTR(-EINVAL);
	*n_ioc = tmp / sizeof(struct spi_ioc_transfer);
	if (*n_ioc == 0)
		return NULL;

	/* copy into scratch area */
	return memdup_user(u_ioc, tmp);
}

static long
elbasr_spi_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int retval = 0;
	struct elbasr_data *elbasr;
	struct spi_device *spi;
	u32 tmp;
	unsigned int n_ioc;
	struct spi_ioc_transfer	*ioc;

	/* Check type and command number */
	if (_IOC_TYPE(cmd) != SPI_IOC_MAGIC)
		return -ENOTTY;

	/* guard against device removal before, or while,
	 * we issue this ioctl.
	 */
	elbasr = filp->private_data;
	spin_lock_irq(&elbasr->spi_lock);
	spi = spi_dev_get(elbasr->spi);
	spin_unlock_irq(&elbasr->spi_lock);

	if (spi == NULL)
		return -ESHUTDOWN;

	/* use the buffer lock here for triple duty:
	 *  - prevent I/O (from us) so calling spi_setup() is safe;
	 *  - prevent concurrent SPI_IOC_WR_* from morphing
	 *    data fields while SPI_IOC_RD_* reads them;
	 *  - SPI_IOC_MESSAGE needs the buffer locked "normally".
	 */
	mutex_lock(&elbasr->buf_lock);

	switch (cmd) {
	/* read requests */
	case SPI_IOC_RD_MODE:
		retval = put_user(spi->mode & SPI_MODE_MASK,
					(__u8 __user *)arg);
		break;
	case SPI_IOC_RD_MODE32:
		retval = put_user(spi->mode & SPI_MODE_MASK,
					(__u32 __user *)arg);
		break;
	case SPI_IOC_RD_LSB_FIRST:
		retval = put_user((spi->mode & SPI_LSB_FIRST) ?  1 : 0,
					(__u8 __user *)arg);
		break;
	case SPI_IOC_RD_BITS_PER_WORD:
		retval = put_user(spi->bits_per_word, (__u8 __user *)arg);
		break;
	case SPI_IOC_RD_MAX_SPEED_HZ:
		retval = put_user(elbasr->speed_hz, (__u32 __user *)arg);
		break;

	/* write requests */
	case SPI_IOC_WR_MODE:
	case SPI_IOC_WR_MODE32:
		if (cmd == SPI_IOC_WR_MODE)
			retval = get_user(tmp, (u8 __user *)arg);
		else
			retval = get_user(tmp, (u32 __user *)arg);
		if (retval == 0) {
			struct spi_controller *ctlr = spi->controller;
			u32	save = spi->mode;

			if (tmp & ~SPI_MODE_MASK) {
				retval = -EINVAL;
				break;
			}

			if (ctlr->use_gpio_descriptors && ctlr->cs_gpiods &&
			    ctlr->cs_gpiods[spi->chip_select])
				tmp |= SPI_CS_HIGH;

			tmp |= spi->mode & ~SPI_MODE_MASK;
			spi->mode = (u16)tmp;
			retval = spi_setup(spi);
			if (retval < 0)
				spi->mode = save;
			else
				dev_dbg(&spi->dev, "spi mode %x\n", tmp);
		}
		break;
	case SPI_IOC_WR_LSB_FIRST:
		retval = get_user(tmp, (__u8 __user *)arg);
		if (retval == 0) {
			u32	save = spi->mode;

			if (tmp)
				spi->mode |= SPI_LSB_FIRST;
			else
				spi->mode &= ~SPI_LSB_FIRST;
			retval = spi_setup(spi);
			if (retval < 0)
				spi->mode = save;
			else
				dev_dbg(&spi->dev, "%csb first\n",
						tmp ? 'l' : 'm');
		}
		break;
	case SPI_IOC_WR_BITS_PER_WORD:
		retval = get_user(tmp, (__u8 __user *)arg);
		if (retval == 0) {
			u8	save = spi->bits_per_word;

			spi->bits_per_word = tmp;
			retval = spi_setup(spi);
			if (retval < 0)
				spi->bits_per_word = save;
			else
				dev_dbg(&spi->dev, "%d bits per word\n", tmp);
		}
		break;
	case SPI_IOC_WR_MAX_SPEED_HZ:
		retval = get_user(tmp, (__u32 __user *)arg);
		if (retval == 0) {
			u32	save = spi->max_speed_hz;

			spi->max_speed_hz = tmp;
			retval = spi_setup(spi);
			if (retval == 0) {
				elbasr->speed_hz = tmp;
				dev_dbg(&spi->dev, "%d Hz (max)\n",
					elbasr->speed_hz);
			}
			spi->max_speed_hz = save;
		}
		break;

	default:
		/* segmented and/or full-duplex I/O request */
		/* Check message and copy into scratch area */
		ioc = elbasr_spi_get_ioc_message(cmd,
				(struct spi_ioc_transfer __user *)arg, &n_ioc);
		if (IS_ERR(ioc)) {
			retval = PTR_ERR(ioc);
			break;
		}
		if (!ioc)
			break;	/* n_ioc is also 0 */

		/* translate to spi_message, execute */
		retval = elbasr_spi_message(elbasr, ioc, n_ioc);
		kfree(ioc);
		break;
	}

	mutex_unlock(&elbasr->buf_lock);
	spi_dev_put(spi);
	return retval;
}

#ifdef CONFIG_COMPAT
static long
elbasr_spi_compat_ioc_message(struct file *filp, unsigned int cmd,
			      unsigned long arg)
{
	struct spi_ioc_transfer __user *u_ioc;
	int retval = 0;
	struct elbasr_data *elbasr;
	struct spi_device *spi;
	unsigned int n_ioc, n;
	struct spi_ioc_transfer *ioc;

	u_ioc = (struct spi_ioc_transfer __user *) compat_ptr(arg);

	/* guard against device removal before, or while,
	 * we issue this ioctl.
	 */
	elbasr = filp->private_data;
	spin_lock_irq(&elbasr->spi_lock);
	spi = spi_dev_get(elbasr->spi);
	spin_unlock_irq(&elbasr->spi_lock);

	if (spi == NULL)
		return -ESHUTDOWN;

	/* SPI_IOC_MESSAGE needs the buffer locked "normally" */
	mutex_lock(&elbasr->buf_lock);

	/* Check message and copy into scratch area */
	ioc = elbasr_spi_get_ioc_message(cmd, u_ioc, &n_ioc);
	if (IS_ERR(ioc)) {
		retval = PTR_ERR(ioc);
		goto done;
	}
	if (!ioc)
		goto done;	/* n_ioc is also 0 */

	/* Convert buffer pointers */
	for (n = 0; n < n_ioc; n++) {
		ioc[n].rx_buf = (uintptr_t) compat_ptr(ioc[n].rx_buf);
		ioc[n].tx_buf = (uintptr_t) compat_ptr(ioc[n].tx_buf);
	}

	/* translate to spi_message, execute */
	retval = elbasr_spi_message(elbasr, ioc, n_ioc);
	kfree(ioc);

done:
	mutex_unlock(&elbasr->buf_lock);
	spi_dev_put(spi);
	return retval;
}

static long
elbasr_spi_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	if (_IOC_TYPE(cmd) == SPI_IOC_MAGIC
			&& _IOC_NR(cmd) == _IOC_NR(SPI_IOC_MESSAGE(0))
			&& _IOC_DIR(cmd) == _IOC_WRITE)
		return elbasr_spi_compat_ioc_message(filp, cmd, arg);

	return elbasr_spi_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#else
#define elbasr_spi_compat_ioctl NULL
#endif /* CONFIG_COMPAT */

static int elbasr_spi_open(struct inode *inode, struct file *filp)
{
	struct elbasr_data *elbasr;
	int status = -ENXIO;

	mutex_lock(&device_list_lock);

	list_for_each_entry(elbasr, &device_list, device_entry) {
		if (elbasr->devt == inode->i_rdev) {
			status = 0;
			break;
		}
	}

	if (status) {
		pr_debug("elbasr_spi: nothing for minor %d\n", iminor(inode));
		goto err_find_dev;
	}

	if (!elbasr->tx_buffer) {
		elbasr->tx_buffer = kmalloc(bufsiz, GFP_KERNEL);
		if (!elbasr->tx_buffer) {
			status = -ENOMEM;
			goto err_find_dev;
		}
	}

	if (!elbasr->rx_buffer) {
		elbasr->rx_buffer = kmalloc(bufsiz, GFP_KERNEL);
		if (!elbasr->rx_buffer) {
			status = -ENOMEM;
			goto err_alloc_rx_buf;
		}
	}

	elbasr->users++;
	filp->private_data = elbasr;
	stream_open(inode, filp);

	mutex_unlock(&device_list_lock);
	return 0;

err_alloc_rx_buf:
	kfree(elbasr->tx_buffer);
	elbasr->tx_buffer = NULL;
err_find_dev:
	mutex_unlock(&device_list_lock);
	return status;
}

static int elbasr_spi_release(struct inode *inode, struct file *filp)
{
	struct elbasr_data *elbasr;
	int dofree;

	mutex_lock(&device_list_lock);
	elbasr = filp->private_data;
	filp->private_data = NULL;

	spin_lock_irq(&elbasr->spi_lock);
	/* ... after we unbound from the underlying device? */
	dofree = (elbasr->spi == NULL);
	spin_unlock_irq(&elbasr->spi_lock);

	/* last close? */
	elbasr->users--;
	if (!elbasr->users) {

		kfree(elbasr->tx_buffer);
		elbasr->tx_buffer = NULL;

		kfree(elbasr->rx_buffer);
		elbasr->rx_buffer = NULL;

		if (dofree)
			kfree(elbasr);
		else
			elbasr->speed_hz = elbasr->spi->max_speed_hz;
	}
#ifdef CONFIG_SPI_SLAVE
	if (!dofree)
		spi_slave_abort(elbasr->spi);
#endif
	mutex_unlock(&device_list_lock);

	return 0;
}

static const struct file_operations elbasr_spi_fops = {
	.owner =	THIS_MODULE,
	.write =	elbasr_spi_write,
	.read =		elbasr_spi_read,
	.unlocked_ioctl = elbasr_spi_ioctl,
	.compat_ioctl = elbasr_spi_compat_ioctl,
	.open =		elbasr_spi_open,
	.release =	elbasr_spi_release,
	.llseek =	no_llseek,
};

static bool
elbasr_reg_readable(struct device *dev, unsigned int reg)
{
	return reg <= ELBASR_MAX_REG;
}

static bool
elbasr_reg_writeable(struct device *dev, unsigned int reg)
{
	return reg <= ELBASR_MAX_REG;
}

static int
elbasr_regs_read(void *ctx, u32 reg, u32 *val)
{
	struct elbasr_data *elbasr = dev_get_drvdata(ctx);
	struct spi_message m;
	struct spi_transfer t[2] = { { 0 } };
	int ret;
	u8 txbuf[3];
	u8 rxbuf[1];

	spi_message_init(&m);

	txbuf[0] = ELBASR_SPI_CMD_REGRD;
	txbuf[1] = reg;
	txbuf[2] = 0x0;
	t[0].tx_buf = (u8 *)txbuf;
	t[0].len = 3;

	rxbuf[0] = 0x0;
	t[1].rx_buf = rxbuf;
	t[1].len = 1;

	spi_message_add_tail(&t[0], &m);
	spi_message_add_tail(&t[1], &m);

	ret = elbasr_spi_sync(elbasr, &m);
	if (ret == 4) {
		// 3 Tx + 1 Rx = 4
		*val = rxbuf[0];
		return 0;
	}
	return -EIO;
}

static int
elbasr_regs_write(void *ctx, u32 reg, u32 val)
{
	struct elbasr_data *elbasr = dev_get_drvdata(ctx);
	struct spi_message m;
	struct spi_transfer t[1] = { { 0 } };
	u8 txbuf[4];

	spi_message_init(&m);
	txbuf[0] = ELBASR_SPI_CMD_REGWR;
	txbuf[1] = reg;
	txbuf[2] = val;
	txbuf[3] = 0;

	t[0].tx_buf = txbuf;
	t[0].len = 4;

	spi_message_add_tail(&t[0], &m);

	return elbasr_spi_sync(elbasr, &m);
}

static const struct regmap_config pensando_elbasr_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.cache_type = REGCACHE_NONE,
	.readable_reg = elbasr_reg_readable,
	.writeable_reg = elbasr_reg_writeable,
	.reg_read = elbasr_regs_read,
	.reg_write = elbasr_regs_write,
	.max_register = ELBASR_MAX_REG
};

/*
 * Setup Elba SPI access to System Resource Chip registers on CS0
 */
static int
elbasr_regs_setup(struct spi_device *spi, struct elbasr_data *elbasr)
{
	int ret;

	spi->bits_per_word = 8;
	spi_setup(spi);
	elbasr->elbasr_regs = devm_regmap_init(&spi->dev, NULL, spi,
					       &pensando_elbasr_regmap_config);
	if (IS_ERR(elbasr->elbasr_regs)) {
		ret = PTR_ERR(elbasr->elbasr_regs);
		dev_err(&spi->dev, "Failed to allocate register map: %d\n", ret);
		return ret;
	}

	ret = devm_mfd_add_devices(&spi->dev, PLATFORM_DEVID_NONE,
				   pensando_elbasr_subdev_info,
				   ARRAY_SIZE(pensando_elbasr_subdev_info),
				   NULL, 0, NULL);
	if (ret)
		dev_err(&spi->dev, "Failed to register sub-devices: %d\n", ret);

	return ret;
}

static int elbasr_spi_probe(struct spi_device *spi)
{
	struct elbasr_data *elbasr;
	unsigned long minor;
	int status;

	if (spi->chip_select == 0) {
		status = alloc_chrdev_region(&elbasr_devt, 0, ELBASR_MAX_DEVS,
					     "elbasr");
		if (status < 0)
			return status;

		elbasr_class = class_create(THIS_MODULE, "elbasr");
		if (IS_ERR(elbasr_class)) {
			unregister_chrdev(MAJOR(elbasr_devt), "elbasr");
			return PTR_ERR(elbasr_class);
		}
	}

	/* Allocate driver data */
	elbasr = kzalloc(sizeof(*elbasr), GFP_KERNEL);
	if (!elbasr) {
		if (spi->chip_select == 0)
			unregister_chrdev(MAJOR(elbasr_devt), "elbasr");
		return -ENOMEM;
	}

	/* Initialize the driver data */
	elbasr->spi = spi;
	elbasr->speed_hz = spi->max_speed_hz;
	spin_lock_init(&elbasr->spi_lock);
	mutex_init(&elbasr->buf_lock);

	INIT_LIST_HEAD(&elbasr->device_entry);

	mutex_lock(&device_list_lock);
	minor = find_first_zero_bit(minors, ELBASR_MAX_DEVS);
	if (minor < ELBASR_MAX_DEVS) {
		struct device *dev;

		elbasr->devt = MKDEV(MAJOR(elbasr_devt), minor);
		dev = device_create(elbasr_class,
				    &spi->dev,
				    elbasr->devt,
				    elbasr,
				    "spidev%d.%d",
				    spi->master->bus_num,
				    spi->chip_select);

		status = PTR_ERR_OR_ZERO(dev);
	} else {
		dev_dbg(&spi->dev, "no minor number available\n");
		status = -ENODEV;
		mutex_unlock(&device_list_lock);
		goto minor_failed;
	}

	set_bit(minor, minors);
	list_add(&elbasr->device_entry, &device_list);
	dev_dbg(&spi->dev,
		"created device for major %d, minor %lu\n",
		MAJOR(elbasr_devt), minor);
	mutex_unlock(&device_list_lock);

	/* Create cdev */
	elbasr->cdev = cdev_alloc();
	if (!elbasr->cdev) {
		dev_err(elbasr->dev, "allocation of cdev failed");
		status = -ENOMEM;
		goto cdev_failed;
	}
	elbasr->cdev->owner = THIS_MODULE;
	cdev_init(elbasr->cdev, &elbasr_spi_fops);

	status = cdev_add(elbasr->cdev, elbasr->devt, 1);
	if (status) {
		dev_err(elbasr->dev, "register of cdev failed");
		goto cdev_delete;
	}
	spi_set_drvdata(spi, elbasr);

	/* Add Elba reset driver sub-device */
	if (spi->chip_select == 0)
		elbasr_regs_setup(spi, elbasr);

	return 0;

cdev_delete:
	if (spi->chip_select == 0)
		cdev_del(elbasr->cdev);
cdev_failed:
	if (spi->chip_select == 0)
		device_destroy(elbasr_class, elbasr->devt);
minor_failed:
	kfree(elbasr);

	return status;
}

static const struct of_device_id elbasr_spi_of_match[] = {
	{ .compatible = "amd,pensando-elbasr" },
	{ /* sentinel */ },
};

static struct spi_driver elbasr_spi_driver = {
	.probe = elbasr_spi_probe,
	.driver = {
		.name = "elbasr",
		.of_match_table = of_match_ptr(elbasr_spi_of_match),
	},
};
builtin_driver(elbasr_spi_driver, spi_register_driver)
