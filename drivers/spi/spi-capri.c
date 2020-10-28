
/*
 * Copyright (c) 2020, Pensando Systems Inc.
 *
 * Pensando Capri SPI Driver.
 *
 * Based on spi-dw.c
 */

#include <linux/clk.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/io.h>

/* Register offsets */
#define DW_SPI_CTRL0			0x00
#define DW_SPI_CTRL1			0x04
#define DW_SPI_SSIENR			0x08
#define DW_SPI_SER			0x10
#define DW_SPI_BAUDR			0x14
#define DW_SPI_TXFLTR			0x18
#define DW_SPI_TXFLR			0x20
#define DW_SPI_RXFLR			0x24
#define DW_SPI_IMR			0x2c
#define DW_SPI_DR			0x60

/* Bit fields in CTRLR0 */
#define SPI_FRF_OFFSET			4
#define SPI_FRF_SPI			0x0

#define SPI_MODE_OFFSET			6

#define SPI_TMOD_OFFSET			8
#define SPI_TMOD_EPROMREAD		0x3

struct cspi {
	void __iomem *regs;
	struct clk *clk;
	u16 bus_num;
	u32 max_freq;
	struct spi_master *master;
	u32 fifo_len;
	u32 current_freq;
	const u8 *tx;
	const u8 *tx_end;
	u8 *rx;
	u8 *rx_end;
	unsigned len;
};

static inline u32 cspi_readl(struct cspi *cspi, u32 offset)
{
	return readl(cspi->regs + offset);
}

static inline void cspi_writel(struct cspi *cspi, u32 offset, u32 val)
{
	writel(val, cspi->regs + offset);
}

static void cspi_set_clk(struct cspi *cspi, u16 div)
{
	cspi_writel(cspi, DW_SPI_BAUDR, div);
}

static void cspi_enable_chip(struct cspi *cspi, int enable)
{
	cspi_writel(cspi, DW_SPI_SSIENR, (enable ? 1 : 0));
}

static void cspi_shutdown_chip(struct cspi *cspi)
{
	cspi_enable_chip(cspi, 0);
	cspi_set_clk(cspi, 0);
}

static void cspi_reset_chip(struct cspi *cspi)
{
	cspi_enable_chip(cspi, 0);
	cspi_writel(cspi, DW_SPI_IMR, 0xff);
	cspi_enable_chip(cspi, 1);
}

static u32 tx_max(struct cspi *cspi)
{
	u32 tx_left, tx_room, rxtx_gap;

	tx_left = cspi->tx_end - cspi->tx;
	tx_room = cspi->fifo_len - cspi_readl(cspi, DW_SPI_TXFLR);
	rxtx_gap = (cspi->rx_end - cspi->rx) - (cspi->tx_end - cspi->tx);
	return min3(tx_left, tx_room, (u32) (cspi->fifo_len - rxtx_gap));
}

static u32 rx_max(struct cspi *cspi)
{
	u32 rx_left = cspi->rx_end - cspi->rx;

	return min_t(u32, rx_left, cspi_readl(cspi, DW_SPI_RXFLR));
}

static void cspi_writer(struct cspi *cspi)
{
	u32 max = tx_max(cspi);
	u16 txw = 0;

	while (max--) {
		if (cspi->tx_end - cspi->len)
			txw = *(u8 *)cspi->tx;
		cspi_writel(cspi, DW_SPI_DR, txw);
		++cspi->tx;
	}
}

static void cspi_reader(struct cspi *cspi)
{
	u32 max = rx_max(cspi);
	u16 rxw;

	while (max--) {
		rxw = cspi_readl(cspi, DW_SPI_DR);
		if (cspi->rx_end - cspi->len) {
			*(u8 *)cspi->rx = rxw;
		}
		++cspi->rx;
	}
}

static int cspi_transfer_one(struct spi_master *master,
		struct spi_device *spi, struct spi_transfer *xfer)
{
	struct cspi *cspi = spi_master_get_devdata(master);
	u32 cr0;

	/* Transfers are always 8-bits */
	if (xfer->bits_per_word != 8)
		return -EINVAL;

	cspi->tx = xfer->tx_buf;
	cspi->tx_end = cspi->tx + xfer->len;
	cspi->rx = xfer->rx_buf;
	cspi->rx_end = cspi->rx + xfer->len;
	cspi->len = xfer->len;

	cspi_enable_chip(cspi, 0);

	if (xfer->speed_hz != cspi->current_freq) {
		/* clk_div doesn't support odd number */
		u16 clk_div = (DIV_ROUND_UP(cspi->max_freq,
				xfer->speed_hz) + 1) & 0xfffe;
		cspi_set_clk(cspi, clk_div);
		cspi->current_freq = xfer->speed_hz;
	}

	/* All transfers are EPROM read-style. */
	cr0 = (xfer->bits_per_word - 1)
		| (SPI_FRF_SPI << SPI_FRF_OFFSET)
		| (spi->mode << SPI_MODE_OFFSET)
		| (SPI_TMOD_EPROMREAD << SPI_TMOD_OFFSET);
	cspi_writel(cspi, DW_SPI_CTRL0, cr0);
	cspi_writel(cspi, DW_SPI_CTRL1, cspi->len - 1);

	/*
	 * Begin with no slave enabled so as to hold the TX FIFO
	 * until we're ready.
	 */
	cspi_writel(cspi, DW_SPI_SER, 0);

	cspi_enable_chip(cspi, 1);

	/*
	 * Do the initial writes to the TX FIFO, and then release it.
	 */
	cspi_writer(cspi);
	cspi_writel(cspi, DW_SPI_SER, BIT(spi->chip_select));
	do {
		cspi_writer(cspi);
		cspi_reader(cspi);
		cpu_relax();
	} while (cspi->rx_end > cspi->rx);

	return 0;
}

static void cspi_hw_init(struct device *dev, struct cspi *cspi)
{
	cspi_reset_chip(cspi);

	if (!cspi->fifo_len) {
		u32 fifo;

		for (fifo = 1; fifo < 256; fifo++) {
			cspi_writel(cspi, DW_SPI_TXFLTR, fifo);
			if (fifo != cspi_readl(cspi, DW_SPI_TXFLTR))
				break;
		}
		cspi_writel(cspi, DW_SPI_TXFLTR, 0);

		cspi->fifo_len = (fifo == 1) ? 0 : fifo;
		dev_dbg(dev, "Detected FIFO size: %u bytes\n", cspi->fifo_len);
	}
}

static int cspi_add_host(struct device *dev, struct cspi *cspi)
{
	struct spi_master *master;
	int ret;

	master = spi_alloc_master(dev, 0);
	if (!master)
		return -ENOMEM;

	cspi->master = master;

	master->mode_bits = SPI_CPOL | SPI_CPHA;
	master->bits_per_word_mask = SPI_BPW_MASK(8);
	master->bus_num = cspi->bus_num;
	master->num_chipselect = 2;
	master->transfer_one = cspi_transfer_one;
	master->max_speed_hz = cspi->max_freq;
	master->dev.of_node = dev->of_node;

	cspi_hw_init(dev, cspi);

	spi_master_set_devdata(master, cspi);
	ret = devm_spi_register_master(dev, master);
	if (ret) {
		dev_err(&master->dev, "problem registering spi master\n");
		goto err;
	}

	return 0;

err:
	cspi_enable_chip(cspi, 0);
	spi_master_put(master);
	return ret;
}

static void cspi_remove_host(struct cspi *cspi)
{
	cspi_shutdown_chip(cspi);
}

static int cspi_probe(struct platform_device *pdev)
{
	struct resource *res;
	struct cspi *cspi;
	int ret;

	cspi = devm_kzalloc(&pdev->dev, sizeof (*cspi), GFP_KERNEL);
	if (!cspi)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	cspi->regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(cspi->regs)) {
		dev_err(&pdev->dev, "SPI region map failed\n");
		return PTR_ERR(cspi->regs);
	}

	cspi->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(cspi->clk))
		return PTR_ERR(cspi->clk);
	ret = clk_prepare_enable(cspi->clk);
	if (ret)
		return ret;

	cspi->bus_num = pdev->id;
	cspi->max_freq = clk_get_rate(cspi->clk);

	ret = cspi_add_host(&pdev->dev, cspi);
	if (ret)
		goto out;

	platform_set_drvdata(pdev, cspi);
	return 0;

out:
	clk_disable_unprepare(cspi->clk);
	return ret;
}

static int cspi_remove(struct platform_device *pdev)
{
	struct cspi *cspi = platform_get_drvdata(pdev);

	cspi_remove_host(cspi);
	clk_disable_unprepare(cspi->clk);

	return 0;
}

static const struct of_device_id cspi_of_match[] = {
	{ .compatible = "pensando,capri-spi", },
	{}
};
MODULE_DEVICE_TABLE(of, cspi_of_match);

static struct platform_driver cspi_driver = {
	.probe		= cspi_probe,
	.remove		= cspi_remove,
	.driver		= {
		.name	= "capri-spi",
		.of_match_table = cspi_of_match,
	},
};
module_platform_driver(cspi_driver);

MODULE_DESCRIPTION("Pensando Capri SPI controller driver");
MODULE_LICENSE("GPL v2");
