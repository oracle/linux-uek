/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SPI_OCTEONTX2_H
#define __SPI_OCTEONTX2_H

#include <linux/clk.h>

#define PCI_DEVID_OCTEONTX2_SPI 0xA00B
#define PCI_SUBSYS_DEVID_OTX2_98XX 0xB100
#define PCI_SUBSYS_DEVID_OTX2_96XX 0xB200
#define PCI_SUBSYS_DEVID_OTX2_95XX 0xB300
#define PCI_SUBSYS_DEVID_OTX2_LOKI 0xB400
#define PCI_SUBSYS_DEVID_OTX2_95MM 0xB500

#define OCTEONTX2_SPI_MAX_BYTES 1024
#define OCTEONTX2_SPI_MAX_CLOCK_HZ 25000000

struct octeontx2_spi_regs {
	int config;
	int status;
	int xmit;
	int wbuf;
	int rcvd;
};

struct octeontx2_spi {
	void __iomem *register_base;
	u64 last_cfg;
	u64 cs_enax;
	int sys_freq;
	bool rcvd_present;
	struct octeontx2_spi_regs regs;
	struct clk *clk;
};

#define OCTEONTX2_SPI_CFG(x)	((x)->regs.config)
#define OCTEONTX2_SPI_STS(x)	((x)->regs.status)
#define OCTEONTX2_SPI_XMIT(x)	((x)->regs.xmit)
#define OCTEONTX2_SPI_WBUF(x)	((x)->regs.wbuf)
#define OCTEONTX2_SPI_RCVD(x)	((x)->regs.rcvd)

int octeontx2_spi_transfer_one_message(struct spi_master *master,
				       struct spi_message *msg);


union mpix_cfg {
	uint64_t u64;
	struct mpix_cfg_s {
#ifdef __BIG_ENDIAN_BITFIELD
		uint64_t reserved_50_63:14;
		uint64_t tb100_en:1;
		uint64_t reserved_48:1;
		uint64_t cs_espi_en:4;
		uint64_t reserved_36_43:8;
		uint64_t iomode:2;
		uint64_t reserved_32_33:2;
		uint64_t legacy_dis:1;
		uint64_t reserved_29_30:2;
		uint64_t clkdiv:13;
		uint64_t csena3:1;
		uint64_t csena2:1;
		uint64_t csena1:1;
		uint64_t csena0:1;
		uint64_t cslate:1;
		uint64_t tritx:1;
		uint64_t idleclks:2;
		uint64_t cshi:1;
		uint64_t reserved_6:1;
		uint64_t cs_sticky:1;
		uint64_t lsbfirst:1;
		uint64_t wireor:1;
		uint64_t clk_cont:1;
		uint64_t idlelo:1;
		uint64_t enable:1;
#else
		uint64_t enable:1;
		uint64_t idlelo:1;
		uint64_t clk_cont:1;
		uint64_t wireor:1;
		uint64_t lsbfirst:1;
		uint64_t cs_sticky:1;
		uint64_t reserved_6:1;
		uint64_t cshi:1;
		uint64_t idleclks:2;
		uint64_t tritx:1;
		uint64_t cslate:1;
		uint64_t csena0:1;
		uint64_t csena1:1;
		uint64_t csena2:1;
		uint64_t csena3:1;
		uint64_t clkdiv:13;
		uint64_t reserved_29_30:2;
		uint64_t legacy_dis:1;
		uint64_t reserved_32_33:2;
		uint64_t iomode:2;
		uint64_t reserved_36_43:8;
		uint64_t cs_espi_en:4;
		uint64_t reserved_48:1;
		uint64_t tb100_en:1;
		uint64_t reserved_50_63:14;
#endif
	} s;
};

union mpix_sts {
	uint64_t u64;
	struct mpix_sts_s {
#ifdef __BIG_ENDIAN_BITFIELD
		uint64_t reserved_40_63:24;
		uint64_t crc:8;
		uint64_t reserved_27_31:5;
		uint64_t crc_err:1;
		uint64_t reserved_19_25:7;
		uint64_t rxnum:11;
		uint64_t reserved_2_7:6;
		uint64_t mpi_intr:1;
		uint64_t busy:1;
#else
		uint64_t busy:1;
		uint64_t mpi_intr:1;
		uint64_t reserved_2_7:6;
		uint64_t rxnum:11;
		uint64_t reserved_19_25:7;
		uint64_t crc_err:1;
		uint64_t reserved_27_31:5;
		uint64_t crc:8;
		uint64_t reserved_40_63:24;
#endif
	} s;
};

union mpix_xmit {
	uint64_t u64;
	struct mpix_xmit_s {
#ifdef __BIG_ENDIAN_BITFIELD
		uint64_t reserved_63:1;
		uint64_t csid:2;
		uint64_t leavecs:1;
		uint64_t reserved_31_59:29;
		uint64_t txnum:11;
		uint64_t reserved_11_19:9;
		uint64_t totnum:11;
#else
		uint64_t totnum:11;
		uint64_t reserved_11_19:9;
		uint64_t txnum:11;
		uint64_t reserved_31_59:29;
		uint64_t leavecs:1;
		uint64_t csid:2;
		uint64_t reserved_63:1;
#endif
	} s;
};
#endif /* __SPI_OCTEONTX2_H */
