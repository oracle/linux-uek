// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016 Socionext Inc.
 *   Author: Masahiro Yamada <yamada.masahiro@socionext.com>
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/mmc/host.h>
#include <linux/mmc/mmc.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <soc/marvell/octeontx/octeontx_smc.h>

#include "sdhci-pltfm.h"

#ifdef CONFIG_MMC_SDHCI_CADENCE_DEBUG
#define DEBUG_DRV	pr_info
#endif

#define DRV_CALC_SETTINGS	(1)

#define SDMCLK_MAX_FREQ		200000000

#define SDHCI_CDNS_HRS00			0x00
#define SDHCI_CDNS_HRS00_SWR			BIT(0)

#define SDHCI_CDNS_HRS02			0x08		/* PHY access port */
#define SDHCI_CDNS_HRS04			0x10		/* PHY access port */
/* SD 4.0 Controller HRS - Host Register Set (specific to Cadence) */
#define SDHCI_CDNS_SD4_HRS04_ACK		BIT(26)
#define SDHCI_CDNS_SD4_HRS04_RD			BIT(25)
#define SDHCI_CDNS_SD4_HRS04_WR			BIT(24)
#define SDHCI_CDNS_SD4_HRS04_RDATA		GENMASK(23, 16)
#define SDHCI_CDNS_SD4_HRS04_WDATA		GENMASK(15, 8)
#define SDHCI_CDNS_SD4_HRS04_ADDR		GENMASK(5, 0)

#define SDHCI_CDNS_HRS06			0x18		/* eMMC control */
#define SDHCI_CDNS_HRS06_TUNE_UP		BIT(15)
#define SDHCI_CDNS_HRS06_TUNE			GENMASK(13, 8)
#define SDHCI_CDNS_HRS06_MODE			GENMASK(2, 0)
#define SDHCI_CDNS_HRS06_MODE_SD		0x0
#define SDHCI_CDNS_HRS06_MODE_LEGACY		0x1
#define SDHCI_CDNS_HRS06_MODE_MMC_SDR		0x2
#define SDHCI_CDNS_HRS06_MODE_MMC_DDR		0x3
#define SDHCI_CDNS_HRS06_MODE_MMC_HS200		0x4
#define SDHCI_CDNS_HRS06_MODE_MMC_HS400		0x5
#define SDHCI_CDNS_HRS06_MODE_MMC_HS400ES	0x6

/* SD 6.0 Controller HRS - Host Register Set (Specific to Cadence) */
#define SDHCI_CDNS_SD6_HRS04_ADDR		GENMASK(15, 0)

#define SDHCI_CDNS_HRS05			0x14

#define SDHCI_CDNS_HRS07			0x1C
#define	SDHCI_CDNS_HRS07_RW_COMPENSATE		GENMASK(20, 16)
#define	SDHCI_CDNS_HRS07_IDELAY_VAL		GENMASK(4, 0)

#define SDHCI_CDNS_HRS09			0x24
#define	SDHCI_CDNS_HRS09_RDDATA_EN		BIT(5)
#define	SDHCI_CDNS_HRS09_RDCMD_EN		BIT(4)
#define	SDHCI_CDNS_HRS09_EXTENDED_WR_MODE	BIT(3)
#define	SDHCI_CDNS_HRS09_EXTENDED_RD_MODE	BIT(2)
#define	SDHCI_CDNS_HRS09_PHY_INIT_COMPLETE	BIT(1)
#define	SDHCI_CDNS_HRS09_PHY_SW_RESET		BIT(0)

#define SDHCI_CDNS_HRS10			0x28
#define	SDHCI_CDNS_HRS10_HCSDCLKADJ		GENMASK(19, 16)

#define SDHCI_CDNS_HRS11			0x2c
/*Reset related*/
#define SDHCI_CDNS_SRS11_SW_RESET_ALL (1 << 24)
#define SDHCI_CDNS_SRS11_SW_RESET_CMD (1 << 25)
#define SDHCI_CDNS_SRS11_SW_RESET_DAT (1 << 26)


#define SDHCI_CDNS_HRS16			0x40
#define SDHCI_CDNS_HRS16_WRDATA1_SDCLK_DLY	GENMASK(31, 28)
#define SDHCI_CDNS_HRS16_WRDATA0_SDCLK_DLY	GENMASK(27, 24)
#define SDHCI_CDNS_HRS16_WRCMD1_SDCLK_DLY	GENMASK(23, 20)
#define SDHCI_CDNS_HRS16_WRCMD0_SDCLK_DLY	GENMASK(19, 16)
#define SDHCI_CDNS_HRS16_WRDATA1_DLY		GENMASK(15, 12)
#define SDHCI_CDNS_HRS16_WRDATA0_DLY		GENMASK(11, 8)
#define SDHCI_CDNS_HRS16_WRCMD1_DLY		GENMASK(7, 4)
#define SDHCI_CDNS_HRS16_WRCMD0_DLY		GENMASK(3, 0)


/* PHY registers for SD6 controller */
#define SDHCI_CDNS_SD6_PHY_DQ_TIMING				0x2000
#define	SDHCI_CDNS_SD6_PHY_DQ_TIMING_IO_MASK_ALWAYS_ON		BIT(31)
#define	SDHCI_CDNS_SD6_PHY_DQ_TIMING_IO_MASK_END		GENMASK(29, 27)
#define	SDHCI_CDNS_SD6_PHY_DQ_TIMING_IO_MASK_START		GENMASK(26, 24)
#define	SDHCI_CDNS_SD6_PHY_DQ_TIMING_DATA_SELECT_OE_END		GENMASK(2, 0)

#define SDHCI_CDNS_SD6_PHY_DQS_TIMING				0x2004
#define	SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_EXT_LPBK_DQS		BIT(22)
#define	SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_LPBK_DQS		BIT(21)
#define	SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_PHONY_DQS		BIT(20)
#define	SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_PHONY_DQS_CMD		BIT(19)

#define SDHCI_CDNS_SD6_PHY_GATE_LPBK				0x2008
#define	SDHCI_CDNS_SD6_PHY_GATE_LPBK_SYNC_METHOD		BIT(31)
#define	SDHCI_CDNS_SD6_PHY_GATE_LPBK_SW_HALF_CYCLE_SHIFT	BIT(28)
#define	SDHCI_CDNS_SD6_PHY_GATE_LPBK_RD_DEL_SEL			GENMASK(24, 19)
#define	SDHCI_CDNS_SD6_PHY_GATE_LPBK_GATE_CFG_ALWAYS_ON		BIT(6)

#define SDHCI_CDNS_SD6_PHY_DLL_MASTER				0x200C
#define	SDHCI_CDNS_SD6_PHY_DLL_MASTER_BYPASS_MODE		BIT(23)
#define	SDHCI_CDNS_SD6_PHY_DLL_MASTER_PHASE_DETECT_SEL		GENMASK(22, 20)
#define	SDHCI_CDNS_SD6_PHY_DLL_MASTER_DLL_LOCK_NUM		GENMASK(18, 16)
#define	SDHCI_CDNS_SD6_PHY_DLL_MASTER_DLL_START_POINT		GENMASK(7, 0)

#define SDHCI_CDNS_SD6_PHY_DLL_SLAVE				0x2010
#define	SDHCI_CDNS_SD6_PHY_DLL_SLAVE_READ_DQS_CMD_DELAY		GENMASK(31, 24)
#define	SDHCI_CDNS_SD6_PHY_DLL_SLAVE_CLK_WRDQS_DELAY		GENMASK(23, 16)
#define	SDHCI_CDNS_SD6_PHY_DLL_SLAVE_CLK_WR_DELAY		GENMASK(15, 8)
#define	SDHCI_CDNS_SD6_PHY_DLL_SLAVE_READ_DQS_DELAY		GENMASK(7, 0)

#define SDHCI_CDNS_SD6_PHY_CTRL					0x2080
#define	SDHCI_CDNS_SD6_PHY_CTRL_PHONY_DQS_TIMING		GENMASK(9, 4)

#define SDHCI_CDNS_SD6_PHY_GPIO_CTRL0				0x2088
#define SDHCI_CDNS_SD6_PHY_GPIO_CTRL0_DRV			GENMASK(6, 5)
#define SDHCI_CDNS_SD6_PHY_GPIO_CTRL0_DRV_OVR_EN		BIT(4)
#define SDHCI_CDNS_SD6_PHY_GPIO_CTRL0_SLEW			GENMASK(2, 1)
#define SDHCI_CDNS_SD6_PHY_GPIO_CTRL0_SLEW_OVR_EN		BIT(0)

/* SRS - Slot Register Set (SDHCI-compatible) */
#define SDHCI_CDNS_SRS_BASE		0x200

/* PHY registers for SD4 controller */
#define SDHCI_CDNS_PHY_DLY_SD_HS	0x00
#define SDHCI_CDNS_PHY_DLY_SD_DEFAULT	0x01
#define SDHCI_CDNS_PHY_DLY_UHS_SDR12	0x02
#define SDHCI_CDNS_PHY_DLY_UHS_SDR25	0x03
#define SDHCI_CDNS_PHY_DLY_UHS_SDR50	0x04
#define SDHCI_CDNS_PHY_DLY_UHS_DDR50	0x05
#define SDHCI_CDNS_PHY_DLY_EMMC_LEGACY	0x06
#define SDHCI_CDNS_PHY_DLY_EMMC_SDR	0x07
#define SDHCI_CDNS_PHY_DLY_EMMC_DDR	0x08
#define SDHCI_CDNS_PHY_DLY_SDCLK	0x0b
#define SDHCI_CDNS_PHY_DLY_HSMMC	0x0c
#define SDHCI_CDNS_PHY_DLY_STROBE	0x0d

#define CN10K_MSIX_INTR			0x718

/*
 * The tuned val register is 6 bit-wide, but not the whole of the range is
 * available.  The range 0-42 seems to be available (then 43 wraps around to 0)
 * but I am not quite sure if it is official.  Use only 0 to 39 for safety.
 */
#define SDHCI_CDNS_MAX_TUNING_LOOP	40

static int cn10k_irq_workaround;

struct sdhci_cdns_priv;

struct sdhci_cdns_sd4_phy_param {
	u8 addr;
	u8 data;
};

struct sdhci_cdns_data {
	int (*phy_init)(struct sdhci_cdns_priv *priv);
	int (*set_tune_val)(struct sdhci_host *host, unsigned int val);
};

struct sdhci_cdns_sd4_phy {
	unsigned int nr_phy_params;
	struct sdhci_cdns_sd4_phy_param phy_params[];
};

struct sdhci_cdns_priv {
	void __iomem *hrs_addr;
	bool enhanced_strobe;
	const struct sdhci_cdns_data *cdns_data;
	void *phy;
};

struct sdhci_cdns_sd4_phy_cfg {
	const char *property;
	u8 addr;
};

struct sdhci_cdns_of_data {
	const struct sdhci_pltfm_data *pltfm_data;
	const struct sdhci_cdns_data *cdns_data;
	int (*phy_probe)(struct platform_device *pdev,
			 struct sdhci_cdns_priv *priv);
};

static const struct sdhci_cdns_sd4_phy_cfg sdhci_cdns_sd4_phy_cfgs[] = {
	{ "cdns,phy-input-delay-sd-highspeed", SDHCI_CDNS_PHY_DLY_SD_HS, },
	{ "cdns,phy-input-delay-legacy", SDHCI_CDNS_PHY_DLY_SD_DEFAULT, },
	{ "cdns,phy-input-delay-sd-uhs-sdr12", SDHCI_CDNS_PHY_DLY_UHS_SDR12, },
	{ "cdns,phy-input-delay-sd-uhs-sdr25", SDHCI_CDNS_PHY_DLY_UHS_SDR25, },
	{ "cdns,phy-input-delay-sd-uhs-sdr50", SDHCI_CDNS_PHY_DLY_UHS_SDR50, },
	{ "cdns,phy-input-delay-sd-uhs-ddr50", SDHCI_CDNS_PHY_DLY_UHS_DDR50, },
	{ "cdns,phy-input-delay-mmc-highspeed", SDHCI_CDNS_PHY_DLY_EMMC_SDR, },
	{ "cdns,phy-input-delay-mmc-ddr", SDHCI_CDNS_PHY_DLY_EMMC_DDR, },
	{ "cdns,phy-dll-delay-sdclk", SDHCI_CDNS_PHY_DLY_SDCLK, },
	{ "cdns,phy-dll-delay-sdclk-hsmmc", SDHCI_CDNS_PHY_DLY_HSMMC, },
	{ "cdns,phy-dll-delay-strobe", SDHCI_CDNS_PHY_DLY_STROBE, },
};

enum sdhci_cdns_sd6_phy_lock_mode {
	SDHCI_CDNS_SD6_PHY_LOCK_MODE_FULL_CLK = 0,
	SDHCI_CDNS_SD6_PHY_LOCK_MODE_HALF_CLK = 2,
	SDHCI_CDNS_SD6_PHY_LOCK_MODE_SATURATION = 3,
};

struct sdhci_cdns_sd6_phy_timings {
	u32 t_cmd_output_min;
	u32 t_cmd_output_max;
	u32 t_dat_output_min;
	u32 t_dat_output_max;
	u32 t_cmd_input_min;
	u32 t_cmd_input_max;
	u32 t_dat_input_min;
	u32 t_dat_input_max;
	u32 t_sdclk_min;
	u32 t_sdclk_max;
};

struct sdhci_cdns_sd6_phy_delays {
	u32 phy_sdclk_delay;
	u32 phy_cmd_o_delay;
	u32 phy_dat_o_delay;
	u32 iocell_input_delay;
	u32 iocell_output_delay;
	u32 delay_element_org;
	u32 delay_element;
};

struct sdhci_cdns_sd6_phy_settings {
	/* SDHCI_CDNS_SD6_PHY_DLL_SLAVE */
	u32 cp_read_dqs_cmd_delay;
	u32 cp_read_dqs_delay;
	u32 cp_clk_wr_delay;
	u32 cp_clk_wrdqs_delay;

	/* SDHCI_CDNS_SD6_PHY_DLL_MASTER */
	u32 cp_dll_bypass_mode;
	u32 cp_dll_start_point;

	/* SDHCI_CDNS_SD6_PHY_DLL_OBS_REG0 */
	u32 cp_dll_locked_mode;

	/* SDHCI_CDNS_SD6_PHY_GATE_LPBK */
	u32 cp_gate_cfg_always_on;
	u32 cp_sync_method;
	u32 cp_rd_del_sel;
	u32 cp_sw_half_cycle_shift;
	u32 cp_underrun_suppress;

	/* SDHCI_CDNS_SD6_PHY_DQ_TIMING */
	u32 cp_io_mask_always_on;
	u32 cp_io_mask_end;
	u32 cp_io_mask_start;
	u32 cp_data_select_oe_end;

	/* SDHCI_CDNS_SD6_PHY_DQS_TIMING */
	u32 cp_use_ext_lpbk_dqs;
	u32 cp_use_lpbk_dqs;
	u8 cp_use_phony_dqs;
	u8 cp_use_phony_dqs_cmd;

	/* HRS 09 */
	u8 sdhc_extended_rd_mode;
	u8 sdhc_extended_wr_mode;
	u32 sdhc_rdcmd_en;
	u32 sdhc_rddata_en;

	/* HRS10 */
	u32 sdhc_hcsdclkadj;

	/* HRS 07 */
	u32 sdhc_idelay_val;
	u32 sdhc_rw_compensate;

	/* SRS 11 */
	u32 sdhc_sdcfsh;
	u32 sdhc_sdcfsl;

	/* HRS 16 */
	u32 sdhc_wrcmd0_dly;
	u32 sdhc_wrcmd0_sdclk_dly;
	u32 sdhc_wrcmd1_dly;
	u32 sdhc_wrcmd1_sdclk_dly;
	u32 sdhc_wrdata0_dly;
	u32 sdhc_wrdata0_sdclk_dly;
	u32 sdhc_wrdata1_dly;
	u32 sdhc_wrdata1_sdclk_dly;

	u32 hs200_tune_val;
	u32 drive;
	u32 slew;
};

struct sdhci_cdns_sd6_phy_intermediate_results {
	/* TODO consider to move the following variables to out calculations */
	u32 t_sdmclk_calc;
	u32 dll_max_value;
};

struct sdhci_cdns_sd6_phy {
	struct sdhci_cdns_sd6_phy_timings t;
	struct sdhci_cdns_sd6_phy_delays d;
	u32 t_sdmclk;
	struct sdhci_cdns_sd6_phy_settings settings;
	struct sdhci_cdns_sd6_phy_intermediate_results vars;
	bool ddr;
	bool tune_cmd;
	bool tune_dat;
	bool strobe_cmd;
	bool strobe_dat;
	int mode;
	int t_sdclk;
};

static void init_hs(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 2000, .t_cmd_output_max = t_sdclk - 6000,
		.t_dat_output_min = 2000, .t_dat_output_max = t_sdclk - 6000,
		.t_cmd_input_min = 14000, .t_cmd_input_max = t_sdclk + 2500,
		.t_dat_input_min = 14000, .t_dat_input_max = t_sdclk + 2500,
		.t_sdclk_min = 1000000 / 50, .t_sdclk_max = 1000000 / 0.4
	};
}

static void init_uhs_sdr12(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 800, .t_cmd_output_max = t_sdclk - 3000,
		.t_dat_output_min = 800, .t_dat_output_max = t_sdclk - 3000,
		.t_cmd_input_min = 14000, .t_cmd_input_max = t_sdclk + 1500,
		.t_dat_input_min = 14000, .t_dat_input_max = t_sdclk + 1500,
		.t_sdclk_min = 1000000 / 25, .t_sdclk_max = 1000000 / 0.4
	};
}

static void init_uhs_sdr25(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 800, .t_cmd_output_max = t_sdclk - 3000,
		.t_dat_output_min = 800, .t_dat_output_max = t_sdclk - 3000,
		.t_cmd_input_min = 14000, .t_cmd_input_max = t_sdclk + 1500,
		.t_dat_input_min = 14000, .t_dat_input_max = t_sdclk + 1500,
		.t_sdclk_min = 1000000 / 50, .t_sdclk_max = 1000000 / 0.4
	};
}

static void init_uhs_sdr50(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 800, .t_cmd_output_max = t_sdclk - 3000,
		.t_dat_output_min = 800, .t_dat_output_max = t_sdclk - 3000,
		.t_cmd_input_min = 7500, .t_cmd_input_max = t_sdclk + 1500,
		.t_dat_input_min = 7500, .t_dat_input_max = t_sdclk + 1500,
		.t_sdclk_min = 1000000 / 100, .t_sdclk_max = 1000000 / 0.4
	};
}

static void init_uhs_sdr104(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 800, .t_cmd_output_max = t_sdclk - 1400,
		.t_dat_output_min = 800, .t_dat_output_max = t_sdclk - 1400,
		.t_cmd_input_min = 1000, .t_cmd_input_max = t_sdclk + 1000,
		.t_dat_input_min = 1000, .t_dat_input_max = t_sdclk + 1000,
		.t_sdclk_min = 1000000 / 200, .t_sdclk_max = 1000000 / 100
	};
}

static void init_uhs_ddr50(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 800, .t_cmd_output_max = t_sdclk - 3000,
		.t_dat_output_min = 800, .t_dat_output_max = t_sdclk - 3000,
		.t_cmd_input_min = 13700, .t_cmd_input_max = t_sdclk + 1500,
		.t_dat_input_min = 7000, .t_dat_input_max = t_sdclk + 1500,
		.t_sdclk_min = 1000000 / 50, .t_sdclk_max = 1000000 / 0.4
	};
}

static void init_emmc_legacy(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 3000, .t_cmd_output_max = t_sdclk - 3000,
		.t_dat_output_min = 3000, .t_dat_output_max = t_sdclk - 3000,
		.t_cmd_input_min = 11700, .t_cmd_input_max = t_sdclk + 8300,
		.t_dat_input_min = 11700, .t_dat_input_max = t_sdclk + 8300,
		.t_sdclk_min = 1000000 / 25, .t_sdclk_max = 1000000 / 0.4
	};
}

static void init_emmc_sdr(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 3000, .t_cmd_output_max = t_sdclk - 3000,
		.t_dat_output_min = 3000, .t_dat_output_max = t_sdclk - 3000,
		.t_cmd_input_min = 13700, .t_cmd_input_max = t_sdclk + 2500,
		.t_dat_input_min = 13700, .t_dat_input_max = t_sdclk + 2500,
		.t_sdclk_min = 1000000 / 50, .t_sdclk_max = 1000000 / 0.4
	};
}

static void init_emmc_ddr(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 3000, .t_cmd_output_max = t_sdclk - 3000,
		.t_dat_output_min = 2500, .t_dat_output_max = t_sdclk - 2500,
		.t_cmd_input_min = 13700, .t_cmd_input_max = t_sdclk + 2500,
		.t_dat_input_min = 7000, .t_dat_input_max = t_sdclk + 1500,
		.t_sdclk_min = 1000000 / 50, .t_sdclk_max = 1000000 / 0.4
	};
}

static void init_emmc_hs200(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 800, .t_cmd_output_max = t_sdclk - 1400,
		.t_dat_output_min = 800, .t_dat_output_max = t_sdclk - 1400,
		.t_cmd_input_min = 1000, .t_cmd_input_max = t_sdclk + 1000,
		.t_dat_input_min = 1000, .t_dat_input_max = t_sdclk + 1000,
		.t_sdclk_min = 1000000 / 200, .t_sdclk_max = 1000000 / 100
	};
}

/* HS400 and HS400ES */
static void init_emmc_hs400(struct sdhci_cdns_sd6_phy_timings *t, int t_sdclk)
{
	*t = (struct sdhci_cdns_sd6_phy_timings){
		.t_cmd_output_min = 800, .t_cmd_output_max = t_sdclk - 1400,
		.t_dat_output_min = 400, .t_dat_output_max = t_sdclk - 400,
		.t_cmd_input_min = 1000, .t_cmd_input_max = t_sdclk + 1000,
		.t_dat_input_min = 1000, .t_dat_input_max = t_sdclk + 1000,
		.t_sdclk_min = 1000000 / 200, .t_sdclk_max = 1000000 / 100
	};
}

static void (*(init_timings[]))(struct sdhci_cdns_sd6_phy_timings*, int) = {
	&init_hs, &init_emmc_legacy, &init_emmc_sdr,
	&init_emmc_ddr, &init_emmc_hs200, &init_emmc_hs400,
	&init_uhs_sdr12, &init_uhs_sdr25, &init_uhs_sdr50,
	&init_uhs_sdr104, &init_uhs_ddr50
};

static u32 sdhci_cdns_sd6_get_mode(struct sdhci_host *host, unsigned int timing);

#ifdef CONFIG_MMC_SDHCI_IO_ACCESSORS
static u32 sdhci_cdns_sd6_readl(struct sdhci_host *host, int reg)
{
	return readl(host->ioaddr + reg);
}

static void sdhci_cdns_sd6_writel(struct sdhci_host *host, u32 val, int reg)
{
	writel(val, host->ioaddr + reg);
}

static u16 sdhci_cdns_sd6_readw(struct sdhci_host *host, int reg)
{
	u32 val, regoff;

	regoff = reg & ~3;

	val = readl(host->ioaddr + regoff);
	if ((reg & 0x3) == 0)
		return (val & 0xFFFF);
	else
		return ((val >> 16) & 0xFFFF);
}

static void sdhci_cdns_sd6_writew(struct sdhci_host *host, u16 val, int reg)
{
	writew(val, host->ioaddr + reg);
}

static u8 sdhci_cdns_sd6_readb(struct sdhci_host *host, int reg)
{
	u32 val, regoff;

	regoff = reg & ~3;

	val = readl(host->ioaddr + regoff);
	switch (reg & 3) {
	case 0:
		return (val & 0xFF);
	case 1:
		return ((val >> 8) & 0xFF);
	case 2:
		return ((val >> 16) & 0xFF);
	case 3:
		return ((val >> 24) & 0xFF);
	}
	return 0;
}

static void sdhci_cdns_sd6_writeb(struct sdhci_host *host, u8 val, int reg)
{
	writeb(val, host->ioaddr + reg);
}
#endif

static int sdhci_cdns_sd6_phy_clock_validate(struct sdhci_cdns_sd6_phy *phy)
{
	int status = 0;
	u32 t_sdclk;

	if (phy->t_sdclk < phy->t.t_sdclk_min)
		t_sdclk = phy->t.t_sdclk_min;
	else
		t_sdclk = phy->t_sdclk;

#ifndef DRV_CALC_SETTINGS
	if (t_sdclk < phy->t_sdmclk)
		status = -1;

	if (t_sdclk % phy->t_sdmclk)
		status = -1;

	if ((t_sdclk < phy->t.t_sdclk_min) || (t_sdclk > phy->t.t_sdclk_max))
		status = -1;
#endif

	return status;
}

static int sdhci_cdns_sd6_phy_lock_dll(struct sdhci_cdns_sd6_phy *phy)
{
	u32 delay_element = phy->d.delay_element_org;
	u32 delay_elements_in_sdmclk;
	enum sdhci_cdns_sd6_phy_lock_mode mode;

	delay_elements_in_sdmclk = DIV_ROUND_UP(phy->t_sdmclk, delay_element);
	if (delay_elements_in_sdmclk > 256) {
		delay_element *= 2;
		delay_elements_in_sdmclk = DIV_ROUND_UP(phy->t_sdmclk,
							delay_element);

		if (delay_elements_in_sdmclk > 256)
			return -1;

		mode = SDHCI_CDNS_SD6_PHY_LOCK_MODE_HALF_CLK;
		phy->vars.dll_max_value = 127;
	} else {
		mode = SDHCI_CDNS_SD6_PHY_LOCK_MODE_FULL_CLK;
		phy->vars.dll_max_value = 255;
	}

	phy->vars.t_sdmclk_calc = delay_element * delay_elements_in_sdmclk;
	phy->d.delay_element = delay_element;
	phy->settings.cp_dll_locked_mode = mode;
	phy->settings.cp_dll_bypass_mode = 0;

	return 0;
}

static void sdhci_cdns_sd6_phy_dll_bypass(struct sdhci_cdns_sd6_phy *phy)
{
	phy->vars.dll_max_value = 256;
	phy->settings.cp_dll_bypass_mode = 1;
	phy->settings.cp_dll_locked_mode =
		SDHCI_CDNS_SD6_PHY_LOCK_MODE_SATURATION;
}

static void sdhci_cdns_sd6_phy_configure_dll(struct sdhci_cdns_sd6_phy *phy)
{
	if (phy->settings.sdhc_extended_wr_mode == 0) {
		if (sdhci_cdns_sd6_phy_lock_dll(phy) == 0)
			return;
	}
	sdhci_cdns_sd6_phy_dll_bypass(phy);
}

static void sdhci_cdns_sd6_phy_calc_out(struct sdhci_cdns_sd6_phy *phy,
					bool cmd_not_dat)
{
	u32 wr0_dly = 0, wr1_dly = 0, output_min, output_max, phy_o_delay,
	    clk_wr_delay = 0, wr0_sdclk_dly = 0, wr1_sdclk_dly = 0;
	bool data_ddr = phy->ddr && !cmd_not_dat;
	int t;

	if (cmd_not_dat) {
		output_min = phy->t.t_cmd_output_min;
		output_max = phy->t.t_cmd_output_max;
		phy_o_delay = phy->d.phy_cmd_o_delay;
	} else {
		output_min = phy->t.t_dat_output_min;
		output_max = phy->t.t_dat_output_max;
		phy_o_delay = phy->d.phy_dat_o_delay;
	}

	clk_wr_delay = 0;
	if (data_ddr)
		wr0_sdclk_dly = wr1_sdclk_dly = 1;

	t = phy_o_delay - phy->d.phy_sdclk_delay - output_min;
	if ((t < 0) && (phy->settings.sdhc_extended_wr_mode == 1)) {
		u32 n_half_cycle = DIV_ROUND_UP(-t * 2, phy->t_sdmclk);

		wr0_dly = (n_half_cycle + 1) / 2;
		if (data_ddr)
			wr1_dly = (n_half_cycle + 1) / 2;
		else
			wr1_dly = (n_half_cycle + 1) % 2 + wr0_dly - 1;
	}

	if (phy->settings.sdhc_extended_wr_mode == 0) {
		u32 out_hold, out_setup, out_hold_margin;
		u32 n;

		if (!data_ddr)
			wr0_dly = 1;

		out_setup = output_max;
		out_hold = output_min;
		out_hold_margin = DIV_ROUND_UP(out_setup - out_hold, 4);
		out_hold += out_hold_margin;

		if (phy->settings.cp_dll_bypass_mode == 0)
			n = DIV_ROUND_UP(256 * out_hold, phy->vars.t_sdmclk_calc);
		else
			n = DIV_ROUND_UP(out_hold, phy->d.delay_element) - 1;

		if (n <= phy->vars.dll_max_value)
			clk_wr_delay = n;
		else
			clk_wr_delay = 255;
	} else {
		/*  sdhc_extended_wr_mode = 1 - PHY IO cell work in SDR mode */
		clk_wr_delay = 0;
	}

	if (cmd_not_dat) {
		phy->settings.sdhc_wrcmd0_dly = wr0_dly;
		phy->settings.sdhc_wrcmd1_dly = wr1_dly;
		phy->settings.cp_clk_wrdqs_delay = clk_wr_delay;
		phy->settings.sdhc_wrcmd0_sdclk_dly = wr0_sdclk_dly;
		phy->settings.sdhc_wrcmd1_sdclk_dly = wr1_sdclk_dly;
	} else {
		phy->settings.sdhc_wrdata0_dly = wr0_dly;
		phy->settings.sdhc_wrdata1_dly = wr1_dly;
		phy->settings.cp_clk_wr_delay = clk_wr_delay;
		phy->settings.sdhc_wrdata0_sdclk_dly = wr0_sdclk_dly;
		phy->settings.sdhc_wrdata1_sdclk_dly = wr1_sdclk_dly;
	}
}

static void sdhci_cdns_sd6_phy_calc_cmd_out(struct sdhci_cdns_sd6_phy *phy)
{
	sdhci_cdns_sd6_phy_calc_out(phy, true);
}

static void sdhci_cdns_sd6_phy_calc_cmd_in(struct sdhci_cdns_sd6_phy *phy)
{
	phy->settings.cp_io_mask_end =
		((phy->d.iocell_output_delay + phy->d.iocell_input_delay) * 2)
		/ phy->t_sdmclk;

	if (phy->settings.cp_io_mask_end >= 8)
		phy->settings.cp_io_mask_end = 7;

	if (phy->strobe_cmd && (phy->settings.cp_io_mask_end > 0))
		phy->settings.cp_io_mask_end--;

	if (phy->strobe_cmd) {
		phy->settings.cp_use_phony_dqs_cmd = 0;
		phy->settings.cp_read_dqs_cmd_delay = 64;
	} else {
		phy->settings.cp_use_phony_dqs_cmd = 1;
		phy->settings.cp_read_dqs_cmd_delay = 0;
	}

	if ((phy->mode == MMC_TIMING_MMC_HS400 && !phy->strobe_cmd)
	    || phy->mode == MMC_TIMING_MMC_HS200)
		phy->settings.cp_read_dqs_cmd_delay =
			phy->settings.hs200_tune_val;
}

static void sdhci_cdns_sd6_phy_calc_dat_in(struct sdhci_cdns_sd6_phy *phy)
{
	u32 hcsdclkadj = 0;

	if (phy->strobe_dat) {
		phy->settings.cp_use_phony_dqs = 0;
		phy->settings.cp_read_dqs_delay = 64;
	} else {
		phy->settings.cp_use_phony_dqs = 1;
		phy->settings.cp_read_dqs_delay = 0;
	}

	if (phy->mode == MMC_TIMING_MMC_HS200)
		phy->settings.cp_read_dqs_delay =
			phy->settings.hs200_tune_val;

	if (phy->strobe_dat) {
		/* dqs loopback input via IO cell */
		hcsdclkadj += phy->d.iocell_input_delay;
		/* dfi_dqs_in: mem_dqs -> clean_dqs_mod; delay of hic_dll_dqs_nand2 */
		hcsdclkadj += phy->d.delay_element / 2;
		/* delay line */
		hcsdclkadj += phy->t_sdclk / 2;
		/* PHY FIFO write pointer */
		hcsdclkadj += phy->t_sdclk / 2 + phy->d.delay_element;
		/* 1st synchronizer */
		hcsdclkadj += DIV_ROUND_UP(hcsdclkadj, phy->t_sdmclk)
			* phy->t_sdmclk - hcsdclkadj;
		/*
		 * 2nd synchronizer + PHY FIFO read pointer + PHY rddata
		 * + PHY rddata registered, + FIFO 1st ciu_en
		 */
		hcsdclkadj += 5 * phy->t_sdmclk;
		/* FIFO 2st ciu_en */
		hcsdclkadj += phy->t_sdclk;

		hcsdclkadj /= phy->t_sdclk;
	} else {
		u32 n;

		/* rebar PHY delay */
		hcsdclkadj += 2 * phy->t_sdmclk;
		/* rebar output via IO cell */
		hcsdclkadj += phy->d.iocell_output_delay;
		/* dqs loopback input via IO cell */
		hcsdclkadj += phy->d.iocell_input_delay;
		/* dfi_dqs_in: mem_dqs -> clean_dqs_mod delay of hic_dll_dqs_nand2 */
		hcsdclkadj += phy->d.delay_element / 2;
		/* dll: one delay element between SIGI_0 and SIGO_0 */
		hcsdclkadj += phy->d.delay_element;
		/* dfi_dqs_in: mem_dqs_delayed -> clk_dqs delay of hic_dll_dqs_nand2 */
		hcsdclkadj += phy->d.delay_element / 2;
		/* deskew DLL: clk_dqs -> clk_dqN: one delay element */
		hcsdclkadj += phy->d.delay_element;

		if (phy->t_sdclk == phy->t_sdmclk)
			n = (hcsdclkadj - 2 * phy->t_sdmclk) / phy->t_sdclk;
		else
			n = hcsdclkadj / phy->t_sdclk;

		/* phase shift within one t_sdclk clock cycle caused by rebar - lbk dqs delay */
		hcsdclkadj = hcsdclkadj % phy->t_sdclk;
		/* PHY FIFO write pointer */
		hcsdclkadj += phy->t_sdclk / 2;
		/* 1st synchronizer */
		hcsdclkadj += DIV_ROUND_UP(hcsdclkadj, phy->t_sdmclk)
			* phy->t_sdmclk - hcsdclkadj;
		/*
		 * 2nd synchronizer + PHY FIFO read pointer + PHY rddata
		 * + PHY rddata registered
		 */
		hcsdclkadj += 4 * phy->t_sdmclk;

		if ((phy->t_sdclk / phy->t_sdmclk) > 1) {
			u32 tmp1, tmp2;

			tmp1 = hcsdclkadj;
			tmp2 = (hcsdclkadj / phy->t_sdclk) * phy->t_sdclk
				+ phy->t_sdclk - phy->t_sdmclk;
			if (tmp1 == tmp2)
				tmp2 += phy->t_sdclk;

			/* FIFO aligns to clock cycle before ciu_en */
			hcsdclkadj += tmp2 - tmp1;
		}

		/* FIFO 1st ciu_en */
		hcsdclkadj += phy->t_sdmclk;
		/* FIFO 2nd ciu_en */
		hcsdclkadj += phy->t_sdclk;

		hcsdclkadj /= phy->t_sdclk;

		hcsdclkadj += n;

		if ((phy->t_sdclk / phy->t_sdmclk) >= 2) {
			if ((phy->mode == MMC_TIMING_UHS_DDR50)
			    || (phy->mode == MMC_TIMING_MMC_DDR52))
				hcsdclkadj -= 2;
			else
				hcsdclkadj -= 1;
		} else if ((phy->t_sdclk / phy->t_sdmclk) == 1) {
			hcsdclkadj += 2;
		}

		if (phy->tune_dat)
			hcsdclkadj -= 1;
	}

	if (hcsdclkadj > 15)
		hcsdclkadj = 15;

	phy->settings.sdhc_hcsdclkadj = hcsdclkadj;
}

static void sdhci_cdns_sd6_phy_calc_dat_out(struct sdhci_cdns_sd6_phy *phy)
{
	sdhci_cdns_sd6_phy_calc_out(phy, false);
}

static void sdhci_cdns_sd6_phy_calc_io(struct sdhci_cdns_sd6_phy *phy)
{
	u32 rw_compensate;

	rw_compensate = (phy->d.iocell_input_delay + phy->d.iocell_output_delay)
		/ phy->t_sdmclk + phy->settings.sdhc_wrdata0_dly + 5 + 3;

	phy->settings.sdhc_idelay_val = (2 * phy->d.iocell_input_delay)
		/ phy->t_sdmclk;

	phy->settings.cp_io_mask_start = 0;
	if ((phy->t_sdclk == phy->t_sdmclk) && (rw_compensate > 10))
		phy->settings.cp_io_mask_start = 2 * (rw_compensate - 10);

	if (phy->mode == MMC_TIMING_UHS_SDR104)
		phy->settings.cp_io_mask_start++;

	if ((phy->t_sdclk == phy->t_sdmclk) && (phy->mode == MMC_TIMING_UHS_SDR50))
		phy->settings.cp_io_mask_start++;

	phy->settings.sdhc_rw_compensate = rw_compensate;
}

static void sdhci_cdns_sd6_phy_calc_settings(struct sdhci_cdns_sd6_phy *phy)
{
	sdhci_cdns_sd6_phy_calc_cmd_out(phy);
	sdhci_cdns_sd6_phy_calc_cmd_in(phy);
	sdhci_cdns_sd6_phy_calc_dat_out(phy);
	sdhci_cdns_sd6_phy_calc_dat_in(phy);
	sdhci_cdns_sd6_phy_calc_io(phy);
}

static int sdhci_cdns_sd4_write_phy_reg(struct sdhci_cdns_priv *priv,
					u8 addr, u8 data)
{
	void __iomem *reg = priv->hrs_addr + SDHCI_CDNS_HRS04;
	u32 tmp;
	int ret;

	ret = readl_poll_timeout(reg, tmp, !(tmp & SDHCI_CDNS_SD4_HRS04_ACK),
				 0, 10);
	if (ret)
		return ret;

	tmp = FIELD_PREP(SDHCI_CDNS_SD4_HRS04_WDATA, data) |
	      FIELD_PREP(SDHCI_CDNS_SD4_HRS04_ADDR, addr);
	writel(tmp, reg);

	tmp |= SDHCI_CDNS_SD4_HRS04_WR;
	writel(tmp, reg);

	ret = readl_poll_timeout(reg, tmp, tmp & SDHCI_CDNS_SD4_HRS04_ACK, 0, 10);
	if (ret)
		return ret;

	tmp &= ~SDHCI_CDNS_SD4_HRS04_WR;
	writel(tmp, reg);

	ret = readl_poll_timeout(reg, tmp, !(tmp & SDHCI_CDNS_SD4_HRS04_ACK),
				 0, 10);

	return ret;
}

static unsigned int sdhci_cdns_sd4_phy_param_count(struct device_node *np)
{
	unsigned int count = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(sdhci_cdns_sd4_phy_cfgs); i++)
		if (of_property_read_bool(np, sdhci_cdns_sd4_phy_cfgs[i].property))
			count++;

	return count;
}

static void sdhci_cdns_sd4_phy_param_parse(struct device_node *np,
					   struct sdhci_cdns_sd4_phy *phy)
{
	struct sdhci_cdns_sd4_phy_param *p = phy->phy_params;
	u32 val;
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(sdhci_cdns_sd4_phy_cfgs); i++) {
		ret = of_property_read_u32(np, sdhci_cdns_sd4_phy_cfgs[i].property,
					   &val);
		if (ret)
			continue;

		p->addr = sdhci_cdns_sd4_phy_cfgs[i].addr;
		p->data = val;
		p++;
	}
}

static int sdhci_cdns_sd4_phy_init(struct sdhci_cdns_priv *priv)
{
	int ret, i;
	struct sdhci_cdns_sd4_phy *phy = priv->phy;

	for (i = 0; i < phy->nr_phy_params; i++) {
		ret = sdhci_cdns_sd4_write_phy_reg(priv, phy->phy_params[i].addr,
					       phy->phy_params[i].data);
		if (ret)
			return ret;
	}
	return 0;
}

void sdhci_cdns_sd6_fullsw_reset(struct sdhci_cdns_priv *priv)
{
	u32 regval;

	regval = readl(priv->hrs_addr + SDHCI_CDNS_HRS00);
	regval |= SDHCI_CDNS_HRS00_SWR;
	writel(regval, priv->hrs_addr + SDHCI_CDNS_HRS00);

	do {
		regval = readl(priv->hrs_addr + SDHCI_CDNS_HRS00);
	} while (regval & SDHCI_CDNS_HRS00_SWR);

	pr_debug("Success in reset of eMMC controller 0x%x\n", regval);
}

static u32 sdhci_cdns_sd6_read_phy_reg(struct sdhci_cdns_priv *priv,
				       u32 addr)
{
	writel(FIELD_PREP(SDHCI_CDNS_SD6_HRS04_ADDR, addr),
	       priv->hrs_addr + SDHCI_CDNS_HRS04);
	return readl(priv->hrs_addr + SDHCI_CDNS_HRS05);
}

static void sdhci_cdns_sd6_write_phy_reg(struct sdhci_cdns_priv *priv,
					 u32 addr, u32 data)
{
	u32 data_read;

	writel(FIELD_PREP(SDHCI_CDNS_SD6_HRS04_ADDR, addr),
	       priv->hrs_addr + SDHCI_CDNS_HRS04);
	writel(data, priv->hrs_addr + SDHCI_CDNS_HRS05);

	//TODO remove it
	writel(FIELD_PREP(SDHCI_CDNS_SD6_HRS04_ADDR, addr),
	       priv->hrs_addr + SDHCI_CDNS_HRS04);
	data_read = readl(priv->hrs_addr + SDHCI_CDNS_HRS05);
}


static int sdhci_cdns_sd6_dll_reset(struct sdhci_cdns_priv *priv, bool doReset)
{
	uint32_t reg;
	int ret = 0;

	reg = readl(priv->hrs_addr + SDHCI_CDNS_HRS09);
	if (doReset)
		reg &= ~SDHCI_CDNS_HRS09_PHY_SW_RESET;
	else
		reg |= SDHCI_CDNS_HRS09_PHY_SW_RESET;

	writel(reg, priv->hrs_addr + SDHCI_CDNS_HRS09);

	if (!doReset)
		ret = readl_poll_timeout(priv->hrs_addr + SDHCI_CDNS_HRS09,
					 reg,
					 (reg &
					  SDHCI_CDNS_HRS09_PHY_INIT_COMPLETE),
					 0, 0);

	return ret;
}

static void sdhci_cdns_sd6_calc_phy(struct sdhci_cdns_sd6_phy *phy)
{
	if (phy->mode == MMC_TIMING_MMC_HS) {
		phy->settings.cp_clk_wr_delay = 0;
		phy->settings.cp_clk_wrdqs_delay = 0;
		phy->settings.cp_data_select_oe_end = 1;
		phy->settings.cp_dll_bypass_mode = 1;
		phy->settings.cp_dll_locked_mode = 3;
		phy->settings.cp_dll_start_point = 4;
		phy->settings.cp_gate_cfg_always_on = 1;
		phy->settings.cp_io_mask_always_on = 0;
		phy->settings.cp_io_mask_end = 0;
		phy->settings.cp_io_mask_start = 0;
		phy->settings.cp_rd_del_sel = 52;
		phy->settings.cp_read_dqs_cmd_delay = 0;
		phy->settings.cp_read_dqs_delay = 0;
		phy->settings.cp_sw_half_cycle_shift = 0;
		phy->settings.cp_sync_method = 1;
		phy->settings.cp_underrun_suppress = 1;
		phy->settings.cp_use_ext_lpbk_dqs = 1;
		phy->settings.cp_use_lpbk_dqs = 1;
		phy->settings.cp_use_phony_dqs = 1;
		phy->settings.cp_use_phony_dqs_cmd = 1;
		phy->settings.sdhc_extended_rd_mode = 1;
		phy->settings.sdhc_extended_wr_mode = 1;
		phy->settings.sdhc_hcsdclkadj = 2;
		phy->settings.sdhc_idelay_val = 0;
		phy->settings.sdhc_rdcmd_en = 1;
		phy->settings.sdhc_rddata_en = 1;
		phy->settings.sdhc_rw_compensate = 9;
		phy->settings.sdhc_sdcfsh = 0;
		phy->settings.sdhc_sdcfsl = 4;
		phy->settings.sdhc_wrcmd0_dly = 1;
		phy->settings.sdhc_wrcmd0_sdclk_dly = 0;
		phy->settings.sdhc_wrcmd1_dly = 0;
		phy->settings.sdhc_wrcmd1_sdclk_dly = 0;
		phy->settings.sdhc_wrdata0_dly = 1;
		phy->settings.sdhc_wrdata0_sdclk_dly = 0;
		phy->settings.sdhc_wrdata1_dly = 0;
		phy->settings.sdhc_wrdata1_sdclk_dly = 0;
	}
}

#ifdef CONFIG_MMC_SDHCI_CADENCE_DEBUG
static void sdhci_cdns_sd6_phy_dump(struct sdhci_cdns_sd6_phy *phy)
{
	DEBUG_DRV("PHY Timings\n");
	DEBUG_DRV("mode %d t_sdclk %d\n", phy->mode, phy->t_sdclk);

	DEBUG_DRV("cp_clk_wr_delay %d\n", phy->settings.cp_clk_wr_delay);
	DEBUG_DRV("cp_clk_wrdqs_delay %d\n", phy->settings.cp_clk_wrdqs_delay);
	DEBUG_DRV("cp_data_select_oe_end %d\n", phy->settings.cp_data_select_oe_end);
	DEBUG_DRV("cp_dll_bypass_mode %d\n", phy->settings.cp_dll_bypass_mode);
	DEBUG_DRV("cp_dll_locked_mode %d\n", phy->settings.cp_dll_locked_mode);
	DEBUG_DRV("cp_dll_start_point %d\n", phy->settings.cp_dll_start_point);
	DEBUG_DRV("cp_io_mask_always_on %d\n", phy->settings.cp_io_mask_always_on);
	DEBUG_DRV("cp_io_mask_end %d\n", phy->settings.cp_io_mask_end);
	DEBUG_DRV("cp_io_mask_start %d\n", phy->settings.cp_io_mask_start);
	DEBUG_DRV("cp_rd_del_sel %d\n", phy->settings.cp_rd_del_sel);
	DEBUG_DRV("cp_read_dqs_cmd_delay %d\n", phy->settings.cp_read_dqs_cmd_delay);
	DEBUG_DRV("cp_read_dqs_delay %d\n", phy->settings.cp_read_dqs_delay);
	DEBUG_DRV("cp_sw_half_cycle_shift %d\n", phy->settings.cp_sw_half_cycle_shift);
	DEBUG_DRV("cp_sync_method %d\n", phy->settings.cp_sync_method);
	DEBUG_DRV("cp_use_ext_lpbk_dqs %d\n", phy->settings.cp_use_ext_lpbk_dqs);
	DEBUG_DRV("cp_use_lpbk_dqs %d\n", phy->settings.cp_use_lpbk_dqs);
	DEBUG_DRV("cp_use_phony_dqs %d\n", phy->settings.cp_use_phony_dqs);
	DEBUG_DRV("cp_use_phony_dqs_cmd %d\n", phy->settings.cp_use_phony_dqs_cmd);
	DEBUG_DRV("sdhc_extended_rd_mode %d\n", phy->settings.sdhc_extended_rd_mode);
	DEBUG_DRV("sdhc_extended_wr_mode %d\n", phy->settings.sdhc_extended_wr_mode);

	DEBUG_DRV("sdhc_hcsdclkadj %d\n", phy->settings.sdhc_hcsdclkadj);
	DEBUG_DRV("sdhc_idelay_val %d\n", phy->settings.sdhc_idelay_val);
	DEBUG_DRV("sdhc_rdcmd_en %d\n", phy->settings.sdhc_rdcmd_en);
	DEBUG_DRV("sdhc_rddata_en %d\n", phy->settings.sdhc_rddata_en);
	DEBUG_DRV("sdhc_rw_compensate %d\n", phy->settings.sdhc_rw_compensate);
	DEBUG_DRV("sdhc_sdcfsh %d\n", phy->settings.sdhc_sdcfsh);
	DEBUG_DRV("sdhc_sdcfsl %d\n", phy->settings.sdhc_sdcfsl);
	DEBUG_DRV("sdhc_wrcmd0_dly %d %d\n",
			phy->settings.sdhc_wrcmd0_dly, phy->settings.sdhc_wrcmd0_sdclk_dly);
	DEBUG_DRV("sdhc_wrcmd1_dly %d %d\n",
			phy->settings.sdhc_wrcmd1_dly, phy->settings.sdhc_wrcmd1_sdclk_dly);
	DEBUG_DRV("sdhc_wrdata0_dly %d %d\n",
			phy->settings.sdhc_wrdata0_dly, phy->settings.sdhc_wrdata0_sdclk_dly);

	DEBUG_DRV("sdhc_wrdata1_dly %d %d\n",
			phy->settings.sdhc_wrdata1_dly, phy->settings.sdhc_wrdata1_sdclk_dly);
	DEBUG_DRV("hs200_tune_val %d\n", phy->settings.hs200_tune_val);
}

void sdhci_cdns_sd6_dump(struct sdhci_cdns_priv *priv)
{
	struct sdhci_cdns_sd6_phy *phy = priv->phy;
	int id;

	sdhci_cdns_sd6_phy_dump(phy);

	DEBUG_DRV("Host controller Register Dump\n");
	for (id = 0; id < 14; id++)
		DEBUG_DRV("HRS%d 0x%x\n", id, readl(priv->hrs_addr + (id * 4)));

	id = 29;
	DEBUG_DRV("HRS%d 0x%x\n", id, readl(priv->hrs_addr + (id * 4)));
	id = 30;
	DEBUG_DRV("HRS%d 0x%x\n", id, readl(priv->hrs_addr + (id * 4)));

	for (id = 0; id < 27; id++)
		DEBUG_DRV("SRS%d 0x%x\n", id, readl(priv->hrs_addr + 0x200 + (id * 4)));

	DEBUG_DRV("SDHCI_CDNS_SD6_PHY_DQS_TIMING 0x%x\n",
			sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_DQS_TIMING));
	DEBUG_DRV("SDHCI_CDNS_SD6_PHY_GATE_LPBK 0x%x\n",
			sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_GATE_LPBK));
	DEBUG_DRV("SDHCI_CDNS_SD6_PHY_DLL_MASTER 0x%x\n",
			sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_DLL_MASTER));
	DEBUG_DRV("SDHCI_CDNS_SD6_PHY_DLL_SLAVE 0x%x\n",
			sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_DLL_SLAVE));
	DEBUG_DRV("SDHCI_CDNS_SD6_PHY_CTRL 0x%x\n",
			sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_CTRL));
	DEBUG_DRV("SDHCI_CDNS_SD6_PHY_GPIO_CTRL0 0x%x\n",
			sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_GPIO_CTRL0));
	DEBUG_DRV("SDHCI_CDNS_SD6_PHY_DQ_TIMING 0x%x\n",
			sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_DQ_TIMING));
}
#endif

static int sdhci_cdns_sd6_phy_init(struct sdhci_cdns_priv *priv)
{
	int ret;
	u32 reg;
	struct sdhci_cdns_sd6_phy *phy = priv->phy;

#ifndef DRV_CALC_SETTINGS
	/* Override the values for now till the driver is fixed */
	sdhci_cdns_sd6_calc_phy(phy);
#endif
	sdhci_cdns_sd6_dll_reset(priv, true);

	reg = sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_DQS_TIMING);
	reg &= ~SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_EXT_LPBK_DQS;
	reg &= ~SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_LPBK_DQS;
	reg &= ~SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_PHONY_DQS;
	reg &= ~SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_PHONY_DQS_CMD;
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_EXT_LPBK_DQS,
			phy->settings.cp_use_ext_lpbk_dqs);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_LPBK_DQS,
			phy->settings.cp_use_lpbk_dqs);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_PHONY_DQS,
			  phy->settings.cp_use_phony_dqs);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DQS_TIMING_USE_PHONY_DQS_CMD,
			  phy->settings.cp_use_phony_dqs_cmd);
	sdhci_cdns_sd6_write_phy_reg(priv, SDHCI_CDNS_SD6_PHY_DQS_TIMING, reg);

	reg = sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_GATE_LPBK);
	reg &= ~SDHCI_CDNS_SD6_PHY_GATE_LPBK_SYNC_METHOD;
	reg &= ~SDHCI_CDNS_SD6_PHY_GATE_LPBK_SW_HALF_CYCLE_SHIFT;
	reg &= ~SDHCI_CDNS_SD6_PHY_GATE_LPBK_RD_DEL_SEL;
	reg &= ~SDHCI_CDNS_SD6_PHY_GATE_LPBK_GATE_CFG_ALWAYS_ON;
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_GATE_LPBK_SYNC_METHOD,
			phy->settings.cp_sync_method);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_GATE_LPBK_SW_HALF_CYCLE_SHIFT,
			phy->settings.cp_sw_half_cycle_shift);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_GATE_LPBK_RD_DEL_SEL,
			phy->settings.cp_rd_del_sel);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_GATE_LPBK_GATE_CFG_ALWAYS_ON,
			phy->settings.cp_gate_cfg_always_on);
	sdhci_cdns_sd6_write_phy_reg(priv, SDHCI_CDNS_SD6_PHY_GATE_LPBK, reg);

	reg = 0x0;
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DLL_MASTER_BYPASS_MODE,
			 phy->settings.cp_dll_bypass_mode);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DLL_MASTER_PHASE_DETECT_SEL, 2);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DLL_MASTER_DLL_LOCK_NUM, 0);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DLL_MASTER_DLL_START_POINT,
			phy->settings.cp_dll_start_point);
	sdhci_cdns_sd6_write_phy_reg(priv, SDHCI_CDNS_SD6_PHY_DLL_MASTER, reg);

	reg = 0x0;
	reg = FIELD_PREP(SDHCI_CDNS_SD6_PHY_DLL_SLAVE_READ_DQS_CMD_DELAY,
			 phy->settings.cp_read_dqs_cmd_delay);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DLL_SLAVE_CLK_WRDQS_DELAY,
			  phy->settings.cp_clk_wrdqs_delay);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DLL_SLAVE_CLK_WR_DELAY,
			  phy->settings.cp_clk_wr_delay);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DLL_SLAVE_READ_DQS_DELAY,
			  phy->settings.cp_read_dqs_delay);
	sdhci_cdns_sd6_write_phy_reg(priv, SDHCI_CDNS_SD6_PHY_DLL_SLAVE, reg);

	reg = sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_CTRL);
	reg &= ~SDHCI_CDNS_SD6_PHY_CTRL_PHONY_DQS_TIMING;
	sdhci_cdns_sd6_write_phy_reg(priv, SDHCI_CDNS_SD6_PHY_CTRL, reg);

	reg = sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_GPIO_CTRL0);
	if (phy->settings.drive != 0xFF) {
		reg |= SDHCI_CDNS_SD6_PHY_GPIO_CTRL0_DRV_OVR_EN;
		reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_GPIO_CTRL0_DRV,
			phy->settings.drive);
	}
	if (phy->settings.slew != 0xFF) {
		reg |= SDHCI_CDNS_SD6_PHY_GPIO_CTRL0_SLEW_OVR_EN;
		reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_GPIO_CTRL0_SLEW,
			phy->settings.slew);
	}
	sdhci_cdns_sd6_write_phy_reg(priv, SDHCI_CDNS_SD6_PHY_GPIO_CTRL0, reg);

	ret = sdhci_cdns_sd6_dll_reset(priv, false);
	if (ret)
		return ret;

	reg = sdhci_cdns_sd6_read_phy_reg(priv, SDHCI_CDNS_SD6_PHY_DQ_TIMING);
	reg &= ~SDHCI_CDNS_SD6_PHY_DQ_TIMING_IO_MASK_ALWAYS_ON;
	reg &= ~SDHCI_CDNS_SD6_PHY_DQ_TIMING_IO_MASK_END;
	reg &= ~SDHCI_CDNS_SD6_PHY_DQ_TIMING_IO_MASK_START;
	reg &= ~SDHCI_CDNS_SD6_PHY_DQ_TIMING_DATA_SELECT_OE_END;
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DQ_TIMING_IO_MASK_ALWAYS_ON,
			phy->settings.cp_io_mask_always_on);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DQ_TIMING_IO_MASK_END,
			  phy->settings.cp_io_mask_end);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DQ_TIMING_IO_MASK_START,
			  phy->settings.cp_io_mask_start);
	reg |= FIELD_PREP(SDHCI_CDNS_SD6_PHY_DQ_TIMING_DATA_SELECT_OE_END,
			phy->settings.cp_data_select_oe_end);
	sdhci_cdns_sd6_write_phy_reg(priv, SDHCI_CDNS_SD6_PHY_DQ_TIMING, reg);

	reg = readl(priv->hrs_addr + SDHCI_CDNS_HRS09);
	if (phy->settings.sdhc_extended_wr_mode)
		reg |= SDHCI_CDNS_HRS09_EXTENDED_WR_MODE;
	else
		reg &= ~SDHCI_CDNS_HRS09_EXTENDED_WR_MODE;

	if (phy->settings.sdhc_extended_rd_mode)
		reg |= SDHCI_CDNS_HRS09_EXTENDED_RD_MODE;
	else
		reg &= ~SDHCI_CDNS_HRS09_EXTENDED_RD_MODE;

	if (phy->settings.sdhc_rddata_en)
		reg |= SDHCI_CDNS_HRS09_RDDATA_EN;
	else
		reg &= ~SDHCI_CDNS_HRS09_RDDATA_EN;

	if (phy->settings.sdhc_rdcmd_en)
		reg |= SDHCI_CDNS_HRS09_RDCMD_EN;
	else
		reg &= ~SDHCI_CDNS_HRS09_RDCMD_EN;

	writel(reg, priv->hrs_addr + SDHCI_CDNS_HRS09);

	writel(0x30004, priv->hrs_addr + SDHCI_CDNS_HRS02);

	reg = 0x0;
	reg = FIELD_PREP(SDHCI_CDNS_HRS10_HCSDCLKADJ, phy->settings.sdhc_hcsdclkadj);
	writel(reg, priv->hrs_addr + SDHCI_CDNS_HRS10);

	reg = 0x0;
	reg = FIELD_PREP(SDHCI_CDNS_HRS16_WRDATA1_SDCLK_DLY,
			 phy->settings.sdhc_wrdata1_sdclk_dly);
	reg |= FIELD_PREP(SDHCI_CDNS_HRS16_WRDATA0_SDCLK_DLY,
			 phy->settings.sdhc_wrdata0_sdclk_dly);
	reg |= FIELD_PREP(SDHCI_CDNS_HRS16_WRCMD1_SDCLK_DLY,
			 phy->settings.sdhc_wrcmd1_sdclk_dly);
	reg |= FIELD_PREP(SDHCI_CDNS_HRS16_WRCMD0_SDCLK_DLY,
			 phy->settings.sdhc_wrcmd0_sdclk_dly);
	reg |= FIELD_PREP(SDHCI_CDNS_HRS16_WRDATA1_DLY,
			 phy->settings.sdhc_wrdata1_dly);
	reg |= FIELD_PREP(SDHCI_CDNS_HRS16_WRDATA0_DLY,
			 phy->settings.sdhc_wrdata0_dly);
	reg |= FIELD_PREP(SDHCI_CDNS_HRS16_WRCMD1_DLY,
			 phy->settings.sdhc_wrcmd1_dly);
	reg |= FIELD_PREP(SDHCI_CDNS_HRS16_WRCMD0_DLY,
			 phy->settings.sdhc_wrcmd0_dly);
	writel(reg, priv->hrs_addr + SDHCI_CDNS_HRS16);

	reg = 0x0;
	reg = FIELD_PREP(SDHCI_CDNS_HRS07_RW_COMPENSATE,
			 phy->settings.sdhc_rw_compensate);
	reg |= FIELD_PREP(SDHCI_CDNS_HRS07_IDELAY_VAL,
			 phy->settings.sdhc_idelay_val);
	writel(reg, priv->hrs_addr + SDHCI_CDNS_HRS07);
	return 0;
}

static void *sdhci_cdns_priv(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);

	return sdhci_pltfm_priv(pltfm_host);
}

static int sdhci_cdns_sd6_set_tune_val(struct sdhci_host *host,
				       unsigned int val)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	struct sdhci_cdns_sd6_phy *phy = priv->phy;

	phy->settings.hs200_tune_val = val;
	phy->settings.cp_read_dqs_cmd_delay = val;
	phy->settings.cp_read_dqs_delay = val;

	return sdhci_cdns_sd6_phy_init(priv);
}

static unsigned int sdhci_cdns_get_timeout_clock(struct sdhci_host *host)
{
	/*
	 * Cadence's spec says the Timeout Clock Frequency is the same as the
	 * Base Clock Frequency.
	 */
	return host->max_clk;
}

static unsigned int sdhci_cdns_get_max_clock(struct sdhci_host *host)
{
	return SDMCLK_MAX_FREQ;
}

static void sdhci_cdns_set_emmc_mode(struct sdhci_cdns_priv *priv, u32 mode)
{
	u32 tmp;

	/* The speed mode for eMMC is selected by HRS06 register */
	tmp = readl(priv->hrs_addr + SDHCI_CDNS_HRS06);
	tmp &= ~SDHCI_CDNS_HRS06_MODE;
	tmp |= FIELD_PREP(SDHCI_CDNS_HRS06_MODE, mode);
	writel(tmp, priv->hrs_addr + SDHCI_CDNS_HRS06);
}

static u32 sdhci_cdns_get_emmc_mode(struct sdhci_cdns_priv *priv)
{
	u32 tmp;

	tmp = readl(priv->hrs_addr + SDHCI_CDNS_HRS06);
	return FIELD_GET(SDHCI_CDNS_HRS06_MODE, tmp);
}

static void sdhci_cdns_set_uhs_signaling(struct sdhci_host *host,
					 unsigned int timing)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	u32 mode;

	switch (timing) {
	case MMC_TIMING_MMC_HS:
		mode = SDHCI_CDNS_HRS06_MODE_MMC_SDR;
		break;
	case MMC_TIMING_MMC_DDR52:
		mode = SDHCI_CDNS_HRS06_MODE_MMC_DDR;
		break;
	case MMC_TIMING_MMC_HS200:
		mode = SDHCI_CDNS_HRS06_MODE_MMC_HS200;
		break;
	case MMC_TIMING_MMC_HS400:
		if (priv->enhanced_strobe)
			mode = SDHCI_CDNS_HRS06_MODE_MMC_HS400ES;
		else
			mode = SDHCI_CDNS_HRS06_MODE_MMC_HS400;
		break;
	case MMC_TIMING_SD_HS:
		mode = SDHCI_CDNS_HRS06_MODE_SD;
		break;
	default:
		mode = SDHCI_CDNS_HRS06_MODE_LEGACY;
		break;
	}

	pr_debug("%s mode %d timing %d\n", __func__, mode, timing);
	sdhci_cdns_set_emmc_mode(priv, mode);

	/* For SD, fall back to the default handler */
	if (mode == SDHCI_CDNS_HRS06_MODE_SD)
		sdhci_set_uhs_signaling(host, timing);
}

static int sdhci_cdns_sd6_phy_update_timings(struct sdhci_host *host)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	struct sdhci_cdns_sd6_phy *phy = priv->phy;
	int t_sdmclk = phy->t_sdmclk;
	int mode;

	mode = sdhci_cdns_sd6_get_mode(host, host->mmc->ios.timing);
	/* initialize input */
	init_timings[mode](&phy->t, phy->t_sdclk);

	phy->mode = host->mmc->ios.timing;
	phy->strobe_dat = false;

	switch (phy->mode) {
	case MMC_TIMING_UHS_SDR104:
		phy->tune_cmd = true;
		phy->tune_dat = true;
		break;
	case MMC_TIMING_UHS_DDR50:
		phy->ddr = true;
		break;
	case MMC_TIMING_MMC_DDR52:
		phy->ddr = true;
		break;
	case MMC_TIMING_MMC_HS200:
		phy->tune_dat = true;
		phy->tune_cmd = true;
		break;
	case MMC_TIMING_MMC_HS400:
		phy->tune_cmd = true;
		phy->ddr = true;
		phy->strobe_dat = true;
		break;
	}

	if (priv->enhanced_strobe)
		phy->strobe_cmd = true;

	phy->d.phy_sdclk_delay = 2 * t_sdmclk;
	phy->d.phy_cmd_o_delay = 2 * t_sdmclk + t_sdmclk / 2;
	phy->d.phy_dat_o_delay = 2 * t_sdmclk + t_sdmclk / 2;

	if (sdhci_cdns_sd6_phy_clock_validate(phy))
		return -1;

	if (phy->t_sdclk == phy->t_sdmclk) {
		phy->settings.sdhc_extended_wr_mode = 0;
		phy->settings.sdhc_extended_rd_mode = 0;
	} else {
		phy->settings.sdhc_extended_wr_mode = 1;
		phy->settings.sdhc_extended_rd_mode = 1;
	}

	phy->settings.cp_gate_cfg_always_on = 1;
	//phy->settings.sdhc_rdcmd_en = 1;
	//phy->settings.sdhc_rddata_en = 1;

	sdhci_cdns_sd6_phy_configure_dll(phy);

	sdhci_cdns_sd6_phy_calc_settings(phy);

	return 0;
}

static u32 sdhci_cdns_sd6_get_mode(struct sdhci_host *host,
				unsigned int timing)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	u32 mode;

	switch (timing) {
	case MMC_TIMING_MMC_HS:
		mode = SDHCI_CDNS_HRS06_MODE_MMC_SDR;
		break;
	case MMC_TIMING_MMC_DDR52:
		mode = SDHCI_CDNS_HRS06_MODE_MMC_DDR;
		break;
	case MMC_TIMING_MMC_HS200:
		mode = SDHCI_CDNS_HRS06_MODE_MMC_HS200;
		break;
	case MMC_TIMING_MMC_HS400:
		if (priv->enhanced_strobe)
			mode = SDHCI_CDNS_HRS06_MODE_MMC_HS400ES;
		else
			mode = SDHCI_CDNS_HRS06_MODE_MMC_HS400;
		break;
	case MMC_TIMING_SD_HS:
		mode = SDHCI_CDNS_HRS06_MODE_SD;
		break;
	default:
		mode = SDHCI_CDNS_HRS06_MODE_MMC_SDR;
		break;
	}

	return mode;
}

static uint32_t sdhci_cdns_sd6_irq(struct sdhci_host *host, u32 intmask)
{
	struct sdhci_cdns_priv *priv;
	uint64_t reg1, reg;

	/* If errata workaround is not required, return */
	if (!cn10k_irq_workaround)
		return intmask;

	priv = sdhci_cdns_priv(host);
	reg = readq(priv->hrs_addr + CN10K_MSIX_INTR);

	if (intmask)
		sdhci_cdns_sd6_writel(host, intmask, SDHCI_INT_STATUS);

	writeq(reg, priv->hrs_addr + CN10K_MSIX_INTR);
	reg1 = readq(priv->hrs_addr + CN10K_MSIX_INTR);

	return intmask;
}

static void sdhci_cdns_sd6_set_uhs_signaling(struct sdhci_host *host,
					     unsigned int timing)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	struct sdhci_cdns_sd6_phy *phy = priv->phy;

	sdhci_cdns_set_uhs_signaling(host, timing);

	if ((phy->mode == -1) || (phy->t_sdclk == -1))
		return;

	if (sdhci_cdns_sd6_phy_update_timings(host))
		pr_debug("%s: update timings failed\n", __func__);

	if (sdhci_cdns_sd6_phy_init(priv))
		pr_debug("%s: phy init failed\n", __func__);
}

static void sdhci_cdns_sd6_set_clock(struct sdhci_host *host,
				     unsigned int clock)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	struct sdhci_cdns_sd6_phy *phy = priv->phy;

#ifdef DRV_CALC_SETTINGS
	phy->t_sdclk = DIV_ROUND_DOWN_ULL(1e12, clock);
#endif

	pr_debug("%s %d %d\n", __func__, phy->mode, clock);

	if (sdhci_cdns_sd6_phy_update_timings(host))
		pr_debug("%s: update timings failed\n", __func__);

	if (sdhci_cdns_sd6_phy_init(priv))
		pr_debug("%s: phy init failed\n", __func__);

	sdhci_set_clock(host, clock);

#ifdef CONFIG_MMC_SDHCI_CADENCE_DEBUG
	sdhci_cdns_sd6_dump(priv);
#endif
}

static int sdhci_cdns_sd4_phy_probe(struct platform_device *pdev,
				    struct sdhci_cdns_priv *priv)
{
	unsigned int nr_phy_params;
	struct sdhci_cdns_sd4_phy *phy;
	struct device *dev = &pdev->dev;

	nr_phy_params = sdhci_cdns_sd4_phy_param_count(dev->of_node);
	phy = devm_kzalloc(dev, struct_size(phy, phy_params, nr_phy_params),
			   GFP_KERNEL);
	if (!phy)
		return -ENOMEM;

	phy->nr_phy_params = nr_phy_params;

	sdhci_cdns_sd4_phy_param_parse(dev->of_node, phy);
	priv->phy = phy;

	return 0;
}

static int sdhci_cdns_sd6_phy_probe(struct platform_device *pdev,
				    struct sdhci_cdns_priv *priv)
{
	struct device *dev = &pdev->dev;
	struct sdhci_cdns_sd6_phy *phy;
#ifdef DRV_CALC_SETTINGS
	u32 val;
	struct clk *clk;
#endif
	int ret;
	const char *mode_name;

	phy = devm_kzalloc(dev, sizeof(*phy), GFP_KERNEL);
	if (!phy)
		return -ENOMEM;

	clk = devm_clk_get(dev, "sdmclk");
	if (IS_ERR(clk)) {
		dev_err(dev, "sdmclk get error\n");
		return PTR_ERR(clk);
	}

	val = clk_get_rate(clk);
	phy->t_sdmclk = DIV_ROUND_DOWN_ULL(1e12, val);

	ret = of_property_read_u32(dev->of_node, "cdns,host_slew",
				   &phy->settings.slew);
	if (ret)
		phy->settings.slew = 0xFF;

	ret = of_property_read_u32(dev->of_node, "cdns,host_drive",
				   &phy->settings.drive);
	if (ret)
		phy->settings.drive = 0xFF;

	ret = of_property_read_u32(dev->of_node, "cdns,iocell_input_delay",
				   &phy->d.iocell_input_delay);
	if (ret)
		phy->d.iocell_input_delay = 2500;

	ret = of_property_read_u32(dev->of_node, "cdns,iocell_output_delay",
				   &phy->d.iocell_output_delay);
	if (ret)
		phy->d.iocell_output_delay = 2500;

	ret = of_property_read_u32(dev->of_node, "cdns,delay_element",
				   &phy->d.delay_element);
	if (ret)
		phy->d.delay_element = 24;

	ret = of_property_read_string_index(dev->of_node, "cdns,mode", 0,
					&mode_name);
	if (!ret) {
		if (!strcmp("emmc_sdr", mode_name))
			phy->mode = MMC_TIMING_MMC_HS;
		else if (!strcmp("emmc_ddr", mode_name))
			phy->mode = MMC_TIMING_MMC_DDR52;
		else if (!strcmp("emmc_hs200", mode_name))
			phy->mode = MMC_TIMING_MMC_HS200;
		else if (!strcmp("emmc_hs400", mode_name))
			phy->mode = MMC_TIMING_MMC_HS400;
		else if (!strcmp("sd_hs", mode_name))
			phy->mode = MMC_TIMING_SD_HS;
		else
			phy->mode = MMC_TIMING_MMC_HS;
	} else
		phy->mode = MMC_TIMING_MMC_HS;

	/* Override dts entry for now */
	phy->d.delay_element_org = phy->d.delay_element = 24;
	phy->d.iocell_input_delay = 650;
	phy->d.iocell_output_delay = 1800;

	switch (phy->mode) {
	case MMC_TIMING_MMC_HS:
		phy->t_sdclk =  10000;
		break;
	case MMC_TIMING_MMC_DDR52:
		phy->t_sdclk = 10000;
		break;
	case MMC_TIMING_MMC_HS200:
		phy->t_sdclk = 5000;
		break;
	case MMC_TIMING_MMC_HS400:
		phy->t_sdclk = 5000;
		break;
	case MMC_TIMING_SD_HS:
		phy->t_sdclk = 100000;
		break;
	default:
		phy->t_sdclk = 10000;
		break;
	}

	priv->phy = phy;

	sdhci_cdns_sd6_calc_phy(phy);
	return 0;
}

static int sdhci_cdns_sd4_set_tune_val(struct sdhci_host *host, unsigned int val)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	void __iomem *reg = priv->hrs_addr + SDHCI_CDNS_HRS06;
	u32 tmp;
	int i, ret;

	if (WARN_ON(!FIELD_FIT(SDHCI_CDNS_HRS06_TUNE, val)))
		return -EINVAL;

	tmp = readl(reg);
	tmp &= ~SDHCI_CDNS_HRS06_TUNE;
	tmp |= FIELD_PREP(SDHCI_CDNS_HRS06_TUNE, val);

	/*
	 * Workaround for IP errata:
	 * The IP6116 SD/eMMC PHY design has a timing issue on receive data
	 * path. Send tune request twice.
	 */
	for (i = 0; i < 2; i++) {
		tmp |= SDHCI_CDNS_HRS06_TUNE_UP;
		writel(tmp, reg);

		ret = readl_poll_timeout(reg, tmp,
					 !(tmp & SDHCI_CDNS_HRS06_TUNE_UP),
					 0, 1);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * In SD mode, software must not use the hardware tuning and instead perform
 * an almost identical procedure to eMMC.
 */
static int sdhci_cdns_execute_tuning(struct sdhci_host *host, u32 opcode)
{
//	struct sdhci_host *host = mmc_priv(mmc);
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	int cur_streak = 0;
	int max_streak = 0;
	int end_of_streak = 0;
	int i;

	/*
	 * Do not execute tuning for UHS_SDR50 or UHS_DDR50.
	 * The delay is set by probe, based on the DT properties.
	 */
	if (host->timing != MMC_TIMING_MMC_HS200 &&
	    host->timing != MMC_TIMING_UHS_SDR104)
		return 0;

	for (i = 0; i < SDHCI_CDNS_MAX_TUNING_LOOP; i++) {
		if (priv->cdns_data->set_tune_val(host, i) ||
		    mmc_send_tuning(host->mmc, opcode, NULL)) { /* bad */
			cur_streak = 0;
		} else { /* good */
			cur_streak++;
			if (cur_streak > max_streak) {
				max_streak = cur_streak;
				end_of_streak = i;
			}
		}
	}

	if (!max_streak) {
		dev_err(mmc_dev(host->mmc), "no tuning point found\n");
		return -EIO;
	}

	return priv->cdns_data->set_tune_val(host, end_of_streak - max_streak / 2);
}

static const struct sdhci_ops sdhci_cdns_sd4_ops = {
	.set_clock = sdhci_set_clock,
	.get_timeout_clock = sdhci_cdns_get_timeout_clock,
	.set_bus_width = sdhci_set_bus_width,
	.reset = sdhci_reset,
	//.platform_execute_tuning = sdhci_cdns_execute_tuning,
	.set_uhs_signaling = sdhci_cdns_set_uhs_signaling,
};

static const struct sdhci_ops sdhci_cdns_sd6_ops = {
#ifdef CONFIG_MMC_SDHCI_IO_ACCESSORS
	.read_l = sdhci_cdns_sd6_readl,
	.write_l = sdhci_cdns_sd6_writel,
	.read_w = sdhci_cdns_sd6_readw,
	.write_w = sdhci_cdns_sd6_writew,
	.read_b = sdhci_cdns_sd6_readb,
	.write_b = sdhci_cdns_sd6_writeb,
#endif
	.get_max_clock = sdhci_cdns_get_max_clock,
	.set_clock = sdhci_cdns_sd6_set_clock,
	.get_timeout_clock = sdhci_cdns_get_timeout_clock,
	.set_bus_width = sdhci_set_bus_width,
	.reset = sdhci_reset,
	.platform_execute_tuning = sdhci_cdns_execute_tuning,
	.set_uhs_signaling = sdhci_cdns_sd6_set_uhs_signaling,
	.irq = sdhci_cdns_sd6_irq,
};
static const struct sdhci_pltfm_data sdhci_cdns_uniphier_pltfm_data = {
	.ops = &sdhci_cdns_sd4_ops,
	.quirks2 = SDHCI_QUIRK2_PRESET_VALUE_BROKEN,
};

static const struct sdhci_pltfm_data sdhci_cdns_sd4_pltfm_data = {
	.ops = &sdhci_cdns_sd4_ops,
};

static const struct sdhci_pltfm_data sdhci_cdns_sd6_pltfm_data = {
	.ops = &sdhci_cdns_sd6_ops,
};

static const struct sdhci_cdns_data sdhci_cdns_sd4_data = {
	.phy_init = sdhci_cdns_sd4_phy_init,
	.set_tune_val = sdhci_cdns_sd4_set_tune_val,
};

static const struct sdhci_cdns_data sdhci_cdns_sd6_data = {
	.phy_init = sdhci_cdns_sd6_phy_init,
	.set_tune_val = sdhci_cdns_sd6_set_tune_val,
};

static const struct sdhci_cdns_of_data sdhci_cdns_sd4_of_data = {
	.pltfm_data = &sdhci_cdns_sd4_pltfm_data,
	.cdns_data = &sdhci_cdns_sd4_data,
	.phy_probe = sdhci_cdns_sd4_phy_probe,
};

static const struct sdhci_cdns_of_data sdhci_cdns_sd6_of_data = {
	.pltfm_data = &sdhci_cdns_sd6_pltfm_data,
	.cdns_data = &sdhci_cdns_sd6_data,
	.phy_probe = sdhci_cdns_sd6_phy_probe,
};


static void sdhci_cdns_hs400_enhanced_strobe(struct mmc_host *mmc,
					     struct mmc_ios *ios)
{
	struct sdhci_host *host = mmc_priv(mmc);
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	u32 mode;

	priv->enhanced_strobe = ios->enhanced_strobe;

	mode = sdhci_cdns_get_emmc_mode(priv);

	if (mode == SDHCI_CDNS_HRS06_MODE_MMC_HS400 && ios->enhanced_strobe)
		sdhci_cdns_set_emmc_mode(priv,
					 SDHCI_CDNS_HRS06_MODE_MMC_HS400ES);

	if (mode == SDHCI_CDNS_HRS06_MODE_MMC_HS400ES && !ios->enhanced_strobe)
		sdhci_cdns_set_emmc_mode(priv,
					 SDHCI_CDNS_HRS06_MODE_MMC_HS400);
}

static int sdhci_cdns_probe(struct platform_device *pdev)
{
	struct sdhci_host *host;
	const struct sdhci_cdns_of_data *data;
	struct sdhci_pltfm_host *pltfm_host;
	struct sdhci_cdns_priv *priv;
	struct clk *clk;
	int ret;
	struct device *dev = &pdev->dev;

	clk = devm_clk_get(dev, NULL);
	if (IS_ERR(clk))
		return PTR_ERR(clk);

	ret = clk_prepare_enable(clk);
	if (ret)
		return ret;

	data = of_device_get_match_data(dev);
	if (!data) {
		return PTR_ERR(clk);
		goto disable_clk;
	}

	host = sdhci_pltfm_init(pdev, data->pltfm_data, sizeof(*priv));
	if (IS_ERR(host)) {
		ret = PTR_ERR(host);
		goto disable_clk;
	}

	pltfm_host = sdhci_priv(host);
	pltfm_host->clk = clk;

	host->clk_mul = 0;
	host->max_clk = SDMCLK_MAX_FREQ;
	host->quirks |=  SDHCI_QUIRK_CAP_CLOCK_BASE_BROKEN;
	host->quirks2 |= SDHCI_QUIRK2_PRESET_VALUE_BROKEN;
	priv = sdhci_pltfm_priv(pltfm_host);
	priv->hrs_addr = host->ioaddr;
	priv->enhanced_strobe = false;
	priv->cdns_data = data->cdns_data;
	host->ioaddr += SDHCI_CDNS_SRS_BASE;
	host->mmc_host_ops.hs400_enhanced_strobe =
				sdhci_cdns_hs400_enhanced_strobe;

	if (is_soc_cn10ka_ax() || is_soc_cnf10ka_ax())
		cn10k_irq_workaround = 1;

	sdhci_get_of_property(pdev);

	ret = mmc_of_parse(host->mmc);
	if (ret)
		goto free;

	ret = data->phy_probe(pdev, priv);
	if (ret)
		goto free;

	ret = priv->cdns_data->phy_init(priv);
	if (ret)
		goto free;

	sdhci_enable_v4_mode(host);
	ret = sdhci_add_host(host);
	if (ret)
		goto free;

	return 0;
free:
	sdhci_pltfm_free(pdev);
disable_clk:
	clk_disable_unprepare(clk);

	return ret;
}

#ifdef CONFIG_PM_SLEEP
static int sdhci_cdns_resume(struct device *dev)
{
	struct sdhci_host *host = dev_get_drvdata(dev);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_cdns_priv *priv = sdhci_pltfm_priv(pltfm_host);
	int ret;

	ret = clk_prepare_enable(pltfm_host->clk);
	if (ret)
		return ret;

	ret = priv->cdns_data->phy_init(priv);
	if (ret)
		goto disable_clk;

	ret = sdhci_resume_host(host);
	if (ret)
		goto disable_clk;

	return 0;

disable_clk:
	clk_disable_unprepare(pltfm_host->clk);

	return ret;
}
#endif

static const struct dev_pm_ops sdhci_cdns_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(sdhci_pltfm_suspend, sdhci_cdns_resume)
};

static const struct of_device_id sdhci_cdns_match[] = {
	{
		.compatible = "socionext,uniphier-sd4hc",
		.data = &sdhci_cdns_uniphier_pltfm_data,
	},
	{
		.compatible = "cdns,sd4hc",
		.data = &sdhci_cdns_sd4_of_data,
	},
	{
		.compatible = "cdns,sd6hc",
		.data = &sdhci_cdns_sd6_of_data,
	},
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, sdhci_cdns_match);

static struct platform_driver sdhci_cdns_driver = {
	.driver = {
		.name = "sdhci-cdns",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
		.pm = &sdhci_cdns_pm_ops,
		.of_match_table = sdhci_cdns_match,
	},
	.probe = sdhci_cdns_probe,
	.remove = sdhci_pltfm_unregister,
};
module_platform_driver(sdhci_cdns_driver);

MODULE_AUTHOR("Masahiro Yamada <yamada.masahiro@socionext.com>");
MODULE_DESCRIPTION("Cadence SD/SDIO/eMMC Host Controller Driver");
MODULE_LICENSE("GPL");
