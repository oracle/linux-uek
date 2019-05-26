/*
 *    Based on code from Cortina Systems, Inc.
 *
 *    Copyright (C) 2011 by Cortina Systems, Inc.
 *    Copyright (C) 2011 - 2012 Cavium, Inc.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/phy.h>
#include <linux/of.h>

#define CS4321_API_VERSION_MAJOR       3
#define CS4321_API_VERSION_MINOR       0
#define CS4321_API_VERSION_UPDATE      113

enum cs4321_host_mode {
	RXAUI,
	XAUI,
	SGMII
};

struct cs4321_private {
	enum cs4321_host_mode mode;
};

struct cs4321_reg_modify {
	u16 reg;
	u16 mask_bits;
	u16 set_bits;
};

struct cs4321_multi_seq {
	int reg_offset;
	const struct cs4321_reg_modify *seq;
};

#include "cs4321-regs.h"
#include "cs4321-ucode.h"

static const struct cs4321_reg_modify cs4321_soft_reset_registers[] = {
	/* Enable all the clocks */
	{CS4321_GLOBAL_INGRESS_CLKEN, 0, 0xffff},
	{CS4321_GLOBAL_INGRESS_CLKEN2, 0, 0xffff},
	{CS4321_GLOBAL_EGRESS_CLKEN, 0, 0xffff},
	{CS4321_GLOBAL_EGRESS_CLKEN2, 0, 0xffff},
	/* Reset MPIF registers */
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, 0, 0x0},
	/* Re-assert the reset */
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, 0, 0xffff},

	/* Disable all the clocks */
	{CS4321_GLOBAL_INGRESS_CLKEN, 0, 0x0},
	{CS4321_GLOBAL_INGRESS_CLKEN2, 0, 0x0},
	{CS4321_GLOBAL_EGRESS_CLKEN, 0, 0x0},
	{CS4321_GLOBAL_EGRESS_CLKEN2, 0, 0x0},
	{0}
};

static const struct cs4321_reg_modify cs4321_68xx_4_nic_init[] = {
	/* Configure chip for common reference clock */
	{CS4321_LINE_SDS_COMMON_STXP0_TX_CONFIG, 0, 0x2700},
	/* Set GPIO3 to drive low to enable laser output*/
	{CS4321_GPIO_GPIO3, 0, 0x11},

	{0}
};

#define CS4321_API_VERSION_VALUE			\
	(((CS4321_API_VERSION_MAJOR & 0xF) << 12) |	\
	((CS4321_API_VERSION_MINOR & 0xF) << 8)  |	\
	(CS4321_API_VERSION_UPDATE))

static const struct cs4321_reg_modify cs4321_init_prefix_seq[] = {
	/* MPIF DeAssert System Reset */
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, ~0x0001, 0},
	{CS4321_GLOBAL_SCRATCH7, 0, CS4321_API_VERSION_VALUE},
	/*
	 * Make sure to stall the microsequencer before configuring
	 * the path.
	 */
	{CS4321_GLOBAL_MSEQCLKCTRL, 0, 0x8004},
	{CS4321_MSEQ_OPTIONS, 0, 0xf},
	{CS4321_MSEQ_PC, 0, 0x0},
	/*
	 * Correct some of the h/w defaults that are incorrect.
	 *
	 * The default value of the bias current is incorrect and needs to
	 * be corrected. This is normally done by Microcode but it doesn't
	 * always run.
	 */
	{CS4321_DSP_SDS_SERDES_SRX_DAC_BIAS_SELECT0_MSB, 0, 0x20},
	/*
	 * By default need to power on the voltage monitor since it is required
	 * by the temperature monitor and this is used by the microcode.
	 */
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CONFIG, 0, 0x0},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_ingress_local_timing_rxaui[] = {
	{CS4321_HOST_SDS_COMMON_STX0_TX_CONFIG_LOCAL_TIMING, 0, 0x0001},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_CLKDIV_CTRL, 0, 0x4091},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_CLKOUT_CTRL, 0, 0x1864},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_CONFIG, 0, 0x090c},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_PWRDN, 0, 0x0000},
	{CS4321_HOST_ML_SDS_COMMON_STXP0_TX_CLKDIV_CTRL, 0, 0x4019},
	{CS4321_HOST_ML_SDS_COMMON_STXP0_TX_CONFIG, 0, 0x090c},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, ~0x2, 0x0002},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, ~0x2, 0x0000},

	{CS4321_LINE_SDS_COMMON_SRX0_RX_CONFIG, 0, 0x0000},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CPA, 0, 0x0057},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_LOOP_FILTER, 0, 0x0007},

	{CS4321_GLOBAL_INGRESS_SOFT_RESET, ~0x1, 0x0001},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, ~0x1, 0x0000},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_local_host_timing_mux_demux[] = {
	/* DMUXPD on, MUXPD on, EYEMODE off */
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CONFIG, ~0x1300, 0},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_local_timing_rxaui[] = {
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CLKDIV_CTRL, 0, 0x40d1},
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CONFIG, 0, 0x000c},
	{CS4321_HOST_ML_SDS_COMMON_SRX0_RX_CLKDIV_CTRL, 0, 0x401d},
	{CS4321_HOST_ML_SDS_COMMON_SRX0_RX_CONFIG, 0, 0x000c},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, ~0x1, 0x0001},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, ~0x1, 0x0000},
	{CS4321_HOST_SDS_COMMON_STX0_TX_CONFIG_LOCAL_TIMING, 0, 0x0001},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_CLKOUT_CTRL, 0, 0x0864},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_LOOP_FILTER, 0, 0x0027},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_PWRDN, 0, 0x0000},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, ~0x2, 0x0002},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_line_power_down[] = {
	{CS4321_LINE_SDS_COMMON_STX0_TX_OUTPUT_CTRLA, 0, 0x0000},
	{CS4321_LINE_SDS_COMMON_STX0_TX_OUTPUT_CTRLB, 0, 0x0000},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CONFIG, 0, 0x2040},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_VCO_CTRL, 0, 0x01e7},
	{CS4321_MSEQ_POWER_DOWN_LSB, 0, 0x0000},
	{CS4321_DSP_SDS_SERDES_SRX_DAC_ENABLEB_MSB, 0, 0xffff},
	{CS4321_DSP_SDS_SERDES_SRX_DAC_ENABLEB_LSB, 0, 0xffff},
	{CS4321_DSP_SDS_SERDES_SRX_AGC_MISC, 0, 0x0705},
	{CS4321_DSP_SDS_SERDES_SRX_DFE_MISC, 0, 0x002b},
	{CS4321_DSP_SDS_SERDES_SRX_FFE_PGA_CTRL, 0, 0x0021},
	{CS4321_DSP_SDS_SERDES_SRX_FFE_MISC, 0, 0x0013},
	{CS4321_DSP_SDS_SERDES_SRX_FFE_INBUF_CTRL, 0, 0x0001},
	{CS4321_DSP_SDS_SERDES_SRX_DFE0_SELECT, 0, 0x0001},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_ingress_rxaui_pcs_ra[] = {
	/* Set fen_radj, rx_fen_xgpcs */
	{CS4321_GLOBAL_INGRESS_FUNCEN, ~0x0081, 0x0081},
	/* Set rx_en_radj, rx_en_xgpcs */
	{CS4321_GLOBAL_INGRESS_CLKEN, ~0x0021, 0x0021},
	/* Set tx_en_hif, tx_en_radj */
	{CS4321_GLOBAL_INGRESS_CLKEN2, ~0x0120, 0x0120},

	{CS4321_GLOBAL_HOST_MULTILANE_CLKSEL, 0, 0x8000},
	{CS4321_GLOBAL_HOST_MULTILANE_FUNCEN, 0, 0x0006},

	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0xffff},
	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0x0000},
	/* MPIF DeAssert Ingress Reset */
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, ~0x0004, 0},

	{CS4321_XGMAC_LINE_RX_CFG_COM, 0, 0x8010},
	{CS4321_XGPCS_LINE_RX_RXCNTRL, 0, 0x5000},

	{CS4321_RADJ_INGRESS_RX_NRA_MIN_IFG, 0, 0x0004},
	{CS4321_RADJ_INGRESS_RX_NRA_SETTLE, 0, 0x0000},
	{CS4321_RADJ_INGRESS_TX_ADD_FILL_CTRL, 0, 0xf001},
	{CS4321_RADJ_INGRESS_TX_ADD_FILL_DATA0, 0, 0x0707},
	{CS4321_RADJ_INGRESS_TX_ADD_FILL_DATA1, 0, 0x0707},
	{CS4321_RADJ_INGRESS_TX_PRA_MIN_IFG, 0, 0x0004},
	{CS4321_RADJ_INGRESS_TX_PRA_SETTLE, 0, 0x0000},
	{CS4321_RADJ_INGRESS_MISC_RESET, 0, 0x0000},

	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0002},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0000},
	{CS4321_RADJ_INGRESS_MISC_RESET, 0, 0x0000},

	{CS4321_PM_CTRL, 0, 0x0000},
	{CS4321_HIF_COMMON_TXCONTROL3, 0, 0x0010},

	{CS4321_MSEQ_POWER_DOWN_LSB, 0, 0xe01f},

	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_egress_rxaui_pcs_ra[] = {
	/* Set tx_fen_xgpcs, fen_radj */
	{CS4321_GLOBAL_EGRESS_FUNCEN, ~0x0180, 0x0180},
	/* Set rx_en_hif, rx_en_radj */
	{CS4321_GLOBAL_EGRESS_CLKEN, ~0x0120, 0x0120},
	/* Set tx_en_radj, tx_en_xgpcs */
	{CS4321_GLOBAL_EGRESS_CLKEN2, ~0x0021, 0x0021},

	{CS4321_GLOBAL_HOST_MULTILANE_CLKSEL, 0, 0x8000},
	{CS4321_GLOBAL_HOST_MULTILANE_FUNCEN, 0, 0x0006},

	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0xffff},
	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0x0000},
	/* MPIF DeAssert Egress Reset */
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, ~0x0002, 0},

	{CS4321_XGMAC_LINE_TX_CFG_COM, 0, 0xc000},
	{CS4321_XGMAC_LINE_TX_CFG_TX_IFG, 0, 0x0005},
	{CS4321_XGPCS_LINE_TX_TXCNTRL, 0, 0x0000},
	{CS4321_XGRS_LINE_TX_TXCNTRL, 0, 0xc000},

	{CS4321_RADJ_EGRESS_RX_NRA_MIN_IFG, 0, 0x0004},
	{CS4321_RADJ_EGRESS_RX_NRA_SETTLE, 0, 0x0000},
	{CS4321_RADJ_EGRESS_TX_ADD_FILL_CTRL, 0, 0xf001},
	{CS4321_RADJ_EGRESS_TX_ADD_FILL_DATA0, 0, 0x0707},
	{CS4321_RADJ_EGRESS_TX_ADD_FILL_DATA1, 0, 0x0707},
	{CS4321_RADJ_EGRESS_TX_PRA_MIN_IFG, 0, 0x0004},
	{CS4321_RADJ_EGRESS_TX_PRA_SETTLE, 0, 0x0000},
	{CS4321_RADJ_EGRESS_MISC_RESET, 0, 0x0000},

	{CS4321_PM_CTRL, 0, 0x0000},
	{CS4321_HIF_COMMON_TXCONTROL3, 0, 0x0010},
	{CS4321_MSEQ_POWER_DOWN_LSB, 0, 0xe01f},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_ingress_line_rx_1g[] = {
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CLKDIV_CTRL, 0, 0x3023},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_LOOP_FILTER, 0, 0x0007},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CPA, 0, 0x0077},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_ingress_host_rx_1g[] = {
	{CS4321_HOST_SDS_COMMON_STXP0_TX_CLKOUT_CTRL, 0, 0x1806},
	{CS4321_LINE_SDS_COMMON_RXVCO0_CONTROL, (uint16_t)~0x8000, 0x8000},
	{CS4321_LINE_SDS_COMMON_RXVCO0_CONTROL, (uint16_t)~0x8000, 0x0000},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_egress_line_rx_1g[] = {
	{CS4321_LINE_SDS_COMMON_STXP0_TX_CLKOUT_CTRL, 0, 0x1806},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_egress_host_rx_1g[] = {
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CLKDIV_CTRL, 0, 0x3023},
	{CS4321_HOST_SDS_COMMON_SRX0_RX_LOOP_FILTER, 0, 0x0007},
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CPA, 0, 0x0077},
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL, (uint16_t)~0x8000, 0x8000},
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL, (uint16_t)~0x8000, 0x0000},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_line_through_timing_1g[] = {
	{CS4321_LINE_SDS_COMMON_TXELST0_CONTROL, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_host_through_timing_1g[] = {
	{CS4321_HOST_SDS_COMMON_TXELST0_CONTROL, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify cs4321_enable_aneg_1g[] = {
	/* Enable auto negotiation and restart it */
	{CS4321_GIGEPCS_LINE_DEV_ABILITY, 0, 0x1a0},
	{CS4321_GIGEPCS_LINE_CONTROL, 0, 0x1340},
	{CS4321_GIGEPCS_HOST_DEV_ABILITY, 0, 0x1a0},
	{CS4321_GIGEPCS_HOST_CONTROL, 0, 0x1340},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_ingress_through_timing_mux_demux[] = {
	/* MUXPD on, EYE monitor on */
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CONFIG, ~0x1200, 0},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_through_timing_mux_demux[] = {
	/* DMUXPD on, MUXPD on, EYE monitor on */
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CONFIG, ~0x1300, 0},
	{0},
};

static const struct cs4321_reg_modify cs4321_init_dpath_ingress_ra_1g[] = {
	/* ren_fen_gepcs = 1, fen_radj = 1, tx_fen_gepcs = 1 */
	{CS4321_GLOBAL_INGRESS_FUNCEN, ~0x484, 0x0484},
	/* rx_en_gepcs = 1, rx_en_radj = 1, rx_en_xgrs = 0, rx_en_xgpcs = 0 */
	{CS4321_GLOBAL_INGRESS_CLKEN, ~0x002D, 0x0024},
	/* rx_en_gepcs = 1, rx_en_radj = 1, rx_en_xgrs = 0, rx_en_xgpcs = 0 */
	{CS4321_GLOBAL_INGRESS_CLKEN2, ~0x002D, 0x0024},
	/* DeAassert MPIF  ingress reset */
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, ~0x0004, 0x0000},
	/* Remove Line Rx/Host TX PCS Reset */
	/* line_rx_sr = 0, host_tx_sr = 0 */
	{CS4321_GLOBAL_GIGEPCS_SOFT_RESET, ~0x0201, 0x0000},
	/* set nra_in_pairs */
	{CS4321_RADJ_INGRESS_RX_NRA_EXTENT, 0, 0x0011},
	{CS4321_RADJ_INGRESS_TX_PRA_EXTENT, 0, 0x0011},
	/* Remove RA Reset */
	{CS4321_RADJ_INGRESS_MISC_RESET, 0, 0x0000},
	/* Remove PM Reset */
	{CS4321_PM_CTRL, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_dpath_egress_ra_1g[] = {
	/* ren_fen_gepcs = 1, fen_radj = 1, tx_fen_gepcs = 1 */
	{CS4321_GLOBAL_EGRESS_FUNCEN, ~0x484, 0x0484},
	/* rx_en_gepcs = 1, rx_en_radj = 1, rx_en_xgrs = 0, rx_en_xgpcs = 0 */
	{CS4321_GLOBAL_EGRESS_CLKEN, ~0x002D, 0x0024},
	/* rx_en_gepcs = 1, rx_en_radj = 1, rx_en_xgrs = 0, rx_en_xgpcs = 0 */
	{CS4321_GLOBAL_EGRESS_CLKEN2, ~0x002D, 0x0024},
	/* DeAassert MPIF  ingress reset */
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, ~0x0002, 0x0000},
	/* Remove Line Rx/Host TX PCS Reset */
	/* line_tx_sr = 0, host_rx_sr = 0 */
	{CS4321_GLOBAL_GIGEPCS_SOFT_RESET, ~0x0102, 0x0000},
	/* set nra_in_pairs */
	{CS4321_RADJ_EGRESS_RX_NRA_EXTENT, 0, 0x0011},
	{CS4321_RADJ_EGRESS_TX_PRA_EXTENT, 0, 0x0011},
	/* Remove RA Reset */
	{CS4321_RADJ_EGRESS_MISC_RESET, 0, 0x0000},
	/* Remove PM Reset */
	{CS4321_PM_CTRL, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify cs4321_resync_vcos_1g[] = {
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL,  (u16)~0x8000, 0x8000},
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL,  (u16)~0x8000, 0},

	{CS4321_HOST_SDS_COMMON_TXVCO0_CONTROL,  (u16)~0x8000, 0x8000},
	{CS4321_HOST_SDS_COMMON_TXVCO0_CONTROL,  (u16)~0x8000, 0},

	{CS4321_LINE_SDS_COMMON_RXVCO0_CONTROL,  (u16)~0x8000, 0x8000},
	{CS4321_LINE_SDS_COMMON_RXVCO0_CONTROL,  (u16)~0x8000, 0},

	{CS4321_LINE_SDS_COMMON_TXVCO0_CONTROL,  (u16)~0x8000, 0x8000},
	{CS4321_LINE_SDS_COMMON_TXVCO0_CONTROL,  (u16)~0x8000, 0},

	{0}
};

static const struct cs4321_reg_modify cs4321_soft_reset[] = {
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0003},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0x0003},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0000},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_line_if_mode_none[] = {
	/* Stall the microsequencer */
	{CS4321_GLOBAL_MSEQCLKCTRL, 0, (uint16_t)0x8004},
	{CS4321_MSEQ_OPTIONS, 0, 0x000f},
	{CS4321_MSEQ_PC, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_unlock_tx_elastic_store_host[] = {
	{CS4321_LINE_SDS_COMMON_TXELST0_CONTROL, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_rate_adj_1g[] = {
	{CS4321_RADJ_INGRESS_RX_NRA_MIN_IFG, 0, 0x0005},
	{CS4321_RADJ_INGRESS_TX_PRA_MIN_IFG, 0, 0x0005},
	{CS4321_RADJ_EGRESS_RX_NRA_MIN_IFG, 0, 0x0005},
	{CS4321_RADJ_EGRESS_TX_PRA_MIN_IFG, 0, 0x0005},
	{0}
};

/**
 * Initializes the host divider
 *
 * @see cs4321_init_line_frac_1g
 */
static const struct cs4321_reg_modify cs4321_init_host_frac_1g[] = {
	/* Initialize host divider, VCO rate: 10000, pilot: 100 */
	{CS4321_HOST_SDS_COMMON_FRAC0_RESET, 0, 0},
	/* Set the RDIV_SEL field to Fractional-N */
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CLKDIV_CTRL, 0xff0f, 0x0070},
	/* Turn on the frac-N clock: provide SRX_PILOT */
	{CS4321_HOST_SDS_COMMON_FRAC0_EN, 0, 1},
	/* Setup to use a 24 bit accumulator */
	{CS4321_HOST_SDS_COMMON_FRAC0_WIDTH,
	0, CS4321_FRACDIV_ACCUM_WIDTH_24BIT},
	/* floor(10000.0 / 8 / 100.0) = floor(12.5) */
	{CS4321_HOST_SDS_COMMON_FRAC0_INTDIV, 0, 12},
	/* (12.5 - 12) * 0x1000000 = 0x800000 */
	/* lower 16-bits */
	{CS4321_HOST_SDS_COMMON_FRAC0_NUMERATOR0, 0, 0},
	/* upper 8-bits */
	{CS4321_HOST_SDS_COMMON_FRAC0_NUMERATOR1, 0, 0x80},
	/* 0.8GHz clock */
	{CS4321_HOST_SDS_COMMON_FRAC0_1P6G_EN, 0, 1},
	/* CONFIGure stage 1 preload value */
	{CS4321_HOST_SDS_COMMON_FRAC0_STAGE1PRELOAD0, 0, 0x5DC6},
	{CS4321_HOST_SDS_COMMON_FRAC0_STAGE1PRELOAD1, 0, 0x34},
	/* CONFIGure stage 2 preload value */
	{CS4321_HOST_SDS_COMMON_FRAC0_STAGE2PRELOAD0, 0, 0x5DC6},
	{CS4321_HOST_SDS_COMMON_FRAC0_STAGE2PRELOAD1, 0, 0x34},
	/* CONFIGure stage 3 preload value */
	{CS4321_HOST_SDS_COMMON_FRAC0_STAGE3PRELOAD0, 0, 0x5DC6},
	{CS4321_HOST_SDS_COMMON_FRAC0_STAGE3PRELOAD1, 0, 0x34},
	/* Enable stage 1/2 but stage 3 is not necessary */
	{CS4321_HOST_SDS_COMMON_FRAC0_STAGE1_EN, 0, 1},
	{CS4321_HOST_SDS_COMMON_FRAC0_STAGE2_EN, 0, 1},
	{CS4321_HOST_SDS_COMMON_FRAC0_STAGE3_EN, 0, 0},
	/* Bring fractional divider out of reset */
	{CS4321_HOST_SDS_COMMON_FRAC0_RESET, 0, 1},
	{CS4321_HOST_SDS_COMMON_FRAC0_RESET, 0, 0},

	/* Re-trigger VCO coarse tuning */
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL, 0x7FFF, 0x8000},
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL, 0x7FFF, 0},
	{0},
};

/**
 * Initializes the line divider
 *
 * @see cs4321_init_host_frac_1g
 */
static const struct cs4321_reg_modify cs4321_init_line_frac_1g[] = {
	/* Initialize line divider, VCO rate: 10000, pilot: 100 */
	{CS4321_LINE_SDS_COMMON_FRAC0_RESET, 0, 0},
	/* Set the RDIV_SEL field to Fractional-N */
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CLKDIV_CTRL, 0xff0f, 0x0070},
	/* Turn on the frac-N clock: provide SRX_PILOT */
	{CS4321_LINE_SDS_COMMON_FRAC0_EN, 0, 1},
	/* Setup to use a 24 bit accumulator */
	{CS4321_LINE_SDS_COMMON_FRAC0_WIDTH,
		0, CS4321_FRACDIV_ACCUM_WIDTH_24BIT},
	/* floor(10000.0 / 8 / 100.0) = floor(12.5) */
	{CS4321_LINE_SDS_COMMON_FRAC0_INTDIV, 0, 12},
	/* (12.5 - 12) * 0x1000000 = 0x800000 */
	/* lower 16-bits */
	{CS4321_LINE_SDS_COMMON_FRAC0_NUMERATOR0, 0, 0},
	/* upper 8-bits */
	{CS4321_LINE_SDS_COMMON_FRAC0_NUMERATOR1, 0, 0x80},
	/* CONFIGure stage 1 preload value */
	{CS4321_LINE_SDS_COMMON_FRAC0_STAGE1PRELOAD0, 0, 0x5DC6},
	{CS4321_LINE_SDS_COMMON_FRAC0_STAGE1PRELOAD1, 0, 0x34},
	/* CONFIGure stage 2 preload value */
	{CS4321_LINE_SDS_COMMON_FRAC0_STAGE2PRELOAD0, 0, 0x5DC6},
	{CS4321_LINE_SDS_COMMON_FRAC0_STAGE2PRELOAD1, 0, 0x34},
	/* CONFIGure stage 3 preload value */
	{CS4321_LINE_SDS_COMMON_FRAC0_STAGE3PRELOAD0, 0, 0x5DC6},
	{CS4321_LINE_SDS_COMMON_FRAC0_STAGE3PRELOAD1, 0, 0x34},
	/* Don't need dithering enabled */
	{CS4321_LINE_SDS_COMMON_FRAC0_DITHER_EN, 0, 0},
	{CS4321_LINE_SDS_COMMON_FRAC0_DITHER_SEL, 0,
	CS4321_FRACDIV_2EXP32_MINUS1},
	/* Enable stage 1/2 but stage 3 is not necessary */
	{CS4321_LINE_SDS_COMMON_FRAC0_STAGE1_EN, 0, 1},
	{CS4321_LINE_SDS_COMMON_FRAC0_STAGE2_EN, 0, 1},
	{CS4321_LINE_SDS_COMMON_FRAC0_STAGE3_EN, 0, 0},
	/* Bring fractional divider out of reset */
	{CS4321_LINE_SDS_COMMON_FRAC0_RESET, 0, 1},
	{CS4321_LINE_SDS_COMMON_FRAC0_RESET, 0, 0},

	/* Re-trigger VCO coarse tuning */
	{CS4321_LINE_SDS_COMMON_RXVCO0_CONTROL, 0x7FFF, 0x8000},
	{CS4321_LINE_SDS_COMMON_RXVCO0_CONTROL, 0x7FFF, 0},
	{0},
};

static const struct cs4321_reg_modify cs4321_retrigger_vcos_1g[] = {
	{CS4321_LINE_SDS_COMMON_TXVCO0_CONTROL, 0x7FFF, 0x8000},
	{CS4321_LINE_SDS_COMMON_TXVCO0_CONTROL, 0x7FFF, 0x0000},
	{CS4321_HOST_SDS_COMMON_TXVCO0_CONTROL, 0x7FFF, 0x8000},
	{CS4321_HOST_SDS_COMMON_TXVCO0_CONTROL, 0x7FFF, 0x0000},
	{CS4321_LINE_SDS_COMMON_RXVCO0_CONTROL, 0x7FFF, 0x8000},
	{CS4321_LINE_SDS_COMMON_RXVCO0_CONTROL, 0x7FFF, 0x0000},
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL, 0x7FFF, 0x8000},
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL, 0x7FFF, 0x0000},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_global_timer_156_25[] = {
	{CS4321_GLOBAL_GT_10KHZ_REF_CLK_CNT0, 0, 15625},
	{CS4321_GLOBAL_GT_10KHZ_REF_CLK_CNT1, 0, 0},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_global_timer_100[] = {
	{CS4321_GLOBAL_GT_10KHZ_REF_CLK_CNT0, 0, 10000},
	{CS4321_GLOBAL_GT_10KHZ_REF_CLK_CNT1, 0, 0},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_mac_latency[] = {
	{CS4321_MAC_LAT_CTRL_CONFIG, 0, 0},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_ref_clk_src_xaui_rxaui[] = {
	/* Set edc_stxp_lptime_sel = 1, edc_stxp_pilot_sel = 7 */
	{CS4321_GLOBAL_MISC_CONFIG, (u16)~0xe700, 0x2700},
	/* Set STXP_PILOT_SEL = 7, STXP_LPTIME_SEL = 1 */
	{CS4321_LINE_SDS_COMMON_STXP0_TX_CONFIG, (u16)~0xe700, 0x2700},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_ref_clk_src[] = {
	/* Set edc_stxp_lptime_sel = 1, edc_stxp_pilot_sel = 7 */
	{CS4321_GLOBAL_MISC_CONFIG, (u16)~0xe700, 0x2700},
	/* Set STXP_PILOT_SEL = 7, STXP_LPTIME_SEL = 1 */
	{CS4321_LINE_SDS_COMMON_STXP0_TX_CONFIG, (u16)~0xe700, 0x2700},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_CONFIG, (u16)~0xe700, 0x2700},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_polarity_inv[] = {
	/* Inversion disabled */
	/* config the slice not to invert polarity on egress */
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CONFIG, ~0x0800, 0},
	/* config the slice not to invert polarity on ingress */
	{CS4321_MSEQ_ENABLE_MSB, ~0x4000, 0},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_lane_swap_xaui_rxaui[] = {
	{CS4321_HIF_COMMON_RXCONTROL0, ~0x00FF, 0x00E4},
	{CS4321_HIF_COMMON_TXCONTROL0, ~0x00FF, 0x00E4},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0003},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0xFFFF},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0},
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL, (uint16_t)(~0x8000),
		(uint16_t)0x8000},
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL, (uint16_t)(~0x8000), 0},
	{0}
};

static const struct cs4321_reg_modify cs4321_assert_reset_ingress_block[] = {
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, ~0x0004, 0x0004},
	{0}
};

static const struct cs4321_reg_modify cs4321_deassert_reset_ingress_block[] = {
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, ~0x0004, 0},
	{0}
};

static const struct cs4321_reg_modify cs4321_assert_reset_egress_block[] = {
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, ~0x0002, 0x0002},
	{0}
};

static const struct cs4321_reg_modify cs4321_deassert_reset_egress_block[] = {
	{CS4321_GLOBAL_MPIF_RESET_DOTREG, ~0x0002, 0},
	{0}
};

static const struct cs4321_reg_modify cs4321_hsif_elec_mode_set_none[] = {
	{CS4321_GLOBAL_MSEQCLKCTRL, 0, 0x8004},
	{CS4321_MSEQ_OPTIONS, 0, 0xf},
	{CS4321_MSEQ_PC, 0, 0x0},
	{0},
};


static const struct cs4321_reg_modify cs4321_hsif_elec_mode_set_sr_pre[] = {
	/* Stop the micro-sequencer */
	{CS4321_GLOBAL_MSEQCLKCTRL, 0, 0x8004},
	{CS4321_MSEQ_OPTIONS, 0, 0xf},
	{CS4321_MSEQ_PC, 0, 0x0},

	/* Configure the micro-sequencer for an SR transceiver */
	{CS4321_MSEQ_COEF_DSP_DRIVE128, 0, 0x0134},
	{CS4321_MSEQ_COEF_INIT_SEL, 0, 0x0006},
	{CS4321_MSEQ_LEAK_INTERVAL_FFE, 0, 0x8010},
	{CS4321_MSEQ_BANKSELECT, 0, 0x0},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CPA, 0, 0x55},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_LOOP_FILTER, 0, 0x3},
	{CS4321_DSP_SDS_SERDES_SRX_DFE0_SELECT, 0, 0x1},
	{CS4321_DSP_SDS_DSP_COEF_DFE0_SELECT, 0, 0x2},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CPB, 0, 0x2003},
	{CS4321_DSP_SDS_SERDES_SRX_FFE_DELAY_CTRL, 0, 0xF047},

	{CS4321_MSEQ_RESET_COUNT_LSB, 0, 0x0},
	/* enable power savings, ignore */
	{CS4321_MSEQ_SPARE2_LSB, 0, 0x5},
	/* enable power savings */
	{CS4321_MSEQ_SPARE9_LSB, 0, 0x5},

	{CS4321_MSEQ_CAL_RX_PHSEL, 0, 0x1e},
	{CS4321_DSP_SDS_DSP_COEF_LARGE_LEAK, 0, 0x2},
	{CS4321_DSP_SDS_SERDES_SRX_DAC_ENABLEB_LSB, 0, 0xD000},
	{CS4321_MSEQ_POWER_DOWN_LSB, 0, 0xFFFF},
	{CS4321_MSEQ_POWER_DOWN_MSB, 0, 0x0},
	{CS4321_MSEQ_CAL_RX_SLICER, 0, 0x80},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_SPARE, 0, 0xE0E0},
	{CS4321_DSP_SDS_SERDES_SRX_DAC_BIAS_SELECT1_MSB, 0, 0xff},

	{CS4321_DSP_SDS_DSP_PRECODEDINITFFE21, 0, 0x41},
	/* Setup the trace lengths for the micro-sequencer */
	{CS4321_MSEQ_SERDES_PARAM_LSB, 0, 0x0603},

	{0}
};

static const struct cs4321_reg_modify cs4321_hsif_elec_mode_set_sr_2in[] = {
	{CS4321_MSEQ_CAL_RX_EQADJ, 0, 0x0},
	{0}
};

static const struct cs4321_reg_modify cs4321_hsif_elec_mode_set_sr_post[] = {
	{CS4321_MSEQ_CAL_RX_DFE_EQ, 0, 0x0},
	/* Restart the micro-sequencer */
	{CS4321_GLOBAL_MSEQCLKCTRL, 0, 0x4},
	{CS4321_MSEQ_OPTIONS, 0, 0x7},
	{0}
};

static const struct cs4321_reg_modify cs4321_trace_line_driver_2in[] = {
	{CS4321_LINE_SDS_COMMON_STX0_TX_OUTPUT_CTRLA, 0, 0x201E},
	{CS4321_LINE_SDS_COMMON_STX0_TX_OUTPUT_CTRLB, 0, 0xC010},
	{0}
};

static const struct cs4321_reg_modify cs4321_trace_host_driver_2in[] = {
	{CS4321_HOST_SDS_COMMON_STX0_TX_OUTPUT_CTRLA, 0, 0x201E},
	{CS4321_HOST_SDS_COMMON_STX0_TX_OUTPUT_CTRLB, 0, 0xC010},
	{CS4321_HOST_ML_SDS_COMMON_STX0_TX_OUTPUT_CTRLA, 0, 0x201E},
	{CS4321_HOST_ML_SDS_COMMON_STX0_TX_OUTPUT_CTRLB, 0, 0xC010},
	{0}
};

static const struct cs4321_reg_modify cs4321_trace_line_equal_2in[] = {
	{CS4321_LINE_SDS_COMMON_SRX0_RX_MISC, 0, 0x0011},
	{0}
};

static const struct cs4321_reg_modify cs4321_resync_vcos_xaui_rxaui[] = {
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL,  (u16)~0x8000, 0x8000},
	{CS4321_HOST_SDS_COMMON_RXVCO0_CONTROL,  (u16)~0x8000, 0},

	{CS4321_HOST_SDS_COMMON_TXVCO0_CONTROL,  (u16)~0x8000, 0x8000},
	{CS4321_HOST_SDS_COMMON_TXVCO0_CONTROL,  (u16)~0x8000, 0},

	{CS4321_LINE_SDS_COMMON_RXVCO0_CONTROL,  (u16)~0x8000, 0x8000},
	{CS4321_LINE_SDS_COMMON_RXVCO0_CONTROL,  (u16)~0x8000, 0},

	{CS4321_LINE_SDS_COMMON_TXVCO0_CONTROL,  (u16)~0x8000, 0x8000},
	{CS4321_LINE_SDS_COMMON_TXVCO0_CONTROL,  (u16)~0x8000, 0},

	{CS4321_HOST_ML_SDS_COMMON_RXVCO0_CONTROL,  (u16)~0x8000, 0x8000},
	{CS4321_HOST_ML_SDS_COMMON_RXVCO0_CONTROL,  (u16)~0x8000, 0},

	{CS4321_HOST_ML_SDS_COMMON_TXVCO0_CONTROL,  (u16)~0x8000, 0x8000},
	{CS4321_HOST_ML_SDS_COMMON_TXVCO0_CONTROL,  (u16)~0x8000, 0},

	{0}
};

static const struct cs4321_reg_modify cs4321_powerup_ml_serdes[] = {
	{CS4321_HOST_ML_SDS_COMMON_SRX0_RX_CONFIG, ~0x0020, 0},
	{CS4321_HOST_ML_SDS_COMMON_STXP0_TX_PWRDN, ~0x0100, 0},
	{0}
};

static const struct cs4321_reg_modify cs4321_powerdown_ml_serdes[] = {
	{CS4321_HOST_ML_SDS_COMMON_SRX0_RX_CONFIG, ~0x0020, 0x0020},
	{CS4321_HOST_ML_SDS_COMMON_STXP0_TX_PWRDN, ~0x0100, 0x0100},
	{0}
};

static const struct cs4321_reg_modify cs4321_toggle_resets_xaui_rxaui[] = {
	/*
	 * Now that the device is configured toggle the ingress and
	 * egress soft resets to make sure the device re-syncs
	 * properly.
	 */
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x3},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0x3},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0000},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0x0000},

	{0}
};

static const struct cs4321_reg_modify cs4321_init_trace_2in_host_xaui[] = {
	{CS4321_HOST_SDS_COMMON_STX0_TX_OUTPUT_CTRLA, 0, 0x3030},
	{CS4321_HOST_SDS_COMMON_STX0_TX_OUTPUT_CTRLB, 0, 0xC003},
	{CS4321_HOST_ML_SDS_COMMON_STX0_TX_OUTPUT_CTRLA, 0, 0x3030},
	{CS4321_HOST_ML_SDS_COMMON_STX0_TX_OUTPUT_CTRLB, 0, 0xC003},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_line_equalize_2in[] = {
	{CS4321_LINE_SDS_COMMON_SRX0_RX_MISC, 0, 0x0011},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_through_timing_xaui_1[] = {
	{CS4321_LINE_SDS_COMMON_STX0_TX_CONFIG_LOCAL_TIMING, 0, 0x0001},
	{CS4321_LINE_SDS_COMMON_STXP0_TX_CLKOUT_CTRL, 0, 0x0864},
	{CS4321_LINE_SDS_COMMON_STXP0_TX_LOOP_FILTER, 0, 0x0027},
	{CS4321_LINE_SDS_COMMON_STXP0_TX_PWRDN, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_through_timing_xaui_2e[] = {
	{CS4321_LINE_SDS_COMMON_STXP0_TX_CONFIG, (uint16_t)(~0xF800), 0x1000},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_through_timing_xaui_2o[] = {
	{CS4321_LINE_SDS_COMMON_STXP0_TX_CONFIG, (uint16_t)(~0xF800), 0x0800},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_through_timing_xaui_3[] = {
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CLKDIV_CTRL, 0, 0x45d2},
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CONFIG, 0, 0x000c},
	{CS4321_HOST_ML_SDS_COMMON_SRX0_RX_CLKDIV_CTRL, 0, 0x412d},
	{CS4321_HOST_ML_SDS_COMMON_SRX0_RX_CONFIG, 0, 0x000c},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_through_timing_xaui_4e[] = {
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CLKOUT_CTRL, 0, 0x6a05},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_through_timing_xaui_4o[] = {
	{CS4321_HOST_SDS_COMMON_SRX0_RX_CLKOUT_CTRL, 0, 0x6a03},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_egress_through_timing_xaui_5[] = {
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0003},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0xffff},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0000},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0x0000},
	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0xffff},
	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_ingress_local_timing_xaui[] = {
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CONFIG, 0, 0x0000},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_CPA, 0, 0x0057},
	{CS4321_LINE_SDS_COMMON_SRX0_RX_LOOP_FILTER, 0, 0x0007},

	{CS4321_HOST_SDS_COMMON_STX0_TX_CONFIG_LOCAL_TIMING, 0, 0x0001},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_CLKDIV_CTRL, 0, 0x4492},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_CLKOUT_CTRL, 0, 0x1864},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_CONFIG, 0, 0x090c},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_PWRDN, 0, 0x0000},
	{CS4321_HOST_ML_SDS_COMMON_STXP0_TX_CLKDIV_CTRL, 0, 0x4429},
	{CS4321_HOST_ML_SDS_COMMON_STXP0_TX_CONFIG, 0, 0x090c},

	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0003},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0xffff},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0000},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0x0000},
	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0xffff},
	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_ingress_1[] = {
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0002},
	{CS4321_GLOBAL_INGRESS_SOFT_RESET, 0, 0x0000},
	{CS4321_HOST_SDS_COMMON_STXP0_TX_PWRDN, 0, 0x0000},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_dpath_xaui_pcs_ra_2e[] = {
	{CS4321_GLOBAL_HOST_MULTILANE_CLKSEL, 0, 0x8000},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_dpath_xaui_pcs_ra_2o[] = {
	{CS4321_GLOBAL_HOST_MULTILANE_CLKSEL, 0, 0x8300},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_ingress_3[] = {
	/* Set the device in XAUI mode */
	{CS4321_GLOBAL_HOST_MULTILANE_FUNCEN, 0, 0x0005},

	/* Enable the XGPCS and the Rate Adjust block */
	/* Set fen_radj, rx_fen_xgpcs */
	{CS4321_GLOBAL_INGRESS_FUNCEN, ~0x0081, 0x0081},

	/* Setup the clock enables for the XGPCS and Rate Adjust block */
	/* Set rx_en_radj, rx_en_xgpcs */
	{CS4321_GLOBAL_INGRESS_CLKEN, ~0x0021, 0x0021},

	/* Setup the clock enables for the HIF and the Rate Adjust block */
	/* Set tx_en_hif, tx_en_radj */
	{CS4321_GLOBAL_INGRESS_CLKEN2, ~0x0120, 0x0120},

	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0xffff},
	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0x0000},

	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_ingress_4e[] = {
	{CS4321_XGMAC_LINE_RX_CFG_COM, 0, 0x8010},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_ingress_4o[] = {
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_ingress_5[] = {
	{CS4321_XGMAC_HOST_TX_CFG_TX_IFG, 0, 0x0005},
	{CS4321_XGPCS_LINE_RX_RXCNTRL, 0, 0x5000},
	{CS4321_XGRS_HOST_TX_TXCNTRL, 0, 0xc000},
	{CS4321_GIGEPCS_LINE_CONTROL, 0, 0x0000},
	{CS4321_GIGEPCS_HOST_CONTROL, 0, 0x0000},

	{CS4321_RADJ_INGRESS_RX_NRA_MIN_IFG, 0, 0x0004},
	{CS4321_RADJ_INGRESS_RX_NRA_SETTLE, 0, 0x0000},
	{CS4321_RADJ_INGRESS_TX_ADD_FILL_CTRL, 0, 0xf001},
	{CS4321_RADJ_INGRESS_TX_ADD_FILL_DATA0, 0, 0x0707},
	{CS4321_RADJ_INGRESS_TX_ADD_FILL_DATA1, 0, 0x0707},
	{CS4321_RADJ_INGRESS_TX_PRA_MIN_IFG, 0, 0x0004},
	{CS4321_RADJ_INGRESS_TX_PRA_SETTLE, 0, 0x0000},
	{CS4321_RADJ_INGRESS_MISC_RESET, 0, 0x0000},
	{CS4321_PM_CTRL, 0, 0x0002},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_dpath_xaui_pcs_ra_6e[] = {
	{CS4321_HIF_COMMON_TXCONTROL3, 0, 0x0010},
	{0}
};

static const struct cs4321_reg_modify cs4321_init_dpath_xaui_pcs_ra_6o[] = {
	{CS4321_HIF_COMMON_TXCONTROL3, 0, 0x0011},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_egress_1[] = {
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0x1},
	{CS4321_GLOBAL_EGRESS_SOFT_RESET, 0, 0x0000},
	{CS4321_LINE_SDS_COMMON_STXP0_TX_PWRDN, 0, 0x0000},

	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_egress_2e[] = {
	{CS4321_GLOBAL_HOST_MULTILANE_CLKSEL, 0, 0x8000},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_egress_2o[] = {
	{CS4321_GLOBAL_HOST_MULTILANE_CLKSEL, 0, 0x8300},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_egress_3[] = {
	/* Set the device in XAUI mode */
	{CS4321_GLOBAL_HOST_MULTILANE_FUNCEN, 0, 0x0005},

	/* Enable the XGPCS and the Rate Adjust block */
	/* Set tx_fen_xgpcs, fen_radj */
	{CS4321_GLOBAL_EGRESS_FUNCEN, ~0x0180, 0x0180},

	/* Setup the clock enables for the HIF and the Rate Adjust block */
	/* Set rx_en_hif, rx_en_radj */
	{CS4321_GLOBAL_EGRESS_CLKEN, ~0x0120, 0x0120},

	/* Setup the clock enables for the XGPCS and Rate Adjust block */
	/* Set tx_en_radj, tx_en_xgpcs */
	{CS4321_GLOBAL_EGRESS_CLKEN2, ~0x0021, 0x0021},

	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0xffff},
	{CS4321_GLOBAL_REF_SOFT_RESET, 0, 0x0000},

	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_egress_4e[] = {
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_egress_4o[] = {
	{CS4321_XGMAC_LINE_TX_CFG_COM, 0, 0xc000},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_egress_5[] = {
	{CS4321_XGMAC_LINE_TX_CFG_TX_IFG, 0, 0x0005},
	{CS4321_XGPCS_LINE_TX_TXCNTRL, 0, 0x0000},
	{CS4321_XGRS_LINE_TX_TXCNTRL, 0, 0xc000},

	{CS4321_RADJ_EGRESS_RX_NRA_MIN_IFG, 0, 0x0004},
	{CS4321_RADJ_EGRESS_RX_NRA_SETTLE, 0, 0x0000},
	{CS4321_RADJ_EGRESS_TX_ADD_FILL_CTRL, 0, 0xf001},
	{CS4321_RADJ_EGRESS_TX_ADD_FILL_DATA0, 0, 0x0707},
	{CS4321_RADJ_EGRESS_TX_ADD_FILL_DATA1, 0, 0x0707},
	{CS4321_RADJ_EGRESS_TX_PRA_MIN_IFG, 0, 0x0004},
	{CS4321_RADJ_EGRESS_TX_PRA_SETTLE, 0, 0x0000},
	{CS4321_RADJ_EGRESS_MISC_RESET, 0, 0x0000},
	{CS4321_PM_CTRL, 0, 0x0002},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_egress_6e[] = {
	{CS4321_HIF_COMMON_TXCONTROL3, 0, 0x0010},
	{0}
};

static const struct cs4321_reg_modify
cs4321_init_dpath_xaui_pcs_ra_egress_6o[] = {
	{CS4321_HIF_COMMON_TXCONTROL3, 0, 0x0011},
	{0}
};

const struct cs4321_multi_seq cs4321_init_rxaui_seq[] = {
	{0, cs4321_init_prefix_seq},
	{0, cs4321_init_egress_local_timing_rxaui},
	{0, cs4321_init_ingress_local_timing_rxaui},
	{0, cs4321_init_lane_swap_xaui_rxaui},
	{0, cs4321_init_dpath_ingress_rxaui_pcs_ra},
	{0, cs4321_init_dpath_egress_rxaui_pcs_ra},
	{0, cs4321_resync_vcos_xaui_rxaui},
	{0, cs4321_powerup_ml_serdes},
	{0, cs4321_toggle_resets_xaui_rxaui},
	{0, cs4321_hsif_elec_mode_set_sr_pre},
	{0, cs4321_hsif_elec_mode_set_sr_2in},
	{0, cs4321_hsif_elec_mode_set_sr_post},
	{0, cs4321_trace_host_driver_2in},
	{0, cs4321_trace_line_driver_2in},
	{0, cs4321_init_line_equalize_2in},
	{0, cs4321_init_global_timer_156_25},
	{0, cs4321_init_mac_latency},
	{0, cs4321_init_ref_clk_src_xaui_rxaui},
	{0, cs4321_init_polarity_inv},

	{1, cs4321_init_prefix_seq},
	{1, cs4321_init_egress_local_timing_rxaui},
	{1, cs4321_init_ingress_local_timing_rxaui},
	{1, cs4321_init_lane_swap_xaui_rxaui},
	{1, cs4321_init_dpath_ingress_rxaui_pcs_ra},
	{1, cs4321_init_dpath_egress_rxaui_pcs_ra},
	{1, cs4321_resync_vcos_xaui_rxaui},
	{1, cs4321_powerup_ml_serdes},
	{1, cs4321_toggle_resets_xaui_rxaui},
	{1, cs4321_hsif_elec_mode_set_none},
	{1, cs4321_trace_host_driver_2in},
	{1, cs4321_trace_line_driver_2in},
	{1, cs4321_trace_line_equal_2in},
	{1, cs4321_init_global_timer_156_25},
	{1, cs4321_init_mac_latency},
	{1, cs4321_init_ref_clk_src_xaui_rxaui},
	{1, cs4321_init_polarity_inv},

	{0, NULL}
};

const struct cs4321_multi_seq cs4321_init_xaui_seq[] = {
	{0, cs4321_init_prefix_seq},
	/* Init egress even and odd */
	{0, cs4321_init_egress_through_timing_xaui_1},
	{0, cs4321_init_egress_through_timing_xaui_2e},
	{0, cs4321_init_egress_through_timing_xaui_3},
	{0, cs4321_init_egress_through_timing_xaui_4e},
	{0, cs4321_init_egress_through_timing_xaui_5},

	{1, cs4321_init_egress_through_timing_xaui_1},
	{1, cs4321_init_egress_through_timing_xaui_2o},
	{1, cs4321_init_egress_through_timing_xaui_3},
	{1, cs4321_init_egress_through_timing_xaui_4o},
	{1, cs4321_init_egress_through_timing_xaui_5},

	/* Init ingress even and odd */
	{0, cs4321_init_ingress_local_timing_xaui},
	{1, cs4321_init_ingress_local_timing_xaui},

	{0, cs4321_init_lane_swap_xaui_rxaui},

	/* dpath ingress even and odd */
	{0, cs4321_init_dpath_xaui_pcs_ra_ingress_1},
	{0, cs4321_init_dpath_xaui_pcs_ra_2e},
	{0, cs4321_init_dpath_xaui_pcs_ra_ingress_3},
	{0, cs4321_deassert_reset_ingress_block},
	{0, cs4321_init_dpath_xaui_pcs_ra_ingress_4e},
	{0, cs4321_init_dpath_xaui_pcs_ra_ingress_5},
	{0, cs4321_init_dpath_xaui_pcs_ra_6e},


	{1, cs4321_init_dpath_xaui_pcs_ra_ingress_1},
	{1, cs4321_init_dpath_xaui_pcs_ra_2o},
	{1, cs4321_init_dpath_xaui_pcs_ra_ingress_3},
	{0, cs4321_deassert_reset_ingress_block},
	{1, cs4321_init_dpath_xaui_pcs_ra_ingress_4o},
	{1, cs4321_init_dpath_xaui_pcs_ra_ingress_5},
	{1, cs4321_init_dpath_xaui_pcs_ra_6o},
	/*{1, cs4321_init_line_power_down},*/

	/* dpath egress even and odd */
	{0, cs4321_init_dpath_xaui_pcs_ra_egress_1},
	{0, cs4321_init_dpath_xaui_pcs_ra_2e},
	{0, cs4321_init_dpath_xaui_pcs_ra_egress_3},
	{0, cs4321_deassert_reset_egress_block},
	{0, cs4321_init_dpath_xaui_pcs_ra_egress_4e},
	{0, cs4321_init_dpath_xaui_pcs_ra_egress_5},
	{0, cs4321_init_dpath_xaui_pcs_ra_6e},

	{1, cs4321_init_dpath_xaui_pcs_ra_egress_1},
	{1, cs4321_init_dpath_xaui_pcs_ra_2o},
	{1, cs4321_init_dpath_xaui_pcs_ra_egress_3},
	{0, cs4321_deassert_reset_egress_block},
	{1, cs4321_init_dpath_xaui_pcs_ra_egress_4o},
	{1, cs4321_init_dpath_xaui_pcs_ra_egress_5},
	{1, cs4321_init_dpath_xaui_pcs_ra_6o},

	/* power down the odd slice's line side */
	/*	{1, cs4321_init_line_power_down}, */

	{0, cs4321_resync_vcos_xaui_rxaui},
	{0, cs4321_powerup_ml_serdes},
	{0, cs4321_toggle_resets_xaui_rxaui},
	{0, cs4321_hsif_elec_mode_set_sr_pre},
	{0, cs4321_hsif_elec_mode_set_sr_2in},
	{0, cs4321_hsif_elec_mode_set_sr_post},
	{0, cs4321_init_trace_2in_host_xaui},
	{0, cs4321_trace_line_driver_2in},
	{0, cs4321_trace_line_equal_2in},
	{0, cs4321_init_global_timer_156_25},
	{0, cs4321_init_mac_latency},
	{0, cs4321_init_ref_clk_src_xaui_rxaui},
	{0, cs4321_init_polarity_inv},
	{1, cs4321_init_prefix_seq},
	{1, cs4321_init_lane_swap_xaui_rxaui},
	{1, cs4321_init_line_power_down},
	{1, cs4321_resync_vcos_xaui_rxaui},
	{1, cs4321_powerup_ml_serdes},
	{1, cs4321_toggle_resets_xaui_rxaui},
	{1, cs4321_hsif_elec_mode_set_none},
	{1, cs4321_init_trace_2in_host_xaui},
	{1, cs4321_trace_line_equal_2in},
	{1, cs4321_trace_line_driver_2in},
	{1, cs4321_init_global_timer_156_25},
	{1, cs4321_init_mac_latency},
	{1, cs4321_init_ref_clk_src_xaui_rxaui},
	{1, cs4321_init_polarity_inv},

	{0, NULL}
};

const struct cs4321_multi_seq cs4321_init_sgmii_seq[] = {
	{0, cs4321_init_prefix_seq},
	{0, cs4321_init_egress_host_rx_1g},
	{0, cs4321_init_egress_line_rx_1g},
	{0, cs4321_init_unlock_tx_elastic_store_host},
	{0, cs4321_init_egress_local_host_timing_mux_demux},

	{0, cs4321_init_ingress_line_rx_1g},
	{0, cs4321_init_ingress_host_rx_1g},
	{0, cs4321_init_egress_host_through_timing_1g},
	{0, cs4321_init_ingress_through_timing_mux_demux},
	{0, cs4321_init_dpath_ingress_ra_1g},
	{0, cs4321_powerdown_ml_serdes},
	{0, cs4321_init_dpath_egress_ra_1g},
	{0, cs4321_resync_vcos_1g},
	{0, cs4321_soft_reset},
	{0, cs4321_init_line_if_mode_none},
	{0, cs4321_init_global_timer_100},
	{0, cs4321_init_mac_latency},
	{0, cs4321_init_ref_clk_src},
	{0, cs4321_init_polarity_inv},
	{0, cs4321_init_rate_adj_1g},
	{0, cs4321_init_host_frac_1g},
	{0, cs4321_init_line_frac_1g},
	{0, cs4321_retrigger_vcos_1g},
	{0, cs4321_enable_aneg_1g},
	{0, NULL}
};

static int cs4321_phy_read_x(struct phy_device *phydev, int off, u16 regnum)
{
	return mdiobus_read(phydev->mdio.bus, phydev->mdio.addr + off,
			    MII_ADDR_C45 | regnum);
}

static int cs4321_phy_write_x(struct phy_device *phydev, int off,
			      u16 regnum, u16 val)
{
	return mdiobus_write(phydev->mdio.bus, phydev->mdio.addr + off,
			     MII_ADDR_C45 | regnum, val);
}
static int cs4321_phy_read(struct phy_device *phydev, u16 regnum)
{
	return cs4321_phy_read_x(phydev, 0, regnum);
}

static int cs4321_phy_write(struct phy_device *phydev, u16 regnum, u16 val)
{
	return cs4321_phy_write_x(phydev, 0, regnum, val);
}

static int cs4321_write_seq_x(struct phy_device *phydev, int off,
			    const struct cs4321_reg_modify *seq)
{
	int last_reg = -1;
	int last_val = 0;
	int ret = 0;

	while (seq->reg) {
		if (seq->mask_bits) {
			if (last_reg != seq->reg) {
				ret = cs4321_phy_read_x(phydev, off, seq->reg);
				if (ret < 0)
					goto err;
				last_val = ret;
			}
			last_val &= seq->mask_bits;
		} else {
			last_val = 0;
		}
		last_val |= seq->set_bits;
		ret = cs4321_phy_write_x(phydev, off, seq->reg, last_val);
		if (ret < 0)
			goto err;
		seq++;
	}
err:
	return ret;
}

static int cs4321_write_multi_seq(struct phy_device *phydev,
				  const struct cs4321_multi_seq *m)
{
	int ret = 0;

	while (m->seq) {
		ret = cs4321_write_seq_x(phydev, m->reg_offset, m->seq);
		if (ret)
			goto err;
		m++;
	}

err:
	return ret;
}

static int cs4321_write_seq(struct phy_device *phydev,
			    const struct cs4321_reg_modify *seq)
{
	return cs4321_write_seq_x(phydev, 0, seq);
}

static int cs4321_write_microcode_bank(struct phy_device *phydev,
					uint16_t bank_start_addr,
					uint32_t data[], int size)
{
	int i;
	int ret;

	for (i = 0; i < size; i++) {
		ret = cs4321_phy_write(phydev,
					0x0201,
					data[i] >> 16);
		if (ret)
			return ret;

		ret = cs4321_phy_write(phydev,
					0x0202,
					data[i] & 0xffff);
		if (ret)
			return ret;
		ret = cs4321_phy_write(phydev, 0x0200, bank_start_addr + i);
		if (ret)
			return ret;
	}
	return 0;
}

static int cs4321_write_microcode(struct phy_device *phydev)
{
	int ret;
	int bank;
	int checksum_status;

	ret = cs4321_write_seq(phydev, cs4321_pre_ucode_load_init);
	if (ret) {
		printk(KERN_ERR "Error writing CS4321 pre-ucode load init\n");
		return ret;
	}

	for (bank = 0; bank < CS4321_BANK_COUNT; bank++) {
		ret = cs4321_phy_write(phydev, CS4321_MSEQ_BANKSELECT, bank);
		if (ret) {
			printk(KERN_ERR "Error selecting bank %d\n", bank);
			return ret;
		}

		ret = cs4321_write_microcode_bank(phydev,
					CS4321_BANK_START_ADDR,
					cs4321_microcode_image_banks[bank],
					CS4321_BANK_SIZE);
		if (ret) {
			printk(KERN_ERR "Error writing CS4321 firmware bank %d\n",
					bank);
			return ret;
		}
	}

	ret = cs4321_write_microcode_bank(phydev,
					CS4321_BANK_OTHER_START_ADDR,
					cs4321_microcode_image_other,
					CS4321_BANK_OTHER_SIZE);
	if (ret) {
		printk(KERN_ERR "Error writing CS4321 other bank\n");
		return ret;
	}

	ret = cs4321_write_seq(phydev, cs4321_post_ucode_load_init);
	if (ret)
		return ret;

	checksum_status = cs4321_phy_read(phydev,
					CS4321_GLOBAL_DWNLD_CHECKSUM_STATUS);
	if (checksum_status == 0x1) {
		printk(KERN_ERR "Firmware checksum status error\n");
		ret = -1;
	}
	return ret;
}

static int cs4321_reset(struct phy_device *phydev)
{
	int ret;
	int retry;
	struct cs4321_private *p = phydev->priv;

	ret = cs4321_phy_write(phydev, CS4321_GLOBAL_MPIF_SOFT_RESET, 0xdead);
	if (ret)
		goto err;

	msleep(100);

	/* Disable eeprom loading */
	ret = cs4321_phy_write(phydev, CS4321_EEPROM_LOADER_CONTROL, 2);
	if (ret)
		goto err;

	retry = 0;
	do {
		if (retry > 0)
			mdelay(1);
		ret = cs4321_phy_read(phydev, CS4321_EEPROM_LOADER_STATUS);
		if (ret < 0)
			goto err;
		retry++;
	} while ((ret & 4) == 0 && retry < 10);

	if ((ret & 4) == 0) {
		ret = -ENXIO;
		goto err;
	}

	msleep(10);

	if (p->mode != SGMII) {
		ret = cs4321_write_microcode(phydev);
		if (ret)
			goto err;
	}

	ret = cs4321_write_seq(phydev, cs4321_68xx_4_nic_init);
	if (ret)
		goto err;

err:
	return ret;
}

int cs4321_init_sgmii(struct phy_device *phydev)
{
	return cs4321_write_multi_seq(phydev, cs4321_init_sgmii_seq);
}

int cs4321_read_status(struct phy_device *phydev)
{
	struct cs4321_private *p = phydev->priv;
	int value = 0;

	if (p->mode != SGMII) {
		value = cs4321_phy_read(phydev, CS4321_GPIO_GPIO_INTS);
		if (value < 0)
			goto err;
		phydev->speed = SPEED_10000;
		phydev->duplex = DUPLEX_FULL;
		phydev->link = !!(value & 3);
	} else {
		value = cs4321_phy_read(phydev, CS4321_GIGEPCS_LINE_STATUS);
		phydev->speed = SPEED_1000;
		phydev->duplex = DUPLEX_FULL;
		phydev->link = !!(value & 4);
	}

err:
	return (value < 0 ? -1 : 0);
}

int cs4321_init_rxaui(struct phy_device *phydev)
{
	return cs4321_write_multi_seq(phydev,
				      cs4321_init_rxaui_seq);
}

int cs4321_init_xaui(struct phy_device *phydev)
{
	return cs4321_write_multi_seq(phydev,
				      cs4321_init_xaui_seq);

}

int cs4321_config_init(struct phy_device *phydev)
{
	int ret;
	struct cs4321_private *p = phydev->priv;
	const struct cs4321_multi_seq *init_seq;

	ret = cs4321_reset(phydev);
	if (ret) {
		printk(KERN_ERR "Error initializing CS4321 PHY device\n");
		goto err;
	}

printk("mode = %d\n", p->mode);
	switch (p->mode) {
	case RXAUI:
		init_seq = cs4321_init_rxaui_seq;
		break;
	case XAUI:
		init_seq = cs4321_init_xaui_seq;
		break;
	case SGMII:
		init_seq = cs4321_init_sgmii_seq;
printk("initializing sgmii seq\n");
		break;
	default:
		printk(KERN_ERR "Unknown host mode for CS4321 PHY device\n");
		return -1;
	}

	ret = cs4321_write_multi_seq(phydev, init_seq);
	if (ret < 0)
		goto err;

	ret = cs4321_read_status(phydev);

	/* Enable autonegotiation. */
	phydev->autoneg = AUTONEG_ENABLE;

err:
	return ret;
}

int cs4321_probe(struct phy_device *phydev)
{
	int ret = 0;
	int id_lsb, id_msb;
	enum cs4321_host_mode host_mode;
	const char *prop_val;
	struct cs4321_private *p;
	/*
	 * CS4312 keeps its ID values in non-standard registers, make
	 * sure we are talking to what we think we are.
	 */
	id_lsb = cs4321_phy_read(phydev, CS4321_GLOBAL_CHIP_ID_LSB);
	if (id_lsb < 0) {
		ret = id_lsb;
		goto err;
	}
	id_msb = cs4321_phy_read(phydev, CS4321_GLOBAL_CHIP_ID_MSB);
	if (id_msb < 0) {
		ret = id_msb;
		goto err;
	}

	if (id_lsb != 0x23E5 || id_msb != 0x1002) {
		ret = -ENODEV;
		goto err;
	}
	ret = of_property_read_string(phydev->mdio.dev.of_node,
				      "cortina,host-mode", &prop_val);
	if (ret)
		goto err;

	if (strcmp(prop_val, "rxaui") == 0)
		host_mode = RXAUI;
	else if (strcmp(prop_val, "xaui") == 0)
		host_mode = XAUI;
	else if (strcmp(prop_val, "sgmii") == 0)
		host_mode = SGMII;
	else {
		dev_err(&phydev->mdio.dev,
			"Invalid \"cortina,host-mode\" property: \"%s\"\n",
			prop_val);
		ret = -EINVAL;
		goto err;
	}
	p = devm_kzalloc(&phydev->mdio.dev, sizeof(*p), GFP_KERNEL);
	if (!p) {
		ret = -ENOMEM;
		goto err;
	}
	p->mode = host_mode;
	phydev->priv = p;
err:
	return ret;
}

int cs4321_config_aneg(struct phy_device *phydev)
{
	int err;

	err = genphy_config_aneg(phydev);
	if (err < 0)
		return err;

	return 0;
}

static struct of_device_id cs4321_match[] = {
	{
		.compatible = "cortina,cs4321",
	},
	{
		.compatible = "cortina,cs4318",
	},
	{},
};
MODULE_DEVICE_TABLE(of, cs4321_match);

static struct phy_driver cs4321_phy_driver = {
	.phy_id		= 0xffffffff,
	.phy_id_mask	= 0xffffffff,
	.name		= "Cortina CS4321",
	.config_init	= cs4321_config_init,
	.probe		= cs4321_probe,
	.config_aneg	= cs4321_config_aneg,
	.read_status	= cs4321_read_status,
	.mdiodrv.driver		= {
		/* .owner = THIS_MODULE, */
		.of_match_table = cs4321_match,
	},
};

static int __init cs4321_drv_init(void)
{
	int ret;

	ret = phy_driver_register(&cs4321_phy_driver, THIS_MODULE);

	return ret;
}
module_init(cs4321_drv_init);

static void __exit cs4321_drv_exit(void)
{
	phy_driver_unregister(&cs4321_phy_driver);
}
module_exit(cs4321_drv_exit);
