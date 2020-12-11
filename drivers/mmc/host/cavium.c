/*
 * Shared part of driver for MMC/SDHC controller on Cavium OCTEON and
 * ThunderX SOCs.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2012-2017 Cavium Inc.
 * Authors:
 *   David Daney <david.daney@cavium.com>
 *   Peter Swain <pswain@cavium.com>
 *   Steven J. Hill <steven.hill@cavium.com>
 *   Jan Glauber <jglauber@cavium.com>
 */
#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/slot-gpio.h>
#include <linux/module.h>
#include <linux/regulator/consumer.h>
#include <linux/scatterlist.h>
#include <linux/time.h>
#include <linux/iommu.h>
#include <linux/swiotlb.h>

#include "cavium.h"

const char *cvm_mmc_irq_names[] = {
	"MMC Buffer",
	"MMC Command",
	"MMC DMA",
	"MMC Command Error",
	"MMC DMA Error",
	"MMC Switch",
	"MMC Switch Error",
	"MMC DMA int Fifo",
	"MMC DMA int",
	"MMC NCB Fault",
	"MMC RAS",
};

/*
 * The Cavium MMC host hardware assumes that all commands have fixed
 * command and response types.  These are correct if MMC devices are
 * being used.  However, non-MMC devices like SD use command and
 * response types that are unexpected by the host hardware.
 *
 * The command and response types can be overridden by supplying an
 * XOR value that is applied to the type.  We calculate the XOR value
 * from the values in this table and the flags passed from the MMC
 * core.
 */
static struct cvm_mmc_cr_type cvm_mmc_cr_types[] = {
	{0, 0},		/* CMD0 */
	{0, 3},		/* CMD1 */
	{0, 2},		/* CMD2 */
	{0, 1},		/* CMD3 */
	{0, 0},		/* CMD4 */
	{0, 1},		/* CMD5 */
	{0, 1},		/* CMD6 */
	{0, 1},		/* CMD7 */
	{1, 1},		/* CMD8 */
	{0, 2},		/* CMD9 */
	{0, 2},		/* CMD10 */
	{1, 1},		/* CMD11 */
	{0, 1},		/* CMD12 */
	{0, 1},		/* CMD13 */
	{1, 1},		/* CMD14 */
	{0, 0},		/* CMD15 */
	{0, 1},		/* CMD16 */
	{1, 1},		/* CMD17 */
	{1, 1},		/* CMD18 */
	{2, 1},		/* CMD19 */
	{2, 1},		/* CMD20 */
	{0, 0},		/* CMD21 */
	{0, 0},		/* CMD22 */
	{0, 1},		/* CMD23 */
	{2, 1},		/* CMD24 */
	{2, 1},		/* CMD25 */
	{2, 1},		/* CMD26 */
	{2, 1},		/* CMD27 */
	{0, 1},		/* CMD28 */
	{0, 1},		/* CMD29 */
	{1, 1},		/* CMD30 */
	{1, 1},		/* CMD31 */
	{0, 0},		/* CMD32 */
	{0, 0},		/* CMD33 */
	{0, 0},		/* CMD34 */
	{0, 1},		/* CMD35 */
	{0, 1},		/* CMD36 */
	{0, 0},		/* CMD37 */
	{0, 1},		/* CMD38 */
	{0, 4},		/* CMD39 */
	{0, 5},		/* CMD40 */
	{0, 0},		/* CMD41 */
	{2, 1},		/* CMD42 */
	{0, 0},		/* CMD43 */
	{0, 0},		/* CMD44 */
	{0, 0},		/* CMD45 */
	{0, 0},		/* CMD46 */
	{0, 0},		/* CMD47 */
	{0, 0},		/* CMD48 */
	{0, 0},		/* CMD49 */
	{0, 0},		/* CMD50 */
	{0, 0},		/* CMD51 */
	{0, 0},		/* CMD52 */
	{0, 0},		/* CMD53 */
	{0, 0},		/* CMD54 */
	{0, 1},		/* CMD55 */
	{0xff, 0xff},	/* CMD56 */
	{0, 0},		/* CMD57 */
	{0, 0},		/* CMD58 */
	{0, 0},		/* CMD59 */
	{0, 0},		/* CMD60 */
	{0, 0},		/* CMD61 */
	{0, 0},		/* CMD62 */
	{0, 0}		/* CMD63 */
};

/*
 * EMM_CMD hold time from rising edge of EMMC_CLK.
 * Typically 3.0 ns at frequencies < 26 MHz.
 * Typically 3.0 ns at frequencies <= 52 MHz SDR.
 * Typically 2.5 ns at frequencies <= 52 MHz DDR.
 * Typically 0.8 ns at frequencies > 52 MHz SDR.
 * Typically 0.8 ns at frequencies > 52 MHz DDR.
 *
 * Values are expressed in picoseconds (ps)
 */
static const u32 default_cmd_out_taps_dly[MMC_OUT_TAPS_DELAY_COUNT] = {
	5000, /* Legacy */
	2500, /* MMC_HS */
	2000, /* SD_HS */
	3000, /* UHS_SDR12 */
	2000, /* UHS_SDR25 */
	2000, /* UHS_SDR50 */
	 800, /* UHS_SDR104 */
	1500, /* UHS_DDR50 */
	1500, /* MMC_DDR52 */
	 800, /* HS200 */
	 800  /* HS400 */
};

/* Hints are expressed as number of taps (clock cycles) */
static const u32 default_hints_taps_dly[MMC_OUT_TAPS_DELAY_COUNT] = {
	39, /* Legacy */
	32, /* MMC_HS */
	26, /* SD_HS */
	39, /* UHS_SDR12 */
	26, /* UHS_SDR25 */
	26, /* UHS_SDR50 */
	10, /* UHS_SDR104 */
	20, /* UHS_DDR50 */
	20, /* MMC_DDR52 */
	10, /* HS200 */
	10  /* HS400 */
};

static const char * const mmc_modes_name[] = {
	"Legacy",
	"MMC HS",
	"SD HS",
	"SD UHS SDR12",
	"SD UHS SDR25",
	"SD UHS SDR50",
	"SD UHS SDR104",
	"SD UHS DDR50",
	"MMC DDR52",
	"MMC HS200",
	"MMC HS400"
};

static int tapdance;
module_param(tapdance, int, 0644);
MODULE_PARM_DESC(tapdance, "adjust bus-timing: (0=mid-eye, positive=Nth_fastest_tap)");

static int clk_scale = 100;
module_param(clk_scale, int, 0644);
MODULE_PARM_DESC(clk_scale, "percent scale data_/cmd_out taps (default 100)");

static bool fixed_timing;
module_param(fixed_timing, bool, 0444);
MODULE_PARM_DESC(fixed_timing, "use fixed data_/cmd_out taps");

static bool ddr_cmd_taps;
module_param(ddr_cmd_taps, bool, 0644);
MODULE_PARM_DESC(ddr_cmd_taps, "reduce cmd_out_taps in DDR modes, as before");

static bool __cvm_is_mmc_timing_ddr(unsigned char timing)
{
	switch (timing) {
	case MMC_TIMING_UHS_DDR50:
	case MMC_TIMING_MMC_DDR52:
	case MMC_TIMING_MMC_HS400:
		return true;
	default:
		return false;
	}
	return false;
}

bool cvm_is_mmc_timing_ddr(struct cvm_mmc_slot *slot)
{
	return __cvm_is_mmc_timing_ddr(slot->mmc->ios.timing);
}

static void cvm_mmc_clk_config(struct cvm_mmc_host *host, bool flag)
{
	u64 emm_debug;

	if (!host->tap_requires_noclk)
		return;

	/* Turn off the clock */
	if (flag) {
		emm_debug = readq(host->base + MIO_EMM_DEBUG(host));
		emm_debug |= MIO_EMM_DEBUG_CLK_DIS;
		writeq(emm_debug, host->base + MIO_EMM_DEBUG(host));
		udelay(1);
		emm_debug = readq(host->base + MIO_EMM_DEBUG(host));
		emm_debug |= MIO_EMM_DEBUG_RDSYNC;
		writeq(emm_debug, host->base + MIO_EMM_DEBUG(host));
		udelay(1);
	} else {
		/* Turn on the clock */
		emm_debug = readq(host->base + MIO_EMM_DEBUG(host));
		emm_debug &= MIO_EMM_DEBUG_RDSYNC;
		writeq(emm_debug, host->base + MIO_EMM_DEBUG(host));
		udelay(1);
		emm_debug = readq(host->base + MIO_EMM_DEBUG(host));
		emm_debug &= MIO_EMM_DEBUG_CLK_DIS;
		writeq(emm_debug, host->base + MIO_EMM_DEBUG(host));
		udelay(1);
	}
}

static void cvm_mmc_set_timing(struct cvm_mmc_slot *slot)
{
	struct cvm_mmc_host *host = slot->host;

	if (is_mmc_8xxx(host))
		return;

	cvm_mmc_clk_config(host, CLK_OFF);
	writeq(slot->taps, host->base + MIO_EMM_TIMING(host));
	cvm_mmc_clk_config(host, CLK_ON);
}

static int tout(struct cvm_mmc_slot *slot, int ps, int hint)
{
	struct cvm_mmc_host *host = slot->host;
	struct mmc_host *mmc = slot->mmc;
	int tap_ps = host->per_tap_delay;
	int timing = mmc->ios.timing;
	static int old_scale;
	int taps;

	if (fixed_timing)
		return hint;

	if (!hint)
		hint = 63;

	if (!tap_ps)
		return hint;

	taps = min_t(int, DIV_ROUND_UP(ps * clk_scale, (tap_ps * 100)), 63);

	/* when modparam is adjusted, re-announce timing */
	if (old_scale != clk_scale) {
		host->delay_logged = 0;
		old_scale = clk_scale;
	}

	if (!test_and_set_bit(timing,
			&host->delay_logged))
		dev_info(host->dev, "mmc%d.ios_timing:%d %dpS hint:%d taps:%d\n",
			mmc->index, timing, ps, hint, taps);

	return taps;
}

static int cvm_mmc_configure_delay(struct cvm_mmc_slot *slot)
{
	struct cvm_mmc_host *host = slot->host;
	struct mmc_host *mmc = slot->mmc;
	const char *mode;

	pr_debug("slot%d.configure_delay\n", slot->bus_id);

	if (is_mmc_8xxx(host)) {
		/* MIO_EMM_SAMPLE is till T83XX */
		u64 emm_sample =
			FIELD_PREP(MIO_EMM_SAMPLE_CMD_CNT, slot->cmd_cnt) |
			FIELD_PREP(MIO_EMM_SAMPLE_DAT_CNT, slot->data_cnt);
		writeq(emm_sample, host->base + MIO_EMM_SAMPLE(host));
	} else {
		int half = MAX_NO_OF_TAPS / 2;
		int cin = FIELD_GET(MIO_EMM_TIMING_CMD_IN, slot->taps);
		int din = FIELD_GET(MIO_EMM_TIMING_DATA_IN, slot->taps);
		int cout, dout;

		if (!slot->taps)
			cin = din = half;

		dev_dbg(host->dev, "%s: mode=%s, cmd=%ups, data=%ups\n",
			__func__, mmc_modes_name[mmc->ios.timing],
			slot->cmd_out_taps_dly[mmc->ios.timing],
			slot->data_out_taps_dly[mmc->ios.timing]);
		/* Configure timings */
		cout = tout(slot,
			    slot->cmd_out_taps_dly[mmc->ios.timing],
			    default_hints_taps_dly[mmc->ios.timing]);
		dout = tout(slot,
			    slot->data_out_taps_dly[mmc->ios.timing],
			    default_hints_taps_dly[mmc->ios.timing]);
		mode = mmc_modes_name[mmc->ios.timing];

		dev_dbg(host->dev,
			"%s: command in tap: %d, command out tap: %d, data in tap: %d, data out tap: %d\n",
			mode, cin, cout, din, dout);
		slot->taps =
			FIELD_PREP(MIO_EMM_TIMING_CMD_IN, cin) |
			FIELD_PREP(MIO_EMM_TIMING_CMD_OUT, cout) |
			FIELD_PREP(MIO_EMM_TIMING_DATA_IN, din) |
			FIELD_PREP(MIO_EMM_TIMING_DATA_OUT, dout);

		pr_debug("slot%d.taps %llx\n", slot->bus_id, slot->taps);
		cvm_mmc_set_timing(slot);
	}

	return 0;
}

static struct cvm_mmc_cr_mods cvm_mmc_get_cr_mods(struct mmc_command *cmd)
{
	struct cvm_mmc_cr_type *cr;
	u8 hardware_ctype, hardware_rtype;
	u8 desired_ctype = 0, desired_rtype = 0;
	struct cvm_mmc_cr_mods r;

	cr = cvm_mmc_cr_types + (cmd->opcode & 0x3f);
	hardware_ctype = cr->ctype;
	hardware_rtype = cr->rtype;
	if (cmd->opcode == MMC_GEN_CMD)
		hardware_ctype = (cmd->arg & 1) ? 1 : 2;

	switch (mmc_cmd_type(cmd)) {
	case MMC_CMD_ADTC:
		desired_ctype = (cmd->data->flags & MMC_DATA_WRITE) ? 2 : 1;
		break;
	case MMC_CMD_AC:
	case MMC_CMD_BC:
	case MMC_CMD_BCR:
		desired_ctype = 0;
		break;
	}

	switch (mmc_resp_type(cmd)) {
	case MMC_RSP_NONE:
		desired_rtype = 0;
		break;
	case MMC_RSP_R1:/* MMC_RSP_R5, MMC_RSP_R6, MMC_RSP_R7 */
	case MMC_RSP_R1B:
		desired_rtype = 1;
		break;
	case MMC_RSP_R2:
		desired_rtype = 2;
		break;
	case MMC_RSP_R3: /* MMC_RSP_R4 */
		desired_rtype = 3;
		break;
	}
	r.ctype_xor = desired_ctype ^ hardware_ctype;
	r.rtype_xor = desired_rtype ^ hardware_rtype;
	return r;
}

static void check_switch_errors(struct cvm_mmc_host *host)
{
	u64 emm_switch;

	emm_switch = readq(host->base + MIO_EMM_SWITCH(host));
	if (emm_switch & MIO_EMM_SWITCH_ERR0)
		dev_err(host->dev, "Switch power class error\n");
	if (emm_switch & MIO_EMM_SWITCH_ERR1)
		dev_err(host->dev, "Switch hs timing error\n");
	if (emm_switch & MIO_EMM_SWITCH_ERR2)
		dev_err(host->dev, "Switch bus width error\n");
}

static inline void clear_bus_id(u64 *reg)
{
	u64 bus_id_mask = GENMASK_ULL(61, 60);

	*reg &= ~bus_id_mask;
}

static inline void set_bus_id(u64 *reg, int bus_id)
{
	clear_bus_id(reg);
	*reg |= FIELD_PREP(GENMASK(61, 60), bus_id);
}

static int get_bus_id(u64 reg)
{
	return FIELD_GET(GENMASK_ULL(61, 60), reg);
}

/* save old slot details, switch power */
static bool pre_switch(struct cvm_mmc_host *host, u64 emm_switch)
{
	int bus_id = get_bus_id(emm_switch);
	struct cvm_mmc_slot *slot = host->slot[bus_id];
	struct cvm_mmc_slot *old_slot;
	bool same_vqmmc = false;

	if (host->last_slot == bus_id)
		return false;

	/* when VQMMC is switched, tri-state CMDn over any slot change
	 * to avoid transient states on D0-7 or CLK from level-shifters
	 */
	if (host->use_vqmmc) {
		writeq(1ull << 3, host->base + MIO_EMM_CFG(host));
		udelay(10);
	}

	if (host->last_slot >= 0 && host->slot[host->last_slot]) {
		old_slot = host->slot[host->last_slot];
		old_slot->cached_switch =
		    readq(host->base + MIO_EMM_SWITCH(host));
		old_slot->cached_rca = readq(host->base + MIO_EMM_RCA(host));

		same_vqmmc = (slot->mmc->supply.vqmmc ==
				old_slot->mmc->supply.vqmmc);
		if (!same_vqmmc && !IS_ERR_OR_NULL(old_slot->mmc->supply.vqmmc))
			regulator_disable(old_slot->mmc->supply.vqmmc);
	}

	if (!same_vqmmc && !IS_ERR_OR_NULL(slot->mmc->supply.vqmmc)) {
		int e = regulator_enable(slot->mmc->supply.vqmmc);

		if (e)
			dev_err(host->dev, "mmc-slot@%d.vqmmc err %d\n",
						bus_id, e);
	}

	host->last_slot = slot->bus_id;

	return true;
}

static void post_switch(struct cvm_mmc_host *host, u64 emm_switch)
{
	int bus_id = get_bus_id(emm_switch);
	struct cvm_mmc_slot *slot = host->slot[bus_id];

	if (host->use_vqmmc) {
		/* enable new CMDn */
		writeq(1ull << bus_id, host->base + MIO_EMM_CFG(host));
		udelay(10);
	}

	writeq(slot->cached_rca, host->base + MIO_EMM_RCA(host));
}

static inline void mode_switch(struct cvm_mmc_host *host, u64 emm_switch)
{
	u64 rsp_sts;
	int retries = 100;

	writeq(emm_switch, host->base + MIO_EMM_SWITCH(host));

	/* wait for the switch to finish */
	do {
		rsp_sts = readq(host->base + MIO_EMM_RSP_STS(host));
		if (!(rsp_sts & MIO_EMM_RSP_STS_SWITCH_VAL))
			break;
		udelay(10);
	} while (--retries);
}

/*
 * We never set the switch_exe bit since that would interfere
 * with the commands send by the MMC core.
 */
static void do_switch(struct cvm_mmc_host *host, u64 emm_switch)
{
	int bus_id = get_bus_id(emm_switch);
	struct cvm_mmc_slot *slot = host->slot[bus_id];
	bool slot_changed = pre_switch(host, emm_switch);

	/*
	 * Modes setting only taken from slot 0. Work around that hardware
	 * issue by first switching to slot 0.
	 */
	if (bus_id) {
		u64 switch0 = emm_switch;

		clear_bus_id(&switch0);
		mode_switch(host, switch0);
	}

	mode_switch(host, emm_switch);

	check_switch_errors(host);

	if (slot_changed)
		post_switch(host, emm_switch);
	slot->cached_switch = emm_switch;
	if (emm_switch & MIO_EMM_SWITCH_CLK)
		slot->cmd6_pending = false;
}

/* need to change hardware state to match software requirements? */
static bool switch_val_changed(struct cvm_mmc_slot *slot, u64 new_val)
{
	/* Match BUS_ID, HS_TIMING, BUS_WIDTH, POWER_CLASS, CLK_HI, CLK_LO */
	/* For 9xxx add HS200_TIMING and HS400_TIMING */
	u64 match = (is_mmc_8xxx(slot->host)) ?
		0x3001070fffffffffull : 0x3007070fffffffffull;

	if (!slot->host->powered)
		return true;
	return (slot->cached_switch & match) != (new_val & match);
}

static void set_wdog(struct cvm_mmc_slot *slot, unsigned int ns)
{
	u64 timeout;

	if (!slot->clock)
		return;

	if (ns)
		timeout = (slot->clock * ns) / NSEC_PER_SEC;
	else
		timeout = (slot->clock * 850ull) / 1000ull;
	writeq(timeout, slot->host->base + MIO_EMM_WDOG(slot->host));
}

static void emmc_io_drive_setup(struct cvm_mmc_slot *slot)
{
	u64 ioctl_cfg;
	struct cvm_mmc_host *host = slot->host;

	if (!is_mmc_8xxx(host)) {
		if ((slot->drive < 0) || (slot->slew < 0))
			return;
		/* Setup the emmc interface current drive
		 * strength & clk slew rate.
		 */
		ioctl_cfg = FIELD_PREP(MIO_EMM_IO_CTL_DRIVE, slot->drive) |
			FIELD_PREP(MIO_EMM_IO_CTL_SLEW, slot->slew);
		writeq(ioctl_cfg, host->base + MIO_EMM_IO_CTL(host));
	}
}

static void cvm_mmc_reset_bus(struct cvm_mmc_slot *slot)
{
	struct cvm_mmc_host *host = slot->host;
	u64 emm_switch, wdog;

	emm_switch = readq(host->base + MIO_EMM_SWITCH(host));
	emm_switch &= ~(MIO_EMM_SWITCH_EXE | MIO_EMM_SWITCH_ERRS);
	set_bus_id(&emm_switch, slot->bus_id);

	wdog = readq(host->base + MIO_EMM_WDOG(host));
	do_switch(host, emm_switch);
	host->powered = true;

	msleep(20);

	writeq(wdog, host->base + MIO_EMM_WDOG(host));
}

/* Switch to another slot if needed */
static void cvm_mmc_switch_to(struct cvm_mmc_slot *slot)
{
	struct cvm_mmc_host *host = slot->host;

	if (slot->bus_id == host->last_slot)
		return;

	do_switch(host, slot->cached_switch);
	host->powered = true;

	emmc_io_drive_setup(slot);
	cvm_mmc_configure_delay(slot);
}

static void do_read(struct cvm_mmc_slot *slot, struct mmc_request *req,
		    u64 dbuf)
{
	struct cvm_mmc_host *host = slot->host;
	struct sg_mapping_iter *smi = &slot->smi;
	int data_len = req->data->blocks * req->data->blksz;
	int bytes_xfered, shift = -1;
	u64 dat = 0;

	/* Auto inc from offset zero */
	writeq((0x10000 | (dbuf << 6)), host->base + MIO_EMM_BUF_IDX(host));

	for (bytes_xfered = 0; bytes_xfered < data_len;) {
		if (smi->consumed >= smi->length) {
			if (!sg_miter_next(smi))
				break;
			smi->consumed = 0;
		}

		if (shift < 0) {
			dat = readq(host->base + MIO_EMM_BUF_DAT(host));
			shift = 56;
		}

		while (smi->consumed < smi->length && shift >= 0) {
			((u8 *)smi->addr)[smi->consumed] = (dat >> shift) & 0xff;
			bytes_xfered++;
			smi->consumed++;
			shift -= 8;
		}
	}

	sg_miter_stop(smi);
	req->data->bytes_xfered = bytes_xfered;
	req->data->error = 0;
}

static void do_write(struct mmc_request *req)
{
	req->data->bytes_xfered = req->data->blocks * req->data->blksz;
	req->data->error = 0;
}

static void set_cmd_response(struct cvm_mmc_host *host, struct mmc_request *req,
			     u64 rsp_sts)
{
	u64 rsp_hi, rsp_lo;

	if (!(rsp_sts & MIO_EMM_RSP_STS_RSP_VAL))
		return;

	rsp_lo = readq(host->base + MIO_EMM_RSP_LO(host));

	switch (FIELD_GET(MIO_EMM_RSP_STS_RSP_TYPE, rsp_sts)) {
	case 1:
	case 3:
		req->cmd->resp[0] = (rsp_lo >> 8) & 0xffffffff;
		req->cmd->resp[1] = 0;
		req->cmd->resp[2] = 0;
		req->cmd->resp[3] = 0;
		break;
	case 2:
		req->cmd->resp[3] = rsp_lo & 0xffffffff;
		req->cmd->resp[2] = (rsp_lo >> 32) & 0xffffffff;
		rsp_hi = readq(host->base + MIO_EMM_RSP_HI(host));
		req->cmd->resp[1] = rsp_hi & 0xffffffff;
		req->cmd->resp[0] = (rsp_hi >> 32) & 0xffffffff;
		break;
	}
}

static inline int get_dma_dir(struct mmc_data *data)
{
	return (data->flags & MMC_DATA_WRITE) ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
}

static int finish_dma_single(struct cvm_mmc_host *host, struct mmc_data *data)
{
	data->bytes_xfered = data->blocks * data->blksz;
	data->error = 0;

	writeq(MIO_EMM_DMA_FIFO_CFG_CLR,
		host->dma_base + MIO_EMM_DMA_FIFO_CFG(host));
	dma_unmap_sg(host->dev, data->sg, data->sg_len, get_dma_dir(data));
	return 1;
}

static int finish_dma_sg(struct cvm_mmc_host *host, struct mmc_data *data)
{
	u64 fifo_cfg;
	int count;
	void __iomem *dma_intp = host->dma_base + MIO_EMM_DMA_INT(host);

	/* Check if there are any pending requests left */
	fifo_cfg = readq(host->dma_base + MIO_EMM_DMA_FIFO_CFG(host));
	count = FIELD_GET(MIO_EMM_DMA_FIFO_CFG_COUNT, fifo_cfg);
	if (count)
		dev_err(host->dev, "%u requests still pending\n", count);

	data->bytes_xfered = data->blocks * data->blksz;
	data->error = 0;

	writeq(MIO_EMM_DMA_FIFO_CFG_CLR,
		host->dma_base + MIO_EMM_DMA_FIFO_CFG(host));

	/* on read, wait for internal buffer to flush out to mem */
	if (get_dma_dir(data) == DMA_FROM_DEVICE) {
		while (!(readq(dma_intp) & MIO_EMM_DMA_INT_DMA))
			udelay(10);
		writeq(MIO_EMM_DMA_INT_DMA, dma_intp);
	}

	dma_unmap_sg(host->dev, data->sg, data->sg_len, get_dma_dir(data));
	return 1;
}

static int finish_dma(struct cvm_mmc_host *host, struct mmc_data *data)
{
	if (host->use_sg && data->sg_len > 1)
		return finish_dma_sg(host, data);
	else
		return finish_dma_single(host, data);
}

static int check_status(u64 rsp_sts)
{
	if (rsp_sts & MIO_EMM_RSP_STS_RSP_BAD_STS ||
	    rsp_sts & MIO_EMM_RSP_STS_RSP_CRC_ERR ||
	    rsp_sts & MIO_EMM_RSP_STS_BLK_CRC_ERR)
		return -EILSEQ;
	if (rsp_sts & MIO_EMM_RSP_STS_RSP_TIMEOUT ||
	    rsp_sts & MIO_EMM_RSP_STS_BLK_TIMEOUT)
		return -ETIMEDOUT;
	if (rsp_sts & MIO_EMM_RSP_STS_DBUF_ERR ||
	    rsp_sts & MIO_EMM_RSP_STS_BLK_CRC_ERR)
		return -EIO;
	return 0;
}

/* Try to clean up failed DMA. */
static void cleanup_dma(struct cvm_mmc_host *host, u64 rsp_sts)
{
	u64 emm_dma;

	emm_dma = readq(host->base + MIO_EMM_DMA(host));
	emm_dma |= FIELD_PREP(MIO_EMM_DMA_VAL, 1) |
		   FIELD_PREP(MIO_EMM_DMA_DAT_NULL, 1);
	set_bus_id(&emm_dma, get_bus_id(rsp_sts));
	writeq(emm_dma, host->base + MIO_EMM_DMA(host));
}

irqreturn_t cvm_mmc_interrupt(int irq, void *dev_id)
{
	struct cvm_mmc_host *host = dev_id;
	struct mmc_request *req = NULL;
	struct mmc_host *mmc = NULL;
	struct cvm_mmc_slot *slot = NULL;
	unsigned long flags = 0;
	u64 emm_int, rsp_sts;
	int bus_id;
	bool host_done;

	if (host->need_irq_handler_lock)
		spin_lock_irqsave(&host->irq_handler_lock, flags);
	else
		__acquire(&host->irq_handler_lock);

	rsp_sts = readq(host->base + MIO_EMM_RSP_STS(host));
	bus_id = get_bus_id(rsp_sts);
	slot = host->slot[bus_id];
	if (slot)
		req = slot->current_req;

	emm_int = readq(host->base + MIO_EMM_INT(host));
	/*
	 * Multiple interrupts are handled here, so it is possible
	 * that the condition for this invocation was already handled
	 * by a previous interrupt.  If there is nothing pending, it
	 * must have previously been handled so just exit.
	 */
	if (!emm_int)
		goto out;
	/* Clear interrupt bits (write 1 clears ). */
	writeq(emm_int, host->base + MIO_EMM_INT(host));

	if (emm_int & MIO_EMM_INT_SWITCH_ERR)
		check_switch_errors(host);

	if (!req)
		goto out;

	mmc = req->host;

	/*
	 * dma_pend means DMA has stalled with CRC errs.
	 * start teardown, get irq on completion, mmc stack retries.
	 */
	if ((rsp_sts & MIO_EMM_RSP_STS_DMA_PEND) && slot->dma_active) {
		cleanup_dma(host, rsp_sts);
		goto out;
	}

	/*
	 * dma_val set means DMA is still in progress. Don't touch
	 * the request and wait for the interrupt indicating that
	 * the DMA is finished.
	 */
	if ((rsp_sts & MIO_EMM_RSP_STS_DMA_VAL) && slot->dma_active)
		goto out;

	if (!slot->dma_active && req->data &&
	    (emm_int & MIO_EMM_INT_BUF_DONE)) {
		unsigned int type = (rsp_sts >> 7) & 3;

		if (type == 1)
			do_read(slot, req, rsp_sts & MIO_EMM_RSP_STS_DBUF);
		else if (type == 2)
			do_write(req);
	}

	host_done = emm_int & MIO_EMM_INT_CMD_DONE ||
		    emm_int & MIO_EMM_INT_DMA_DONE ||
		    emm_int & MIO_EMM_INT_CMD_ERR  ||
		    emm_int & MIO_EMM_INT_DMA_ERR;

	/* Add NCB_FLT interrupt for octtx2 */
	if (!is_mmc_8xxx(host))
		host_done = host_done || emm_int & MIO_EMM_INT_NCB_FLT;

	if (!(host_done && req->done))
		goto no_req_done;

	req->cmd->error = check_status(rsp_sts);

	if (slot->dma_active && req->data)
		if (!finish_dma(host, req->data))
			goto no_req_done;

	set_cmd_response(host, req, rsp_sts);
	if ((emm_int & MIO_EMM_INT_DMA_ERR) &&
	    (rsp_sts & MIO_EMM_RSP_STS_DMA_PEND))
		cleanup_dma(host, rsp_sts);

	/* follow CMD6 timing/width with IMMEDIATE switch */
	if (slot && slot->cmd6_pending) {
		if (host_done && !req->cmd->error) {
			do_switch(host, slot->want_switch);
			emmc_io_drive_setup(slot);
			cvm_mmc_configure_delay(slot);
		} else if (slot) {
			slot->cmd6_pending = false;
		}
	}

	slot->current_req = NULL;
	req->done(req);

no_req_done:
	if (host->dmar_fixup_done)
		host->dmar_fixup_done(host);
	if (host_done)
		host->release_bus(host);
out:
	if (host->need_irq_handler_lock)
		spin_unlock_irqrestore(&host->irq_handler_lock, flags);
	else
		__release(&host->irq_handler_lock);
	return IRQ_RETVAL(emm_int != 0);
}

/*
 * Program DMA_CFG and if needed DMA_ADR.
 * Returns 0 on error, DMA address otherwise.
 */
static u64 prepare_dma_single(struct cvm_mmc_host *host, struct mmc_data *data)
{
	u64 dma_cfg, addr;
	int count, rw;

	count = dma_map_sg(host->dev, data->sg, data->sg_len,
			   get_dma_dir(data));
	if (!count)
		return 0;

	rw = (data->flags & MMC_DATA_WRITE) ? 1 : 0;
	dma_cfg = FIELD_PREP(MIO_EMM_DMA_CFG_EN, 1) |
		  FIELD_PREP(MIO_EMM_DMA_CFG_RW, rw);
#ifdef __LITTLE_ENDIAN
	dma_cfg |= FIELD_PREP(MIO_EMM_DMA_CFG_ENDIAN, 1);
#endif
	dma_cfg |= FIELD_PREP(MIO_EMM_DMA_CFG_SIZE,
			      (sg_dma_len(&data->sg[0]) / 8) - 1);

	addr = sg_dma_address(&data->sg[0]);
	if (!host->big_dma_addr)
		dma_cfg |= FIELD_PREP(MIO_EMM_DMA_CFG_ADR, addr);
	writeq(dma_cfg, host->dma_base + MIO_EMM_DMA_CFG(host));

	pr_debug("[%s] sg_dma_len: %u  total sg_elem: %d\n",
		 (rw) ? "W" : "R", sg_dma_len(&data->sg[0]), count);

	if (host->big_dma_addr)
		writeq(addr, host->dma_base + MIO_EMM_DMA_ADR(host));
	return addr;
}

/*
 * Queue complete sg list into the FIFO.
 * Returns 0 on error, 1 otherwise.
 */
static u64 prepare_dma_sg(struct cvm_mmc_host *host, struct mmc_data *data)
{
	struct scatterlist *sg;
	u64 fifo_cmd, addr;
	int count, i, rw;

	count = dma_map_sg(host->dev, data->sg, data->sg_len,
			   get_dma_dir(data));
	if (!count)
		return 0;
	if (count > 16)
		goto error;

	/* Enable FIFO by removing CLR bit */
	writeq(0, host->dma_base + MIO_EMM_DMA_FIFO_CFG(host));

	for_each_sg(data->sg, sg, count, i) {
		/* Program DMA address */
		addr = sg_dma_address(sg);
		if (addr & 7)
			goto error;
		writeq(addr, host->dma_base + MIO_EMM_DMA_FIFO_ADR(host));

		/*
		 * If we have scatter-gather support we also have an extra
		 * register for the DMA addr, so no need to check
		 * host->big_dma_addr here.
		 */
		rw = (data->flags & MMC_DATA_WRITE) ? 1 : 0;
		fifo_cmd = FIELD_PREP(MIO_EMM_DMA_FIFO_CMD_RW, rw);

		/* enable interrupts on the last element */
		fifo_cmd |= FIELD_PREP(MIO_EMM_DMA_FIFO_CMD_INTDIS,
				       (i + 1 == count) ? 0 : 1);

#ifdef __LITTLE_ENDIAN
		fifo_cmd |= FIELD_PREP(MIO_EMM_DMA_FIFO_CMD_ENDIAN, 1);
#endif
		fifo_cmd |= FIELD_PREP(MIO_EMM_DMA_FIFO_CMD_SIZE,
				       sg_dma_len(sg) / 8 - 1);
		/*
		 * The write copies the address and the command to the FIFO
		 * and increments the FIFO's COUNT field.
		 */
		writeq(fifo_cmd, host->dma_base + MIO_EMM_DMA_FIFO_CMD(host));
		pr_debug("[%s] sg_dma_len: %u  sg_elem: %d/%d\n",
			 (rw) ? "W" : "R", sg_dma_len(sg), i, count);
	}

	/*
	 * In difference to prepare_dma_single we don't return the
	 * address here, as it would not make sense for scatter-gather.
	 * The dma fixup is only required on models that don't support
	 * scatter-gather, so that is not a problem.
	 */
	return 1;

error:
	WARN_ON_ONCE(1);
	writeq(MIO_EMM_DMA_FIFO_CFG_CLR,
		host->dma_base + MIO_EMM_DMA_FIFO_CFG(host));
	dma_unmap_sg(host->dev, data->sg, data->sg_len, get_dma_dir(data));
	return 0;
}

static u64 prepare_dma(struct cvm_mmc_host *host, struct mmc_data *data)
{
	if (host->use_sg && data->sg_len > 1)
		return prepare_dma_sg(host, data);
	else
		return prepare_dma_single(host, data);
}

static u64 prepare_ext_dma(struct mmc_host *mmc, struct mmc_request *mrq)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	u64 emm_dma;

	emm_dma = FIELD_PREP(MIO_EMM_DMA_VAL, 1) |
		  FIELD_PREP(MIO_EMM_DMA_SECTOR,
			     mmc_card_is_blockaddr(mmc->card) ? 1 : 0) |
		  FIELD_PREP(MIO_EMM_DMA_RW,
			     (mrq->data->flags & MMC_DATA_WRITE) ? 1 : 0) |
		  FIELD_PREP(MIO_EMM_DMA_BLOCK_CNT, mrq->data->blocks) |
		  FIELD_PREP(MIO_EMM_DMA_CARD_ADDR, mrq->cmd->arg);
	set_bus_id(&emm_dma, slot->bus_id);

	if (mmc_card_mmc(mmc->card) || (mmc_card_sd(mmc->card) &&
	    (mmc->card->scr.cmds & SD_SCR_CMD23_SUPPORT)))
		emm_dma |= FIELD_PREP(MIO_EMM_DMA_MULTI, 1);

	pr_debug("[%s] blocks: %u  multi: %d\n",
		(emm_dma & MIO_EMM_DMA_RW) ? "W" : "R",
		 mrq->data->blocks, (emm_dma & MIO_EMM_DMA_MULTI) ? 1 : 0);
	return emm_dma;
}

static void cvm_mmc_dma_request(struct mmc_host *mmc,
				struct mmc_request *mrq)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct cvm_mmc_host *host = slot->host;
	struct mmc_data *data;
	u64 emm_dma, addr, int_enable_mask = 0;
	int seg;

	/* cleared by successful termination */
	mrq->cmd->error = -EINVAL;

	if (!mrq->data || !mrq->data->sg || !mrq->data->sg_len ||
	    !mrq->stop || mrq->stop->opcode != MMC_STOP_TRANSMISSION) {
		dev_err(&mmc->card->dev,
			"Error: cmv_mmc_dma_request no data\n");
		goto error;
	}

	/* unaligned multi-block DMA has problems, so forbid all unaligned */
	for (seg = 0; seg < mrq->data->sg_len; seg++) {
		struct scatterlist *sg = &mrq->data->sg[seg];
		u64 align = (sg->offset | sg->length | sg->dma_address);

		if (!(align & 7))
			continue;
		dev_info(&mmc->card->dev,
			"Error:64bit alignment required\n");
		goto error;
	}

	cvm_mmc_switch_to(slot);

	data = mrq->data;

	pr_debug("DMA request  blocks: %d  block_size: %d  total_size: %d\n",
		 data->blocks, data->blksz, data->blocks * data->blksz);
	if (data->timeout_ns)
		set_wdog(slot, data->timeout_ns);

	emm_dma = prepare_ext_dma(mmc, mrq);
	addr = prepare_dma(host, data);
	if (!addr) {
		dev_err(host->dev, "prepare_dma failed\n");
		goto error;
	}

	mrq->host = mmc;
	WARN_ON(slot->current_req);
	slot->current_req = mrq;
	slot->dma_active = true;

	int_enable_mask = MIO_EMM_INT_CMD_ERR | MIO_EMM_INT_DMA_DONE |
			MIO_EMM_INT_DMA_ERR;

	/* Add NCB_FLT interrupt for octtx2 */
	if (!is_mmc_8xxx(host))
		int_enable_mask |= MIO_EMM_INT_NCB_FLT;

	host->int_enable(host, int_enable_mask);

	if (host->dmar_fixup)
		host->dmar_fixup(host, mrq->cmd, data, addr);

	/*
	 * If we have a valid SD card in the slot, we set the response
	 * bit mask to check for CRC errors and timeouts only.
	 * Otherwise, use the default power reset value.
	 */
	if (mmc_card_sd(mmc->card))
		writeq(0x00b00000ull, host->base + MIO_EMM_STS_MASK(host));
	else
		writeq(0xe4390080ull, host->base + MIO_EMM_STS_MASK(host));
	writeq(emm_dma, host->base + MIO_EMM_DMA(host));
	return;

error:
	if (mrq->done)
		mrq->done(mrq);
	host->release_bus(host);
}

static void do_read_request(struct cvm_mmc_slot *slot, struct mmc_request *mrq)
{
	sg_miter_start(&slot->smi, mrq->data->sg, mrq->data->sg_len,
		       SG_MITER_ATOMIC | SG_MITER_TO_SG);
}

static void do_write_request(struct cvm_mmc_slot *slot, struct mmc_request *mrq)
{
	struct cvm_mmc_host *host = slot->host;
	unsigned int data_len = mrq->data->blocks * mrq->data->blksz;
	struct sg_mapping_iter *smi = &slot->smi;
	unsigned int bytes_xfered;
	int shift = 56;
	u64 dat = 0;

	/* Copy data to the xmit buffer before issuing the command. */
	sg_miter_start(smi, mrq->data->sg, mrq->data->sg_len, SG_MITER_FROM_SG);

	/* Auto inc from offset zero, dbuf zero */
	writeq(0x10000ull, host->base + MIO_EMM_BUF_IDX(host));

	for (bytes_xfered = 0; bytes_xfered < data_len;) {
		if (smi->consumed >= smi->length) {
			if (!sg_miter_next(smi))
				break;
			smi->consumed = 0;
		}

		while (smi->consumed < smi->length && shift >= 0) {
			dat |= ((u64)((u8 *)smi->addr)[smi->consumed]) << shift;
			bytes_xfered++;
			smi->consumed++;
			shift -= 8;
		}

		if (shift < 0) {
			writeq(dat, host->base + MIO_EMM_BUF_DAT(host));
			shift = 56;
			dat = 0;
		}
	}
	sg_miter_stop(smi);
}

static void cvm_mmc_track_switch(struct cvm_mmc_slot *slot, u32 cmd_arg)
{
	u8 how = (cmd_arg >> 24) & 3;
	u8 where = (u8)(cmd_arg >> 16);
	u8 val = (u8)(cmd_arg >> 8);

	slot->want_switch = slot->cached_switch;

	/*
	 * track ext_csd assignments (how==3) for critical entries
	 * to make sure we follow up with MIO_EMM_SWITCH adjustment
	 * before ANY mmc/core interaction at old settings.
	 * Current mmc/core logic (linux 4.14) does not set/clear
	 * bits (how = 1 or 2), which would require more complex
	 * logic to track the intent of a change
	 */

	if (how != 3)
		return;

	switch (where) {
	case EXT_CSD_BUS_WIDTH:
		slot->want_switch &= ~MIO_EMM_SWITCH_BUS_WIDTH;
		slot->want_switch |=
			FIELD_PREP(MIO_EMM_SWITCH_BUS_WIDTH, val);
		break;
	case EXT_CSD_POWER_CLASS:
		slot->want_switch &= ~MIO_EMM_SWITCH_POWER_CLASS;
		slot->want_switch |=
			FIELD_PREP(MIO_EMM_SWITCH_POWER_CLASS, val);
		break;
	case EXT_CSD_HS_TIMING:
		slot->want_switch &= ~MIO_EMM_SWITCH_TIMING;
		if (val)
			slot->want_switch |=
				FIELD_PREP(MIO_EMM_SWITCH_TIMING,
					(1 << (val - 1)));
		break;
	default:
		return;
	}

	slot->cmd6_pending = true;
}

static void cvm_mmc_request(struct mmc_host *mmc, struct mmc_request *mrq)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct cvm_mmc_host *host = slot->host;
	struct mmc_command *cmd = mrq->cmd;
	struct cvm_mmc_cr_mods mods;
	u64 emm_cmd, rsp_sts;
	int retries = 100;

	/*
	 * Note about locking:
	 * All MMC devices share the same bus and controller. Allow only a
	 * single user of the bootbus/MMC bus at a time. The lock is acquired
	 * on all entry points from the MMC layer.
	 *
	 * For requests the lock is only released after the completion
	 * interrupt!
	 */
	host->acquire_bus(host);

	if (cmd->opcode == MMC_READ_MULTIPLE_BLOCK ||
	    cmd->opcode == MMC_WRITE_MULTIPLE_BLOCK)
		return cvm_mmc_dma_request(mmc, mrq);

	cvm_mmc_switch_to(slot);

	mods = cvm_mmc_get_cr_mods(cmd);

	WARN_ON(slot->current_req);
	mrq->host = mmc;
	slot->current_req = mrq;

	if (cmd->data) {
		if (cmd->data->flags & MMC_DATA_READ)
			do_read_request(slot, mrq);
		else
			do_write_request(slot, mrq);

		if (cmd->data->timeout_ns)
			set_wdog(slot, cmd->data->timeout_ns);
	} else
		set_wdog(slot, 0);

	slot->dma_active = false;
	host->int_enable(host, MIO_EMM_INT_CMD_DONE | MIO_EMM_INT_CMD_ERR);

	if (cmd->opcode == MMC_SWITCH)
		cvm_mmc_track_switch(slot, cmd->arg);

	emm_cmd = FIELD_PREP(MIO_EMM_CMD_VAL, 1) |
		  FIELD_PREP(MIO_EMM_CMD_CTYPE_XOR, mods.ctype_xor) |
		  FIELD_PREP(MIO_EMM_CMD_RTYPE_XOR, mods.rtype_xor) |
		  FIELD_PREP(MIO_EMM_CMD_IDX, cmd->opcode) |
		  FIELD_PREP(MIO_EMM_CMD_ARG, cmd->arg);
	set_bus_id(&emm_cmd, slot->bus_id);
	if (cmd->data && mmc_cmd_type(cmd) == MMC_CMD_ADTC)
		emm_cmd |= FIELD_PREP(MIO_EMM_CMD_OFFSET,
				64 - ((cmd->data->blocks * cmd->data->blksz) / 8));

	writeq(0, host->base + MIO_EMM_STS_MASK(host));

retry:
	rsp_sts = readq(host->base + MIO_EMM_RSP_STS(host));
	if (rsp_sts & MIO_EMM_RSP_STS_DMA_VAL ||
	    rsp_sts & MIO_EMM_RSP_STS_CMD_VAL ||
	    rsp_sts & MIO_EMM_RSP_STS_SWITCH_VAL ||
	    rsp_sts & MIO_EMM_RSP_STS_DMA_PEND) {
		udelay(10);
		if (--retries)
			goto retry;
	}
	if (!retries)
		dev_err(host->dev, "Bad status: %llx before command write\n", rsp_sts);
	writeq(emm_cmd, host->base + MIO_EMM_CMD(host));
	if (cmd->opcode == MMC_SWITCH)
		udelay(1300);
}

static void cvm_mmc_wait_done(struct mmc_request *cvm_mrq)
{
	complete(&cvm_mrq->completion);
}

static int cvm_mmc_r1_cmd(struct mmc_host *mmc, u32 *statp, u32 opcode)
{
	static struct mmc_command cmd = {};
	static struct mmc_request cvm_mrq = {};

	if (!opcode)
		opcode = MMC_SEND_STATUS;
	cmd.opcode = opcode;
	if (mmc->card)
		cmd.arg = mmc->card->rca << 16;
	else
		cmd.arg = 1 << 16;
	cmd.flags = MMC_RSP_SPI_R2 | MMC_RSP_R1 | MMC_CMD_AC;
	cmd.data = NULL;
	cvm_mrq.cmd = &cmd;

	init_completion(&cvm_mrq.completion);
	cvm_mrq.done = cvm_mmc_wait_done;

	cvm_mmc_request(mmc, &cvm_mrq);
	if (!wait_for_completion_timeout(&cvm_mrq.completion,
			msecs_to_jiffies(10))) {
		mmc_abort_tuning(mmc, opcode);
		return -ETIMEDOUT;
	}

	if (statp)
		*statp = cmd.resp[0];

	return cvm_mrq.cmd->error;
}

static int cvm_mmc_data_tuning(struct mmc_host *mmc, u32 *statp, u32 opcode)
{
	int err = 0;
	u8 *ext_csd;
	static struct mmc_command cmd = {};
	static struct mmc_data data = {};
	static struct mmc_request cvm_mrq = {};
	static struct scatterlist sg;
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct mmc_card *card = mmc->card;

	if (!(slot->cached_switch & MIO_EMM_SWITCH_HS400_TIMING)) {
		int edetail = -EINVAL;
		int core_opinion;

		core_opinion =
			mmc_send_tuning(mmc, opcode, &edetail);

		/* only accept mmc/core opinion  when it's happy */
		if (!core_opinion)
			return core_opinion;
	}

	/* EXT_CSD supported only after ver 3 */
	if (card && card->csd.mmca_vsn <= CSD_SPEC_VER_3)
		return -EOPNOTSUPP;
	/*
	 * As the ext_csd is so large and mostly unused, we don't store the
	 * raw block in mmc_card.
	 */
	ext_csd = kzalloc(BLKSZ_EXT_CSD, GFP_KERNEL);
	if (!ext_csd)
		return -ENOMEM;

	cvm_mrq.cmd = &cmd;
	cvm_mrq.data = &data;
	cmd.data = &data;

	cmd.opcode = MMC_SEND_EXT_CSD;
	cmd.arg = 0;
	cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;

	data.blksz = BLKSZ_EXT_CSD;
	data.blocks = 1;
	data.flags = MMC_DATA_READ;
	data.sg = &sg;
	data.sg_len = 1;

	sg_init_one(&sg, ext_csd, BLKSZ_EXT_CSD);

	/* set timeout */
	if (card) {
		/* SD cards use a 100 multiplier rather than 10 */
		u32 mult = mmc_card_sd(card) ? 100 : 10;

		data.timeout_ns = card->csd.taac_ns * mult;
		data.timeout_clks = card->csd.taac_clks * mult;
	} else {
		data.timeout_ns = 50 * NSEC_PER_MSEC;
	}

	init_completion(&cvm_mrq.completion);
	cvm_mrq.done = cvm_mmc_wait_done;

	cvm_mmc_request(mmc, &cvm_mrq);
	if (!wait_for_completion_timeout(&cvm_mrq.completion,
			msecs_to_jiffies(100))) {
		mmc_abort_tuning(mmc, cmd.opcode);
		err = -ETIMEDOUT;
	}

	data.sg_len = 0; /* FIXME: catch over-time completions? */
	kfree(ext_csd);

	if (err)
		return err;

	if (statp)
		*statp = cvm_mrq.cmd->resp[0];

	return cvm_mrq.cmd->error;
}

/* adjusters for the 4 otx2 delay line taps */
struct adj {
	const char *name;
	u64 mask;
	int (*test)(struct mmc_host *mmc, u32 *statp, u32 opcode);
	u32 opcode;
	bool ddr_only;
};

static int adjust_tuning(struct mmc_host *mmc, struct adj *adj, u32 opcode)
{
	int err, start_run = -1, best_run = 0, best_start = -1;
	int last_good = -1;
	bool prev_ok = false;
	u64 timing, tap;
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct cvm_mmc_host *host = slot->host;
	char how[MAX_NO_OF_TAPS+1] = "";

	/* loop over range+1 to simplify processing */
	for (tap = 0; tap <= MAX_NO_OF_TAPS; tap++, prev_ok = !err) {
		if (tap < MAX_NO_OF_TAPS) {
			cvm_mmc_clk_config(host, CLK_OFF);
			timing = readq(host->base + MIO_EMM_TIMING(host));
			timing &= ~adj->mask;
			timing |= (tap << __bf_shf(adj->mask));
			writeq(timing, host->base + MIO_EMM_TIMING(host));

			cvm_mmc_clk_config(host, CLK_ON);
			err = adj->test(mmc, NULL, opcode);

			how[tap] = "-+"[!err];
			if (!err)
				last_good = tap;
		} else {
			/*
			 * putting the end+1 case in loop simplifies
			 * logic, allowing 'prev_ok' to process a
			 * sweet spot in tuning which extends to wall.
			 */
			err = -EINVAL;
		}

		if (!err) {
			/*
			 * If no CRC/etc errors in response, but previous
			 * failed, note the start of a new run
			 */
			if (!prev_ok)
				start_run = tap;
		} else if (prev_ok) {
			int run = tap - 1 - start_run;

			/* did we just exit a wider sweet spot? */
			if (start_run >= 0 && run > best_run) {
				best_start = start_run;
				best_run = run;
			}
		}
	}

	if (best_start < 0) {
		dev_warn(host->dev, "%s %lldMHz tuning %s failed\n",
			mmc_hostname(mmc), slot->clock / 1000000, adj->name);
		return -EINVAL;
	}

	tap = best_start + best_run / 2;
	how[tap] = '@';
	if (tapdance) {
		tap = last_good - tapdance;
		how[tap] = 'X';
	}
	dev_dbg(host->dev, "%s/%s %d/%lld/%d %s\n",
		mmc_hostname(mmc), adj->name,
		best_start, tap, best_start + best_run,
		how);
	slot->taps &= ~adj->mask;
	slot->taps |= (tap << __bf_shf(adj->mask));
	cvm_mmc_set_timing(slot);
	return 0;
}

static const u8 octeontx_hs400_tuning_block[512] = {
	0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00,
	0xff, 0xff, 0xcc, 0xcc, 0xcc, 0x33, 0xcc, 0xcc,
	0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff, 0xff,
	0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee, 0xff,
	0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd, 0xdd,
	0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff, 0xbb,
	0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff, 0xff,
	0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee, 0xff,
	0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00,
	0x00, 0xff, 0xff, 0xcc, 0xcc, 0xcc, 0x33, 0xcc,
	0xcc, 0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff,
	0xff, 0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee,
	0xff, 0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd,
	0xdd, 0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff,
	0xbb, 0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff,
	0xff, 0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee,
	0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00,
	0xff, 0xff, 0xcc, 0xcc, 0xcc, 0x33, 0xcc, 0xcc,
	0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff, 0xff,
	0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee, 0xff,
	0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd, 0xdd,
	0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff, 0xbb,
	0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff, 0xff,
	0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee, 0xff,
	0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00,
	0x00, 0xff, 0xff, 0xcc, 0xcc, 0xcc, 0x33, 0xcc,
	0xcc, 0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff,
	0xff, 0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee,
	0xff, 0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd,
	0xdd, 0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff,
	0xbb, 0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff,
	0xff, 0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee,
	0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00,
	0xff, 0xff, 0xcc, 0xcc, 0xcc, 0x33, 0xcc, 0xcc,
	0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff, 0xff,
	0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee, 0xff,
	0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd, 0xdd,
	0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff, 0xbb,
	0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff, 0xff,
	0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee, 0xff,
	0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00,
	0x00, 0xff, 0xff, 0xcc, 0xcc, 0xcc, 0x33, 0xcc,
	0xcc, 0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff,
	0xff, 0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee,
	0xff, 0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd,
	0xdd, 0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff,
	0xbb, 0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff,
	0xff, 0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee,
	0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00,
	0x00, 0xff, 0x00, 0xff, 0x55, 0xaa, 0x55, 0xaa,
	0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff, 0xff,
	0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee, 0xff,
	0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd, 0xdd,
	0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff, 0xbb,
	0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff, 0xff,
	0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee, 0xff,
	0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
	0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
	0x01, 0xfe, 0x01, 0xfe, 0xcc, 0xcc, 0xcc, 0xff,
	0xff, 0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee,
	0xff, 0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd,
	0xdd, 0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff,
	0xbb, 0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff,
	0xff, 0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee,

};

/* Initialization for single block read/write operation for tuning */
static void hs400_prepare_mrq(const struct cvm_mmc_slot *slot,
			      struct mmc_request *mrq, struct mmc_command *cmd,
			      struct mmc_data *data, struct scatterlist *sg,
			      const void *dat_buf, u32 size, bool write)
{
	struct mmc_host *mmc = slot->mmc;

	memset(data, 0, sizeof(*data));
	memset(cmd, 0, sizeof(*cmd));
	memset(mrq, 0, sizeof(*mrq));

	mrq->cmd = cmd;
	mrq->data = data;
	cmd->opcode = write ? MMC_WRITE_BLOCK : MMC_READ_SINGLE_BLOCK;
	cmd->arg = slot->hs400_tuning_block;
	cmd->flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;
	data->blksz = size;
	data->blocks = 1;
	data->sg = sg;
	data->sg_len = 1;
	data->flags = write ? MMC_DATA_WRITE : MMC_DATA_READ;
	init_completion(&(mrq->completion));
	if (mmc->card)
		mmc_set_data_timeout(data, mmc->card);
	else
		data->timeout_ns = (write ? 80 : 10) * NSEC_PER_MSEC;
	sg_init_one(sg, dat_buf, size);
}

static int access_hs400_tuning_block(struct cvm_mmc_slot *slot, bool write)
{
	struct mmc_request mrq = {};
	struct mmc_command cmd = {};
	struct mmc_data data = {};
	struct scatterlist sg;
	struct mmc_host *mmc = slot->mmc;
	const int size = mmc->max_blk_size;
	u8 *data_buf;

	data_buf = kzalloc(size, GFP_KERNEL);
	if (!data_buf)
		return -ENOMEM;
	if (write)
		memcpy(data_buf, octeontx_hs400_tuning_block, size);

	hs400_prepare_mrq(slot, &mrq, &cmd, &data, &sg, data_buf, size, write);

	mmc_wait_for_req(mmc, &mrq);

	if (!write) {
		if (memcmp(data_buf, octeontx_hs400_tuning_block,
			   sizeof(octeontx_hs400_tuning_block))) {
			kfree(data_buf);
			return -EILSEQ;
		}
	}
	kfree(data_buf);

	if (cmd.error || data.error)
		dev_dbg(slot->host->dev, "%s op failed, cmd: %d, data: %d\n",
			write ? "write" : "read", cmd.error, data.error);
	return (cmd.error || data.error) ? -ENODATA : 0;
}

/* Check for and write if necessary the tuning block for HS4000 tuning */
static int check_and_write_hs400_tuning_block(struct cvm_mmc_slot *slot)
{
	int err;

	if (slot->hs400_tuning_block == -1 ||
	    slot->hs400_tuning_block_present)
		return 0;

	/* Read the tuning block first and see if it's already set */
	err = access_hs400_tuning_block(slot, false);
	if (err == -ENODATA) {
		dev_warn(slot->host->dev,
			 "Could not access HS400 tuning block %d in HS200 mode, err: %d\n",
			 slot->hs400_tuning_block, err);
		return err;
	} else if (!err) {
		/* Everything is good, data matches, we're done */
		goto done;
	}

	/* Attempt to write the tuning block */
	err = access_hs400_tuning_block(slot, true);
	if (err) {
		dev_warn(slot->host->dev,
			 "err: %d, Could not write HS400 tuning block in HS200 mode\n",
			 err);
		goto done;
	}

	/* Read after write, this should pass */
	err = access_hs400_tuning_block(slot, false);
	if (err)
		dev_warn(slot->host->dev,
			 "Could not read HS400 tuning block after write, err: %d\n",
			 err);

done:
	/* Disable HS400 tuning if we can't access the tuning block */
	if (err)
		slot->hs400_tuning_block = -1;

	slot->hs400_tuning_block_present = !err;

	return err;
}

static int tune_hs400(struct cvm_mmc_slot *slot)
{
	int err = 0, start_run = -1, best_run = 0, best_start = -1;
	int last_good = -1;
	bool prev_ok = false;
	u64 timing;
	int tap;
	const int size = sizeof(octeontx_hs400_tuning_block);
	struct mmc_host *mmc = slot->mmc;
	struct cvm_mmc_host *host = slot->host;
	struct mmc_request mrq;
	struct mmc_command cmd;
	struct mmc_data data;
	struct scatterlist sg;
	u8 *data_buf;
	char how[MAX_NO_OF_TAPS+1] = "";

	if (slot->hs400_tuning_block == -1)
		return 0;

	/*
	 * Unfortunately, in their infinite wisdom, the eMMC standard does
	 * not allow for tuning in HS400 mode.  The problem is that what
	 * makes a good tuning point for HS200 often does not work in HS400
	 * mode.  In order to tune HS400 mode, a block (usually block 1) is
	 * set aside for tuning.  U-Boot is responsible for writing a data
	 * pattern designed to generate a worst case signal.  Most of this
	 * pattern is based off of the HS200 pattern.
	 *
	 * Each data in tap is tested by a read of this block and the center
	 * tap of the longest run of good reads is chosen.  This code is
	 * largely similar to adjust_tuning() above.
	 */
	data_buf = kmalloc(size, GFP_KERNEL);
	if (!data_buf)
		return -ENOMEM;

	hs400_prepare_mrq(slot, &mrq, &cmd, &data, &sg, data_buf, size, false);

	/* loop over range+1 to simplify processing */
	for (tap = 0; tap <= MAX_NO_OF_TAPS; tap++, prev_ok = !err) {
		if (tap < MAX_NO_OF_TAPS) {
			cvm_mmc_clk_config(host, CLK_OFF);
			timing = readq(host->base + MIO_EMM_TIMING(host));
			timing = FIELD_PREP(MIO_EMM_TIMING_DATA_IN, tap);
			writeq(timing, host->base + MIO_EMM_TIMING(host));
			cvm_mmc_clk_config(host, CLK_ON);

			dev_dbg(host->dev, "HS400 testing data in tap %d\n",
				 tap);
			mmc_wait_for_req(mmc, &mrq);
			if (cmd.error | data.error) {
				err = cmd.error ? cmd.error : data.error;
				how[tap] = '-';
				dev_dbg(host->dev,
					 "HS400 tuning cmd err: %d, data error: %d\n",
					 cmd.error, data.error);
			} else  {	/* Validate data */
				err = memcmp(data_buf,
					     octeontx_hs400_tuning_block, size);

				how[tap] = "d+"[!err];
				dev_dbg(host->dev,
					"HS400 read OK at tap %d, data %s\n",
					tap, err ? "mismatch" : "ok");
			}

			if (!err)
				last_good = tap;
		} else {
			/*
			 * putting the end+1 case in loop simplifies
			 * logic, allowing 'prev_ok' to process a
			 * sweet spot in tuning which extends to wall.
			 */
			err = -EILSEQ;
		}

		if (!err) {
			/*
			 * If no CRC/etc errors in response, but previous
			 * failed, note the start of a new run
			 */
			if (!prev_ok)
				start_run = tap;
		} else if (prev_ok) {
			int run = tap - 1 - start_run;

			/* did we just exit a wider sweet spot? */
			if (start_run >= 0 && run > best_run) {
				best_start = start_run;
				best_run = run;
			}
		}
	}

	kfree(data_buf);
	if (best_start < 0) {
		dev_warn(host->dev, "%s %lldMHz tuning HS400 data in failed\n",
			mmc_hostname(mmc), slot->clock / 1000000);
		return -EINVAL;
	}

	tap = best_start + best_run / 2;
	how[tap] = '@';
	if (tapdance) {
		tap = last_good - tapdance;
		how[tap] = 'X';
	}
	dev_dbg(host->dev, "%s/HS400 data in %d/%d/%d %s\n",
		mmc_hostname(mmc), best_start, tap,
		best_start + best_run, how);
	slot->taps &= ~MIO_EMM_TIMING_DATA_IN;
	slot->taps |= FIELD_PREP(MIO_EMM_TIMING_DATA_IN, tap);
	dev_dbg(host->dev, "HS400 data input tap: %d\n", tap);
	dev_dbg(host->dev, "%s\n", how);
	cvm_mmc_set_timing(slot);

	return 0;
}

static u32 max_supported_frequency(struct cvm_mmc_host *host)
{
	/* Default maximum freqeuncey is 52000000 for chip prior to 9X */
	u32 max_frequency = MHZ_52;

	if (!is_mmc_8xxx(host))
		/* Default max frequency is 200MHz for 9X chips */
		max_frequency = host->max_freq;

	return max_frequency;
}

static void cvm_mmc_set_ios(struct mmc_host *mmc, struct mmc_ios *ios)
{

	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct cvm_mmc_host *host = slot->host;
	int clk_period = 0, power_class = 10, bus_width = 0;
	u64 clock, emm_switch, mode;
	u32 max_f;

	if (ios->power_mode == MMC_POWER_OFF) {
		if (host->powered) {
			cvm_mmc_reset_bus(slot);
			if (host->global_pwr_gpiod)
				host->set_shared_power(host, 0);
			else if (!IS_ERR_OR_NULL(mmc->supply.vmmc))
				mmc_regulator_set_ocr(mmc, mmc->supply.vmmc, 0);
			host->powered = false;
		}
		set_wdog(slot, 0);
		return;
	}

	host->acquire_bus(host);
	cvm_mmc_switch_to(slot);

	if (ios->power_mode == MMC_POWER_UP) {
		if (host->global_pwr_gpiod)
			host->set_shared_power(host, 1);
		else if (!IS_ERR_OR_NULL(mmc->supply.vmmc))
			mmc_regulator_set_ocr(mmc, mmc->supply.vmmc, ios->vdd);
	}

	/* Convert bus width to HW definition */
	switch (ios->bus_width) {
	case MMC_BUS_WIDTH_8:
		bus_width = 2;
		break;
	case MMC_BUS_WIDTH_4:
		bus_width = 1;
		break;
	case MMC_BUS_WIDTH_1:
		bus_width = 0;
		break;
	}

	/* DDR is available for 4/8 bit bus width */
	switch (ios->timing) {
	case MMC_TIMING_UHS_DDR50:
	case MMC_TIMING_MMC_DDR52:
		if (ios->bus_width)
			bus_width |= 4;
		break;
	case MMC_TIMING_MMC_HS400:
		if (ios->bus_width & 2)
			bus_width |= 4;
		break;
	}

	/* Change the clock frequency. */
	clock = ios->clock;
	max_f = max_supported_frequency(host);

	if (clock < mmc->f_min)
		clock = mmc->f_min;
	if (clock > max_f)
		clock = max_f;
	slot->clock = clock;

	if (clock) {
		clk_period = host->sys_freq / (2 * clock);
		/* check to not exceed requested speed */
		while (1) {
			int hz = host->sys_freq / (2 * clk_period);

			if (hz <= clock)
				break;
			clk_period++;
		}
	}

	emm_switch =
		     FIELD_PREP(MIO_EMM_SWITCH_BUS_WIDTH, bus_width) |
		     FIELD_PREP(MIO_EMM_SWITCH_POWER_CLASS, power_class) |
		     FIELD_PREP(MIO_EMM_SWITCH_CLK_HI, clk_period) |
		     FIELD_PREP(MIO_EMM_SWITCH_CLK_LO, clk_period);
	switch (ios->timing) {
	case MMC_TIMING_LEGACY:
		break;
	case MMC_TIMING_MMC_HS:
	case MMC_TIMING_SD_HS:
	case MMC_TIMING_UHS_SDR12:
	case MMC_TIMING_UHS_SDR25:
	case MMC_TIMING_UHS_SDR50:
	case MMC_TIMING_UHS_SDR104:
	case MMC_TIMING_UHS_DDR50:
	case MMC_TIMING_MMC_DDR52:
		emm_switch |= FIELD_PREP(MIO_EMM_SWITCH_HS_TIMING, 1);
		break;
	case MMC_TIMING_MMC_HS200:
		emm_switch |= FIELD_PREP(MIO_EMM_SWITCH_HS200_TIMING, 1);
		break;
	case MMC_TIMING_MMC_HS400:
		emm_switch |= FIELD_PREP(MIO_EMM_SWITCH_HS400_TIMING, 1);
		break;
	}
	set_bus_id(&emm_switch, slot->bus_id);

	pr_debug("mmc-slot%d trying switch %llx w%lld hs%lld hs200:%lld hs400:%lld\n",
		slot->bus_id, emm_switch,
		FIELD_GET(MIO_EMM_SWITCH_BUS_WIDTH, emm_switch),
		FIELD_GET(MIO_EMM_SWITCH_HS_TIMING, emm_switch),
		FIELD_GET(MIO_EMM_SWITCH_HS200_TIMING, emm_switch),
		FIELD_GET(MIO_EMM_SWITCH_HS400_TIMING, emm_switch));

	if (!switch_val_changed(slot, emm_switch))
		goto out;

	set_wdog(slot, 0);
	do_switch(host, emm_switch);

	mode = readq(host->base + MIO_EMM_MODE(host, slot->bus_id));
	pr_debug("mmc-slot%d mode %llx w%lld hs%lld hs200:%lld hs400:%lld\n",
		slot->bus_id, mode,
		(mode >> 40) & 7, (mode >> 48) & 1,
		(mode >> 49) & 1, (mode >> 50) & 1);

	slot->cached_switch = emm_switch;
	host->powered = true;
	cvm_mmc_configure_delay(slot);
out:
	host->release_bus(host);
	if (ios->timing == MMC_TIMING_MMC_HS)
		check_and_write_hs400_tuning_block(slot);
	else if (ios->timing == MMC_TIMING_MMC_HS400)
		tune_hs400(slot);
}

static struct adj adj[] = {
	{ "CMD_IN", MIO_EMM_TIMING_CMD_IN,
		cvm_mmc_r1_cmd, MMC_SEND_STATUS, },
	{ "DATA_IN", MIO_EMM_TIMING_DATA_IN,
		cvm_mmc_data_tuning, },
	{ NULL, },
};

static int cvm_scan_tuning(struct mmc_host *mmc, u32 opcode)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct adj *a;
	int ret;

	for (a = adj; a->name; a++) {
		if (a->ddr_only && !cvm_is_mmc_timing_ddr(slot))
			continue;

		ret = adjust_tuning(mmc, a,
			a->opcode ?: opcode);

		if (ret)
			return ret;
	}

	cvm_mmc_set_timing(slot);
	if (!slot->hs400_tuning_block_present)
		check_and_write_hs400_tuning_block(slot);
	return 0;
}

static int cvm_execute_tuning(struct mmc_host *mmc, u32 opcode)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct cvm_mmc_host *host = slot->host;
	int clk_period, hz;

	int ret;

	do {
		u64 emm_switch =
			readq(host->base + MIO_EMM_MODE(host, slot->bus_id));

		clk_period = FIELD_GET(MIO_EMM_SWITCH_CLK_LO, emm_switch);
		dev_info(slot->host->dev, "%s re-tuning\n",
			mmc_hostname(mmc));
		ret = cvm_scan_tuning(mmc, opcode);
		if (ret) {
			int inc = clk_period >> 3;

			if (!inc)
				inc++;
			clk_period += inc;
			hz = host->sys_freq / (2 * clk_period);
			pr_debug("clk_period %d += %d, now %d Hz\n",
				clk_period - inc, inc, hz);

			if (hz < 400000)
				break;

			slot->clock = hz;
			mmc->ios.clock = hz;

			emm_switch &= ~MIO_EMM_SWITCH_CLK_LO;
			emm_switch |= FIELD_PREP(MIO_EMM_SWITCH_CLK_LO,
						clk_period);
			emm_switch &= ~MIO_EMM_SWITCH_CLK_HI;
			emm_switch |= FIELD_PREP(MIO_EMM_SWITCH_CLK_HI,
						clk_period);
			do_switch(host, emm_switch);
		}
	} while (ret);

	return ret;
}

static int cvm_prepare_hs400_tuning(struct mmc_host *mmc, struct mmc_ios *ios)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);

	return cvm_mmc_configure_delay(slot);
}

static void cvm_mmc_reset(struct mmc_host *mmc)
{
	struct cvm_mmc_slot *slot = mmc_priv(mmc);
	struct cvm_mmc_host *host = slot->host;
	u64 r;

	cvm_mmc_reset_bus(slot);

	r = FIELD_PREP(MIO_EMM_CMD_VAL, 1) |
		FIELD_PREP(MIO_EMM_CMD_BUS_ID, slot->bus_id);

	writeq(r, host->base + MIO_EMM_CMD(host));

	do {
		r = readq(host->base + MIO_EMM_RSP_STS(host));
	} while (!(r & MIO_EMM_RSP_STS_CMD_DONE));
}

static const struct mmc_host_ops cvm_mmc_ops = {
	.request        = cvm_mmc_request,
	.set_ios        = cvm_mmc_set_ios,
	.get_ro		= mmc_gpio_get_ro,
	.get_cd		= mmc_gpio_get_cd,
	.hw_reset	= cvm_mmc_reset,
	.execute_tuning = cvm_execute_tuning,
	.prepare_hs400_tuning = cvm_prepare_hs400_tuning,
};

static void cvm_mmc_set_clock(struct cvm_mmc_slot *slot, unsigned int clock)
{
	struct mmc_host *mmc = slot->mmc;

	clock = min(clock, mmc->f_max);
	clock = max(clock, mmc->f_min);
	slot->clock = clock;
}

static int cvm_mmc_init_lowlevel(struct cvm_mmc_slot *slot)
{
	struct cvm_mmc_host *host = slot->host;
	u64 emm_switch;

	/* Enable this bus slot. Overridden when vqmmc-switching engaged */
	host->emm_cfg |= (1ull << slot->bus_id);
	writeq(host->emm_cfg, slot->host->base + MIO_EMM_CFG(host));
	udelay(10);

	/* Program initial clock speed and power. */
	cvm_mmc_set_clock(slot, slot->mmc->f_min);
	emm_switch = FIELD_PREP(MIO_EMM_SWITCH_POWER_CLASS, 10);
	emm_switch |= FIELD_PREP(MIO_EMM_SWITCH_CLK_HI,
				 (host->sys_freq / slot->clock) / 2);
	emm_switch |= FIELD_PREP(MIO_EMM_SWITCH_CLK_LO,
				 (host->sys_freq / slot->clock) / 2);

	/* Make the changes take effect on this bus slot. */
	set_bus_id(&emm_switch, slot->bus_id);
	do_switch(host, emm_switch);
	slot->cached_switch = emm_switch;
	host->powered = true;

	/*
	 * Set watchdog timeout value and default reset value
	 * for the mask register. Finally, set the CARD_RCA
	 * bit so that we can get the card address relative
	 * to the CMD register for CMD7 transactions.
	 */
	set_wdog(slot, 0);
	writeq(0xe4390080ull, host->base + MIO_EMM_STS_MASK(host));
	writeq(1, host->base + MIO_EMM_RCA(host));
	return 0;
}

static int cvm_mmc_of_parse(struct device *dev, struct cvm_mmc_slot *slot)
{
	u32 id, cmd_skew = 0, dat_skew = 0, bus_width = 0;
	struct device_node *node = dev->of_node;
	struct mmc_host *mmc = slot->mmc;
	u32 max_frequency, current_drive, clk_slew;
	int ret, i;

	ret = of_property_read_u32(node, "reg", &id);
	if (ret) {
		dev_err(dev, "Missing or invalid reg property on %pOF\n", node);
		return ret;
	}

	if (id >= CAVIUM_MAX_MMC) {
		dev_err(dev, "Invalid reg=<%d> property on %pOF\n", id, node);
		return -EINVAL;
	}

	if (slot->host->slot[id]) {
		dev_err(dev, "Duplicate reg=<%d> property on %pOF\n",
			id, node);
		return -EINVAL;
	}

	ret = mmc_regulator_get_supply(mmc);
	if (ret == -EPROBE_DEFER)
		return ret;
	/*
	 * Legacy Octeon firmware has no regulator entry, fall-back to
	 * a hard-coded voltage to get a sane OCR.
	 */
	if (IS_ERR_OR_NULL(mmc->supply.vmmc))
		mmc->ocr_avail = MMC_VDD_32_33 | MMC_VDD_33_34;

	/* Common MMC bindings */
	ret = mmc_of_parse(mmc);
	if (ret)
		return ret;

	slot->hs400_tuning_block = -1U;
	of_property_read_u32(node, "marvell,hs400-tuning-block",
			     &slot->hs400_tuning_block);
	/* Set bus width from obsolete properties, if unset */
	if (!(mmc->caps & (MMC_CAP_8_BIT_DATA | MMC_CAP_4_BIT_DATA))) {
		of_property_read_u32(node, "cavium,bus-max-width", &bus_width);
		if (bus_width == 8)
			mmc->caps |= MMC_CAP_8_BIT_DATA | MMC_CAP_4_BIT_DATA;
		else if (bus_width == 4)
			mmc->caps |= MMC_CAP_4_BIT_DATA;
	}


	/* Initialize list of bus modes timings and customize it by DT */
	memcpy(slot->cmd_out_taps_dly, default_cmd_out_taps_dly,
	       sizeof(slot->cmd_out_taps_dly));

	for (i = 0; i < MMC_OUT_TAPS_DELAY_COUNT; i++) {
		u32 val = slot->cmd_out_taps_dly[i];

		if (__cvm_is_mmc_timing_ddr(i))
			val = DIV_ROUND_UP(val, 2);
		slot->data_out_taps_dly[i] = val;
	}

	of_property_read_u32(node, "marvell,cmd-out-hs200-dly",
			     &slot->cmd_out_taps_dly[MMC_TIMING_MMC_HS200]);
	of_property_read_u32(node, "marvell,data-out-hs200-dly",
			     &slot->data_out_taps_dly[MMC_TIMING_MMC_HS200]);
	of_property_read_u32(node, "marvell,cmd-out-hs400-dly",
			     &slot->cmd_out_taps_dly[MMC_TIMING_MMC_HS400]);
	of_property_read_u32(node, "marvell,data-out-hs400-dly",
			     &slot->data_out_taps_dly[MMC_TIMING_MMC_HS400]);
	of_property_read_u32(node, "marvell,cmd-out-hs-sdr-dly",
			     &slot->cmd_out_taps_dly[MMC_TIMING_MMC_HS]);
	of_property_read_u32(node, "marvell,data-out-hs-sdr-dly",
			     &slot->data_out_taps_dly[MMC_TIMING_MMC_HS]);
	of_property_read_u32(node, "marvell,cmd-out-hs-ddr-dly",
			     &slot->cmd_out_taps_dly[MMC_TIMING_MMC_DDR52]);
	of_property_read_u32(node, "marvell,data-out-hs-ddr-dly",
			     &slot->data_out_taps_dly[MMC_TIMING_MMC_DDR52]);
	of_property_read_u32(node, "marvell,cmd-out-legacy-dly",
			     &slot->cmd_out_taps_dly[MMC_TIMING_LEGACY]);
	of_property_read_u32(node, "marvell,data-out-legacy-dly",
			     &slot->data_out_taps_dly[MMC_TIMING_LEGACY]);

	max_frequency = max_supported_frequency(slot->host);

	/* Set maximum and minimum frequency */
	if (!mmc->f_max)
		of_property_read_u32(node, "spi-max-frequency", &mmc->f_max);
	if (!mmc->f_max || mmc->f_max > max_frequency)
		mmc->f_max = max_frequency;
	mmc->f_min = KHZ_400;

	/* Sampling register settings, period in picoseconds */
	of_property_read_u32(node, "cavium,cmd-clk-skew", &cmd_skew);
	of_property_read_u32(node, "cavium,dat-clk-skew", &dat_skew);
	slot->cmd_cnt = cmd_skew;
	slot->data_cnt = dat_skew;

	/* Get current drive and clk skew */
	ret = of_property_read_u32(node, "cavium,drv-strength", &current_drive);
	if (ret)
		slot->drive = -1;
	else
		slot->drive = current_drive;

	ret = of_property_read_u32(node, "cavium,clk-slew", &clk_slew);
	if (ret)
		slot->slew = -1;
	else
		slot->slew = clk_slew;

	return id;
}

int cvm_mmc_of_slot_probe(struct device *dev, struct cvm_mmc_host *host)
{
	struct cvm_mmc_slot *slot;
	struct mmc_host *mmc;
	struct iommu_domain *dom;
	int ret, id;

	mmc = mmc_alloc_host(sizeof(struct cvm_mmc_slot), dev);
	if (!mmc)
		return -ENOMEM;

	slot = mmc_priv(mmc);
	slot->mmc = mmc;
	slot->host = host;

	ret = cvm_mmc_of_parse(dev, slot);
	if (ret < 0)
		goto error;
	id = ret;

	/* Set up host parameters */
	mmc->ops = &cvm_mmc_ops;

	mmc->caps |= MMC_CAP_ERASE | MMC_CAP_BUS_WIDTH_TEST;
	mmc->caps |= MMC_CAP_CMD23 | MMC_CAP_POWER_OFF_CARD;

	/*
	 * For old firmware which does not describe properties:
	 * We only have a 3.3v supply for slots, we cannot
	 * support any of the UHS modes. We do support the
	 * high speed DDR modes up to 52MHz.
	 */

	if (is_mmc_8xxx(host))
		mmc->caps |= MMC_CAP_3_3V_DDR;

	if (host->use_sg)
		mmc->max_segs = 16;
	else
		mmc->max_segs = 1;

	/* DMA size field can address up to 8 MB */
	mmc->max_seg_size = min_t(unsigned int, 8 * 1024 * 1024,
				  dma_get_max_seg_size(host->dev));
	mmc->max_req_size = mmc->max_seg_size;
	/* External DMA is in 512 byte blocks */
	mmc->max_blk_size = 512;
	/* DMA block count field is 15 bits */
	mmc->max_blk_count = 32767;

	dom = iommu_get_domain_for_dev(dev->parent);
	if (dom && dom->type == IOMMU_DOMAIN_IDENTITY) {
		unsigned int max_size = (1 << IO_TLB_SHIFT) * IO_TLB_SEGSIZE;

		if (mmc->max_seg_size > max_size)
			mmc->max_seg_size = max_size;

		max_size *= mmc->max_segs;

		if (mmc->max_req_size > max_size)
			mmc->max_req_size = max_size;
	}

	mmc_can_retune(mmc);

	slot->clock = mmc->f_min;
	slot->bus_id = id;
	slot->cached_rca = 1;

	host->acquire_bus(host);
	host->slot[id] = slot;
	host->use_vqmmc |= !IS_ERR_OR_NULL(slot->mmc->supply.vqmmc);
	cvm_mmc_init_lowlevel(slot);
	cvm_mmc_switch_to(slot);
	host->release_bus(host);

	ret = mmc_add_host(mmc);
	if (ret) {
		dev_err(dev, "mmc_add_host() returned %d\n", ret);
		slot->host->slot[id] = NULL;
		goto error;
	}
	return 0;

error:
	mmc_free_host(slot->mmc);
	return ret;
}

int cvm_mmc_of_slot_remove(struct cvm_mmc_slot *slot)
{
	mmc_remove_host(slot->mmc);
	slot->host->slot[slot->bus_id] = NULL;
	mmc_free_host(slot->mmc);
	return 0;
}
