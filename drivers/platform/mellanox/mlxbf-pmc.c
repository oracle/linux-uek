// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause

#include <linux/acpi.h>
#include <linux/arm-smccc.h>
#include <linux/bitfield.h>
#include <linux/errno.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/stringify.h>
#include <linux/sysfs.h>
#include <linux/version.h>
#include <uapi/linux/psci.h>

#include "mlxbf-pmc.h"

#define DRIVER_VERSION		2.3

static struct mlxbf_pmc_context *pmc;

#define SIZE_64 0
#define SIZE_32 1

/* Calls an SMC to access a performance register */
static int mlxbf_pmc_secure_read(void *addr, int size, uint64_t *result)
{
	struct arm_smccc_res res;
	uint32_t command;
	int status;

	switch (size) {
	case SIZE_32:
		command = MLNX_READ_REG_32;
		break;
	case SIZE_64:
		command = MLNX_READ_REG_64;
		break;
	default:
		dev_err(pmc->hwmon_dev,
			"%s: invalid size: %d\n", __func__, size);
		return -EINVAL;
	}

	arm_smccc_smc(
		command,
		pmc->sreg_tbl_perf,
		(uintptr_t) addr,
		0, 0, 0, 0, 0, &res);

	status = res.a0;

	switch (status) {
	/*
	 * Note: PSCI_RET_NOT_SUPPORTED is used here to maintain compatibility
	 * with older kernels that do not have SMCCC_RET_NOT_SUPPORTED
	 */
	case PSCI_RET_NOT_SUPPORTED:
		dev_err(pmc->hwmon_dev,
			"%s: required SMC unsupported", __func__);
		return -EINVAL;
	case SMCCC_ACCESS_VIOLATION:
		dev_err(pmc->hwmon_dev,
			"%s: could not read register %p. Is it perf?",
			__func__,
			addr);
		return -EACCES;
	default:
		*result = (uint64_t)res.a1;
		return 0;
	}
}

/* Read from a performance counter */
static int mlxbf_pmc_read(void *addr, int size, uint64_t *result)
{
	if (pmc->svc_sreg_support) {
		if (mlxbf_pmc_secure_read(addr, size, result))
			return -EINVAL;
		else
			return 0;
	} else {
		switch (size) {
		case SIZE_32:
			*result = (uint64_t)readl(addr);
			return 0;
		case SIZE_64:
			*result = readq(addr);
			return 0;
		default:
			dev_err(pmc->hwmon_dev,
				"%s: invalid size: %d\n", __func__, size);
			return -EINVAL;
		}
	}
}

/* Convenience function for 32-bit reads */
static int mlxbf_pmc_readl(uint32_t *result, void *addr)
{
	uint64_t read_out;
	int status;

	status = mlxbf_pmc_read(addr, SIZE_32, &read_out);
	if (status)
		return status;
	*result = (uint32_t)read_out;

	return 0;
}

/* Convenience function for 64-bit reads */
static int mlxbf_pmc_readq(uint64_t *result, void *addr)
{
	return mlxbf_pmc_read(addr, SIZE_64, result);
}

/* Calls an SMC to access a performance register */
static int mlxbf_pmc_secure_write(uint64_t value, void *addr, int size)
{
	struct arm_smccc_res res;
	uint32_t command;
	int status;

	switch (size) {
	case SIZE_32:
		command = MLNX_WRITE_REG_32;
		break;
	case SIZE_64:
		command = MLNX_WRITE_REG_64;
		break;
	default:
		dev_err(pmc->hwmon_dev,
			"%s: invalid size: %d\n", __func__, size);
		return -EINVAL;
	}

	arm_smccc_smc(
		command,
		pmc->sreg_tbl_perf,
		value,
		(uintptr_t) addr,
		0, 0, 0, 0, &res);

	status = res.a0;

	switch (status) {
	case PSCI_RET_NOT_SUPPORTED:
		dev_err(pmc->hwmon_dev,
			"%s: required SMC unsupported", __func__);
		return -EINVAL;
	case SMCCC_ACCESS_VIOLATION:
		dev_err(pmc->hwmon_dev,
			"%s: could not write register %p. Is it perf?",
			__func__,
			addr);
		return -EACCES;
	default:
		return 0;
	}
}

/* Write to a performance counter */
static int mlxbf_pmc_write(uint64_t value, void *addr, int size)
{
	if (pmc->svc_sreg_support)
		return mlxbf_pmc_secure_write(value, addr, size);

	switch (size) {
	case SIZE_32:
		writel((uint32_t)value, addr);
		return 0;
	case SIZE_64:
		writeq(value, addr);
		return 0;
	default:
		dev_err(pmc->hwmon_dev,
			"%s: invalid size: %d\n", __func__, size);
		return -EINVAL;
	}
}

/* Convenience function for 32-bit writes */
static int mlxbf_pmc_writel(uint32_t value, void *addr)
{
	return mlxbf_pmc_write((uint64_t) value, addr, SIZE_32);
}

/* Convenience function for 64-bit writes */
static int mlxbf_pmc_writeq(uint64_t value, void *addr)
{
	return mlxbf_pmc_write(value, addr, SIZE_64);
}

/* Check if the register offset is within the mapped region for the block */
static bool mlxbf_pmc_valid_range(int blk_num, uint32_t offset)
{
	if (offset % 8 != 0)
		return false;  /* unaligned */
	if (offset >= 0 && offset + 8 <= pmc->block[blk_num].blk_size)
		return true;   /* inside the mapped PMC space */

	return false;
}

/* Get the block number using the name */
static int mlxbf_pmc_get_block_num(const char *name)
{
	int i;

	for (i = 0; i < pmc->total_blocks; ++i)
		if (strcmp((char *)name, pmc->block_name[i]) == 0)
			return i;

	return -ENODEV;
}

/* Get the event list corresponding to a certain block */
struct mlxbf_pmc_events *mlxbf_pmc_event_list(char *blk)
{
	struct mlxbf_pmc_events *events;

	if (strstr(blk, "tilenet"))
		events = mlxbf2_hnfnet_events;
	else if (strstr(blk, "tile"))
		events = mlxbf_hnf_events;
	else if (strstr(blk, "triogen"))
		events = mlxbf_smgen_events;
	else if (strstr(blk, "trio"))
		switch (pmc->event_set) {
		case MLNX_EVENT_SET_BF1:
			events = mlxbf1_trio_events;
			break;
		case MLNX_EVENT_SET_BF2:
			events = mlxbf2_trio_events;
			break;
		default:
			events = NULL;
			break;
		}
	else if (strstr(blk, "mss"))
		switch (pmc->event_set) {
		case MLNX_EVENT_SET_BF1:
		case MLNX_EVENT_SET_BF2:
			events = mlxbf_mss_events;
			break;
		case MLNX_EVENT_SET_BF3:
			events = mlxbf3_mss_events;
			break;
		default:
			events = NULL;
			break;
		}
	else if (strstr(blk, "ecc"))
		events = mlxbf_ecc_events;
	else if (strstr(blk, "pcie"))
		events = mlxbf_pcie_events;
	else if (strstr(blk, "l3cache"))
		events = mlxbf_l3cache_events;
	else if (strstr(blk, "gic"))
		events = mlxbf_smgen_events;
	else if (strstr(blk, "smmu"))
		events = mlxbf_smgen_events;
	else if (strstr(blk, "llt_miss"))
		events = mlxbf3_llt_miss_events;
	else if (strstr(blk, "llt"))
		events = mlxbf3_llt_events;
	else
		events = NULL;

	return events;
}

/* Get the event number given the name */
static int mlxbf_pmc_get_event_num(char *blk, char *evt)
{
	struct mlxbf_pmc_events *events;
	int i = 0;

	events = mlxbf_pmc_event_list(blk);
	if (events == NULL)
		return -EINVAL;

	while (events[i].evt_name != NULL) {
		if (strcmp(evt, events[i].evt_name) == 0)
			return events[i].evt_num;
		++i;
	}

	return -ENODEV;
}

/* Get the event number given the name */
static char *mlxbf_pmc_get_event_name(char *blk, int evt)
{
	struct mlxbf_pmc_events *events;
	int i = 0;

	events = mlxbf_pmc_event_list(blk);
	if (events == NULL)
		return NULL;

	while (events[i].evt_name != NULL) {
		if (evt == events[i].evt_num)
			return events[i].evt_name;
		++i;
	}

	return NULL;
}

/* Method to enable/disable/reset l3cache counters */
int mlxbf_config_l3_counters(int blk_num, bool enable, bool reset)
{
	uint32_t perfcnt_cfg = 0;

	if (enable)
		perfcnt_cfg |= MLXBF_L3C_PERF_CNT_CFG__EN;
	if (reset)
		perfcnt_cfg |= MLXBF_L3C_PERF_CNT_CFG__RST;

	return mlxbf_pmc_writel(perfcnt_cfg, pmc->block[blk_num].mmio_base +
				MLXBF_L3C_PERF_CNT_CFG);
}


/* Method to handle l3cache counter programming */
int mlxbf_program_l3_counter(int blk_num, uint32_t cnt_num, uint32_t evt)
{
	uint32_t perfcnt_sel_1 = 0;
	uint32_t perfcnt_sel = 0;
	uint32_t *wordaddr;
	void *pmcaddr;
	int ret;

	/* Disable all counters before programming them */
	if (mlxbf_config_l3_counters(blk_num, false, false))
		return -EINVAL;

	/* Select appropriate register information */
	switch (cnt_num) {
	case 0:
	case 1:
	case 2:
	case 3:
		pmcaddr = pmc->block[blk_num].mmio_base +
			  MLXBF_L3C_PERF_CNT_SEL;
		wordaddr = &perfcnt_sel;
		break;
	case 4:
		pmcaddr = pmc->block[blk_num].mmio_base +
			  MLXBF_L3C_PERF_CNT_SEL_1;
		wordaddr = &perfcnt_sel_1;
		break;
	default:
		return -EINVAL;
	}

	ret = mlxbf_pmc_readl(wordaddr, pmcaddr);
	if (ret)
		return ret;

	switch (cnt_num) {
	case 0:
		perfcnt_sel &= ~MLXBF_L3C_PERF_CNT_SEL__CNT_0;
		perfcnt_sel |= FIELD_PREP(MLXBF_L3C_PERF_CNT_SEL__CNT_0, evt);
		break;
	case 1:
		perfcnt_sel &= ~MLXBF_L3C_PERF_CNT_SEL__CNT_1;
		perfcnt_sel |= FIELD_PREP(MLXBF_L3C_PERF_CNT_SEL__CNT_1, evt);
		break;
	case 2:
		perfcnt_sel &= ~MLXBF_L3C_PERF_CNT_SEL__CNT_2;
		perfcnt_sel |= FIELD_PREP(MLXBF_L3C_PERF_CNT_SEL__CNT_2, evt);
		break;
	case 3:
		perfcnt_sel &= ~MLXBF_L3C_PERF_CNT_SEL__CNT_3;
		perfcnt_sel |= FIELD_PREP(MLXBF_L3C_PERF_CNT_SEL__CNT_3, evt);
		break;
	case 4:
		perfcnt_sel_1 &= ~MLXBF_L3C_PERF_CNT_SEL_1__CNT_4;
		perfcnt_sel_1 |= FIELD_PREP(MLXBF_L3C_PERF_CNT_SEL_1__CNT_4,
					    evt);
		break;
	default:
		return -EINVAL;
	}

	return mlxbf_pmc_writel(*wordaddr, pmcaddr);
}

/* Method to handle crspace counter programming */
int mlxbf_program_crspace_counter(int blk_num, uint32_t cnt_num, uint32_t evt)
{
	int reg_num, ret;
	uint32_t word;
	void *addr;

	reg_num = (cnt_num / 2);
	addr = pmc->block[blk_num].mmio_base + (reg_num * 4);

	ret = mlxbf_pmc_readl(&word, addr);
	if (ret)
		return ret;

	switch(cnt_num % 2) {
	case 0:
		word &= ~MLXBF_CRSPACE_PERFSEL0;
		word |= FIELD_PREP(MLXBF_CRSPACE_PERFSEL0, evt);
		break;
	case 1:
		word &= ~MLXBF_CRSPACE_PERFSEL1;
		word |= FIELD_PREP(MLXBF_CRSPACE_PERFSEL1, evt);
		break;
	default:
		return -EINVAL;
	}

	return mlxbf_pmc_writel(word, addr);
}

int mlxbf_clear_crspace_counter(int blk_num, uint32_t cnt_num)
{
	void *addr;

	addr = pmc->block[blk_num].mmio_base +
		MLXBF_CRSPACE_PERFMON_VAL0(pmc->block[blk_num].counters) +
		(cnt_num * 4);

	return mlxbf_pmc_writel(0x0, addr);
}

/* Method to program a counter to monitor an event */
int mlxbf_program_counter(int blk_num, uint32_t cnt_num, uint32_t evt,
			  bool is_l3)
{
	uint64_t perfctl, perfevt, perfmon_cfg;

	if (cnt_num >= pmc->block[blk_num].counters)
		return -ENODEV;

	if (is_l3)
		return mlxbf_program_l3_counter(blk_num, cnt_num, evt);

	if (pmc->block[blk_num].type == MLXBF_PERFTYPE_CRSPACE)
		return mlxbf_program_crspace_counter(blk_num, cnt_num, evt);

	/* Configure the counter */
	perfctl = 0;
	perfctl |= FIELD_PREP(MLXBF_GEN_PERFCTL__EN0, 1);
	perfctl |= FIELD_PREP(MLXBF_GEN_PERFCTL__EB0, 0);
	perfctl |= FIELD_PREP(MLXBF_GEN_PERFCTL__ETRIG0, 1);
	perfctl |= FIELD_PREP(MLXBF_GEN_PERFCTL__AD0, 0);
	perfctl |= FIELD_PREP(MLXBF_GEN_PERFCTL__ACCM0, 0);
	perfctl |= FIELD_PREP(MLXBF_GEN_PERFCTL__MS0, 0);
	perfctl |= FIELD_PREP(MLXBF_GEN_PERFCTL__FM0, 0);

	perfmon_cfg = 0;
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__WDATA, perfctl);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__ADDR,
				  MLXBF_PERFCTL);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__STROBE, 1);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__WR_R_B, 1);

	if (mlxbf_pmc_writeq(perfmon_cfg,
				pmc->block[blk_num].mmio_base + cnt_num * 8))
		return -EFAULT;

	/* Select the event */
	perfevt = 0;
	perfevt |= FIELD_PREP(MLXBF_GEN_PERFEVT__EVTSEL, evt);

	perfmon_cfg = 0;
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__WDATA, perfevt);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__ADDR,
				  MLXBF_PERFEVT);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__STROBE, 1);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__WR_R_B, 1);

	if (mlxbf_pmc_writeq(perfmon_cfg,
				pmc->block[blk_num].mmio_base + cnt_num * 8))
		return -EFAULT;

	/* Clear the accumulator */
	perfmon_cfg = 0;
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__ADDR,
				  MLXBF_PERFACC0);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__STROBE, 1);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__WR_R_B, 1);

	if (mlxbf_pmc_writeq(perfmon_cfg, pmc->block[blk_num].mmio_base
			     + cnt_num * 8))
		return -EFAULT;

	return 0;
}

/* Method to handle l3 counter reads */
int mlxbf_read_l3_counter(int blk_num, uint32_t cnt_num, uint64_t *result)
{
	uint32_t perfcnt_low = 0, perfcnt_high = 0;
	uint64_t value;
	int status = 0;

	status = mlxbf_pmc_readl(&perfcnt_low, pmc->block[blk_num].mmio_base +
			   MLXBF_L3C_PERF_CNT_LOW + cnt_num * 4);

	if (status)
		return status;

	status = mlxbf_pmc_readl(&perfcnt_high, pmc->block[blk_num].mmio_base +
			   MLXBF_L3C_PERF_CNT_HIGH + cnt_num * 4);

	if (status)
		return status;

	value = perfcnt_high;
	value = value << 32;
	value |= perfcnt_low;
	*result = value;

	return 0;
}

/* Method to handle crspace counter reads */
int mlxbf_read_crspace_counter(int blk_num, uint32_t cnt_num, uint64_t *result)
{
	uint32_t value;
	int status = 0;

	status = mlxbf_pmc_readl(&value, pmc->block[blk_num].mmio_base +
		MLXBF_CRSPACE_PERFMON_VAL0(pmc->block[blk_num].counters) +
		(cnt_num * 4));
	if (status)
		return status;

	*result = value;

	return 0;
}

/* Method to read the counter value */
int mlxbf_read_counter(int blk_num, uint32_t cnt_num, bool is_l3,
		       uint64_t *result)
{
	uint32_t perfcfg_offset, perfval_offset;
	uint64_t perfmon_cfg;
	int status;

	if (cnt_num >= pmc->block[blk_num].counters)
		return -EINVAL;

	if (is_l3)
		return mlxbf_read_l3_counter(blk_num, cnt_num, result);

	if (pmc->block[blk_num].type == MLXBF_PERFTYPE_CRSPACE)
		return mlxbf_read_crspace_counter(blk_num, cnt_num, result);

	perfcfg_offset = cnt_num * 8;
	perfval_offset = perfcfg_offset + pmc->block[blk_num].counters * 8;

	/* Set counter in "read" mode */
	perfmon_cfg = 0;
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__ADDR,
				  MLXBF_PERFACC0);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__STROBE, 1);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__WR_R_B, 0);

	status = mlxbf_pmc_writeq(perfmon_cfg, pmc->block[blk_num].mmio_base +
			    perfcfg_offset);

	if (status)
		return status;

	/* Get the counter value */
	return mlxbf_pmc_readq(result,
			 pmc->block[blk_num].mmio_base + perfval_offset);
}

int mlxbf_read_l3_event(int blk_num, uint32_t cnt_num, uint64_t *result)
{
	uint32_t perfcnt_sel = 0, perfcnt_sel_1 = 0;
	uint32_t *wordaddr;
	void *pmcaddr;
	uint64_t evt;

	/* Select appropriate register information */
	switch (cnt_num) {
	case 0:
	case 1:
	case 2:
	case 3:
		pmcaddr = pmc->block[blk_num].mmio_base +
			  MLXBF_L3C_PERF_CNT_SEL;
		wordaddr = &perfcnt_sel;
		break;
	case 4:
		pmcaddr = pmc->block[blk_num].mmio_base +
			  MLXBF_L3C_PERF_CNT_SEL_1;
		wordaddr = &perfcnt_sel_1;
		break;
	default:
		return -EINVAL;
	}

	if (mlxbf_pmc_readl(wordaddr, pmcaddr))
		return -EINVAL;

	/* Read from appropriate register field for the counter */
	switch (cnt_num) {
	case 0:
		evt = FIELD_GET(MLXBF_L3C_PERF_CNT_SEL__CNT_0, perfcnt_sel);
		break;
	case 1:
		evt = FIELD_GET(MLXBF_L3C_PERF_CNT_SEL__CNT_1, perfcnt_sel);
		break;
	case 2:
		evt = FIELD_GET(MLXBF_L3C_PERF_CNT_SEL__CNT_2, perfcnt_sel);
		break;
	case 3:
		evt = FIELD_GET(MLXBF_L3C_PERF_CNT_SEL__CNT_3, perfcnt_sel);
		break;
	case 4:
		evt = FIELD_GET(MLXBF_L3C_PERF_CNT_SEL_1__CNT_4,
				perfcnt_sel_1);
		break;
	default:
		return -EINVAL;
	}
	*result = evt;

	return 0;
}

int mlxbf_read_crspace_event(int blk_num, uint32_t cnt_num, uint64_t *result)
{
	uint32_t word, evt;
	int reg_num, ret;
	void *addr;

	reg_num = (cnt_num / 2);
	addr = pmc->block[blk_num].mmio_base + (reg_num * 4);

	ret = mlxbf_pmc_readl(&word, addr);
	if (ret)
		return ret;

	switch(cnt_num % 2) {
	case 0:
		evt = FIELD_GET(MLXBF_CRSPACE_PERFSEL0, word);
		break;
	case 1:
		evt = FIELD_GET(MLXBF_CRSPACE_PERFSEL1, word);
		break;
	default:
		return -EINVAL;
	}
	*result = evt;

	return 0;
}

/* Method to find the event currently being monitored by a counter */
int mlxbf_read_event(int blk_num, uint32_t cnt_num, bool is_l3,
		     uint64_t *result)
{
	uint32_t perfcfg_offset, perfval_offset;
	uint64_t perfmon_cfg, perfevt;

	if (cnt_num >= pmc->block[blk_num].counters)
		return -EINVAL;

	if (is_l3)
		return mlxbf_read_l3_event(blk_num, cnt_num, result);

	if (pmc->block[blk_num].type == MLXBF_PERFTYPE_CRSPACE)
		return mlxbf_read_crspace_event(blk_num, cnt_num, result);


	perfcfg_offset = cnt_num * 8;
	perfval_offset = perfcfg_offset + pmc->block[blk_num].counters * 8;

	/* Set counter in "read" mode */
	perfmon_cfg = 0;
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__ADDR,
				  MLXBF_PERFEVT);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__STROBE, 1);
	perfmon_cfg |= FIELD_PREP(MLXBF_GEN_PERFMON_CONFIG__WR_R_B, 0);

	if (mlxbf_pmc_writeq(perfmon_cfg, pmc->block[blk_num].mmio_base +
			     perfcfg_offset))
		return -EFAULT;

	/* Get the event number */
	if (mlxbf_pmc_readq(&perfevt, pmc->block[blk_num].mmio_base +
			    perfval_offset))
		return -EFAULT;

	*result = FIELD_GET(MLXBF_GEN_PERFEVT__EVTSEL, perfevt);

	return 0;
}

/* Method to read a register */
int mlxbf_read_reg(int blk_num, uint32_t offset, uint64_t *result)
{
	uint32_t ecc_out;

	if (strstr(pmc->block_name[blk_num], "ecc")) {
		if (mlxbf_pmc_readl(&ecc_out,
			pmc->block[blk_num].mmio_base + offset))
			return -EFAULT;

		*result = (uint64_t) ecc_out;
		return 0;
	}

	if (mlxbf_pmc_valid_range(blk_num, offset))
		return mlxbf_pmc_readq(result,
			pmc->block[blk_num].mmio_base + offset);

	return -EINVAL;
}

/* Method to write to a register */
int mlxbf_write_reg(int blk_num, uint32_t offset, uint64_t data)
{
	if (strstr(pmc->block_name[blk_num], "ecc")) {
		return mlxbf_pmc_writel((uint32_t)data,
				pmc->block[blk_num].mmio_base + offset);
	}

	if (mlxbf_pmc_valid_range(blk_num, offset))
		return mlxbf_pmc_writeq(data,
			pmc->block[blk_num].mmio_base + offset);

	return -EINVAL;
}

/* Show function for "counter" sysfs files */
static ssize_t mlxbf_counter_read(struct kobject *ko,
				  struct kobj_attribute *attr, char *buf)
{
	int blk_num, cnt_num, offset, err;
	bool is_l3 = false;
	uint64_t value;

	blk_num = mlxbf_pmc_get_block_num(ko->name);
	if (blk_num < 0)
		return -EINVAL;

	if (strstr(ko->name, "l3cache"))
		is_l3 = true;

	if ((pmc->block[blk_num].type == MLXBF_PERFTYPE_COUNTER) ||
	    (pmc->block[blk_num].type == MLXBF_PERFTYPE_CRSPACE)) {
		err = sscanf(attr->attr.name, "counter%d", &cnt_num);
		if (err < 0)
			return -EINVAL;
		if (mlxbf_read_counter(blk_num, cnt_num, is_l3, &value))
			return -EINVAL;
	} else  if (pmc->block[blk_num].type == MLXBF_PERFTYPE_REGISTER) {
		offset = mlxbf_pmc_get_event_num((char *)ko->name,
			(char *)attr->attr.name);
		if (offset < 0)
			return -EINVAL;
		if (mlxbf_read_reg(blk_num, offset, &value))
			return -EINVAL;
	} else
		return -EINVAL;

	return snprintf(buf, PAGE_SIZE, "0x%llx\n", value);
}

/* Store function for "counter" sysfs files */
static ssize_t mlxbf_counter_clear(struct kobject *ko,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int blk_num, cnt_num, offset, err, data;
	bool is_l3 = false;
	uint64_t evt_num;

	blk_num = mlxbf_pmc_get_block_num(ko->name);
	if (blk_num < 0)
		return -EINVAL;

	err = sscanf(buf, "%x\n", &data);
	if (err < 0)
		return -EINVAL;

	/* Allow non-zero writes only to the ecc regs */
	if (!(strstr(ko->name, "ecc")) && (data != 0))
		return -EINVAL;

	if (strstr(ko->name, "l3cache"))
		return -EINVAL;

	if (pmc->block[blk_num].type == MLXBF_PERFTYPE_COUNTER) {
		err = sscanf(attr->attr.name, "counter%d", &cnt_num);
		if (err < 0)
			return -EINVAL;
		err = mlxbf_read_event(blk_num, cnt_num, is_l3, &evt_num);
		if (err < 0)
			return -EINVAL;
		err = mlxbf_program_counter(blk_num, cnt_num, evt_num, is_l3);
		if (err < 0)
			return -EINVAL;
	} else if (pmc->block[blk_num].type == MLXBF_PERFTYPE_REGISTER) {
		offset = mlxbf_pmc_get_event_num((char *)ko->name,
			(char *)attr->attr.name);
		if (offset < 0)
			return -EINVAL;
		err = mlxbf_write_reg(blk_num, offset, data);
		if (err < 0)
			return -EINVAL;
	} else if (pmc->block[blk_num].type == MLXBF_PERFTYPE_CRSPACE) {
		err = sscanf(attr->attr.name, "counter%d", &cnt_num);
		if (err < 0)
			return -EINVAL;
		err = mlxbf_clear_crspace_counter(blk_num, cnt_num);
	} else
		return -EINVAL;

	return count;
}

/* Show function for "event" sysfs files */
static ssize_t mlxbf_event_find(struct kobject *ko,
				struct kobj_attribute *attr, char *buf)
{
	int blk_num, cnt_num, err;
	bool is_l3 = false;
	uint64_t evt_num;
	char *evt_name;

	blk_num = mlxbf_pmc_get_block_num(ko->name);
	if (blk_num < 0)
		return -EINVAL;

	if (strstr(ko->name, "l3cache"))
		is_l3 = true;

	err = sscanf(attr->attr.name, "event%d", &cnt_num);
	if (err < 0)
		return -EINVAL;

	err = mlxbf_read_event(blk_num, cnt_num, is_l3, &evt_num);
	if (err < 0)
		return -EINVAL;

	evt_name = mlxbf_pmc_get_event_name((char *)ko->name, evt_num);

	return snprintf(buf, PAGE_SIZE,
			"0x%llx: %s\n", evt_num, evt_name);
}

/* Store function for "event" sysfs files */
static ssize_t mlxbf_event_set(struct kobject *ko, struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	int blk_num, cnt_num, evt_num, err;
	bool is_l3 = false;

	if (isalpha(buf[0])) {
		evt_num = mlxbf_pmc_get_event_num((char *)ko->name,
						  (char *)buf);
		if (evt_num < 0)
			return -EINVAL;
	} else {
		err = sscanf(buf, "%x\n", &evt_num);
		if (err < 0)
			return -EINVAL;
	}

	blk_num = mlxbf_pmc_get_block_num(ko->name);
	if (blk_num < 0)
		return -EINVAL;

	err = sscanf(attr->attr.name, "event%d", &cnt_num);
	if (err < 0)
		return -EINVAL;

	if (strstr(ko->name, "l3cache"))
		is_l3 = true;

	err = mlxbf_program_counter(blk_num, cnt_num, evt_num, is_l3);
	if (err < 0)
		return -EINVAL;

	return count;
}

/* Show function for "event_list" sysfs files */
static ssize_t mlxbf_print_event_list(struct kobject *ko,
				      struct kobj_attribute *attr, char *buf)
{
	struct mlxbf_pmc_events *events;
	int i = 0, size = 0, ret = 0;
	char e_info[100];

	events = mlxbf_pmc_event_list((char *)ko->name);
	if (events == NULL)
		return -EINVAL;

	buf[0] = '\0';
	while (events[i].evt_name != NULL) {
		size += snprintf(e_info,
				 sizeof(e_info),
				 "%x: %s\n",
				 events[i].evt_num,
				 events[i].evt_name);
		if (size >= PAGE_SIZE)
			break;
		strcat(buf, e_info);
		ret = size;
		++i;
	}

	return ret;
}

/* Show function for "enable" sysfs files - only for l3cache and crspace */
static ssize_t mlxbf_show_counter_state(struct kobject *ko,
					struct kobj_attribute *attr, char *buf)
{
	uint32_t perfcnt_cfg, word;
	int blk_num, value, err;

	blk_num = mlxbf_pmc_get_block_num(ko->name);
	if (blk_num < 0)
		return -EINVAL;

	if (pmc->block[blk_num].type == MLXBF_PERFTYPE_CRSPACE) {
		err = mlxbf_pmc_readl(&word, pmc->block[blk_num].mmio_base +
			MLXBF_CRSPACE_PERFMON_CTL(pmc->block[blk_num].counters));
		if (err)
			return -EINVAL;
		value = FIELD_GET(MLXBF_CRSPACE_PERFMON_EN, word);
	} else {
		if (mlxbf_pmc_readl(&perfcnt_cfg, pmc->block[blk_num].mmio_base
						 + MLXBF_L3C_PERF_CNT_CFG))
			return -EINVAL;

		value = FIELD_GET(MLXBF_L3C_PERF_CNT_CFG__EN, perfcnt_cfg);
	}

	return snprintf(buf, PAGE_SIZE, "%d\n", value);
}

/* Store function for "enable" sysfs files - only for l3cache and crspace */
static ssize_t mlxbf_enable_counters(struct kobject *ko,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	int err, en, blk_num;
	uint32_t word;

	blk_num = mlxbf_pmc_get_block_num(ko->name);
	if (blk_num < 0)
		return -EINVAL;

	err = sscanf(buf, "%x\n", &en);
	if (err < 0)
		return err;
	if (pmc->block[blk_num].type == MLXBF_PERFTYPE_CRSPACE) {
		err = mlxbf_pmc_readl(&word, pmc->block[blk_num].mmio_base +
			MLXBF_CRSPACE_PERFMON_CTL(pmc->block[blk_num].counters));
		if (err)
			return -EINVAL;
		word &= ~MLXBF_CRSPACE_PERFMON_EN;
		word |= FIELD_PREP(MLXBF_CRSPACE_PERFMON_EN, en);
		if (en)
			word |= FIELD_PREP(MLXBF_CRSPACE_PERFMON_CLR, 1);
		mlxbf_pmc_writel(word, pmc->block[blk_num].mmio_base +
			MLXBF_CRSPACE_PERFMON_CTL(pmc->block[blk_num].counters));
	} else {
		if (en == 0) {
			err = mlxbf_config_l3_counters(blk_num, false, false);
			if (err)
				return err;
		} else if (en == 1) {
			err = mlxbf_config_l3_counters(blk_num, false, true);
			if (err)
				return err;
			err = mlxbf_config_l3_counters(blk_num, true, false);
			if (err)
				return err;
		} else
			return -EINVAL;
	}

	return count;
}

/* Helper to create the bfperf sysfs sub-directories and files */
int mlxbf_pmc_create_sysfs(struct device *dev, struct kobject *ko, int blk_num)
{
	int err = 0, j = 0;

	pmc->block[blk_num].block_dir =
		kobject_create_and_add(pmc->block_name[blk_num], ko);
	if (pmc->block[blk_num].block_dir == NULL) {
		dev_err(dev,
			"PMC: Error creating subdirectories\n");
		return -EFAULT;
	}

	if ((pmc->block[blk_num].type == MLXBF_PERFTYPE_COUNTER) ||
	    (pmc->block[blk_num].type == MLXBF_PERFTYPE_CRSPACE)) {
		pmc->block[blk_num].attr_event_list.attr.mode = 0444;
		pmc->block[blk_num].attr_event_list.show =
			mlxbf_print_event_list;
		pmc->block[blk_num].attr_event_list.attr.name =
			kzalloc(20, GFP_KERNEL);
		snprintf((char *)pmc->block[blk_num].attr_event_list.attr.name,
			 20, "event_list");

		err = sysfs_create_file(pmc->block[blk_num].block_dir,
			&pmc->block[blk_num].attr_event_list.attr);
		if (err < 0) {
			dev_err(dev,
			"PMC: Error creating sysfs entries\n");
			return err;
		}

		if ((strstr(pmc->block_name[blk_num], "l3cache")) ||
		    (pmc->block[blk_num].type == MLXBF_PERFTYPE_CRSPACE)) {
			pmc->block[blk_num].attr_enable.attr.mode =
				0644;
			pmc->block[blk_num].attr_enable.show =
				mlxbf_show_counter_state;
			pmc->block[blk_num].attr_enable.store =
				mlxbf_enable_counters;
			pmc->block[blk_num].attr_enable.attr.name =
				kzalloc(20, GFP_KERNEL);
			snprintf((char *)
				pmc->block[blk_num].attr_enable.attr.name,
				20, "enable");

			err = sysfs_create_file(
				pmc->block[blk_num].block_dir,
				&pmc->block[blk_num].attr_enable.attr);
			if (err < 0) {
				dev_err(dev,
				"PMC: Error creating sysfs entries\n");
				return err;
			}

		}

		pmc->block[blk_num].attr_counter =
			kcalloc(pmc->block[blk_num].counters,
				sizeof(struct kobj_attribute), GFP_KERNEL);
		if (!pmc->block[blk_num].attr_counter)
			return -ENOMEM;
		pmc->block[blk_num].attr_event =
			kcalloc(pmc->block[blk_num].counters,
				sizeof(struct kobj_attribute), GFP_KERNEL);
		if (!pmc->block[blk_num].attr_event)
			return -ENOMEM;
		pmc->block[blk_num].sysfs_event_cnt =
			pmc->block[blk_num].counters;

		for (j = 0; j < pmc->block[blk_num].counters; ++j) {
			pmc->block[blk_num].attr_counter[j].attr.mode = 0644;
			pmc->block[blk_num].attr_counter[j].show =
				mlxbf_counter_read;
			pmc->block[blk_num].attr_counter[j].store =
				mlxbf_counter_clear;
			pmc->block[blk_num].attr_counter[j].attr.name =
				kzalloc(20, GFP_KERNEL);
			snprintf((char *)
				pmc->block[blk_num].attr_counter[j].attr.name,
				20, "counter%d", j);

			err = sysfs_create_file(
				pmc->block[blk_num].block_dir,
				&pmc->block[blk_num].attr_counter[j].attr);
			if (err < 0) {
				dev_err(dev,
				"PMC: Error creating sysfs entries\n");
				return err;
			}

			pmc->block[blk_num].attr_event[j].attr.mode = 0644;
			pmc->block[blk_num].attr_event[j].show =
				mlxbf_event_find;
			pmc->block[blk_num].attr_event[j].store =
				mlxbf_event_set;
			pmc->block[blk_num].attr_event[j].attr.name =
				kzalloc(20, GFP_KERNEL);
			snprintf((char *)
				 pmc->block[blk_num].attr_event[j].attr.name,
				 20, "event%d", j);

			err = sysfs_create_file(
				pmc->block[blk_num].block_dir,
				&pmc->block[blk_num].attr_event[j].attr);
			if (err < 0) {
				dev_err(dev,
				"PMC: Error creating sysfs entries\n");
				return err;
			}
		}
	} else if (pmc->block[blk_num].type == MLXBF_PERFTYPE_REGISTER) {
		struct mlxbf_pmc_events *events;

		events = mlxbf_pmc_event_list((char *)pmc->block_name[blk_num]);
		if (events == NULL)
			return -EINVAL;

		while (events[j].evt_name != NULL)
			++j;

		pmc->block[blk_num].sysfs_event_cnt = j;
		pmc->block[blk_num].attr_event =
			kcalloc(j, sizeof(struct kobj_attribute), GFP_KERNEL);
		if (!pmc->block[blk_num].attr_event)
			return -ENOMEM;

		while (j > 0) {
			--j;
			pmc->block[blk_num].attr_event[j].attr.mode = 0644;
			pmc->block[blk_num].attr_event[j].show =
				mlxbf_counter_read;
			pmc->block[blk_num].attr_event[j].store =
				mlxbf_counter_clear;
			pmc->block[blk_num].attr_event[j].attr.name =
				kzalloc(30, GFP_KERNEL);
			strcpy((char *)
			       pmc->block[blk_num].attr_event[j].attr.name,
			       events[j].evt_name);

			err = sysfs_create_file(
				pmc->block[blk_num].block_dir,
				&pmc->block[blk_num].attr_event[j].attr);
			if (err < 0) {
				dev_err(dev,
				"PMC: Error creating sysfs entries\n");
				return err;
			}
		}
	} else
		err = -EINVAL;

	return err;
}

void mlxbf_pmc_delete(void)
{
	hwmon_device_unregister(pmc->hwmon_dev);
	kfree(pmc);
}

static int mlxbf_pmc_probe(struct platform_device *pdev)
{
	struct acpi_device *acpi_dev = ACPI_COMPANION(&pdev->dev);
	const char *hid = acpi_device_hid(acpi_dev);
	int i, version, err = 0, ret = 0;
	struct device *dev = &pdev->dev;
	struct arm_smccc_res res;
	uint64_t info[4];

	/*
	 * Ensure we have the UUID we expect for the Mellanox service.
	 */
	arm_smccc_smc(MLNX_SIP_SVC_UID, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != 0x89c036b4 || res.a1 != 0x11e6e7d7 ||
		res.a2 != 0x1a009787 || res.a3 != 0xc4bf00ca)
		return -ENODEV;

	pmc = kzalloc(sizeof(struct mlxbf_pmc_context), GFP_KERNEL);
	if (!pmc)
		return -ENOMEM;

	platform_set_drvdata(pdev, pmc);
	pmc->pdev = pdev;

	pmc->hwmon_dev = hwmon_device_register_with_info(dev, "bfperf", pmc,
		NULL, NULL);
	pmc->ko = &pmc->hwmon_dev->kobj;

	/*
	 * ACPI indicates whether we use SMCs to access registers or not.
	 * If sreg_tbl_perf is not present, just assume we're not using SMCs.
	 */
	if (device_property_read_u32(dev,
				"sec_reg_block", &pmc->sreg_tbl_perf)) {
		pmc->svc_sreg_support = false;
	} else {
		/*
		 * Check service version to see if we actually do support the
		 * needed SMCs. If we have the calls we need, mark support for
		 * them in the pmc struct.
		 */
		arm_smccc_smc(MLNX_SIP_SVC_VERSION, 0, 0, 0, 0, 0, 0, 0, &res);
		if (res.a0 == MLNX_PMC_SVC_REQ_MAJOR &&
			res.a1 >= MLNX_PMC_SVC_MIN_MINOR)
			pmc->svc_sreg_support = true;
		else {
			dev_err(dev, "Required SMCs are not supported.\n");

			err = -EINVAL;
			goto error;
		}
	}

	if (pmc->ko == NULL) {
		dev_err(dev, "Sysfs creation failed\n");
		err = -EFAULT;
		goto error;
	}

	if (device_property_read_u32(dev, "version", &version)) {
		dev_err(dev, "Version Info not found\n");
		err = -EINVAL;
		goto error;
	}

	if (version != (int)DRIVER_VERSION) {
		dev_err(dev, "Version Mismatch. Expected %d Returned %d\n",
			(int)DRIVER_VERSION, version);
		err = -EINVAL;
		goto error;
	}

	if (strcmp(hid, "MLNXBFD0") == 0)
		pmc->event_set = MLNX_EVENT_SET_BF1;
	else if (strcmp(hid, "MLNXBFD1") == 0)
		pmc->event_set = MLNX_EVENT_SET_BF2;
	else if (strcmp(hid, "MLNXBFD2") == 0)
		pmc->event_set = MLNX_EVENT_SET_BF3;
	else {
		dev_err(dev, "Invalid device ID %s\n", hid);
		err = -ENODEV;
		goto error;
	}

	if (device_property_read_u32(dev, "block_num", &pmc->total_blocks)) {
		dev_err(dev, "Number of performance blocks undefined\n");
		err = -EINVAL;
		goto error;
	}

	ret = device_property_read_string_array(dev, "block_name",
		pmc->block_name, pmc->total_blocks);
	if (ret != pmc->total_blocks) {
		dev_err(dev,
			"Block count mismatch. Expected %d Returned %d\n",
			pmc->total_blocks, ret);
		err = -EFAULT;
		goto error;
	}

	if (device_property_read_u32(dev, "tile_num", &pmc->tile_count)) {
		if (device_property_read_u8(dev, "llt_enable",
					     &pmc->llt_enable)) {
			dev_err(dev, "Number of tiles/LLTs undefined\n");
			err = -EINVAL;
			goto error;
		}
		if (device_property_read_u8(dev, "mss_enable",
					     &pmc->mss_enable)) {
			dev_err(dev, "Number of tiles/MSSs undefined\n");
			err = -EINVAL;
			goto error;
		}
	}

	/* Map the Performance Counters from the varios blocks */
	for (i = 0; i < pmc->total_blocks; ++i) {
		/* Check if block number is within tile_count */
		if (strstr(pmc->block_name[i], "tile")) {
			int tile_num;

			if (sscanf(pmc->block_name[i], "tile%d", &tile_num) != 1) {
				err = -EINVAL;
				goto error;
			}
			if (tile_num >= pmc->tile_count)
				continue;
		}

		/* Create sysfs directories only for enabled MSS blocks */
		if (strstr(pmc->block_name[i], "mss") &&
		    pmc->event_set == MLNX_EVENT_SET_BF3) {
			int mss_num;

			ret = sscanf(pmc->block_name[i], "mss%d", &mss_num);
			if (ret < 0) {
				err = -EINVAL;
				goto error;
			}
			if (!((pmc->mss_enable >> mss_num) & 0x1))
				continue;
		}

		/* Create sysfs directories only for enabled LLTs */
		if (strstr(pmc->block_name[i], "llt_miss")) {
			int llt_num;

			ret = sscanf(pmc->block_name[i], "llt_miss%d", &llt_num);
			if (ret < 0) {
				err = -EINVAL;
				goto error;
			}
			if (!((pmc->llt_enable >> llt_num) & 0x1))
				continue;
		} else if (strstr(pmc->block_name[i], "llt")) {
			int llt_num;

			ret = sscanf(pmc->block_name[i], "llt%d", &llt_num);
			if (ret < 0) {
				err = -EINVAL;
				goto error;
			}
			if (!((pmc->llt_enable >> llt_num) & 0x1))
				continue;
		}

		err = device_property_read_u64_array(dev, pmc->block_name[i],
			info, 4);
		if (err) {
			dev_err(dev, "Failed to find %s block info\n",
				pmc->block_name[i]);
			goto error;
		}

		/*
		 * Do not remap if the proper SMC calls are supported,
		 * since the SMC calls expect physical addresses.
		 */
		if (pmc->svc_sreg_support)
			pmc->block[i].mmio_base = (void *)info[0];
		else
			pmc->block[i].mmio_base = ioremap(info[0], info[1]);

		pmc->block[i].blk_size = info[1];
		pmc->block[i].counters = info[2];
		pmc->block[i].type = info[3];

		if (IS_ERR(pmc->block[i].mmio_base)) {
			dev_err(dev, "%s: ioremap failed base %llx err %p\n",
				__func__, info[0], pmc->block[i].mmio_base);
			err = PTR_ERR(pmc->block[i].mmio_base);
			goto error;
		}

		err = mlxbf_pmc_create_sysfs(dev, pmc->ko, i);
	}

	dev_info(&pdev->dev, "v%d probed\n", (int)DRIVER_VERSION);
	return 0;

error:
	mlxbf_pmc_delete();
	return err;
}

static int mlxbf_pmc_remove(struct platform_device *pdev)
{
	struct mlxbf_pmc_context *pmc = platform_get_drvdata(pdev);
	int i, j;

	for (i = 0; i < pmc->total_blocks; ++i) {
		if (strstr(pmc->block_name[i], "tile")) {
			int tile_num;

			if (sscanf(pmc->block_name[i], "tile%d", &tile_num) != 1)
				return -EINVAL;
			if (tile_num >= pmc->tile_count)
				continue;
		}
		kfree(pmc->block[i].attr_event_list.attr.name);
		if (pmc->block[i].type == MLXBF_PERFTYPE_COUNTER) {
			for (j = 0; j < pmc->block[i].counters; ++j) {
				kfree(pmc->block[i].attr_counter[j].attr.name);
				kfree(pmc->block[i].attr_event[j].attr.name);
			}
		} else if (pmc->block[i].type == MLXBF_PERFTYPE_REGISTER) {
			for (j = 0; j < pmc->block[i].sysfs_event_cnt; ++j)
				kfree(pmc->block[i].attr_event[j].attr.name);
		}

		/* Unmap if SMCs weren't used for access */
		if (pmc->block[i].mmio_base && !(pmc->svc_sreg_support))
			iounmap(pmc->block[i].mmio_base);

		kobject_put(pmc->block[i].block_dir);
		kfree(pmc->block[i].attr_event);
		kfree(pmc->block[i].attr_counter);
	}

	mlxbf_pmc_delete();

	return 0;
}

static const struct acpi_device_id pmc_acpi_ids[] = {
	{"MLNXBFD0", 0},
	{"MLNXBFD1", 0},
	{"MLNXBFD2", 0},
	{},
};

MODULE_DEVICE_TABLE(acpi, pmc_acpi_ids);
static struct platform_driver pmc_driver = {
	.driver = {
		.name = "mlxbf-pmc",
		.acpi_match_table = ACPI_PTR(pmc_acpi_ids),
	},
	.probe = mlxbf_pmc_probe,
	.remove = mlxbf_pmc_remove,
};

module_platform_driver(pmc_driver);

MODULE_AUTHOR("Shravan Kumar Ramani <shravankr@nvidia.com>");
MODULE_DESCRIPTION("Mellanox PMC driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(__stringify(DRIVER_VERSION));
