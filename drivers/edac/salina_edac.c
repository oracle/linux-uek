// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Pensando Salina Memory Controller EDAC Driver
 *
 * Copyright (c) 2026, Advanced Micro Devices Inc.
 */

#include <linux/edac.h>
#include <linux/platform_device.h>
#include <linux/notifier.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/panic_notifier.h>
#include <linux/arm-smccc.h>
#include "edac_module.h"

#define SAL_MC_NCHANS			4
#define SAL_MC_MCTL_OFFS		0x60000

#define SAL_MCTL_ECC_U_ADDR		240
#define SAL_MCTL_ECC_U_SYND		241
#define SAL_MCTL_ECC_C_ADDR		244
#define SAL_MCTL_ECC_C_SYND		245
#define SAL_MCTL_ECC_ID			248
#define SAL_MCTL_INT_STAT_ECC		315
#define SAL_MCTL_INT_ACK_ECC		324

#define SAL_MCTL_ECC_ADDR(a, s)		((a) | ((u64)((s) & 0xff) << 32))
#define SAL_MCTL_ECC_SYND(s)		(((s) >> 8) & 0xff)
#define SAL_MCTL_ECC_U_ID(n)		((n) & 0xffff)
#define SAL_MCTL_ECC_C_ID(n)		(((n) >> 16) & 0xffff)

#define SAL_MCTL_INT_MULTI_U_ECC	BIT(3)
#define SAL_MCTL_INT_U_ECC		BIT(2)
#define SAL_MCTL_INT_MULTI_C_ECC	BIT(1)
#define SAL_MCTL_INT_C_ECC		BIT(0)

#define SAL_MCTL_INT_ACK_MASK		0xf

/* Refer Pensando BL31 Function Registry.docx */
#define PEN_SECREG_SMC_CALL_FID       0xC200000B

enum pen_secreg_smc_sub_fid {
	PEN_SECREG_SMC_REG_READ = 0,
	PEN_SECREG_SMC_REG_WRITE = 1,
};

enum pen_secreg_smc_err_codes {
	PEN_SECREG_SMC_ERR_NONE = 0,
	/* -1 reserved for unknown fid as per smcc calling convention */
	PEN_SECREG_SMC_ERR_INVALID = -2,
	PEN_SECREG_SMC_ERR_UNSUPPORTED = -3,
};

struct salina_mcdata {
	phys_addr_t base[SAL_MC_NCHANS];	/* per-channel MC physical base addresses */
};

static struct salina_mcdata *g_mcp;

struct salina_mcpoll_res {
	u64 ddr_addr;			/* ecc address reported by the mc */
	u64 bus_addr;			/* system bus address (or 0 if no map) */
	u16 cnt;			/* ecc count (1=single, 2=multiple) */
	u16 id;				/* axi source id info */
	u8 synd;			/* ecc syndrome */
	char msg[128];			/* informational message */
};

static inline int salina_mctl_read(struct salina_mcdata *mcp, int chan, int reg,
				   u32 *val)
{
	struct arm_smccc_res res = {0};
	phys_addr_t addr = mcp->base[chan] + SAL_MC_MCTL_OFFS + 4 * reg;

	arm_smccc_smc(PEN_SECREG_SMC_CALL_FID,
		      PEN_SECREG_SMC_REG_READ, addr,
		      0, 0, 0, 0, 0, &res);

	if (res.a0 != PEN_SECREG_SMC_ERR_NONE) {
		pr_err_once("pensando-mctl: read failed! ret=%ld\n", res.a0);
		return -EIO;
	}

	/* result passed back in a1 reg */
	*val = (u32)res.a1;
	return 0;
}

static inline int salina_mctl_write(struct salina_mcdata *mcp, int chan, int reg,
				    u32 data)
{
	struct arm_smccc_res res = {0};
	phys_addr_t addr = mcp->base[chan] + SAL_MC_MCTL_OFFS + 4 * reg;

	arm_smccc_smc(PEN_SECREG_SMC_CALL_FID,
		      PEN_SECREG_SMC_REG_WRITE, addr,
		      data, 0, 0, 0, 0, &res);

	if (res.a0 != PEN_SECREG_SMC_ERR_NONE) {
		pr_err_once("pensando-mctl: failed to write data! ret=%d\n", (int)res.a0);
		return -EIO;
	}

	return 0;
}

/* TODO: implement via Salina BL31 DDR SMC once ATF support lands. */
static u64 salina_ddr_addr_to_bus(struct salina_mcdata *mcp, u64 ddr_addr)
{
	return ddr_addr;
}

static int salina_edac_mc_c_poll(struct salina_mcdata *mcp, int chan, u32 int_stat,
				 struct salina_mcpoll_res *res)
{
	u32 addr, synd, id;

	if (!(int_stat & SAL_MCTL_INT_C_ECC))
		return 0;

	res->cnt = (int_stat & SAL_MCTL_INT_MULTI_C_ECC) ? 2 : 1;
	if (salina_mctl_read(mcp, chan, SAL_MCTL_ECC_C_ADDR, &addr) ||
	    salina_mctl_read(mcp, chan, SAL_MCTL_ECC_C_SYND, &synd) ||
	    salina_mctl_read(mcp, chan, SAL_MCTL_ECC_ID, &id))
		return -EIO;

	res->ddr_addr = SAL_MCTL_ECC_ADDR(addr, synd);
	res->bus_addr = salina_ddr_addr_to_bus(mcp, res->ddr_addr);
	res->synd = SAL_MCTL_ECC_SYND(synd);
	res->id   = SAL_MCTL_ECC_C_ID(id);
	snprintf(res->msg, sizeof(res->msg), "ddr_addr 0x%llx, id 0x%04x",
			res->ddr_addr, res->id);
	return 1;
}

static int salina_edac_mc_u_poll(struct salina_mcdata *mcp, int chan, u32 int_stat,
				 struct salina_mcpoll_res *res)
{
	u32 addr, synd, id;

	if (!(int_stat & SAL_MCTL_INT_U_ECC))
		return 0;

	res->cnt = (int_stat & SAL_MCTL_INT_MULTI_U_ECC) ? 2 : 1;
	if (salina_mctl_read(mcp, chan, SAL_MCTL_ECC_U_ADDR, &addr) ||
	    salina_mctl_read(mcp, chan, SAL_MCTL_ECC_U_SYND, &synd) ||
	    salina_mctl_read(mcp, chan, SAL_MCTL_ECC_ID, &id))
		return -EIO;

	res->ddr_addr = SAL_MCTL_ECC_ADDR(addr, synd);
	res->bus_addr = salina_ddr_addr_to_bus(mcp, res->ddr_addr);
	res->synd = SAL_MCTL_ECC_SYND(synd);
	res->id   = SAL_MCTL_ECC_U_ID(id);
	snprintf(res->msg, sizeof(res->msg), "ddr_addr 0x%llx, id 0x%04x",
			res->ddr_addr, res->id);
	return 1;
}

static void salina_edac_mc_poll_chan(struct mem_ctl_info *mci, int chan)
{
	struct salina_mcdata *mcp = mci->pvt_info;
	struct salina_mcpoll_res res;
	u32 int_stat, int_ack;

	if (salina_mctl_read(mcp, chan, SAL_MCTL_INT_STAT_ECC, &int_stat))
		return;

	if (salina_edac_mc_c_poll(mcp, chan, int_stat, &res) > 0) {
		edac_mc_handle_error(HW_EVENT_ERR_CORRECTED, mci, res.cnt,
			res.bus_addr >> PAGE_SHIFT, res.bus_addr & ~PAGE_MASK,
			res.synd, chan, -1, -1, res.msg, "");
	}

	if (salina_edac_mc_u_poll(mcp, chan, int_stat, &res) > 0) {
		edac_mc_handle_error(HW_EVENT_ERR_UNCORRECTED, mci, res.cnt,
			res.bus_addr >> PAGE_SHIFT, res.bus_addr & ~PAGE_MASK,
			res.synd, chan, -1, -1, res.msg, "");
	}

	int_ack = int_stat & SAL_MCTL_INT_ACK_MASK;
	if (int_ack)
		salina_mctl_write(mcp, chan, SAL_MCTL_INT_ACK_ECC, int_ack);
}

static void salina_edac_mc_poll(struct mem_ctl_info *mci)
{
	int chan;

	for (chan = 0; chan < SAL_MC_NCHANS; chan++)
		salina_edac_mc_poll_chan(mci, chan);
}

/*
 * A read error (SError) that causes a kernel panic won't have been
 * polled yet, so one final check for uncorrectable errors on the way down.
 */
static int salina_edac_mc_panic_notifier(struct notifier_block *nb,
					 unsigned long event, void *ptr)
{
	struct salina_mcdata *mcp = g_mcp;
	struct salina_mcpoll_res res;
	u32 int_stat;
	int chan;

	for (chan = 0; chan < SAL_MC_NCHANS; chan++) {
		if (salina_mctl_read(mcp, chan, SAL_MCTL_INT_STAT_ECC, &int_stat))
			continue;
		if (salina_edac_mc_u_poll(mcp, chan, int_stat, &res) > 0) {
			pr_crit("EDAC MC0: %u UE %s "
				"on unknown memory (channel:%u page:0x%llx "
				"offset:0x%llx grain:8 syndrome:0x%02x)\n",
				res.cnt, res.msg, chan,
				res.bus_addr >> PAGE_SHIFT,
				res.bus_addr & ~PAGE_MASK,
				res.synd);
		}
	}
	return 0;
}

static struct notifier_block panic_block = {
	.notifier_call = salina_edac_mc_panic_notifier
};

static void salina_init_dimms(struct mem_ctl_info *mci)
{
	struct dimm_info *dimm;
	int chan;

	for (chan = 0; chan < SAL_MC_NCHANS; chan++) {
		dimm = mci->dimms[chan];
		dimm->grain = 8;
		dimm->mtype = MEM_DDR5;
		dimm->dtype = DEV_X8;
		dimm->edac_mode = EDAC_SECDED;
		dimm->nr_pages = 1; /* not empty */
	}
}

static int salina_edac_mc_probe(struct platform_device *pdev)
{
	struct edac_mc_layer layers[1];
	struct mem_ctl_info *mci;
	struct salina_mcdata *mcp;
	struct resource *r;
	int chan;

	for (chan = 0; chan < SAL_MC_NCHANS; chan++) {
		r = platform_get_resource(pdev, IORESOURCE_MEM, chan);
		if (!r) {
			dev_err(&pdev->dev, "Unable to get mem resource %d\n",
				chan);
			return -ENODEV;
		}
	}

	layers[0].type = EDAC_MC_LAYER_CHANNEL;
	layers[0].size = SAL_MC_NCHANS;
	layers[0].is_virt_csrow = false;

	mci = edac_mc_alloc(0, 1, layers, sizeof(struct salina_mcdata));
	if (!mci)
		return -ENXIO;

	mcp = mci->pvt_info;
	for (chan = 0; chan < SAL_MC_NCHANS; chan++) {
		r = platform_get_resource(pdev, IORESOURCE_MEM, chan);
		mcp->base[chan] = r->start;
	}

	salina_init_dimms(mci);

	mci->pdev = &pdev->dev;
	mci->dev_name = dev_name(&pdev->dev);

	mci->mod_name = "salina-mc";
	mci->ctl_name = "salina-mc-err";
	mci->edac_check = salina_edac_mc_poll;
	mci->edac_cap = EDAC_FLAG_SECDED;

	if (edac_mc_add_mc(mci)) {
		dev_err(&pdev->dev, "edac_mc_add_mc() failed\n");
		edac_mc_free(mci);
		return -ENXIO;
	}

	platform_set_drvdata(pdev, mci);

	/* hook panic() so we can check for uncorrectable errors */
	g_mcp = mcp;
	atomic_notifier_chain_register(&panic_notifier_list, &panic_block);

	/* set polling mode */
	opstate_init();

	return 0;
}

static void salina_edac_mc_remove(struct platform_device *pdev)
{
	struct mem_ctl_info *mci = platform_get_drvdata(pdev);

	edac_mc_del_mc(&pdev->dev);
	atomic_notifier_chain_unregister(&panic_notifier_list, &panic_block);

	edac_mc_free(mci);
}

static const struct of_device_id salina_edac_mc_of_match[] = {
	{ .compatible = "pensando,salina-edac-mc" },
	{ },
};

static struct platform_driver salina_edac_mc_driver = {
	.probe = salina_edac_mc_probe,
	.remove = salina_edac_mc_remove,
	.driver = {
		.name = "salina_edac_mc",
		.of_match_table = of_match_ptr(salina_edac_mc_of_match),
	}
};
module_platform_driver(salina_edac_mc_driver);

MODULE_DESCRIPTION("AMD Pensando Salina platform EDAC memory controller driver");
MODULE_AUTHOR("Advanced Micro Devices, Inc.");
MODULE_LICENSE("GPL");
