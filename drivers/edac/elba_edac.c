// SPDX-License-Identifier: GPL-2.0
/*
 * Pensando Elba Memory Controller EDAC Driver
 *
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#include <linux/edac.h>
#include <linux/platform_device.h>
#include <linux/notifier.h>
#include <linux/of.h>
#include "edac_module.h"

#define ELB_MC_CHAN_STRIDE		0x80000
#define ELB_MC_NCHANS			2

#define ELB_MC_CONV_MASK_0		0x3010
#define ELB_MC_CONV_MASK_1		0x3020
#define ELB_MC_MCTL			0x30000

#define ELB_MCTL_ECC_U_ADDR		277
#define ELB_MCTL_ECC_U_SYND		278
#define ELB_MCTL_ECC_C_ADDR		281
#define ELB_MCTL_ECC_C_SYND		282
#define ELB_MCTL_ECC_ID			285
#define ELB_MCTL_INT_STAT_ECC		377
#define ELB_MCTL_INT_ACK_ECC		384

#define ELB_MCTL_ECC_ADDR(a, s)		((a) | ((u64)((s) & 0x3f) << 32))
#define ELB_MCTL_ECC_SYND(s)		(((s) >> 8) & 0xff)
#define ELB_MCTL_ECC_U_ID(n)		((n) & 0x3fff)
#define ELB_MCTL_ECC_C_ID(n)		(((n) >> 16) & 0x3fff)

#define ELB_MCTL_INT_MULTI_U_ECC	BIT(3)
#define ELB_MCTL_INT_U_ECC		BIT(2)
#define ELB_MCTL_INT_MULTI_C_ECC	BIT(1)
#define ELB_MCTL_INT_C_ECC		BIT(0)

#define ELB_MCTL_INT_ACK_MASK		0xf

struct ddr_map_func {
	u64 hash;			// bus addr to ddr channel hash
	u64 conv_mask[2];		// bus addr to ddr addr conversion masks
};

struct elba_mcdata {
	void __iomem *base;		// memory controller registers
	struct ddr_map_func llc_map;	// ddr to bus address map for LLC
	struct ddr_map_func ddrb_map; 	// ddr to bus address map for bypass
	u64 byp_start;			// bypass region start
	u64 byp_size;			// bypass region size
	u32 chanmask;			// channel mask (b01, b10, or b11)
	int map_valid;			// ddr to bus map is valid
};

static struct elba_mcdata *g_mcp;

struct elba_mcpoll_res {
	u64 ddr_addr;			// ecc address reported by the mc
	u64 bus_addr;			// system bus address (or 0 if no map)
	u16 cnt;			// ecc count (1=single, 2=multiple)
	u16 id;				// axi source id info
	u8 synd;			// ecc syndrome
	char msg[128];			// informational message
};

static inline u32 elba_mc_read(struct elba_mcdata *mcp, int chan, int offs)
{
	return readl(mcp->base + ELB_MC_CHAN_STRIDE * chan + offs);
}

static inline u32 elba_mctl_read(struct elba_mcdata *mcp, int chan, int reg)
{
	return elba_mc_read(mcp, chan, ELB_MC_MCTL + 4 * reg);
}

static inline void elba_mc_write(struct elba_mcdata *mcp,
		int chan, int offs, u32 data)
{
	return writel(data, mcp->base + ELB_MC_CHAN_STRIDE * chan + offs);
}

static inline void elba_mctl_write(struct elba_mcdata *mcp,
		int chan, int reg, u32 data)
{
	elba_mc_write(mcp, chan, ELB_MC_MCTL + 4 * reg, data);
}

/*
 * Expand a DDR reported address back to a system bus address.
 * In a 2-channel system, each ddr channel takes 1/2 of the bus address
 * space, so one bit is dropped from the original address.
 * This function reverses this, and provides two prospecitve addresses;
 * one with the missing bit clear and the other with the missinog bit set.
 * The channel-selection hash function will be applied with each address
 * to determine the correct one.
 * Only used for 2-channel configurations.
 */
static void elba_ddr_addr_expand(u64 addr, u64 *mask, u64 *res)
{
	u64 addr_o;
	addr_o = ((addr & mask[1]) << 2) |
		 ((addr & mask[0]) << 1) |
		 (addr & ~(mask[0] | mask[1]));
	res[0] = addr_o;
	res[1] = addr_o | ((~(mask[0] | mask[1]) + 1) & 0xfffffffffULL);
}

/*
 * Hash system address to select a ddr channel.
 * The hash_func parameter indicates the bits from the address that
 * should be XORed together to select the target ddr channel.
 * Only used for 2-channel configurations.
 */
static int elba_ddr_hash_func(u64 addr, u64 hash_func)
{
	u64 hash_val;
	int res;

	hash_val = addr & hash_func;

	// reduction XOR
	res = 0;
	while (hash_val) {
		res ^= 1;
		hash_val &= hash_val - 1;
	}
	return res;
}

/*
 * Map a ddr reported ecc address back to an original system bus address.
 * For a 1-channel system, the ddr controller address is the true linear
 * address.
 * For a 2-channel system we first determine the two possible linear address
 * that might map to this channel, then we apply the appropriate hash function
 * to find the final linear address.
 * The llc and bypass regions use different hash and convert functions,
 * so first expand the address using the llc function and then check to see
 * if the linear address is in the bypass range.  If so, switch to the
 * bypass conversion function and hash.
 * Finally, linear addresses outside of 2GB..8GB range must have bit 36 set
 * to recover the original system bus address.
 */
static u64 elba_ddr_addr_to_bus(struct elba_mcdata *mcp, int chan, u64 ddr_addr)
{
	struct ddr_map_func *map = &mcp->llc_map;
	u64 bus_addr = (u64)-1;
	u64 addr_e[2];
	int i;

	if (!mcp->map_valid)
		return 0;

	if (mcp->chanmask == 0x3) {
		elba_ddr_addr_expand(ddr_addr, map->conv_mask, addr_e);
		if (addr_e[0] >= mcp->byp_start &&
		    addr_e[0] < (mcp->byp_start + mcp->byp_size)) {
			map = &mcp->ddrb_map;
			elba_ddr_addr_expand(ddr_addr, map->conv_mask, addr_e);
		}
		for (i = 0; i < 2; i++) {
			if (elba_ddr_hash_func(addr_e[i], map->hash) == chan) {
				bus_addr = addr_e[i];
				break;
			}
		}
	} else {
		bus_addr = ddr_addr;
	}

	if (bus_addr < 0x80000000 || bus_addr >= 0x200000000ULL)
		bus_addr |= 0x1000000000ULL;

	return (bus_addr == (u64)-1) ? 0 : bus_addr;
}

static int elba_edac_mc_c_poll(struct elba_mcdata *mcp, int chan,
			u32 int_stat, struct elba_mcpoll_res *res)
{
	u32 addr, synd, id;

	if (!(int_stat & ELB_MCTL_INT_C_ECC))
		return 0;

	res->cnt = (int_stat & ELB_MCTL_INT_MULTI_C_ECC) ? 2 : 1;
	addr = elba_mctl_read(mcp, chan, ELB_MCTL_ECC_C_ADDR);
	synd = elba_mctl_read(mcp, chan, ELB_MCTL_ECC_C_SYND);
	id   = elba_mctl_read(mcp, chan, ELB_MCTL_ECC_ID);
	res->ddr_addr = ELB_MCTL_ECC_ADDR(addr, synd);
	res->bus_addr = elba_ddr_addr_to_bus(mcp, chan, res->ddr_addr);
	res->synd = ELB_MCTL_ECC_SYND(synd);
	res->id   = ELB_MCTL_ECC_C_ID(id);
	snprintf(res->msg, sizeof(res->msg), "ddr_addr 0x%llx, id 0x%04x",
			res->ddr_addr, res->id);
	return 1;
}

static int elba_edac_mc_u_poll(struct elba_mcdata *mcp, int chan,
			u32 int_stat, struct elba_mcpoll_res *res)
{
	u32 addr, synd, id;

	if (!(int_stat & ELB_MCTL_INT_U_ECC))
		return 0;

	res->cnt = (int_stat & ELB_MCTL_INT_MULTI_U_ECC) ? 2 : 1;
	addr = elba_mctl_read(mcp, chan, ELB_MCTL_ECC_U_ADDR);
	synd = elba_mctl_read(mcp, chan, ELB_MCTL_ECC_U_SYND);
	id   = elba_mctl_read(mcp, chan, ELB_MCTL_ECC_ID);
	res->ddr_addr = ELB_MCTL_ECC_ADDR(addr, synd);
	res->bus_addr = elba_ddr_addr_to_bus(mcp, chan, res->ddr_addr);
	res->synd = ELB_MCTL_ECC_SYND(synd);
	res->id   = ELB_MCTL_ECC_U_ID(id);
	snprintf(res->msg, sizeof(res->msg), "ddr_addr 0x%llx, id 0x%04x",
			res->ddr_addr, res->id);
	return 1;
}

static void elba_edac_mc_poll_chan(struct mem_ctl_info *mci, int chan)
{
	struct elba_mcdata *mcp = mci->pvt_info;
	struct elba_mcpoll_res res;
	u32 int_stat, int_ack;

	if (!(mcp->chanmask & (1 << chan)))
		return;

	int_stat = elba_mctl_read(mcp, chan, ELB_MCTL_INT_STAT_ECC);
	if (elba_edac_mc_c_poll(mcp, chan, int_stat, &res)) {
		edac_mc_handle_error(HW_EVENT_ERR_CORRECTED, mci, res.cnt,
			res.bus_addr >> PAGE_SHIFT, res.bus_addr & ~PAGE_MASK,
			res.synd, chan, -1, -1, res.msg, "");
	}

	if (elba_edac_mc_u_poll(mcp, chan, int_stat, &res)) {
		edac_mc_handle_error(HW_EVENT_ERR_UNCORRECTED, mci, res.cnt,
			res.bus_addr >> PAGE_SHIFT, res.bus_addr & ~PAGE_MASK,
			res.synd, chan, -1, -1, res.msg, "");
	}

	int_ack = int_stat & ELB_MCTL_INT_ACK_MASK;
	if (int_ack)
		elba_mctl_write(mcp, chan, ELB_MCTL_INT_ACK_ECC, int_ack);
}

static void elba_edac_mc_poll(struct mem_ctl_info *mci)
{
	int chan;

	for (chan = 0; chan < ELB_MC_NCHANS; chan++)
		elba_edac_mc_poll_chan(mci, chan);
}

/*
 * A read error (SError) that causes a kernel panic won't have been
 * polled yet, so one final check for uncorrectable errors on the way down.
 */
static int elba_edac_mc_panic_notifier(struct notifier_block *nb,
				       unsigned long event, void *ptr)
{
	struct elba_mcdata *mcp = g_mcp;
	struct elba_mcpoll_res res;
	u32 int_stat;
	int chan;

	for (chan = 0; chan < ELB_MC_NCHANS; chan++) {
		if (!(mcp->chanmask & (1 << chan)))
			continue;
		int_stat = elba_mctl_read(mcp, chan, ELB_MCTL_INT_STAT_ECC);
		if (elba_edac_mc_u_poll(mcp, chan, int_stat, &res)) {
			printk(KERN_CRIT "EDAC MC0: %u UE %s on unknown "
				"memory (channel:%u page:0x%llx offset:0x%llx "
				"grain:8 syndrome:0x%02x)\n", res.cnt, res.msg,
				chan, res.bus_addr >> PAGE_SHIFT,
				res.bus_addr & ~PAGE_MASK, res.synd);
		}
	}
	return 0;
}

static struct notifier_block panic_block = {
	.notifier_call = elba_edac_mc_panic_notifier
};

static void elba_mc_conv_mask_read(struct elba_mcdata *mcp,
		int chan, int offs, u64 *mask)
{
	u32 w[3];
	int i;

	for (i = 0; i < 3; i++)
		w[i] = elba_mc_read(mcp, chan, offs + 4 * i);

	/* pull the two 36-bit masks from the 3 words */
	mask[0] = ((u64)(w[2] & 0xff) << 28) | (w[1] >> 4);
	mask[1] = ((u64)(w[1] & 0xf) << 32) | w[0];
}

static void elba_init_ddr_map(struct platform_device *pdev,
		struct elba_mcdata *mcp)
{
	struct device_node *np = pdev->dev.of_node;
	u64 val[2];
	int r = 0;
	int chan;

	if (np == NULL)
		return;

	r += of_property_read_u32(np, "pensando,ddrchanmask", &mcp->chanmask);
	r += of_property_read_u64(np, "pensando,llchash", &mcp->llc_map.hash);

	chan = (mcp->chanmask & 0x1) ? 0 : 1;
	elba_mc_conv_mask_read(mcp, chan, ELB_MC_CONV_MASK_1,
				mcp->llc_map.conv_mask);

	if (of_property_read_variable_u64_array(np,
				"pensando,bypass", val, 2, 0) == 2) {
		mcp->byp_start = val[0];
		mcp->byp_size = val[1];
		r += of_property_read_u64(np, "pensando,ddrbhash",
				&mcp->ddrb_map.hash);
		elba_mc_conv_mask_read(mcp, chan, ELB_MC_CONV_MASK_0,
					mcp->ddrb_map.conv_mask);
	}

	if (r) {
		dev_warn(&pdev->dev, "ddr map hashes not found\n");
		return;
	}

	edac_dbg(0, "llc_map = { 0x%llx, [0x%llx, 0x%llx] }\n",
		mcp->llc_map.hash,
		mcp->llc_map.conv_mask[0],
		mcp->llc_map.conv_mask[1]);
	edac_dbg(0, "ddrb_map = { 0x%llx, [0x%llx, 0x%llx] }\n",
		mcp->ddrb_map.hash,
		mcp->ddrb_map.conv_mask[0],
		mcp->ddrb_map.conv_mask[1]);
	edac_dbg(0, "bypass = { 0x%llx, 0x%llx }\n",
		mcp->byp_start, mcp->byp_size);
	edac_dbg(0, "ddr_chanmask = 0x%x\n", mcp->chanmask);

	mcp->map_valid = 1;
}

static void elba_init_dimms(struct mem_ctl_info *mci)
{
	struct elba_mcdata *mcp = mci->pvt_info;
	struct dimm_info *dimm;
	int chan;

	for (chan = 0; chan < ELB_MC_NCHANS; chan++) {
		if (!(mcp->chanmask & (1 << chan)))
			continue;
		dimm = mci->dimms[chan];
		dimm->grain = 8;
		dimm->mtype = MEM_DDR4;
		dimm->dtype = DEV_X8;
		dimm->edac_mode = EDAC_SECDED;
		dimm->nr_pages = 1; /* not empty */
	}
}

static int elba_edac_mc_probe(struct platform_device *pdev)
{
	struct edac_mc_layer layers[1];
	struct mem_ctl_info *mci;
	struct elba_mcdata *mcp;
	struct resource *r;
	void __iomem *base;
	static int mc_idx;

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!r) {
		dev_err(&pdev->dev, "Unable to get mem resource\n");
		return -ENODEV;
	}
	base = devm_ioremap_resource(&pdev->dev, r);
	if (IS_ERR(base)) {
		dev_err(&pdev->dev, "Unable to map regs\n");
		return PTR_ERR(base);
	}

	layers[0].type = EDAC_MC_LAYER_CHANNEL;
	layers[0].size = ELB_MC_NCHANS;
	layers[0].is_virt_csrow = false;

	mci = edac_mc_alloc(mc_idx, ARRAY_SIZE(layers),
			layers, sizeof(struct elba_mcdata));
	if (!mci)
		return -ENXIO;

	mcp = mci->pvt_info;
	mcp->base = base;

	elba_init_ddr_map(pdev, mcp);
	elba_init_dimms(mci);

	mci->pdev = &pdev->dev;
	mci->dev_name = dev_name(&pdev->dev);

	mci->mod_name = "elba-mc";
	mci->ctl_name = "elba-mc-err";
	mci->edac_check = elba_edac_mc_poll;
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

static int elba_edac_mc_remove(struct platform_device *pdev)
{
	struct mem_ctl_info *mci = platform_get_drvdata(pdev);

	edac_mc_del_mc(&pdev->dev);
	atomic_notifier_chain_unregister(&panic_notifier_list, &panic_block);

	edac_mc_free(mci);
	return 0;
}

static const struct of_device_id elba_edac_mc_of_match[] = {
	{.compatible = "pensando,elba-edac-mc"},
	{},
};

static struct platform_driver elba_edac_mc_driver = {
	.probe = elba_edac_mc_probe,
	.remove = elba_edac_mc_remove,
	.driver = {
		.name = "elba_edac_mc",
		.of_match_table = of_match_ptr(elba_edac_mc_of_match),
	}
};
module_platform_driver(elba_edac_mc_driver);

MODULE_DESCRIPTION("Pensando Elba platform EDAC memory controller driver");
MODULE_AUTHOR("Pensando Systems, Inc.");
MODULE_LICENSE("GPL v2");
