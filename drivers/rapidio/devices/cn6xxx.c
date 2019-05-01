/*
 * Cavium Inc. CN6XXX support over SRIO
 *
 * Copyright 2010 Cavium, Inc.  Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/module.h>
#include <linux/rio.h>
#include <linux/rio_drv.h>
#include <linux/rio_ids.h>
#include <asm/octeon/cvmx.h>
#include <asm/octeon/cvmx-sli-defs.h>
#include <asm/octeon/cvmx-sriomaintx-defs.h>

/* The defines below control the SRIO memory address map configured
    on CN6XXX. All possible regions are packed together in desending
    size. This way all alignments are honored */
#define BAR1_ADDRESS    0ull
#define BAR1_SHIFT      7 /* 128MB */
#define BAR1_SIZE       (1ull<<(20 + BAR1_SHIFT))
#define MAINT_ADDRESS   (BAR1_ADDRESS + BAR1_SIZE)
#define MAINT_SIZE      (1ull<<24)
#define BAR0_ADDRESS    (MAINT_ADDRESS + MAINT_SIZE)
#define BAR0_SIZE       16384ull
#define BAR2_ADDRESS    (1ull<<41)
#define BAR2_SIZE       (1ull<<41)

static uint64_t c6xxx_read_bar0(struct rio_dev *dev, int offset)
{
	uint64_t result;
	void *bar0 = rio_map_memory(dev, BAR0_ADDRESS, BAR0_SIZE);
	if (!bar0) {
		dev_err(&dev->dev, "Failed to map BAR0\n");
		return 0;
	}
	result = *(uint64_t *)(bar0 + offset);
	rio_unmap_memory(dev, BAR0_ADDRESS, BAR0_SIZE, bar0);
	return result;
}

static void cn6xxx_doorbell(struct rio_mport *mport, void *dev_id, u16 src,
	u16 dst, u16 info)
{
	struct rio_dev *dev = (struct rio_dev *)dev_id;
	dev_info(&dev->dev, "Received doorbell %d\n", info);
}

static int cn6xxx_probe(struct rio_dev *dev, const struct rio_device_id *id)
{
	u32 data;
	union cvmx_sriomaintx_m2s_bar2_start sriomaintx_m2s_bar2_start;
	union cvmx_sriomaintx_lcs_ba0 sriomaintx_lcs_ba0;
	union cvmx_sriomaintx_lcs_ba1 sriomaintx_lcs_ba1;
	union cvmx_sriomaintx_m2s_bar1_start0 sriomaintx_m2s_bar1_start0;
	union cvmx_sriomaintx_m2s_bar1_start1 sriomaintx_m2s_bar1_start1;
	union cvmx_sriomaintx_m2s_bar0_start0 sriomaintx_m2s_bar0_start0;
	union cvmx_sriomaintx_m2s_bar0_start1 sriomaintx_m2s_bar0_start1;
	union cvmx_sriomaintx_core_enables sriomaintx_core_enables;
	union cvmx_sriomaintx_port_gen_ctl sriomaintx_port_gen_ctl;
	union cvmx_sriomaintx_port_0_ctl sriomaintx_port_0_ctl;
	const char *state;
	int index;

	if (rio_read_config_32(dev, CVMX_SRIOMAINTX_IR_PI_PHY_STAT(0), &data))
		return -1;
	switch (data & 0x3ff) {
	case 0x0:
		state = "Silent";
		break;
	case 0x2:
		state = "Seek";
		break;
	case 0x4:
		state = "Discovery";
		break;
	case 0x8:
		state = "1x Mode Lane 0";
		break;
	case 0x10:
		state = "1x Mode Lane 1";
		break;
	case 0x20:
		state = "1x Mode Lane 2";
		break;
	case 0x40:
		state = "1x Recovery";
		break;
	case 0x80:
		state = "2x Mode";
		break;
	case 0x100:
		state = "2x Recovery";
		break;
	case 0x200:
		state = "4x Mode";
		break;
	default:
		state = "Reserved";
		break;
	}
	dev_info(&dev->dev, "Link state: %s\n", state);

	/* Setup BAR2 */
	sriomaintx_m2s_bar2_start.u32 = 0;
	sriomaintx_m2s_bar2_start.s.addr64 = BAR2_ADDRESS >> 48;
	sriomaintx_m2s_bar2_start.cn63xx.addr48 = BAR2_ADDRESS >> 41;
	sriomaintx_m2s_bar2_start.s.esx = 0;
	sriomaintx_m2s_bar2_start.s.cax = 0;
	sriomaintx_m2s_bar2_start.s.addr66 = 0; /* BAR2_ADDRESS >> 64; */
	sriomaintx_m2s_bar2_start.s.enable = 1;
	if (rio_write_config_32(dev, CVMX_SRIOMAINTX_M2S_BAR2_START(0),
		sriomaintx_m2s_bar2_start.u32))
		return -1;
	dev_info(&dev->dev, "BAR2 0x%016llx - 0x%016llx\n", BAR2_ADDRESS,
		BAR2_ADDRESS + BAR2_SIZE - 1);

	/* Setup Maintinance */
	sriomaintx_lcs_ba0.u32 = 0;
	sriomaintx_lcs_ba0.s.lcsba = MAINT_ADDRESS >> 35;
	sriomaintx_lcs_ba1.u32 = 0;
	sriomaintx_lcs_ba1.s.lcsba = (MAINT_ADDRESS >> 24) & 0x7ff;
	if (rio_write_config_32(dev, CVMX_SRIOMAINTX_LCS_BA0(0),
		sriomaintx_lcs_ba0.u32))
		return -1;
	if (rio_write_config_32(dev, CVMX_SRIOMAINTX_LCS_BA1(0),
		sriomaintx_lcs_ba1.u32))
		return -1;
	dev_info(&dev->dev, "Maintenance 0x%016llx - 0x%016llx\n",
		MAINT_ADDRESS, MAINT_ADDRESS + MAINT_SIZE - 1);

	/* Setup BAR1 */
	sriomaintx_m2s_bar1_start0.u32 = 0;
	sriomaintx_m2s_bar1_start0.s.addr64 = BAR1_ADDRESS >> 48;
	sriomaintx_m2s_bar1_start0.s.addr48 = BAR1_ADDRESS >> 32;
	sriomaintx_m2s_bar1_start1.u32 = 0;
	sriomaintx_m2s_bar1_start1.cn63xx.addr32 = (BAR1_ADDRESS >> 20) & 0xfff;
	sriomaintx_m2s_bar1_start1.s.barsize = BAR1_SHIFT;
	sriomaintx_m2s_bar1_start1.s.addr66 = 0; /* BAR1_ADDRESS >> 64; */
	sriomaintx_m2s_bar1_start1.s.enable = 1;
	if (rio_write_config_32(dev, CVMX_SRIOMAINTX_M2S_BAR1_START0(0),
		sriomaintx_m2s_bar1_start0.u32))
		return -1;
	if (rio_write_config_32(dev, CVMX_SRIOMAINTX_M2S_BAR1_START1(0),
		sriomaintx_m2s_bar1_start1.u32))
		return -1;
	dev_info(&dev->dev, "BAR1 0x%016llx - 0x%016llx\n", BAR1_ADDRESS,
		BAR1_ADDRESS + BAR1_SIZE - 1);

	/* Setup BAR0 */
	sriomaintx_m2s_bar0_start0.u32 = 0;
	sriomaintx_m2s_bar0_start0.s.addr64 = BAR0_ADDRESS >> 48;
	sriomaintx_m2s_bar0_start0.s.addr48 = BAR0_ADDRESS >> 32;
	sriomaintx_m2s_bar0_start1.u32 = 0;
	sriomaintx_m2s_bar0_start1.cn63xx.addr32 = (BAR0_ADDRESS >> 14) & 0x3ffff;
	sriomaintx_m2s_bar0_start1.s.addr66 = 0; /* BAR0_ADDRESS >> 64; */
	sriomaintx_m2s_bar0_start1.s.enable = 1;
	if (rio_write_config_32(dev, CVMX_SRIOMAINTX_M2S_BAR0_START0(0),
		sriomaintx_m2s_bar0_start0.u32))
		return -1;
	if (rio_write_config_32(dev, CVMX_SRIOMAINTX_M2S_BAR0_START1(0),
		sriomaintx_m2s_bar0_start1.u32))
		return -1;
	dev_info(&dev->dev, "BAR0 0x%016llx - 0x%016llx\n", BAR0_ADDRESS,
		BAR0_ADDRESS + BAR0_SIZE - 1);

	/* Set enables */
	sriomaintx_core_enables.u32 = 0;
	sriomaintx_core_enables.s.imsg1 = 1;
	sriomaintx_core_enables.s.imsg0 = 1;
	sriomaintx_core_enables.s.doorbell = 1;
	sriomaintx_core_enables.s.memory = 1;
	if (rio_write_config_32(dev, CVMX_SRIOMAINTX_CORE_ENABLES(0),
		sriomaintx_core_enables.u32))
		return -1;

	/* Enable transaction mastering */
	if (rio_read_config_32(dev, CVMX_SRIOMAINTX_PORT_GEN_CTL(0),
		&sriomaintx_port_gen_ctl.u32))
		return -1;
	sriomaintx_port_gen_ctl.s.menable = 1;
	if (rio_write_config_32(dev, CVMX_SRIOMAINTX_PORT_GEN_CTL(0),
		sriomaintx_port_gen_ctl.u32))
		return -1;

	/* Set link I/O enabled */
	if (rio_read_config_32(dev, CVMX_SRIOMAINTX_PORT_0_CTL(0),
		&sriomaintx_port_0_ctl.u32))
		return -1;
	sriomaintx_port_0_ctl.s.o_enable = 1;
	sriomaintx_port_0_ctl.s.i_enable = 1;
	if (rio_write_config_32(dev, CVMX_SRIOMAINTX_PORT_0_CTL(0),
		sriomaintx_port_0_ctl.u32))
		return -1;

	if (rio_request_inb_dbell(dev->net->hport, dev, 0, 1,
		cn6xxx_doorbell)) {
		dev_err(&dev->dev, "Register for incomming doorbells failed\n");
		return -1;
	}

	for (index = 0; index < 16; index++) {
		union cvmx_sriomaintx_bar1_idxx sriomaintx_bar1_idxx;
		sriomaintx_bar1_idxx.u32 = 0;
		sriomaintx_bar1_idxx.cn63xx.la = index;
		sriomaintx_bar1_idxx.s.enable = 1;
		if (rio_write_config_32(dev, CVMX_SRIOMAINTX_BAR1_IDXX(index, 0),
			sriomaintx_bar1_idxx.u32))
			return -1;
	}
	dev_info(&dev->dev, "SLI_MAC_CREDIT_CNT = 0x%llx\n", c6xxx_read_bar0(dev, CVMX_SLI_MAC_CREDIT_CNT));

	if (rio_send_doorbell(dev, 0))
		dev_err(&dev->dev, "Sending doorbell failed\n");

	if (rio_send_doorbell(dev, 1))
		dev_err(&dev->dev, "Sending doorbell failed\n");

	return 0;
}

static void cn6xxx_remove(struct rio_dev *dev)
{
	dev_info(&dev->dev, "Removed\n");
	rio_release_inb_dbell(dev->net->hport, 0, 1);
}

static int cn6xxx_suspend(struct rio_dev *dev, u32 state)
{
	return 0; /* Do nothing */
}

static int cn6xxx_resume(struct rio_dev *dev)
{
	return 0; /* Do nothing */
}

static int cn6xxx_enable_wake(struct rio_dev *dev, u32 state, int enable)
{
	return 0; /* Do nothing */
}

static const struct rio_device_id cn6xxx_id_table[] = {
	{.did = 0x0090, .vid = 0x008c, .asm_did = 0x0000, .asm_vid = 0x008c },
	{.did = 0x0092, .vid = 0x008c, .asm_did = 0x0000, .asm_vid = 0x008c },
	{.did = 0,}
};

static struct rio_driver cn6xxx_driver = {
	.name = "CN6XXX",
	.id_table = cn6xxx_id_table,
	.probe = cn6xxx_probe,
	.remove = cn6xxx_remove,
	.suspend = cn6xxx_suspend,
	.resume = cn6xxx_resume,
	.enable_wake = cn6xxx_enable_wake,
};

static int __init m_load(void)
{
	return rio_register_driver(&cn6xxx_driver);
}

static void __exit m_unload(void)
{
	rio_unregister_driver(&cn6xxx_driver);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cavium Inc. <support@cavium.com>");
MODULE_DESCRIPTION("Cavium Inc. CN6XXX support over SRIO.");
module_init(m_load);
module_exit(m_unload);
