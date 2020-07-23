/*
 * drivers/net/phy/qca833x.c
 *
 * Driver for Qualcomm/Atheros qca8334/8337 PHYs
 *
 * adapted from Matus Ujhelyi's at803x driver by Peter Swain <pswain@cavium.com>,
 * Aaron Williams & others.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/phy.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>

#include "qca833x.h"

/* just one private state (number of ports), so squeeze it into phydev->priv */
#define qports(phydev) (*(int*)&(phydev)->priv)

/* compound read/write must hold mdio mutex */
#define qphy_muget(phydev) mutex_lock(&(phydev)->mdio.bus->mdio_lock)
#define qphy_muput(phydev) mutex_unlock(&(phydev)->mdio.bus->mdio_lock)

/* read/write given mdio addrs, caller holds mutex */
static inline int __phy_read_addr(struct phy_device *phydev, u32 addr,
				  u32 regnum)
{
	return phydev->mdio.bus->read(phydev->mdio.bus, addr, regnum);
}

static inline int __phy_write_addr(struct phy_device *phydev, u32 addr,
				   u32 regnum, u16 val)
{
	return phydev->mdio.bus->write(phydev->mdio.bus, addr, regnum, val);
}

/*
 * read/write 32bit values with qca833x-specific protocol
 * this is conceptually like the Clause-45 2-part access, but different,
 * with 32bit values and a 20-bit address-space.
 * mdio mutex held across transactions to avoid interleave.
 */
static uint32_t __used qphy_read32(struct phy_device *phydev, uint32_t reg_addr)
{
	uint32_t reg_word_addr;
	uint32_t phy_addr, tmp_val, reg_val;
	uint16_t phy_val;
	uint8_t phy_reg;

	/* change reg_addr to 16-bit word address, 32-bit aligned */
	reg_word_addr = (reg_addr & 0xfffffffc) >> 1;

	/* configure register high address */
	phy_val = (uint16_t) ((reg_word_addr >> 8) & 0x1ff);	/* bit16-8 of reg address */
	qphy_muget(phydev);
	__phy_write_addr(phydev, 0x18, 0, phy_val);

	/* For some registers such as MIBs, since it is read/clear, we should */
	/* read the lower 16-bit register then the higher one */

	/* read register in lower address */
	phy_addr = 0x10 | ((reg_word_addr >> 5) & 0x7);	/* bit7-5 of reg address */
	phy_reg = (uint8_t) (reg_word_addr & 0x1f);	/* bit4-0 of reg address */
	reg_val = (uint32_t) __phy_read_addr(phydev, phy_addr, phy_reg);

	/* read register in higher address */
	reg_word_addr++;
	phy_addr = 0x10 | ((reg_word_addr >> 5) & 0x7);	/* bit7-5 of reg address */
	phy_reg = (uint8_t) (reg_word_addr & 0x1f);	/* bit4-0 of reg address */
	tmp_val = (uint32_t) __phy_read_addr(phydev, phy_addr, phy_reg);
	reg_val |= (tmp_val << 16);

	qphy_muput(phydev);

	return reg_val;

}

static void qphy_write32(struct phy_device *phydev, uint32_t reg_addr,
			      uint32_t reg_val)
{
	uint32_t reg_word_addr;
	uint32_t phy_addr;
	uint16_t phy_val;
	uint8_t phy_reg;

	/* change reg_addr to 16-bit word address, 32-bit aligned */
	reg_word_addr = (reg_addr & 0xfffffffc) >> 1;

	/* configure register high address */
	phy_val = (uint16_t) ((reg_word_addr >> 8) & 0x1ff);	/* bit16-8 of reg address */
	qphy_muget(phydev);
	__phy_write_addr(phydev, 0x18, 0, phy_val);

	/* For some registers such as ARL and VLAN, since they include BUSY bit */
	/* in lower address, we should write the higher 16-bit register then the */
	/* lower one */

	/* read register in higher address */
	reg_word_addr++;
	phy_addr = 0x10 | ((reg_word_addr >> 5) & 0x7);	/* bit7-5 of reg address */
	phy_reg = (uint8_t) (reg_word_addr & 0x1f);	/* bit4-0 of reg address */
	phy_val = (uint16_t) ((reg_val >> 16) & 0xffff);
	__phy_write_addr(phydev, phy_addr, phy_reg, phy_val);

	/* write register in lower address */
	reg_word_addr--;
	phy_addr = 0x10 | ((reg_word_addr >> 5) & 0x7);	/* bit7-5 of reg address */
	phy_reg = (uint8_t) (reg_word_addr & 0x1f);	/* bit4-0 of reg address */
	phy_val = (uint16_t) (reg_val & 0xffff);
	__phy_write_addr(phydev, phy_addr, phy_reg, phy_val);
	qphy_muput(phydev);

	pr_debug("%s %x := %x\n", __func__, reg_addr, reg_val);
}


/*
 * mii per-port config, captured at before reset to re-impose after reset
 * see net: phy: at803x: Add support for hardware reset (13a56b44)
 * where at803x driver is fixed to save/restore modes over reset:
 *   "The AT8030 will enter a FIFO error mode if a packet is transmitted while
 *   the cable is unplugged. This hardware issue is acknowledged by the
 *   vendor, and the only proposed solution is to conduct a hardware reset
 *   via the external pin each time the link goes down. There is apparantly
 *   no way to fix up the state via the register set."
 * The qca833x also needs this, but for each of its qports(phydev) ports
 */

struct port_context {
	u16 bmcr;
	u16 advertise;
	u16 control1000;
	u16 int_enable;
	u16 phy_spec;
	u16 led_control;
};
static struct port_context port_context[7]; /* should be in phydev->priv */

/* save relevant PHY registers to private copy */
static void port_context_save(struct phy_device *phydev, int addr,
				struct port_context *context)
{
	qphy_muget(phydev);
	context->bmcr = __phy_read_addr(phydev, addr, MII_BMCR);
	context->advertise = __phy_read_addr(phydev, addr, MII_ADVERTISE);
	context->control1000 = __phy_read_addr(phydev, addr, MII_CTRL1000);
	context->int_enable = __phy_read_addr(phydev, addr, S17_PHY_INT_EN_REG);
	context->phy_spec = __phy_read_addr(phydev, addr, ATHR_PHY_SPEC_CONTROL);
	qphy_muput(phydev);
}

/* restore relevant PHY registers from private copy */
static void port_context_restore(struct phy_device *phydev, int addr,
				   const struct port_context *context)
{
	qphy_muget(phydev);
	__phy_write_addr(phydev, addr, MII_BMCR, context->bmcr);
	__phy_write_addr(phydev, addr, MII_ADVERTISE, context->advertise);
	__phy_write_addr(phydev, addr, MII_CTRL1000, context->control1000);
	__phy_write_addr(phydev, addr, S17_PHY_INT_EN_REG, context->int_enable);
	__phy_write_addr(phydev, addr, ATHR_PHY_SPEC_CONTROL, context->phy_spec);
	qphy_muput(phydev);
}

/*
 * But qca833x also has non-mii switch config (vlan/etc)
 * This is captured at _init to re-impose after reset
 */
static struct qmodes {
	u32 addr;
	u32 val;
	bool saved;
} qmodes[] = {
	{ S17_MASK_CTRL_REG },
	{ S17_P0PAD_MODE_REG },
	{ S17_P0STATUS_REG },
	{ S17_P0PAD_MODE_REG },
	{ S17_P6PAD_MODE_REG },
	{ S17_P6STATUS_REG },
	{ S17_GLOFW_CTRL1_REG },
	{ S17_SGMII_CTRL_REG },
	{ S17_P0LOOKUP_CTRL_REG },
	{ S17_P0VLAN_CTRL0_REG },
	{ S17_P1LOOKUP_CTRL_REG },
	{ S17_P1VLAN_CTRL0_REG },
	{ S17_P2LOOKUP_CTRL_REG },
	{ S17_P2VLAN_CTRL0_REG },
	/* rest are 8337-only? */
	{ S17_P3LOOKUP_CTRL_REG },
	{ S17_P3VLAN_CTRL0_REG },
	{ S17_P4LOOKUP_CTRL_REG },
	{ S17_P4VLAN_CTRL0_REG },
	{ S17_P5LOOKUP_CTRL_REG },
	{ S17_P5VLAN_CTRL0_REG },
	{ S17_P6LOOKUP_CTRL_REG },
	{ S17_P6VLAN_CTRL0_REG },
	{ 0 },
}; /* should be in phydev->priv */

/* save u-boot/platform generated modes to re-impose after reset */
static void qca833x_save_init(struct phy_device *phydev)
{
	struct qmodes *m;
	for (m = qmodes; m->addr; m++) {
		if (m->saved)
			continue;
		m->val = qphy_read32(phydev, m->addr);
		m->saved = true;
	}
}

static int qca833x_re_init(struct phy_device *phydev)
{
	int val;
	u32 features;
	struct qmodes *m;

	/* Reset the PHY */
	val = qphy_read32(phydev, S17_MASK_CTRL_REG);
	val |= S17_MASK_CTRL_SOFT_RESET;
	qphy_write32(phydev, S17_MASK_CTRL_REG, val);

	/* wait for ready */
	while (qphy_read32(phydev, S17_MASK_CTRL_REG)
			& S17_MASK_CTRL_SOFT_RESET)
		msleep(10);

	/*
	 * force initial mode on port 0: SGMII, RX clock on falling edge,
	 * Speed 1000M, Tx MAC enable, Rx MAC enable, Tx MAC flow enable,
	 * Rx MAC flow enable, Full duplex mode
	 */
	qphy_write32(phydev, S17_P0PAD_MODE_REG,
				S17_MAC0_SGMII_EN);
	qphy_write32(phydev, S17_P0STATUS_REG, 0x0000007e);

	/* now unroll the real modes as saved earlier */
	for (m = qmodes; m->addr; m++) {
		if (!m->saved)
			continue;
		qphy_write32(phydev, m->addr, m->val);
	}

	features = SUPPORTED_TP | SUPPORTED_MII | SUPPORTED_AUI |
	    SUPPORTED_FIBRE | SUPPORTED_BNC;

	val = phy_read(phydev, MII_BMSR);
	if (val < 0)
		return val;

	if (val & BMSR_ANEGCAPABLE)
		features |= SUPPORTED_Autoneg;
	if (val & BMSR_100FULL)
		features |= SUPPORTED_100baseT_Full;
	if (val & BMSR_100HALF)
		features |= SUPPORTED_100baseT_Half;
	if (val & BMSR_10FULL)
		features |= SUPPORTED_10baseT_Full;
	if (val & BMSR_10HALF)
		features |= SUPPORTED_10baseT_Half;

	if (val & BMSR_ESTATEN) {
		val = phy_read(phydev, MII_ESTATUS);
		if (val < 0)
			return val;

		if (val & ESTATUS_1000_TFULL)
			features |= SUPPORTED_1000baseT_Full;
		if (val & ESTATUS_1000_THALF)
			features |= SUPPORTED_1000baseT_Half;
	}

	linkmode_set_bit(features,phydev->supported);
	linkmode_set_bit(features,phydev->advertising);

	pr_debug(KERN_ERR "%s: complete\n", __func__);
	return 0;
}

static int qca833x_config_init(struct phy_device *phydev)
{
	int val;
	static bool once;

	val = phy_read(phydev, MII_PHYSID2);
	switch (val & 0xf) {
	case 3: /* qca8334 */
		qports(phydev) = 2;
		break;
	case 6: /* qca8337 */
		qports(phydev) = 4;
		break;
	default:
		pr_err("%s: unknown PHY id %x\n", __func__,
			val | (phy_read(phydev, MII_PHYSID1) << 16));
		return -ENODEV;
	}

#ifdef QCA833X_IRQ
	/* parse from FDT */
#else /* !QCA833X_IRQ */
	phydev->irq = PHY_POLL;
#endif /* !QCA833X_IRQ */

	if (!once)
		pr_info("qca833x %d-port switch\n", qports(phydev));
	once = true;

	qca833x_save_init(phydev);
	return qca833x_re_init(phydev);
}

static void force_reset(struct phy_device *phydev)
{
	int port;

	for (port = 0; port < qports(phydev); port++)
		port_context_save(phydev, port, &port_context[port]);

	qphy_muget(phydev);
	if (phydev->attached_dev
	    && phydev->attached_dev->ethtool_ops
	    && phydev->attached_dev->ethtool_ops->reset) {
		u32 flags = ETH_RESET_PHY | ETH_RESET_FILTER;
		phydev->attached_dev->ethtool_ops->reset(
			phydev->attached_dev, &flags);
	}
	qphy_muput(phydev);
	qca833x_re_init(phydev);

	for (port = 0; port < qports(phydev); port++)
		port_context_restore(phydev, port, &port_context[port]);
}

static int qca833x_read_status(struct phy_device *phydev)
{
	int phy_status = 0;
	int port = 0;
	int was;

	qphy_muget(phydev);
	was = phydev->link;
	phydev->link = 0;

	WARN_ON_ONCE(qports(phydev) <= 0);

	for (port = 0; port < qports(phydev); port++)
	{
		if (phydev->link)
			break;

		/* All the speed information can be read from register 17 in one go. */
		phy_status = __phy_read_addr(phydev, port, ATHR_PHY_SPEC_STATUS);

		/*
		 * If the resolve bit 11 isn't set, see if autoneg is turned off
		 * (bit 12, reg 0). The resolve bit doesn't get set properly when
		 * autoneg is off, so force it
		 */
		if ((phy_status & (1 << 11)) == 0) {
			int auto_status = __phy_read_addr(phydev, port, MII_BMCR);

			if ((auto_status & (1 << 12)) == 0)
				phy_status |= 1 << 11;
		}

		/*
		 * Only return a link if the PHY has finished auto negotiation
		 * and set the resolved bit (bit 11)
		 */
		if (phy_status & (1 << 11)) {
			phydev->link = 1;
			phydev->duplex = DUPLEX_FULL;
			phydev->speed = SPEED_1000;
			phydev->pause = 1;
			phydev->asym_pause = 1;
		}
	}
	qphy_muput(phydev);

	/* when link goes down, reset qca833x by pulsing PCS off */
	if (was && !phydev->link)
		force_reset(phydev);
	return 0;
}


#ifdef QCA833X_IRQ
static int qca833x_ack_interrupt(struct phy_device *phydev)
{
	int err;

	err = phy_read(phydev, S17_PHY_INT_STAT_REG);

	return (err < 0) ? err : 0;
}

static int qca833x_config_interrupt(struct phy_device *phydev)
{
	return phy_write(phydev, S17_PHY_INT_EN_REG,
		(phydev->interrupts == PHY_INTERRUPT_ENABLED)
			* S17_PHY_LINK_INTRS);
}
#endif /* QCA833X_IRQ */

/* QUALCOMM/ATHEROS QCA8334/QCA8337 */
static struct phy_driver qca833x_driver = {
	.name = "Atheros 8334/8337 ethernet",
	.phy_id = 0x004dd036,
	.phy_id_mask = 0xfffffff0,
	.features = PHY_GBIT_FEATURES,
	.config_init = qca833x_config_init,
	.config_aneg = genphy_config_aneg,
	.read_status = qca833x_read_status,
#ifdef QCA833X_IRQ
	.ack_interrupt = qca833x_ack_interrupt,
	.config_intr = qca833x_config_interrupt,
	.flags = PHY_IS_INTERNAL| PHY_HAS_INTERRUPT,
#else /* !QCA833X_IRQ */
	.flags = PHY_IS_INTERNAL,
#endif /* !QCA833X_IRQ */
};

static int __init qca833x_init(void)
{
	return phy_driver_register(&qca833x_driver, THIS_MODULE);
}

static void __exit qca833x_exit(void)
{
	phy_driver_unregister(&qca833x_driver);
}

module_init(qca833x_init);
module_exit(qca833x_exit);

static struct mdio_device_id __maybe_unused qca833x_tbl[] = {
	{0x004dd036, 0xfffffff0}, /* qca8337 */
	{0x004dd033, 0xfffffff0}, /* qca8334 */
	{}
};

MODULE_DEVICE_TABLE(mdio, qca833x_tbl);

MODULE_DESCRIPTION("Qualcomm qca833x PHY driver");
MODULE_LICENSE("GPL");
