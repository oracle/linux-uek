// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright (c) 1998 - 2002 Frodo Looijaard <frodol@dds.nl> and
 *  Philip Edelbrock <phil@netroedge.com>
 *  Copyright (c) 2024  AMD Inc
 */

/*
 * Supports:
 *	AMD E3K
 *
 * Note: we assume there can only be one device, with one or more
 *	 SMBus interfaces.
 *
 * The driver is written by using i2c-piix4.c as reference.
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/dmi.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/stddef.h>

/* ASF SMBus address offsets */
#define SMBHSTSTS	(0 + asf_smba)
#define SMBHSLVSTS	(1 + asf_smba)
#define SMBHSTCNT	(2 + asf_smba)
#define SMBHSTCMD	(3 + asf_smba)
#define SMBHSTADD	(4 + asf_smba)
#define SMBHSTDAT0	(5 + asf_smba)
#define SMBHSTDAT1	(6 + asf_smba)
#define SMBBLKDAT	(7 + asf_smba)
#define ASFINDEX	(7 + asf_smba)
#define ASFLISADDR	(9 + asf_smba)
#define ASFSTA		(0xA + asf_smba)
#define ASFSTAMASK	(0xB + asf_smba)
#define ASFSTAMASK1	(0xC + asf_smba)
#define ASFSLVSTA	(0xD + asf_smba)
#define ASFDATARDPTR	(0x10 + asf_smba)
#define ASFDATARWPTR	(0x11 + asf_smba)
#define ASFSETDATARDPTR	(0x12 + asf_smba)
#define ASFDATABNKSEL	(0x13 + asf_smba)
#define ASFSLVEN	(0x15 + asf_smba)

/* count for request_region */
#define SMBIOSIZE	9

/* PCI Address Constants */
#define SMBBA		0x090
#define SMBHSTCFG	0x0D2
#define SMBSLVC		0x0D3
#define SMBSHDW1	0x0D4
#define SMBSHDW2	0x0D5
#define SMBREV		0x0D6

/* Other settings */
#define MAX_TIMEOUT	500
#define  ENABLE_INT9	0

/* ASF constants */
#define ASF_QUICK		0x00
#define ASF_BYTE		0x04
#define ASF_BYTE_DATA		0x08
#define ASF_WORD_DATA		0x0C
#define ASF_BLOCK_DATA	0x14

/* Multi-port constants */
#define ASF_MAX_ADAPTERS	1

/* SB800 constants */
#define SB800_ASF_SMB_IDX		0xcd6
#define SB800_ASF_SMB_MAP_SIZE	2

#define KERNCZ_IMC_IDX			0x3e
#define KERNCZ_IMC_DATA			0x3f

/*
 * SB800 port is selected by bits 2:1 of the smb_en register (0x2c)
 * or the smb_sel register (0x2e), depending on bit 0 of register 0x2f.
 * Hudson-2/Bolton port is always selected by bits 2:1 of register 0x2f.
 */
#define SB800_ASF_PORT_IDX		0x2c
#define SB800_ASF_PORT_IDX_ALT	0x2e
#define SB800_ASF_PORT_IDX_SEL	0x2f
#define SB800_ASF_PORT_IDX_MASK	0x06
#define SB800_ASF_PORT_IDX_SHIFT	1

/* On kerncz and Hudson2, SmBus0Sel is at bit 20:19 of PMx00 DecodeEn */
#define SB800_ASF_PORT_IDX_KERNCZ		0x02
#define SB800_ASF_PORT_IDX_MASK_KERNCZ	0x18
#define SB800_ASF_PORT_IDX_SHIFT_KERNCZ	3

#define SB800_ASF_FCH_PM_ADDR			0xFED80300
#define SB800_ASF_FCH_PM_SIZE			8

static struct pci_driver asf_driver;

/*
 * SB800 globals
 */
static u8 asf_port_sel_sb800;
static u8 asf_port_mask_sb800;
static u8 asf_port_shift_sb800;
static const char *asf_main_port_names_sb800[ASF_MAX_ADAPTERS] = {
	" port 0"
};

struct sb800_mmio_cfg {
	void __iomem *addr;
	bool use_mmio;
};

struct i2c_asf_adapdata {
	unsigned short smba;
	u8 port;		/* Port number, shifted */
	struct sb800_mmio_cfg mmio_cfg;
	struct timer_list slave_timer;
	struct i2c_client	*slave;
};

static spinlock_t asf_spinlock;
static void __iomem *asf_scl_muxbase;
static void __iomem *asf_sda_muxbase;

/*
 * This gets called whenever an I2C slave interrupt/status change
 * occurs.
 */
static int asf_slave_process(struct i2c_asf_adapdata *adapdata)
{
	u8 data[72], val = 0, cmd, reg_datab_sel, reg_sta, count;
	int nextdatabank, databank0status, databank1status;
	unsigned short asf_smba = adapdata->smba;
	unsigned long flags;
	int i = 0;

	spin_lock_irqsave(&asf_spinlock, flags);
	reg_sta = inb_p(ASFSTA);
	if ((reg_sta & 0x40) == 0) {
		spin_unlock_irqrestore(&asf_spinlock, flags);
		return 0;
	}
	outb_p(reg_sta | 0x40, ASFSTA);

	while (inb_p(ASFSTA) & 0x80);

	reg_datab_sel = inb_p(ASFDATABNKSEL);
	databank0status = (reg_datab_sel & BIT(2)) >> 2;
	databank1status = (reg_datab_sel & BIT(3)) >> 3;

	if (databank0status || databank1status) {
		reg_sta = inb_p(ASFSLVSTA);
		if (!(reg_sta & 0xE)) {
			/* no error */
			if ((databank0status == 0 && databank1status == 1) ||
			    (databank0status == 1 && databank1status == 0)) {
				if (databank1status == 1) {
					reg_datab_sel = reg_datab_sel | BIT(4);
					reg_datab_sel = reg_datab_sel & ~BIT(3);
					outb_p(reg_datab_sel, ASFDATABNKSEL);
					while(!(inb_p(ASFDATABNKSEL) & 0x10));

					cmd = inb_p(ASFINDEX);
					count = inb_p(0x11 + asf_smba);
					for (i = 0; i < count; i++)
						data[i] = inb_p(ASFINDEX);
					reg_datab_sel = reg_datab_sel | BIT(3);
					outb_p(reg_datab_sel, ASFDATABNKSEL);
				} else {
					reg_datab_sel = reg_datab_sel & ~BIT(4);
					reg_datab_sel = reg_datab_sel & ~BIT(2);
					outb_p(reg_datab_sel, ASFDATABNKSEL);
					while((inb_p(ASFDATABNKSEL) & 0x10));

					cmd = inb_p(ASFINDEX);
					count = inb_p(0x11 + asf_smba);
					for (i = 0; i < count; i++)
						data[i] = inb_p(ASFINDEX);
					reg_datab_sel = reg_datab_sel | BIT(2);
					outb_p(reg_datab_sel, ASFDATABNKSEL);
				}
			} else if (((databank0status == 1) && (databank1status == 1))) {
				nextdatabank = reg_datab_sel & 1;
				if (!nextdatabank) {
					reg_datab_sel = reg_datab_sel & ~BIT(4);
					reg_datab_sel = reg_datab_sel & ~BIT(2);
					outb_p(reg_datab_sel, ASFDATABNKSEL);

					reg_datab_sel = reg_datab_sel | BIT(2);
					outb_p(reg_datab_sel, ASFDATABNKSEL);
				} else {
					reg_datab_sel = reg_datab_sel | BIT(4);
					reg_datab_sel = reg_datab_sel & ~BIT(3);
					outb_p(reg_datab_sel, ASFDATABNKSEL);

					reg_datab_sel = reg_datab_sel | BIT(3);
					outb_p(reg_datab_sel, ASFDATABNKSEL);
				}
			}
		} else {
			reg_datab_sel = reg_datab_sel | (BIT(3) | BIT(2));
			outb_p(reg_datab_sel, ASFDATABNKSEL);
			outb_p(0xF, ASFSLVSTA);
		}
	}
	outb_p(0, 0x12 + asf_smba);
	outb_p(0xF, ASFSLVSTA);
	spin_unlock_irqrestore(&asf_spinlock, flags);

	if ((cmd & 1) == 0) {
		i2c_slave_event(adapdata->slave, I2C_SLAVE_WRITE_REQUESTED, &val);
		for (i = 0; i < count; i++) {
			val = data[i];
			i2c_slave_event(adapdata->slave, I2C_SLAVE_WRITE_RECEIVED, &val);
		}
		i2c_slave_event(adapdata->slave, I2C_SLAVE_STOP, &val);
	}
	return 0;
}

static void slave_event_timer(struct timer_list *t)
{
	struct i2c_asf_adapdata *adapdata = from_timer(adapdata, t, slave_timer);

	asf_slave_process(adapdata);

	mod_timer(&adapdata->slave_timer, jiffies + msecs_to_jiffies(100));
}

static int asf_sb800_region_request(struct device *dev,
				    struct sb800_mmio_cfg *mmio_cfg)
{
	if (mmio_cfg->use_mmio) {
		void __iomem *addr;

		if (!request_mem_region_muxed(SB800_ASF_FCH_PM_ADDR,
					      SB800_ASF_FCH_PM_SIZE,
					      "sb800_asf_smb")) {
			dev_err(dev,
				"SMBus base address memory region 0x%x already in use.\n",
				SB800_ASF_FCH_PM_ADDR);
			return -EBUSY;
		}

		addr = ioremap(SB800_ASF_FCH_PM_ADDR,
			       SB800_ASF_FCH_PM_SIZE);
		if (!addr) {
			release_mem_region(SB800_ASF_FCH_PM_ADDR,
					   SB800_ASF_FCH_PM_SIZE);
			dev_err(dev, "SMBus base address mapping failed.\n");
			return -ENOMEM;
		}

		mmio_cfg->addr = addr;

		return 0;
	}

	if (!request_muxed_region(SB800_ASF_SMB_IDX, SB800_ASF_SMB_MAP_SIZE,
				  "sb800_asf_smb")) {
		dev_err(dev,
			"SMBus base address index region 0x%x already in use.\n",
			SB800_ASF_SMB_IDX);
		return -EBUSY;
	}

	return 0;
}

static void asf_sb800_region_release(struct device *dev,
				     struct sb800_mmio_cfg *mmio_cfg)
{
	if (mmio_cfg->use_mmio) {
		iounmap(mmio_cfg->addr);
		release_mem_region(SB800_ASF_FCH_PM_ADDR,
				   SB800_ASF_FCH_PM_SIZE);
		return;
	}

	release_region(SB800_ASF_SMB_IDX, SB800_ASF_SMB_MAP_SIZE);
}

static bool asf_sb800_use_mmio(struct pci_dev *ASF_dev)
{
	/*
	 * cd6h/cd7h port I/O accesses can be disabled on AMD processors
	 * w/ SMBus PCI revision ID 0x51 or greater. MMIO is supported on
	 * the same processors and is the recommended access method.
	 */
	return (ASF_dev->vendor == PCI_VENDOR_ID_AMD &&
		ASF_dev->device == PCI_DEVICE_ID_AMD_KERNCZ_SMBUS &&
		ASF_dev->revision >= 0x51);
}

static int
asf_setup_sb800_smba(struct pci_dev *ASF_dev, u8 smb_en, u8 aux, u8 *smb_en_status,
		     unsigned short *asf_smba)
{
	struct sb800_mmio_cfg mmio_cfg;
	u8 smba_en_lo, smba_en_hi;
	int reg, retval;

	asf_scl_muxbase = ioremap(0xFED80D13, 1);
	iowrite8(0, asf_scl_muxbase);
	asf_sda_muxbase = ioremap(0xFED80D14, 1);
	iowrite8(0, asf_sda_muxbase);

	mmio_cfg.use_mmio = asf_sb800_use_mmio(ASF_dev);
	retval = asf_sb800_region_request(&ASF_dev->dev, &mmio_cfg);
	if (retval)
		return retval;

	if (mmio_cfg.use_mmio) {
		smba_en_lo = ioread8(mmio_cfg.addr);
		smba_en_hi = ioread8(mmio_cfg.addr + 1);
	}

	reg = ioread32(mmio_cfg.addr);
	reg = reg | BIT(16);
	iowrite32(reg, mmio_cfg.addr);

	asf_sb800_region_release(&ASF_dev->dev, &mmio_cfg);

	*smb_en_status = smba_en_lo & 0x10;
	*asf_smba = smba_en_hi << 8;

	if (!*smb_en_status) {
		dev_err(&ASF_dev->dev, "SMBus Host Controller not enabled!\n");
		return -ENODEV;
	}

	*asf_smba |= 0x20;

	return 0;
}

static int asf_setup_sb800(struct pci_dev *ASF_dev, const struct pci_device_id *id, u8 aux)
{
	u8 i2ccfg_offset = 0x10, i2ccfg, smb_en, smb_en_status;
	unsigned short asf_smba;
	int retval;

	/* Determine the address of the SMBus areas */
	if ((ASF_dev->vendor == PCI_VENDOR_ID_AMD &&
	     ASF_dev->device == PCI_DEVICE_ID_AMD_HUDSON2_SMBUS && ASF_dev->revision >= 0x41) ||
	    (ASF_dev->vendor == PCI_VENDOR_ID_AMD &&
	     ASF_dev->device == PCI_DEVICE_ID_AMD_KERNCZ_SMBUS && ASF_dev->revision >= 0x49) ||
	    (ASF_dev->vendor == PCI_VENDOR_ID_HYGON &&
	     ASF_dev->device == PCI_DEVICE_ID_AMD_KERNCZ_SMBUS))
		smb_en = 0x00;
	else
		return -1;

	retval = asf_setup_sb800_smba(ASF_dev, smb_en, aux, &smb_en_status, &asf_smba);

	if (retval)
		return retval;

	if (acpi_check_region(asf_smba, SMBIOSIZE, asf_driver.name))
		return -ENODEV;

	if (!request_region(asf_smba, SMBIOSIZE, asf_driver.name)) {
		dev_err(&ASF_dev->dev, "SMBus region 0x%x already in use!\n", asf_smba);
		return -EBUSY;
	}

	/* Request the SMBus I2C bus config region */
	if (!request_region(asf_smba + i2ccfg_offset, 1, "i2ccfg")) {
		dev_err(&ASF_dev->dev, "SMBus I2C bus config region 0x%x already in use!\n",
			asf_smba + i2ccfg_offset);
		release_region(asf_smba, SMBIOSIZE);
		return -EBUSY;
	}
	i2ccfg = inb_p(asf_smba + i2ccfg_offset);

	release_region(asf_smba + i2ccfg_offset, 1);

	if (i2ccfg & 1)
		dev_dbg(&ASF_dev->dev, "Using IRQ for SMBus\n");
	else
		dev_dbg(&ASF_dev->dev, "Using SMI# for SMBus\n");

	dev_info(&ASF_dev->dev, "SMBus Host Controller at 0x%x, revision %d\n",
		 asf_smba, i2ccfg >> 4);

	/* Find which register is used for port selection */
	if (ASF_dev->vendor == PCI_VENDOR_ID_AMD ||
	    ASF_dev->vendor == PCI_VENDOR_ID_HYGON) {
		if (ASF_dev->device == PCI_DEVICE_ID_AMD_KERNCZ_SMBUS ||
		    (ASF_dev->device == PCI_DEVICE_ID_AMD_HUDSON2_SMBUS &&
		     ASF_dev->revision >= 0x1F)) {
			asf_port_sel_sb800 = SB800_ASF_PORT_IDX_KERNCZ;
			asf_port_mask_sb800 = SB800_ASF_PORT_IDX_MASK_KERNCZ;
			asf_port_shift_sb800 = SB800_ASF_PORT_IDX_SHIFT_KERNCZ;
		} else {
			asf_port_sel_sb800 = SB800_ASF_PORT_IDX_ALT;
			asf_port_mask_sb800 = SB800_ASF_PORT_IDX_MASK;
			asf_port_shift_sb800 = SB800_ASF_PORT_IDX_SHIFT;
		}
	}
	dev_info(&ASF_dev->dev, "Using register 0x%02x for SMBus port selection\n",
		 (unsigned int)asf_port_sel_sb800);
	release_region(asf_smba, SMBIOSIZE);
	return asf_smba;
}

static int asf_transaction(struct i2c_adapter *asf_adapter)
{
	struct i2c_asf_adapdata *adapdata = i2c_get_adapdata(asf_adapter);
	unsigned short asf_smba = adapdata->smba;
	int result = 0, timeout = 0, temp;

	dev_dbg(&asf_adapter->dev, "Transaction (pre): CNT=%02x, CMD=%02x, ADD=%02x, DAT0=%02x, DAT1=%02x\n",
		inb_p(SMBHSTCNT), inb_p(SMBHSTCMD), inb_p(SMBHSTADD), inb_p(SMBHSTDAT0),
		inb_p(SMBHSTDAT1));

	/* Make sure the SMBus host is ready to start transmitting */
	temp = inb_p(SMBHSTSTS);
	if (temp) {
		dev_dbg(&asf_adapter->dev, "SMBus busy (%02x). Resetting...\n", temp);
		outb_p(temp, SMBHSTSTS);
		temp = inb_p(SMBHSTSTS);
		if (temp) {
			dev_err(&asf_adapter->dev, "Failed! (%02x)\n", temp);
			return -EBUSY;
		}
		dev_dbg(&asf_adapter->dev, "Successful!\n");
	}

	/* start the transaction by setting bit 6 */
	outb_p(inb(SMBHSTCNT) | 0x040, SMBHSTCNT);

	/* We will always wait for a fraction of a second! (See ASF docs errata) */
	udelay(250);

	while ((++timeout < MAX_TIMEOUT) &&
	       ((temp = inb_p(SMBHSTSTS)) & 0x01))
		udelay(250);

	/* If the SMBus is still busy, we give up */
	if (timeout == MAX_TIMEOUT) {
		dev_err(&asf_adapter->dev, "SMBus Timeout!\n");
		result = -ETIMEDOUT;
	}

	if (temp & 0x10) {
		result = -EIO;
		dev_err(&asf_adapter->dev, "Error: Failed bus transaction\n");
	}

	if (temp & 0x08) {
		/* Clock stops and slave is stuck in mid-transmission */
		result = -EIO;
		dev_dbg(&asf_adapter->dev, "Bus collision! SMBus may be locked until next hard reset.\n");
	}

	if (temp & 0x04) {
		result = -ENXIO;
		dev_dbg(&asf_adapter->dev, "Error: no response!\n");
	}

	if (inb_p(SMBHSTSTS) != 0x00)
		outb_p(inb(SMBHSTSTS), SMBHSTSTS);

	temp = inb_p(SMBHSTSTS);
	if (temp)
		dev_err(&asf_adapter->dev, "Failed reset at end of transaction (%02x)\n", temp);
	dev_dbg(&asf_adapter->dev, "Transaction (post): CNT=%02x, CMD=%02x, ADD=%02x, DAT0=%02x, DAT1=%02x\n",
		inb_p(SMBHSTCNT), inb_p(SMBHSTCMD), inb_p(SMBHSTADD), inb_p(SMBHSTDAT0),
		inb_p(SMBHSTDAT1));
	return result;
}

/* Return negative errno on error. */
static s32
asf_access(struct i2c_adapter *adap, u16 addr, unsigned short flags, char read_write, u8 command,
	   int size, union i2c_smbus_data *data)
{
	struct i2c_asf_adapdata *adapdata = i2c_get_adapdata(adap);
	unsigned short asf_smba = adapdata->smba;
	int i, len;
	int status;

	switch (size) {
	case I2C_SMBUS_QUICK:
		outb_p((addr << 1) | read_write,
		       SMBHSTADD);
		size = ASF_QUICK;
		break;
	case I2C_SMBUS_BYTE:
		outb_p((addr << 1) | read_write,
		       SMBHSTADD);
		if (read_write == I2C_SMBUS_WRITE)
			outb_p(command, SMBHSTCMD);
		size = ASF_BYTE;
		break;
	case I2C_SMBUS_BYTE_DATA:
		outb_p((addr << 1) | read_write,
		       SMBHSTADD);
		outb_p(command, SMBHSTCMD);
		if (read_write == I2C_SMBUS_WRITE)
			outb_p(data->byte, SMBHSTDAT0);
		size = ASF_BYTE_DATA;
		break;
	case I2C_SMBUS_WORD_DATA:
		outb_p((addr << 1) | read_write,
		       SMBHSTADD);
		outb_p(command, SMBHSTCMD);
		if (read_write == I2C_SMBUS_WRITE) {
			outb_p(data->word & 0xff, SMBHSTDAT0);
			outb_p((data->word & 0xff00) >> 8, SMBHSTDAT1);
		}
		size = ASF_WORD_DATA;
		break;
	case I2C_SMBUS_BLOCK_DATA:
		outb_p((addr << 1) | read_write,
		       SMBHSTADD);
		outb_p(command, SMBHSTCMD);
		if (read_write == I2C_SMBUS_WRITE) {
			len = data->block[0];
			if (len == 0 || len > 70)
				return -EINVAL;
			outb_p(len, SMBHSTDAT0);
			inb_p(SMBHSTCNT);	/* Reset SMBBLKDAT */
			for (i = 1; i <= len; i++)
				outb_p(data->block[i], SMBBLKDAT);
		}
		size = ASF_BLOCK_DATA;
		break;
	default:
		dev_warn(&adap->dev, "Unsupported transaction %d\n", size);
		return -EOPNOTSUPP;
	}

    /* Enable PEC and PEC append */
	outb_p(((size & 0x1C) + (ENABLE_INT9 & 1)) | (BIT(7)) | (BIT(5)), SMBHSTCNT);

	status = asf_transaction(adap);
	if (status)
		return status;

	if (read_write == I2C_SMBUS_WRITE || size == ASF_QUICK)
		return 0;

	switch (size) {
	case ASF_BYTE:
	case ASF_BYTE_DATA:
		data->byte = inb_p(SMBHSTDAT0);
		break;
	case ASF_WORD_DATA:
		data->word = inb_p(SMBHSTDAT0) + (inb_p(SMBHSTDAT1) << 8);
		break;
	case ASF_BLOCK_DATA:
		data->block[0] = inb_p(SMBHSTDAT0);
		if (data->block[0] == 0 || data->block[0] > I2C_SMBUS_BLOCK_MAX)
			return -EPROTO;
		inb_p(SMBHSTCNT);
		/* Reset SMBBLKDAT */
		for (i = 1; i <= data->block[0]; i++)
			data->block[i] = inb_p(SMBBLKDAT);
		break;
	}
	return 0;
}

static int asf_sb800_port_sel(u8 port, struct sb800_mmio_cfg *mmio_cfg)
{
	u8 smba_en_lo, val;

	if (mmio_cfg->use_mmio) {
		smba_en_lo = ioread8(mmio_cfg->addr + asf_port_sel_sb800);
		val = (smba_en_lo & ~asf_port_mask_sb800) | port;
		if (smba_en_lo != val)
			iowrite8(val, mmio_cfg->addr + asf_port_sel_sb800);

		return (smba_en_lo & asf_port_mask_sb800);
	}

	outb_p(asf_port_sel_sb800, SB800_ASF_SMB_IDX);
	smba_en_lo = inb_p(SB800_ASF_SMB_IDX + 1);

	val = (smba_en_lo & ~asf_port_mask_sb800) | port;
	if (smba_en_lo != val)
		outb_p(val, SB800_ASF_SMB_IDX + 1);

	return (smba_en_lo & asf_port_mask_sb800);
}

/*
 * Handles access to multiple SMBus ports on the SB800.
 * The port is selected by bits 2:1 of the smb_en register (0x2c).
 * Returns negative errno on error.
 *
 * Note: The selected port must be returned to the initial selection to avoid
 * problems on certain systems.
 */
static s32
asf_access_sb800(struct i2c_adapter *adap, u16 addr, unsigned short flags, char read_write,
		 u8 command, int size, union i2c_smbus_data *data)
{
	struct i2c_asf_adapdata *adapdata = i2c_get_adapdata(adap);
	unsigned short asf_smba = adapdata->smba;
	unsigned long lock_flags;
	int reg, retval;
	u8 prev_port;

	retval = asf_sb800_region_request(&adap->dev, &adapdata->mmio_cfg);
	if (retval)
		return retval;

	spin_lock_irqsave(&asf_spinlock, lock_flags);
	reg = inb_p(ASFSLVEN);
	reg = reg | (BIT(4));
	outb_p(reg, ASFSLVEN);
	outb_p(0, SMBHSTCMD);
	outb_p(0, SMBHSTDAT0);
	outb_p(0, SMBHSTDAT1);
	outb_p(0, ASFSLVSTA);
	reg = ioread32(adapdata->mmio_cfg.addr);
	reg = reg | BIT(16);
	iowrite32(reg, adapdata->mmio_cfg.addr);
	prev_port = asf_sb800_port_sel(adapdata->port, &adapdata->mmio_cfg);
	retval = asf_access(adap, addr, flags, read_write, command, size, data);
	asf_sb800_port_sel(prev_port, &adapdata->mmio_cfg);

	/*  set asf as slave */
	outb_p(0, SMBHSTSTS);
	outb_p(0, ASFSLVSTA);
	outb_p(0, ASFSTA);
	reg = ioread32(adapdata->mmio_cfg.addr);
	reg = reg & ~BIT(16);
	reg = reg | BIT(17);
	iowrite32(reg, adapdata->mmio_cfg.addr);
	reg = inb(ASFSLVEN);
	reg = reg & ~BIT(4);
	outb_p(reg, ASFSLVEN);
	/* Enable PEC and PEC append */
	reg = inb(SMBHSTCNT);
	reg = reg | BIT(7) | BIT(5);
	outb_p(reg, SMBHSTCNT);
	spin_unlock_irqrestore(&asf_spinlock, lock_flags);
	asf_sb800_region_release(&adap->dev, &adapdata->mmio_cfg);

	return retval;
}

static int asf_access_i2c(struct i2c_adapter *adap, struct i2c_msg *msgs, int num)
{
	unsigned short flags = 0;
	struct i2c_msg *msg;
	char read_write;
	int size, ret;
	u8 command;
	u16 addr;
	union i2c_mctp_data {
		__u8 byte;
		__u16 word;
		__u8 block[72 + 2]; /* block[0] is used for length */
	} smbus_data;

	msg = &msgs[0];
	if (msgs->flags & I2C_M_RD) {
		dev_err(&adap->dev, "Read not supported\n");
		return -EOPNOTSUPP;
	}

	if (num != 1) {
		dev_err(&adap->dev, "multiple i2c messages not supported\n");
		return -EOPNOTSUPP;
	}

	if (msg->len - 1 > 72) {
		dev_err(&adap->dev, "max mtu is 68\n");
		return -EOPNOTSUPP;
	}

	addr = msg->addr;
	read_write = 0;
	command = msg[0].buf[0];
	size = I2C_SMBUS_BLOCK_DATA;
	smbus_data.block[0] = msg->len - 1;
	memcpy(smbus_data.block + 1, msg[0].buf + 1, msg->len - 1);
	ret = asf_access_sb800(adap, addr, flags, read_write, command, size,
			       (union i2c_smbus_data *)&smbus_data);
	return ret;
}

static int asf_reg_slave(struct i2c_client *slave)
{
	struct i2c_asf_adapdata *adapdata = i2c_get_adapdata(slave->adapter);
	unsigned short asf_smba = adapdata->smba;
	int retval, config_reg;
	unsigned long flags;
	u8 reg;

	if (adapdata->slave)
		return -EBUSY;

	retval = asf_sb800_region_request(&slave->dev, &adapdata->mmio_cfg);
	if (retval)
		return retval;

        spin_lock_irqsave(&asf_spinlock, flags);

	reg = (slave->addr << 1) | 1;
	outb_p(reg, ASFLISADDR);
	outb_p(0, SMBHSTSTS);
	outb_p(0, ASFSLVSTA);
	outb_p(0, ASFSTA);
	reg = inb_p(ASFSLVEN);
	reg = reg | BIT(1) | BIT(4);
	outb_p(reg, ASFSLVEN);
	reg = reg & ~BIT(4);
	outb_p(reg, ASFSLVEN);
	adapdata->slave = slave;
	reg = inb_p(SMBHSTCNT);
	reg = reg | BIT(7) | BIT(5);
	outb_p(reg, SMBHSTCNT);
	reg = inb_p(ASFDATABNKSEL);
	reg = reg & ~BIT(7);
	outb_p(reg, ASFDATABNKSEL);

	config_reg = ioread32(adapdata->mmio_cfg.addr);
	config_reg = config_reg & (~BIT(16));
	config_reg = config_reg | (BIT(17));
	iowrite32(config_reg, adapdata->mmio_cfg.addr);
	spin_unlock_irqrestore(&asf_spinlock, flags);
	asf_sb800_region_release(&slave->dev, &adapdata->mmio_cfg);

	timer_setup(&adapdata->slave_timer, slave_event_timer, 0);
	mod_timer(&adapdata->slave_timer, jiffies + HZ);

	return 0;
}

static int asf_unreg_slave(struct i2c_client *slave)
{
	struct i2c_asf_adapdata *adapdata = i2c_get_adapdata(slave->adapter);
	unsigned short asf_smba = adapdata->smba;
	u8 reg;

	reg = inb(ASFSLVEN);
	reg &= ~BIT(1);
	reg = reg | BIT(4);
	outb_p(reg, ASFSLVEN);

	adapdata->slave = NULL;
	del_timer_sync(&adapdata->slave_timer);
	return 0;
}

static u32 asf_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_SMBUS_QUICK | I2C_FUNC_SMBUS_BYTE | I2C_FUNC_SMBUS_BYTE_DATA |
	       I2C_FUNC_SMBUS_WORD_DATA | I2C_FUNC_SLAVE | I2C_FUNC_SMBUS_PEC |
	       I2C_FUNC_SMBUS_WRITE_BLOCK_DATA;
}

static const struct i2c_algorithm asf_smbus_algorithm_sb800 = {
	.smbus_xfer	= asf_access_sb800,
	.master_xfer	= asf_access_i2c,
	.functionality	= asf_func,
	.reg_slave	= asf_reg_slave,
	.unreg_slave	= asf_unreg_slave,
};

static const struct pci_device_id asf_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_KERNCZ_SMBUS) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HYGON, PCI_DEVICE_ID_AMD_KERNCZ_SMBUS) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, asf_ids);

static struct i2c_adapter *asf_main_adapters[ASF_MAX_ADAPTERS];
static struct i2c_adapter *asf_aux_adapter;
static int asf_adapter_count;

static int
asf_add_adapter(struct pci_dev *dev, unsigned short smba, u8 port, u8 hw_port_nr, const char *name,
		struct i2c_adapter **padap)
{
	struct i2c_asf_adapdata *adapdata;
	struct i2c_adapter *adap;
	int retval;

	adap = kzalloc(sizeof(*adap), GFP_KERNEL);
	if (!adap) {
		release_region(smba, SMBIOSIZE);
		return -ENOMEM;
	}

	adap->owner = THIS_MODULE;
	adap->class = I2C_CLASS_HWMON;
	adap->algo = &asf_smbus_algorithm_sb800;

	adapdata = kzalloc(sizeof(*adapdata), GFP_KERNEL);
	if (!adapdata) {
		kfree(adap);
		release_region(smba, SMBIOSIZE);
		return -ENOMEM;
	}

	adapdata->mmio_cfg.use_mmio = asf_sb800_use_mmio(dev);
	adapdata->smba = smba;
	adapdata->port = port << asf_port_shift_sb800;

	/* set up the sysfs linkage to our parent device */
	adap->dev.parent = &dev->dev;

	if (has_acpi_companion(&dev->dev)) {
		acpi_preset_companion(&adap->dev,
				      ACPI_COMPANION(&dev->dev),
				      hw_port_nr);
	}

	snprintf(adap->name, sizeof(adap->name), "SMBus ASF adapter%s at %04x", name, smba);
	i2c_set_adapdata(adap, adapdata);
	retval = i2c_add_adapter(adap);
	if (retval) {
		kfree(adapdata);
		kfree(adap);
		release_region(smba, SMBIOSIZE);
		return retval;
	}

	*padap = adap;
	return 0;
}

static int asf_add_adapters_sb800(struct pci_dev *dev, unsigned short smba)
{
	struct i2c_asf_adapdata *adapdata;
	int port;
	int retval;

	asf_adapter_count = ASF_MAX_ADAPTERS;

	for (port = 0; port < asf_adapter_count; port++) {
		u8 hw_port_nr = port == 0 ? 0 : port + 1;

		retval = asf_add_adapter(dev, smba, port, hw_port_nr,
					 asf_main_port_names_sb800[port],
					 &asf_main_adapters[port]);
		if (retval < 0)
			goto error;
	}

	return retval;

error:
	dev_err(&dev->dev, "Error setting up SB800 adapters. Unregistering!\n");
	while (--port >= 0) {
		adapdata = i2c_get_adapdata(asf_main_adapters[port]);
		if (adapdata->smba) {
			i2c_del_adapter(asf_main_adapters[port]);
			kfree(adapdata);
			kfree(asf_main_adapters[port]);
			asf_main_adapters[port] = NULL;
		}
	}

	return retval;
}

static int asf_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int retval;

	if ((dev->vendor == PCI_VENDOR_ID_ATI && dev->device == PCI_DEVICE_ID_ATI_SBX00_SMBUS &&
	     dev->revision >= 0x40) || dev->vendor == PCI_VENDOR_ID_AMD) {
		spin_lock_init(&asf_spinlock);
		retval = asf_setup_sb800(dev, id, 0);
		if (retval < 0)
			return retval;
		retval = asf_add_adapters_sb800(dev, retval);
		if (retval < 0)
			return retval;
	}

	return 0;
}

static void asf_adap_remove(struct i2c_adapter *adap)
{
	struct i2c_asf_adapdata *adapdata = i2c_get_adapdata(adap);

	del_timer_sync(&adapdata->slave_timer);

	if (adapdata->smba) {
		i2c_del_adapter(adap);
		if (adapdata->port == (0 << asf_port_shift_sb800))
			release_region(adapdata->smba, SMBIOSIZE);
		kfree(adapdata);
		kfree(adap);
	}
}

static void asf_remove(struct pci_dev *dev)
{
	int port = asf_adapter_count;

	while (--port >= 0) {
		if (asf_main_adapters[port]) {
			asf_adap_remove(asf_main_adapters[port]);
			asf_main_adapters[port] = NULL;
		}
	}

	if (asf_aux_adapter) {
		asf_adap_remove(asf_aux_adapter);
		asf_aux_adapter = NULL;
	}
}

static struct pci_driver asf_driver = {
	.name		= "asf_smbus",
	.id_table	= asf_ids,
	.probe		= asf_probe,
	.remove		= asf_remove,
};

module_pci_driver(asf_driver);

MODULE_AUTHOR("dl.amdindia.embedded.ps.linux.all@amd.com");
MODULE_DESCRIPTION("ASF SMBus driver");
MODULE_LICENSE("GPL");
