/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2016, 2017 Cavium Inc.
 */

#include <linux/bitops.h>
#include <linux/gpio/driver.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_irq.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#ifdef CONFIG_MRVL_OCTEONTX_EL0_INTR
#include <linux/arm-smccc.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <linux/mmu_context.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#endif

#define GPIO_RX_DAT	0x0
#define GPIO_TX_SET	0x8
#define GPIO_TX_CLR	0x10
#define GPIO_CONST	0x90
#define  GPIO_CONST_GPIOS_MASK 0xff
#define GPIO_BIT_CFG	0x400
#define  GPIO_BIT_CFG_TX_OE		BIT(0)
#define  GPIO_BIT_CFG_PIN_XOR		BIT(1)
#define  GPIO_BIT_CFG_INT_EN		BIT(2)
#define  GPIO_BIT_CFG_INT_TYPE		BIT(3)
#define  GPIO_BIT_CFG_FIL_MASK		GENMASK(11, 4)
#define  GPIO_BIT_CFG_FIL_CNT_SHIFT	4
#define  GPIO_BIT_CFG_FIL_SEL_SHIFT	8
#define  GPIO_BIT_CFG_TX_OD		BIT(12)
#define  GPIO_BIT_CFG_PIN_SEL_MASK	GENMASK(26, 16)
#define  GPIO_BIT_CFG_PIN_SEL_SHIFT	16
#define GPIO_INTR	0x800
#define  GPIO_INTR_INTR			BIT(0)
#define  GPIO_INTR_INTR_W1S		BIT(1)
#define  GPIO_INTR_ENA_W1C		BIT(2)
#define  GPIO_INTR_ENA_W1S		BIT(3)
#define GPIO_2ND_BANK	0x1400
#define MRVL_OCTEONTX2_96XX_PARTNUM	0xB2

#define GLITCH_FILTER_400NS ((4u << GPIO_BIT_CFG_FIL_SEL_SHIFT) | \
			     (9u << GPIO_BIT_CFG_FIL_CNT_SHIFT))

#ifdef CONFIG_MRVL_OCTEONTX_EL0_INTR
#define DEVICE_NAME	"otx-gpio-ctr"
#define OTX_IOC_MAGIC	0xF2
#define MAX_GPIO	80

static struct device *otx_device;
static struct class *otx_class;
static struct cdev *otx_cdev;
static dev_t otx_dev;
static DEFINE_SPINLOCK(el3_inthandler_lock);
static int gpio_in_use;
static int gpio_installed[MAX_GPIO];
static struct thread_info *gpio_installed_threads[MAX_GPIO];
static struct task_struct *gpio_installed_tasks[MAX_GPIO];

/* THUNDERX SMC definitons */
/* X1 - gpio_num, X2 - sp, X3 - cpu, X4 - ttbr0 */
#define THUNDERX_INSTALL_GPIO_INT       0xc2000801
/* X1 - gpio_num */
#define THUNDERX_REMOVE_GPIO_INT        0xc2000802

struct intr_hand {
	u64	mask;
	char	name[50];
	u64	coffset;
	u64	soffset;
	irqreturn_t (*handler)(int, void *);
};

struct otx_gpio_usr_data {
	u64	isr_base;
	u64	sp;
	u64	cpu;
	u64	gpio_num;
};


#define OTX_IOC_SET_GPIO_HANDLER \
	_IOW(OTX_IOC_MAGIC, 1, struct otx_gpio_usr_data)

#define OTX_IOC_CLR_GPIO_HANDLER \
	_IO(OTX_IOC_MAGIC, 2)
#endif

struct thunderx_gpio;

struct thunderx_line {
	struct thunderx_gpio	*txgpio;
	unsigned int		line;
	unsigned int		fil_bits;
};

struct thunderx_gpio {
	struct gpio_chip	chip;
	u8 __iomem		*register_base;
	struct irq_domain	*irqd;
	struct msix_entry	*msix_entries;	/* per line MSI-X */
	struct thunderx_line	*line_entries;	/* per line irq info */
	raw_spinlock_t		lock;
	unsigned long		invert_mask[2];
	unsigned long		od_mask[2];
	int			base_msi;
};

#ifdef CONFIG_MRVL_OCTEONTX_EL0_INTR
static inline int __install_el3_inthandler(unsigned long gpio_num,
					   unsigned long sp,
					   unsigned long cpu,
					   unsigned long ttbr0)
{
	struct arm_smccc_res res;
	unsigned long flags;
	int retval = -1;

	spin_lock_irqsave(&el3_inthandler_lock, flags);
	if (!gpio_installed[gpio_num]) {
		lock_context(current->group_leader->mm, gpio_num);
		arm_smccc_smc(THUNDERX_INSTALL_GPIO_INT, gpio_num,
			      sp, cpu, ttbr0, 0, 0, 0, &res);
		if (res.a0 == 0) {
			gpio_installed[gpio_num] = 1;
			gpio_installed_threads[gpio_num]
				= current_thread_info();
			gpio_installed_tasks[gpio_num]
				= current->group_leader;
			retval = 0;
		} else {
			unlock_context_by_index(gpio_num);
		}
	}
	spin_unlock_irqrestore(&el3_inthandler_lock, flags);
	return retval;
}

static inline int __remove_el3_inthandler(unsigned long gpio_num)
{
	struct arm_smccc_res res;
	unsigned long flags;
	unsigned int retval;

	spin_lock_irqsave(&el3_inthandler_lock, flags);
	if (gpio_installed[gpio_num]) {
		arm_smccc_smc(THUNDERX_REMOVE_GPIO_INT, gpio_num,
			      0, 0, 0, 0, 0, 0, &res);
		gpio_installed[gpio_num] = 0;
		gpio_installed_threads[gpio_num] = NULL;
		gpio_installed_tasks[gpio_num] = NULL;
		unlock_context_by_index(gpio_num);
		retval = 0;
	} else {
		retval = -1;
	}
	spin_unlock_irqrestore(&el3_inthandler_lock, flags);
	return retval;
}

static long otx_dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	struct otx_gpio_usr_data gpio_usr;
	u64 gpio_ttbr, gpio_isr_base, gpio_sp, gpio_cpu, gpio_num;
	int ret;
	//struct task_struct *task = current;

	if (!gpio_in_use)
		return -EINVAL;

	if (_IOC_TYPE(cmd) != OTX_IOC_MAGIC)
		return -ENOTTY;

	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user *)arg,
				 _IOC_SIZE(cmd));
	else if (_IOC_TYPE(cmd) & _IOC_WRITE)
		err = !access_ok(VERIFY_READ, (void __user *)arg,
				 _IOC_SIZE(cmd));

	if (err)
		return -EFAULT;

	switch (cmd) {
	case OTX_IOC_SET_GPIO_HANDLER: /*Install GPIO ISR handler*/
		ret = copy_from_user(&gpio_usr, (void *)arg, _IOC_SIZE(cmd));
		if (gpio_usr.gpio_num >= MAX_GPIO)
			return -EINVAL;
		if (ret)
			return -EFAULT;
		gpio_ttbr = 0;
		//TODO: reserve a asid to avoid asid rollovers
		asm volatile("mrs %0, ttbr0_el1\n\t" : "=r"(gpio_ttbr));
		gpio_isr_base = gpio_usr.isr_base;
		gpio_sp = gpio_usr.sp;
		gpio_cpu = gpio_usr.cpu;
		gpio_num = gpio_usr.gpio_num;
		ret = __install_el3_inthandler(gpio_num, gpio_sp,
					       gpio_cpu, gpio_isr_base);
		if (ret != 0)
			return -EEXIST;
		break;
	case OTX_IOC_CLR_GPIO_HANDLER: /*Clear GPIO ISR handler*/
		gpio_usr.gpio_num = arg;
		if (gpio_usr.gpio_num >= MAX_GPIO)
			return -EINVAL;
		ret = __remove_el3_inthandler(gpio_usr.gpio_num);
		if (ret != 0)
			return -ENOENT;
		break;
	default:
		return -ENOTTY;
	}
	return 0;
}

static void cleanup_el3_irqs(struct task_struct *task)
{
	int i;

	for (i = 0; i < MAX_GPIO; i++) {
		if (gpio_installed[i] &&
		    gpio_installed_tasks[i] &&
		    (gpio_installed_tasks[i] == task)) {
			pr_alert("Exiting, removing handler for GPIO %d\n",
				 i);
			__remove_el3_inthandler(i);
			pr_alert("Exited, removed handler for GPIO %d\n",
				 i);
		} else {
			if (gpio_installed[i] &&
			    (gpio_installed_threads[i]
			     == current_thread_info()))
				pr_alert(
	    "Exiting, thread info matches, not removing handler for GPIO %d\n",
					 i);
		}
	}
}

static int otx_dev_open(struct inode *inode, struct file *fp)
{
	gpio_in_use = 1;
	return 0;
}

static int otx_dev_release(struct inode *inode, struct file *fp)
{
	if (gpio_in_use == 0)
		return -EINVAL;
	gpio_in_use = 0;
	return 0;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = otx_dev_open,
	.release = otx_dev_release,
	.unlocked_ioctl = otx_dev_ioctl
};
#endif

static unsigned int bit_cfg_reg(unsigned int line)
{
	return 8 * line + GPIO_BIT_CFG;
}

static unsigned int intr_reg(unsigned int line)
{
	return 8 * line + GPIO_INTR;
}

static bool thunderx_gpio_is_gpio_nowarn(struct thunderx_gpio *txgpio,
					 unsigned int line)
{
	u64 bit_cfg = readq(txgpio->register_base + bit_cfg_reg(line));

	return (bit_cfg & GPIO_BIT_CFG_PIN_SEL_MASK) == 0;
}

/*
 * Check (and WARN) that the pin is available for GPIO.  We will not
 * allow modification of the state of non-GPIO pins from this driver.
 */
static bool thunderx_gpio_is_gpio(struct thunderx_gpio *txgpio,
				  unsigned int line)
{
	bool rv = thunderx_gpio_is_gpio_nowarn(txgpio, line);

	WARN_RATELIMIT(!rv, "Pin %d not available for GPIO\n", line);

	return rv;
}

static int thunderx_gpio_request(struct gpio_chip *chip, unsigned int line)
{
	struct thunderx_gpio *txgpio = gpiochip_get_data(chip);

	return thunderx_gpio_is_gpio(txgpio, line) ? 0 : -EIO;
}

static int thunderx_gpio_dir_in(struct gpio_chip *chip, unsigned int line)
{
	struct thunderx_gpio *txgpio = gpiochip_get_data(chip);
	unsigned long flags;

	if (!thunderx_gpio_is_gpio(txgpio, line))
		return -EIO;

	raw_spin_lock_irqsave(&txgpio->lock, flags);
	clear_bit(line, txgpio->invert_mask);
	clear_bit(line, txgpio->od_mask);
	writeq(txgpio->line_entries[line].fil_bits,
	       txgpio->register_base + bit_cfg_reg(line));
	raw_spin_unlock_irqrestore(&txgpio->lock, flags);
	return 0;
}

static void thunderx_gpio_set(struct gpio_chip *chip, unsigned int line,
			      int value)
{
	struct thunderx_gpio *txgpio = gpiochip_get_data(chip);
	int bank = line / 64;
	int bank_bit = line % 64;

	void __iomem *reg = txgpio->register_base +
		(bank * GPIO_2ND_BANK) + (value ? GPIO_TX_SET : GPIO_TX_CLR);

	writeq(BIT_ULL(bank_bit), reg);
}

static int thunderx_gpio_dir_out(struct gpio_chip *chip, unsigned int line,
				 int value)
{
	struct thunderx_gpio *txgpio = gpiochip_get_data(chip);
	u64 bit_cfg = txgpio->line_entries[line].fil_bits | GPIO_BIT_CFG_TX_OE;
	unsigned long flags;

	if (!thunderx_gpio_is_gpio(txgpio, line))
		return -EIO;

	raw_spin_lock_irqsave(&txgpio->lock, flags);

	thunderx_gpio_set(chip, line, value);

	if (test_bit(line, txgpio->invert_mask))
		bit_cfg |= GPIO_BIT_CFG_PIN_XOR;

	if (test_bit(line, txgpio->od_mask))
		bit_cfg |= GPIO_BIT_CFG_TX_OD;

	writeq(bit_cfg, txgpio->register_base + bit_cfg_reg(line));

	raw_spin_unlock_irqrestore(&txgpio->lock, flags);
	return 0;
}

static int thunderx_gpio_get_direction(struct gpio_chip *chip, unsigned int line)
{
	struct thunderx_gpio *txgpio = gpiochip_get_data(chip);
	u64 bit_cfg;

	if (!thunderx_gpio_is_gpio_nowarn(txgpio, line))
		/*
		 * Say it is input for now to avoid WARNing on
		 * gpiochip_add_data().  We will WARN if someone
		 * requests it or tries to use it.
		 */
		return 1;

	bit_cfg = readq(txgpio->register_base + bit_cfg_reg(line));

	return !(bit_cfg & GPIO_BIT_CFG_TX_OE);
}

static int thunderx_gpio_set_config(struct gpio_chip *chip,
				    unsigned int line,
				    unsigned long cfg)
{
	bool orig_invert, orig_od, orig_dat, new_invert, new_od;
	u32 arg, sel;
	u64 bit_cfg;
	int bank = line / 64;
	int bank_bit = line % 64;
	int ret = -ENOTSUPP;
	struct thunderx_gpio *txgpio = gpiochip_get_data(chip);
	void __iomem *reg = txgpio->register_base + (bank * GPIO_2ND_BANK) + GPIO_TX_SET;
	unsigned long flags;

	if (!thunderx_gpio_is_gpio(txgpio, line))
		return -EIO;

	raw_spin_lock_irqsave(&txgpio->lock, flags);
	orig_invert = test_bit(line, txgpio->invert_mask);
	new_invert  = orig_invert;
	orig_od = test_bit(line, txgpio->od_mask);
	new_od = orig_od;
	orig_dat = ((readq(reg) >> bank_bit) & 1) ^ orig_invert;
	bit_cfg = readq(txgpio->register_base + bit_cfg_reg(line));
	switch (pinconf_to_config_param(cfg)) {
	case PIN_CONFIG_DRIVE_OPEN_DRAIN:
		/*
		 * Weird, setting open-drain mode causes signal
		 * inversion.  Note this so we can compensate in the
		 * dir_out function.
		 */
		set_bit(line, txgpio->invert_mask);
		new_invert  = true;
		set_bit(line, txgpio->od_mask);
		new_od = true;
		ret = 0;
		break;
	case PIN_CONFIG_DRIVE_PUSH_PULL:
		clear_bit(line, txgpio->invert_mask);
		new_invert  = false;
		clear_bit(line, txgpio->od_mask);
		new_od  = false;
		ret = 0;
		break;
	case PIN_CONFIG_INPUT_DEBOUNCE:
		arg = pinconf_to_config_argument(cfg);
		if (arg > 1228) { /* 15 * 2^15 * 2.5nS maximum */
			ret = -EINVAL;
			break;
		}
		arg *= 400; /* scale to 2.5nS clocks. */
		sel = 0;
		while (arg > 15) {
			sel++;
			arg++; /* always round up */
			arg >>= 1;
		}
		txgpio->line_entries[line].fil_bits =
			(sel << GPIO_BIT_CFG_FIL_SEL_SHIFT) |
			(arg << GPIO_BIT_CFG_FIL_CNT_SHIFT);
		bit_cfg &= ~GPIO_BIT_CFG_FIL_MASK;
		bit_cfg |= txgpio->line_entries[line].fil_bits;
		writeq(bit_cfg, txgpio->register_base + bit_cfg_reg(line));
		ret = 0;
		break;
	default:
		break;
	}
	raw_spin_unlock_irqrestore(&txgpio->lock, flags);

	/*
	 * If currently output and OPEN_DRAIN changed, install the new
	 * settings
	 */
	if ((new_invert != orig_invert || new_od != orig_od) &&
	    (bit_cfg & GPIO_BIT_CFG_TX_OE))
		ret = thunderx_gpio_dir_out(chip, line, orig_dat ^ new_invert);

	return ret;
}

static int thunderx_gpio_get(struct gpio_chip *chip, unsigned int line)
{
	struct thunderx_gpio *txgpio = gpiochip_get_data(chip);
	int bank = line / 64;
	int bank_bit = line % 64;
	u64 read_bits = readq(txgpio->register_base + (bank * GPIO_2ND_BANK) + GPIO_RX_DAT);
	u64 masked_bits = read_bits & BIT_ULL(bank_bit);

	if (test_bit(line, txgpio->invert_mask))
		return masked_bits == 0;
	else
		return masked_bits != 0;
}

static void thunderx_gpio_set_multiple(struct gpio_chip *chip,
				       unsigned long *mask,
				       unsigned long *bits)
{
	int bank;
	u64 set_bits, clear_bits;
	struct thunderx_gpio *txgpio = gpiochip_get_data(chip);

	for (bank = 0; bank <= chip->ngpio / 64; bank++) {
		set_bits = bits[bank] & mask[bank];
		clear_bits = ~bits[bank] & mask[bank];
		writeq(set_bits, txgpio->register_base + (bank * GPIO_2ND_BANK) + GPIO_TX_SET);
		writeq(clear_bits, txgpio->register_base + (bank * GPIO_2ND_BANK) + GPIO_TX_CLR);
	}
}

#ifdef CONFIG_MRVL_OCTEONTX_EL0_INTR
static void thunderx_gpio_spi_irq_ack(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;

	writeq(GPIO_INTR_INTR,
	       gpio->register_base + intr_reg(line));
}

static void thunderx_gpio_spi_irq_mask(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;

	writeq(GPIO_INTR_ENA_W1C, gpio->register_base + intr_reg(line));
}

static void thunderx_gpio_spi_irq_mask_ack(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;

	writeq(GPIO_INTR_ENA_W1C | GPIO_INTR_INTR,
	       gpio->register_base + intr_reg(line));
}

static void thunderx_gpio_spi_irq_unmask(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;

	writeq(GPIO_INTR_ENA_W1S, gpio->register_base + intr_reg(line));
}

/*
 *  Do not set msix_entries for SPI IRQs.
 */
static int thunderx_gpio_spi_irq_request_resources(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;

	if (!thunderx_gpio_is_gpio(gpio, line))
		return -EIO;

	writeq(GPIO_INTR_ENA_W1C, gpio->register_base + intr_reg(line));

	return 0;
}

static void thunderx_gpio_spi_irq_release_resources(struct irq_data *data)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;

	writeq(GPIO_INTR_ENA_W1C, gpio->register_base + intr_reg(line));

}

static int thunderx_gpio_spi_irq_set_type(struct irq_data *data,
				      unsigned int flow_type)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);
	unsigned int line = data->hwirq;
	u64 bit_cfg;
	unsigned long flags;

	irqd_set_trigger_type(data, flow_type);

	bit_cfg = GLITCH_FILTER_400NS | GPIO_BIT_CFG_INT_EN;

	raw_spin_lock_irqsave(&gpio->lock, flags);
	if (flow_type & IRQ_TYPE_EDGE_BOTH) {
		irq_set_handler_locked(data, handle_edge_irq);
		bit_cfg |= GPIO_BIT_CFG_INT_TYPE;
	} else {
		irq_set_handler_locked(data, handle_level_irq);
	}

	if (flow_type & (IRQ_TYPE_EDGE_FALLING | IRQ_TYPE_LEVEL_LOW)) {
		bit_cfg |= GPIO_BIT_CFG_PIN_XOR;
		set_bit(line, gpio->invert_mask);
	} else {
		clear_bit(line, gpio->invert_mask);
	}
	clear_bit(line, gpio->od_mask);
	writeq(bit_cfg, gpio->register_base + bit_cfg_reg(line));
	raw_spin_unlock_irqrestore(&gpio->lock, flags);

	return IRQ_SET_MASK_OK;
}

static void thunderx_gpio_spi_irq_handler(struct irq_desc *desc)
{
	unsigned int line;
	struct gpio_chip *chip = irq_desc_get_handler_data(desc);
	struct irq_chip *irqchip = irq_desc_get_chip(desc);
	struct thunderx_gpio *gpio =
		container_of(chip, struct thunderx_gpio, chip);

	chained_irq_enter(irqchip, desc);
	for (line = 0; line < chip->ngpio; line++) {
		if (readq(gpio->register_base + intr_reg(line)) &
		    GPIO_INTR_INTR) {
			generic_handle_irq(irq_find_mapping(chip->irqdomain,
							    line));
			writeq(GPIO_INTR_INTR,
			       gpio->register_base + intr_reg(line));
		}
	}
	chained_irq_exit(irqchip, desc);
}

static struct irq_chip thunderx_gpio_spi_irq_chip = {
	.name                   = "GPIO",
	.irq_enable             = thunderx_gpio_spi_irq_unmask,
	.irq_disable            = thunderx_gpio_spi_irq_mask,
	.irq_ack                = thunderx_gpio_spi_irq_ack,
	.irq_mask               = thunderx_gpio_spi_irq_mask,
	.irq_mask_ack           = thunderx_gpio_spi_irq_mask_ack,
	.irq_unmask             = thunderx_gpio_spi_irq_unmask,
	.irq_set_type           = thunderx_gpio_spi_irq_set_type,
	.irq_request_resources  = thunderx_gpio_spi_irq_request_resources,
	.irq_release_resources  = thunderx_gpio_spi_irq_release_resources,
	.flags                  = IRQCHIP_SET_TYPE_MASKED
};
#endif

static void thunderx_gpio_irq_ack(struct irq_data *data)
{
	struct thunderx_line *txline = irq_data_get_irq_chip_data(data);

	writeq(GPIO_INTR_INTR,
	       txline->txgpio->register_base + intr_reg(txline->line));
}

static void thunderx_gpio_irq_mask(struct irq_data *data)
{
	struct thunderx_line *txline = irq_data_get_irq_chip_data(data);

	writeq(GPIO_INTR_ENA_W1C,
	       txline->txgpio->register_base + intr_reg(txline->line));
}

static void thunderx_gpio_irq_mask_ack(struct irq_data *data)
{
	struct thunderx_line *txline = irq_data_get_irq_chip_data(data);

	writeq(GPIO_INTR_ENA_W1C | GPIO_INTR_INTR,
	       txline->txgpio->register_base + intr_reg(txline->line));
}

static void thunderx_gpio_irq_unmask(struct irq_data *data)
{
	struct thunderx_line *txline = irq_data_get_irq_chip_data(data);

	writeq(GPIO_INTR_ENA_W1S,
	       txline->txgpio->register_base + intr_reg(txline->line));
}

static int thunderx_gpio_irq_set_type(struct irq_data *data,
				      unsigned int flow_type)
{
	struct thunderx_line *txline = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *txgpio = txline->txgpio;
	u64 bit_cfg;
	unsigned long flags;

	irqd_set_trigger_type(data, flow_type);

	bit_cfg = txline->fil_bits | GPIO_BIT_CFG_INT_EN;

	raw_spin_lock_irqsave(&txgpio->lock, flags);
	if (flow_type & IRQ_TYPE_EDGE_BOTH) {
		irq_set_handler_locked(data, handle_fasteoi_ack_irq);
		bit_cfg |= GPIO_BIT_CFG_INT_TYPE;
	} else {
		irq_set_handler_locked(data, handle_fasteoi_mask_irq);
	}

	if (flow_type & (IRQ_TYPE_EDGE_FALLING | IRQ_TYPE_LEVEL_LOW)) {
		bit_cfg |= GPIO_BIT_CFG_PIN_XOR;
		set_bit(txline->line, txgpio->invert_mask);
	} else {
		clear_bit(txline->line, txgpio->invert_mask);
	}
	clear_bit(txline->line, txgpio->od_mask);
	writeq(bit_cfg, txgpio->register_base + bit_cfg_reg(txline->line));
	raw_spin_unlock_irqrestore(&txgpio->lock, flags);

	return IRQ_SET_MASK_OK;
}

static void thunderx_gpio_irq_enable(struct irq_data *data)
{
	irq_chip_enable_parent(data);
	thunderx_gpio_irq_unmask(data);
}

static void thunderx_gpio_irq_disable(struct irq_data *data)
{
	thunderx_gpio_irq_mask(data);
	irq_chip_disable_parent(data);
}

static int thunderx_gpio_irq_request_resources(struct irq_data *data)
{
	struct thunderx_line *txline = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *txgpio = txline->txgpio;
	struct irq_data *parent_data = data->parent_data;
	int r;

	r = gpiochip_lock_as_irq(&txgpio->chip, txline->line);
	if (r)
		return r;

	if (parent_data && parent_data->chip->irq_request_resources) {
		r = parent_data->chip->irq_request_resources(parent_data);
		if (r)
			goto error;
	}

	return 0;
error:
	gpiochip_unlock_as_irq(&txgpio->chip, txline->line);
	return r;
}

static void thunderx_gpio_irq_release_resources(struct irq_data *data)
{
	struct thunderx_line *txline = irq_data_get_irq_chip_data(data);
	struct thunderx_gpio *txgpio = txline->txgpio;
	struct irq_data *parent_data = data->parent_data;

	if (parent_data && parent_data->chip->irq_release_resources)
		parent_data->chip->irq_release_resources(parent_data);

	gpiochip_unlock_as_irq(&txgpio->chip, txline->line);
}

/*
 * Interrupts are chained from underlying MSI-X vectors.  We have
 * these irq_chip functions to be able to handle level triggering
 * semantics and other acknowledgment tasks associated with the GPIO
 * mechanism.
 */
static struct irq_chip thunderx_gpio_irq_chip = {
	.name			= "GPIO",
	.irq_enable		= thunderx_gpio_irq_enable,
	.irq_disable		= thunderx_gpio_irq_disable,
	.irq_ack		= thunderx_gpio_irq_ack,
	.irq_mask		= thunderx_gpio_irq_mask,
	.irq_mask_ack		= thunderx_gpio_irq_mask_ack,
	.irq_unmask		= thunderx_gpio_irq_unmask,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.irq_request_resources	= thunderx_gpio_irq_request_resources,
	.irq_release_resources	= thunderx_gpio_irq_release_resources,
	.irq_set_type		= thunderx_gpio_irq_set_type,

	.flags			= IRQCHIP_SET_TYPE_MASKED
};

static int thunderx_gpio_irq_map(struct irq_domain *d, unsigned int irq,
				 irq_hw_number_t hwirq)
{
	struct thunderx_gpio *txgpio = d->host_data;

	if (hwirq >= txgpio->chip.ngpio)
		return -EINVAL;
	if (!thunderx_gpio_is_gpio_nowarn(txgpio, hwirq))
		return -EPERM;
	return 0;
}

static int thunderx_gpio_irq_translate(struct irq_domain *d,
				       struct irq_fwspec *fwspec,
				       irq_hw_number_t *hwirq,
				       unsigned int *type)
{
	struct thunderx_gpio *txgpio = d->host_data;

	if (WARN_ON(fwspec->param_count < 2))
		return -EINVAL;
	if (fwspec->param[0] >= txgpio->chip.ngpio)
		return -EINVAL;
	*hwirq = fwspec->param[0];
	*type = fwspec->param[1] & IRQ_TYPE_SENSE_MASK;
	return 0;
}

static int thunderx_gpio_irq_alloc(struct irq_domain *d, unsigned int virq,
				   unsigned int nr_irqs, void *arg)
{
	struct thunderx_line *txline = arg;

	return irq_domain_set_hwirq_and_chip(d, virq, txline->line,
					     &thunderx_gpio_irq_chip, txline);
}

static const struct irq_domain_ops thunderx_gpio_irqd_ops = {
	.map		= thunderx_gpio_irq_map,
	.alloc		= thunderx_gpio_irq_alloc,
	.translate	= thunderx_gpio_irq_translate
};

static int thunderx_gpio_to_irq(struct gpio_chip *chip, unsigned int offset)
{
	struct thunderx_gpio *txgpio = gpiochip_get_data(chip);

	return irq_find_mapping(txgpio->irqd, offset);
}

static void thunderx_gpio_pinsel(struct device *dev,
				 struct thunderx_gpio *txgpio)
{
	struct device_node *node;
	const __be32 *pinsel;
	int npins, rlen, i;
	uint32_t pin, sel;

	node = dev_of_node(dev);
	if (!node)
		return;

	pinsel = of_get_property(node, "pin-cfg", &rlen);
	if (!pinsel || rlen % 2)
		return;
	npins = rlen / sizeof(__be32) / 2;

	for (i = 0; i < npins; i++) {
		pin = of_read_number(pinsel++, 1);
		sel = of_read_number(pinsel++, 1);
		dev_info(dev, "Set GPIO pin %d CFG register to %x\n", pin, sel);
		writeq(sel, txgpio->register_base + bit_cfg_reg(pin));
	}
}

static int thunderx_gpio_probe(struct pci_dev *pdev,
			       const struct pci_device_id *id)
{
	void __iomem * const *tbl;
	struct device *dev = &pdev->dev;
	struct thunderx_gpio *txgpio;
	struct gpio_chip *chip;
	int ngpio, i;
	int err = 0;

	txgpio = devm_kzalloc(dev, sizeof(*txgpio), GFP_KERNEL);
	if (!txgpio)
		return -ENOMEM;

	raw_spin_lock_init(&txgpio->lock);
	chip = &txgpio->chip;

	pci_set_drvdata(pdev, txgpio);

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device: err %d\n", err);
		goto out;
	}

	err = pcim_iomap_regions(pdev, 1 << 0, KBUILD_MODNAME);
	if (err) {
		dev_err(dev, "Failed to iomap PCI device: err %d\n", err);
		goto out;
	}

	tbl = pcim_iomap_table(pdev);
	txgpio->register_base = tbl[0];
	if (!txgpio->register_base) {
		dev_err(dev, "Cannot map PCI resource\n");
		err = -ENOMEM;
		goto out;
	}

	if (pdev->subsystem_device == 0xa10a) {
		/* CN88XX has no GPIO_CONST register*/
		ngpio = 50;
		txgpio->base_msi = 48;
	} else {
		u64 c = readq(txgpio->register_base + GPIO_CONST);

		ngpio = c & GPIO_CONST_GPIOS_MASK;

		/* Workaround for all passes of T96xx */
		if (((pdev->subsystem_device >> 8) & 0xFF)
				== MRVL_OCTEONTX2_96XX_PARTNUM) {
			txgpio->base_msi = 0x36;
		} else {
			txgpio->base_msi = (c >> 8) & 0xff;
		}
	}

	txgpio->msix_entries = devm_kzalloc(dev,
					  sizeof(struct msix_entry) * ngpio,
					  GFP_KERNEL);
	if (!txgpio->msix_entries) {
		err = -ENOMEM;
		goto out;
	}

#ifdef CONFIG_MRVL_OCTEONTX_EL0_INTR
	pdev->irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
#endif

	txgpio->line_entries =
		devm_kzalloc(dev,
			     sizeof(struct thunderx_line) * ngpio,
			     GFP_KERNEL);
	if (!txgpio->line_entries) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < ngpio; i++) {
		u64 bit_cfg = readq(txgpio->register_base + bit_cfg_reg(i));

		txgpio->msix_entries[i].entry = txgpio->base_msi + (2 * i);
		txgpio->line_entries[i].line = i;
		txgpio->line_entries[i].txgpio = txgpio;
		/*
		 * If something has already programmed the pin, use
		 * the existing glitch filter settings, otherwise go
		 * to 400nS.
		 */
		txgpio->line_entries[i].fil_bits = bit_cfg ?
			(bit_cfg & GPIO_BIT_CFG_FIL_MASK) : GLITCH_FILTER_400NS;

		if ((bit_cfg & GPIO_BIT_CFG_TX_OE) && (bit_cfg & GPIO_BIT_CFG_TX_OD))
			set_bit(i, txgpio->od_mask);
		if (bit_cfg & GPIO_BIT_CFG_PIN_XOR)
			set_bit(i, txgpio->invert_mask);
	}

	/* Enable all MSI-X for interrupts on all possible lines. */
	err = pci_enable_msix_range(pdev, txgpio->msix_entries, ngpio, ngpio);
	if (err < 0)
		goto out;

	if (pdev->irq == 0) {
		/*
		 * Push GPIO specific irqdomain on hierarchy created as a side
		 * effect of the pci_enable_msix()
		 */
		txgpio->irqd = irq_domain_create_hierarchy(irq_get_irq_data(txgpio->msix_entries[0].vector)->domain,
							   0, 0, of_node_to_fwnode(dev->of_node),
							   &thunderx_gpio_irqd_ops, txgpio);
		if (!txgpio->irqd) {
			err = -ENOMEM;
			goto out;
		}

		/* Push on irq_data and the domain for each line. */
		for (i = 0; i < ngpio; i++) {
			err = irq_domain_push_irq(txgpio->irqd,
						  txgpio->msix_entries[i].vector,
						  &txgpio->line_entries[i]);
			if (err < 0)
				dev_err(dev, "irq_domain_push_irq: %d\n", err);
		}
	}

	chip->label = KBUILD_MODNAME;
	chip->parent = dev;
	chip->owner = THIS_MODULE;
	chip->request = thunderx_gpio_request;
	chip->base = -1; /* System allocated */
	chip->can_sleep = false;
	chip->ngpio = ngpio;
	chip->get_direction = thunderx_gpio_get_direction;
	chip->direction_input = thunderx_gpio_dir_in;
	chip->get = thunderx_gpio_get;
	chip->direction_output = thunderx_gpio_dir_out;
	chip->set = thunderx_gpio_set;
	chip->set_multiple = thunderx_gpio_set_multiple;
	chip->set_config = thunderx_gpio_set_config;
	chip->to_irq = thunderx_gpio_to_irq;
	err = devm_gpiochip_add_data(dev, chip, txgpio);
	if (err)
		goto out;

	dev_info(dev, "ThunderX GPIO: %d lines with base %d.\n",
		 ngpio, chip->base);

	/* Configure default functions of GPIO pins */
	thunderx_gpio_pinsel(dev, txgpio);

#ifdef CONFIG_MRVL_OCTEONTX_EL0_INTR
	if (pdev->irq != 0) {
		err = gpiochip_irqchip_add(chip, &thunderx_gpio_spi_irq_chip, 0,
					   handle_bad_irq, IRQ_TYPE_NONE);
		if (err) {
			dev_err(dev, "gpiochip_irqchip_add failed: %d\n", err);
			goto irqchip_out;
		}

		gpiochip_set_chained_irqchip(chip,
					     &thunderx_gpio_spi_irq_chip,
					     pdev->irq,
					     thunderx_gpio_spi_irq_handler);
	}

	/* Register task cleanup handler */
	err = task_cleanup_handler_add(cleanup_el3_irqs);
	if (err != 0) {
		dev_err(dev, "Failed to register cleanup handler: %d\n", err);
		goto cleanup_handler_err;
	}

	/* create a character device */
	err = alloc_chrdev_region(&otx_dev, 1, 1, DEVICE_NAME);
	if (err != 0) {
		dev_err(dev, "Failed to create device: %d\n", err);
		goto alloc_chrdev_err;
	}

	otx_cdev = cdev_alloc();
	if (!otx_cdev) {
		err = -ENODEV;
		goto cdev_alloc_err;
	}

	cdev_init(otx_cdev, &fops);
	err = cdev_add(otx_cdev, otx_dev, 1);
	if (err < 0) {
		err = -ENODEV;
		goto cdev_add_err;
	}

	/* create new class for sysfs*/
	otx_class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR(otx_class)) {
		err = -ENODEV;
		goto class_create_err;
	}

	otx_device = device_create(otx_class, NULL, otx_dev, NULL,
				     DEVICE_NAME);
	if (IS_ERR(otx_device)) {
		err = -ENODEV;
		goto device_create_err;
	}
#endif

	return 0;

#ifdef CONFIG_MRVL_OCTEONTX_EL0_INTR
device_create_err:
	class_destroy(otx_class);

class_create_err:
cdev_add_err:
	cdev_del(otx_cdev);
cdev_alloc_err:
	unregister_chrdev_region(otx_dev, 1);
alloc_chrdev_err:
	task_cleanup_handler_remove(cleanup_el3_irqs);
cleanup_handler_err:
irqchip_out:
	gpiochip_remove(chip);
#endif
out:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void thunderx_gpio_remove(struct pci_dev *pdev)
{
	int i;
	struct thunderx_gpio *txgpio = pci_get_drvdata(pdev);

	if (pdev->irq == 0) {
		for (i = 0; i < txgpio->chip.ngpio; i++)
			irq_domain_pop_irq(txgpio->irqd,
					   txgpio->msix_entries[i].vector);

		irq_domain_remove(txgpio->irqd);
	} else {
		gpiochip_remove(&txgpio->chip);
	}

	pci_set_drvdata(pdev, NULL);

#ifdef CONFIG_MRVL_OCTEONTX_EL0_INTR
	device_destroy(otx_class, otx_dev);
	class_destroy(otx_class);
	cdev_del(otx_cdev);
	unregister_chrdev_region(otx_dev, 1);

	task_cleanup_handler_remove(cleanup_el3_irqs);
#endif
}

static const struct pci_device_id thunderx_gpio_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, 0xA00A) },
	{ 0, }	/* end of table */
};

MODULE_DEVICE_TABLE(pci, thunderx_gpio_id_table);

static struct pci_driver thunderx_gpio_driver = {
	.name = KBUILD_MODNAME,
	.id_table = thunderx_gpio_id_table,
	.probe = thunderx_gpio_probe,
	.remove = thunderx_gpio_remove,
};

module_pci_driver(thunderx_gpio_driver);

MODULE_DESCRIPTION("Cavium Inc. ThunderX/OCTEON-TX GPIO Driver");
MODULE_LICENSE("GPL");
