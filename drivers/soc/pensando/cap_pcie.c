// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019-2021, Pensando Systems Inc.
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <asm/traps.h>
#include "cap_reboot.h"
#include "cap_rstcause.h"
#include "penpcie_dev.h"
#include "cap_pcie_elba.h"

#define DRV_NAME	"cap_pcie"
#define PFX		DRV_NAME ": "

/* device resource indexes */
#define MS_CFG_WDT_IDX  0
#define WDT_IDX         1
#define PCIE_IDX	2

struct pciedev_info {
	u32 __iomem *ms_cfg_wdt;
	u32 __iomem *wdt;
	void __iomem *pcieva;
	u64 pcie_base;
	u64 pcie_size;
	u64 pciep_access_address;
	int pciep_access_error;
	spinlock_t pciep_access_lock;
	long (*saved_panic_blink)(int state);
};

static struct pciedev_info pciedev_info;

static void *pcie_ptov(const u64 pciepa)
{
	struct pciedev_info *pi = &pciedev_info;
	const u64 pcieoff = pciepa - pi->pcie_base;

	return pi->pcieva + pcieoff;
}

static u32 pcie_readl(const u64 pciepa)
{
	return readl(pcie_ptov(pciepa));
}

static void pcie_writel(const u32 val, const u64 pciepa)
{
	writel(val, pcie_ptov(pciepa));
}

static int pciep_access_in_progress(void)
{
	struct pciedev_info *pi = &pciedev_info;

	if (pi->pciep_access_address) {
		pi->pciep_access_error++;
		return 1;
	}
	return 0;
}

int platform_serror(struct pt_regs *regs, unsigned int esr)
{
	if (pciep_access_in_progress())
		return 1;

	if ((esr >> 26) == 0x2f && (esr & 0x3) == 0x0) { /* Decode Error */
		if (user_mode(regs)) {
			struct task_struct *tsk = current;

			pr_info("%s[%d]: serror converted to bus error\n",
				tsk->comm, task_pid_nr(tsk));
			force_signal_inject(SIGBUS, BUS_ADRERR, regs->pc);
		} else {
			/* ignore */
			pr_info("ignoring serror decode-error in kernel mode\n");
		}
		return 1;
	}

	return 0;
}

static void pciep_access_begin(const u64 pciepa)
{
	struct pciedev_info *pi = &pciedev_info;

	pi->pciep_access_address = pciepa;
	pi->pciep_access_error = 0;
}

static int pciep_access_end(void)
{
	struct pciedev_info *pi = &pciedev_info;

	pi->pciep_access_address = 0;
	return pi->pciep_access_error;
}

static int pciep_valid_rw(struct pcie_rw *rw)
{
	struct pciedev_info *pi = &pciedev_info;

	if (!pi->pcieva)
		return -ENXIO;
	if (rw->pciepa < pi->pcie_base ||
	    rw->pciepa > pi->pcie_base + pi->pcie_size ||
	    rw->size > pi->pcie_size ||
	    rw->pciepa + rw->size > pi->pcie_base + pi->pcie_size)
		return -ERANGE;
	if (rw->size != sizeof(u32))
		return -EINVAL;
	return 0;
}

/*
 * Protect reads to pcie registers in the pcie clock domain.
 * The pcie refclock can be removed by the system without warning,
 * and outstanding read requests to these registers will generate
 * an AXI read error response.  ARM will treat this as an asynchronous
 * System Error (SError) event.  The default handling of SError is to
 * send SIGILL if SError arrives while in user space, or panic if the
 * SError arrives when not in process context.  Neither of these responses
 * is desireable for our case where a pcie register might be accessed
 * just as the pcie refclock gets removed.  Here we detect the SError
 * event during our pcie register access and return failure to the
 * caller, but the system continues.
 */
static long pciep_regrd(struct pcie_rw *rw)
{
	struct pciedev_info *pi = &pciedev_info;
	uint32_t v;
	int r;

	r = pciep_valid_rw(rw);
	if (r)
		return r;

	spin_lock(&pi->pciep_access_lock);
	pciep_access_begin(rw->pciepa);

	v = pcie_readl(rw->pciepa);
	asm volatile("msr daifclr, #4" ::: "memory"); /* unmask async SError */
	dsb(sy);		/* sync in-flight ld/st */
	isb();

	r = pciep_access_end();
	spin_unlock(&pi->pciep_access_lock);
	if (r)
		return -EIO;

	return copy_to_user(rw->rdvalp, &v, sizeof(v));
}

static long pcie_unlocked_ioctl(struct file *file,
		unsigned int cmd, unsigned long arg)
{
	void __user *p = (void __user *)arg;
	struct pcie_rw rw;

	switch (cmd) {

	case PCIE_PCIEP_REGRD:
		if (copy_from_user(&rw, p, sizeof(rw)))
			return -EFAULT;
		return pciep_regrd(&rw);

	default:
		return -ENOTTY;
	}
}

const struct file_operations pcie_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= pcie_unlocked_ioctl,
};

static struct miscdevice pcie_dev = {
	MISC_DYNAMIC_MINOR,
	PENPCIE_NAME,
	&pcie_fops
};

static int pcieport_get_ltssm_en(const int port)
{
	const u32 val = pcie_readl(PXC_(CFG_C_PORT_MAC, port));

	return (val & CFG_MACF_(0_2_LTSSM_EN)) != 0;
}

static int pcie_get_ltssm_en(void)
{
	int port;

	for (port = 0; port < PCIEPORT_NPORTS; port++)
		if (pcieport_get_ltssm_en(port))
			return port;
	return -1;
}

static void pcieport_set_crs(const int port, const int on)
{
	u32 val;

	val = pcie_readl(PXC_(CFG_C_PORT_MAC, port));
	if (on)
		val |= CFG_MACF_(0_2_CFG_RETRY_EN);
	else
		val &= ~CFG_MACF_(0_2_CFG_RETRY_EN);
	pcie_writel(val, PXC_(CFG_C_PORT_MAC, port));
}

static void pcie_set_crs(const int on)
{
	int port;

	for (port = 0; port < PCIEPORT_NPORTS; port++)
		pcieport_set_crs(port, on);
}

static int pcieport_poll_for_hostdn(const int port)
{
	const u32 val = pcie_readl(PXC_(INT_C_MAC_INTREG, port));

	return (val & MAC_INTREGF_(RST_DN2UP)) != 0;
}

/*
 * Detect if the host is rebooting by watching the pcie mac
 * for an interrupt indicating the link went into reset.
 */
static int pcie_poll_for_hostdn(void)
{
	int port;

	for (port = 0; port < PCIEPORT_NPORTS; port++)
		if (pcieport_poll_for_hostdn(port))
			return port;
	return -1;
}

/*
 * Asic reset using the WDT0 configured to reset immediately.
 * Note that we do NOT touch the WDT config here until *after*
 * we are in the panic handling.  The WDT might be used by the
 * watchdog driver while the system is up, but here after a panic
 * we take ownership of the WDT to reset the system.
 *
 * Note also this function never returns.
 */
static void cap_reset(void)
{
	struct pciedev_info *pi = &pciedev_info;
	u32 val;

	pr_info(PFX "pensando reset!\n");

	/* Enable WDT0 to reset the system */
	val = ioread32(pi->ms_cfg_wdt);
	val |= (1 << CFG_WDT_RST_EN);
	iowrite32(val, pi->ms_cfg_wdt);

	/* Configure WDT to immediately reset */
	iowrite32(0, pi->wdt + WDT_TORR);
	iowrite32(WDT_KICK_VAL, pi->wdt + WDT_CRR);
	iowrite32(WDT_CR_PCLK_256, pi->wdt + WDT_CR);
	iowrite32(WDT_CR_PCLK_256 | WDT_CR_ENABLE, pi->wdt + WDT_CR);
	for (;;)
		asm volatile("wfi");
	/* NOTREACHED */
}

/*
 * This function is called by the spin loop at the end of a
 * system panic.  We'll watch for the host to reset and
 * reset ourselves at the same time.
 *
 * If we haven't yet initialized the link (ltssm_en=0) then the
 * host side hasn't come up yet.  In that case just reset immediately.
 */
static long pcie_panic_blink(int state)
{
	int port;

	/* Check sysfs for immediate reboot */
	if (cap_panic_reboot())
		cap_reset();

	port = pcie_get_ltssm_en();
	if (port >= 0) {
		pr_info(PFX "port %d enabled\n", port);
		pcie_set_crs(0);
		while ((port = pcie_poll_for_hostdn()) < 0)
			continue;
		pr_info(PFX "port %d hostdn\n", port);
#ifdef CONFIG_PENSANDO_SOC_RSTCAUSE
		/* reflect the pcie reset state in the reset cause */
		cap_rstcause_set(CAP_RSTCAUSE_EV_PCIE_RESET);
#endif
	}
	cap_reset();

	/* NOTREACHED */
	return 0;
}

static int map_resources(struct platform_device *pd)
{
	struct pciedev_info *pi = &pciedev_info;
	struct device_node *dn = pd->dev.of_node;

	pi->ms_cfg_wdt = of_iomap(dn, MS_CFG_WDT_IDX);
	pi->wdt = of_iomap(dn, WDT_IDX);
	pi->pcieva = of_iomap(dn, PCIE_IDX);

	if (IS_ERR(pi->ms_cfg_wdt) ||
		IS_ERR(pi->wdt) ||
		IS_ERR(pi->pcieva)) {
		pr_err(PFX "iomap resources failed\n");
		goto errout;
	}
	return 0;

 errout:
	if (pi->ms_cfg_wdt != NULL)
		iounmap(pi->ms_cfg_wdt);
	if (pi->wdt != NULL)
		iounmap(pi->wdt);
	if (pi->pcieva != NULL)
		iounmap(pi->pcieva);
	return -ENOMEM;
}

static void unmap_resources(struct platform_device *pd)
{
	struct pciedev_info *pi = &pciedev_info;

	if (pi->ms_cfg_wdt != NULL)
		iounmap(pi->ms_cfg_wdt);
	if (pi->wdt != NULL)
		iounmap(pi->wdt);
	if (pi->pcieva != NULL)
		iounmap(pi->pcieva);
}

static int pcie_probe(struct platform_device *pd)
{
	struct pciedev_info *pi = &pciedev_info;
	struct device_node *dn = pd->dev.of_node;
	struct resource res;
	int err;

	spin_lock_init(&pi->pciep_access_lock);

	err = map_resources(pd);
	if (err)
		goto errout;

	err = of_address_to_resource(dn, PCIE_IDX, &res);
	if (err) {
		pr_err(PFX "can't find PCIE_IDX res: %d\n", err);
		goto errout_unmap;
	}
	pi->pcie_base = res.start;
	pi->pcie_size = resource_size(&res);

	err = misc_register(&pcie_dev);
	if (err) {
		pr_err(PFX "register pcie_dev failed: %d\n", err);
		goto errout_unmap;
	}

	/*
	 * Hook the panic_blink handler so we run after
	 * all the panic notifiers and after all the
	 * console msgs have been flushed.
	 */
	pi->saved_panic_blink = panic_blink;
	panic_blink = pcie_panic_blink;
	return 0;

 errout_unmap:
	unmap_resources(pd);
 errout:
	return err;
}

static int pcie_remove(struct platform_device *pd)
{
	struct pciedev_info *pi = &pciedev_info;

	misc_deregister(&pcie_dev);
	panic_blink = pi->saved_panic_blink;
	unmap_resources(pd);
	return 0;
}

static const struct of_device_id pcie_of_match[] = {
	{ .compatible = "pensando,pcie" },
	{ /* end of table */ }
};

static struct platform_driver pcie_driver = {
	.probe = pcie_probe,
	.remove = pcie_remove,
	.driver = {
		.name = "pensando-pcie",
		.owner = THIS_MODULE,
		.of_match_table = pcie_of_match,
	},
};
module_platform_driver(pcie_driver);
