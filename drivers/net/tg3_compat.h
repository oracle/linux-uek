/* Copyright (C) 2008-2012 Broadcom Corporation. */

#ifdef CONFIG_X86
#undef NET_IP_ALIGN
#define NET_IP_ALIGN	0
#endif

#if !defined(__maybe_unused)
#define __maybe_unused  /* unimplemented */
#endif

#if !defined(__iomem)
#define __iomem
#endif

#ifndef __always_unused
#define __always_unused
#endif

#ifndef __acquires
#define __acquires(x)
#endif

#ifndef __releases
#define __releases(x)
#endif

#ifndef mmiowb
#define mmiowb()
#endif

#ifndef WARN_ON
#define WARN_ON(x)
#endif

#ifndef MODULE_VERSION
#define MODULE_VERSION(version)
#endif

#ifndef SET_MODULE_OWNER
#define SET_MODULE_OWNER(dev) do { } while (0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

#ifndef __ALIGN_MASK
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))
#endif

#ifndef ALIGN
#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#endif

#ifndef BCM_HAS_BOOL
typedef int bool;
#define false 0
#define true  1
#endif

#ifndef BCM_HAS_LE32
typedef u32 __le32;
typedef u32 __be32;
#endif

#ifndef BCM_HAS_RESOURCE_SIZE_T
typedef unsigned long resource_size_t;
#endif

#ifndef IRQ_RETVAL
typedef void irqreturn_t;
#define IRQ_RETVAL(x)
#define IRQ_HANDLED
#define IRQ_NONE
#endif

#ifndef IRQF_SHARED
#define IRQF_SHARED SA_SHIRQ
#endif

#ifndef IRQF_SAMPLE_RANDOM
#define IRQF_SAMPLE_RANDOM SA_SAMPLE_RANDOM
#endif

#if (LINUX_VERSION_CODE <= 0x020600)
#define schedule_work(x)	schedule_task(x)
#define work_struct		tq_struct
#define INIT_WORK(x, y, z)	INIT_TQUEUE(x, y, z)
#endif

#ifndef BCM_HAS_KZALLOC
static inline void *kzalloc(size_t size, int flags)
{
	void * memptr = kmalloc(size, flags);
	if (memptr)
		memset(memptr, 0, size);

	return memptr;
}
#endif

#ifndef USEC_PER_SEC
#define USEC_PER_SEC			1000000
#endif

#ifndef MSEC_PER_SEC
#define MSEC_PER_SEC			1000
#endif

#ifndef MAX_JIFFY_OFFSET
#define MAX_JIFFY_OFFSET		((LONG_MAX >> 1)-1)
#endif

#ifndef BCM_HAS_JIFFIES_TO_USECS
static unsigned int inline jiffies_to_usecs(const unsigned long j)
{
#if HZ <= USEC_PER_SEC && !(USEC_PER_SEC % HZ)
	return (USEC_PER_SEC / HZ) * j;
#elif HZ > USEC_PER_SEC && !(HZ % USEC_PER_SEC)
	return (j + (HZ / USEC_PER_SEC) - 1)/(HZ / USEC_PER_SEC);
#else
	return (j * USEC_PER_SEC) / HZ;
#endif
}
#endif /* BCM_HAS_JIFFIES_TO_USECS */

#ifndef BCM_HAS_USECS_TO_JIFFIES
static unsigned long usecs_to_jiffies(const unsigned int u)
{
	if (u > jiffies_to_usecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;
#if HZ <= USEC_PER_SEC && !(USEC_PER_SEC % HZ)
	return (u + (USEC_PER_SEC / HZ) - 1) / (USEC_PER_SEC / HZ);
#elif HZ > USEC_PER_SEC && !(HZ % USEC_PER_SEC)
	return u * (HZ / USEC_PER_SEC);
#else
	return (u * HZ + USEC_PER_SEC - 1) / USEC_PER_SEC;
#endif
}
#endif /* BCM_HAS_USECS_TO_JIFFIES */

#ifndef BCM_HAS_MSECS_TO_JIFFIES
static unsigned long msecs_to_jiffies(const unsigned int m)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	/*
	 * HZ is equal to or smaller than 1000, and 1000 is a nice
	 * round multiple of HZ, divide with the factor between them,
	 * but round upwards:
	 */
	return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	/*
	 * HZ is larger than 1000, and HZ is a nice round multiple of
	 * 1000 - simply multiply with the factor between them.
	 *
	 * But first make sure the multiplication result cannot
	 * overflow:
	 */
	if (m > jiffies_to_msecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;

	return m * (HZ / MSEC_PER_SEC);
#else
	/*
	 * Generic case - multiply, round and divide. But first
	 * check that if we are doing a net multiplication, that
	 * we wouldn't overflow:
	 */
	if (HZ > MSEC_PER_SEC && m > jiffies_to_msecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;

	return (m * HZ + MSEC_PER_SEC - 1) / MSEC_PER_SEC;
#endif
}
#endif /* BCM_HAS_MSECS_TO_JIFFIES */

#ifndef BCM_HAS_MSLEEP
static void msleep(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout) {
		__set_current_state(TASK_UNINTERRUPTIBLE);
		timeout = schedule_timeout(timeout);
	}
}
#endif /* BCM_HAS_MSLEEP */

#ifndef BCM_HAS_MSLEEP_INTERRUPTIBLE
static unsigned long msleep_interruptible(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout) {
		__set_current_state(TASK_UNINTERRUPTIBLE);
		timeout = schedule_timeout(timeout);
	}

	return 0;
}
#endif /* BCM_HAS_MSLEEP_INTERRUPTIBLE */

#ifndef printk_once
#define printk_once(x...) ({			\
	static bool tg3___print_once = false;	\
						\
	if (!tg3___print_once) {		\
		tg3___print_once = true;	\
		printk(x);			\
	}					\
})
#endif

#if !defined(BCM_HAS_DEV_DRIVER_STRING) || defined(__VMKLNX__)
#define dev_driver_string(dev)	"tg3"
#endif

#if !defined(BCM_HAS_DEV_NAME) || defined(__VMKLNX__)
#define dev_name(dev)			""
#endif

#if defined(dev_printk) && ((LINUX_VERSION_CODE < 0x020609) || defined(__VMKLNX__))
/*
 * SLES 9 and VMWare do not populate the pdev->dev.bus_id string soon
 * enough for driver use during boot.  Use our own format instead.
 */
#undef dev_printk
#endif

#ifndef dev_printk
#define dev_printk(level, dev, format, arg...)	\
	printk(level "%s %s: " format , dev_driver_string(dev) , \
	       dev_name(dev) , ## arg)
#endif

#ifndef dev_err
#define dev_err(dev, format, arg...)		\
	dev_printk(KERN_ERR , dev , format , ## arg)
#endif

#ifndef dev_warn
#define dev_warn(dev, format, arg...)		\
	dev_printk(KERN_WARNING , dev , format , ## arg)
#endif

#ifndef BCM_HAS_PCI_IOREMAP_BAR
static inline void * pci_ioremap_bar(struct pci_dev *pdev, int bar)
{
	resource_size_t base, size;

	if (!(pci_resource_flags(pdev, bar) & IORESOURCE_MEM)) {
		printk(KERN_ERR
		       "Cannot find proper PCI device base address for BAR %d.\n",
		       bar);
		return NULL;
	}

	base = pci_resource_start(pdev, bar);
	size = pci_resource_len(pdev, bar);

	return ioremap_nocache(base, size);
}
#endif

#ifndef DEFINE_PCI_DEVICE_TABLE
#define DEFINE_PCI_DEVICE_TABLE(x) struct pci_device_id x[]
#endif

#if (LINUX_VERSION_CODE < 0x020547)
#define pci_set_consistent_dma_mask(pdev, mask) (0)
#endif

#if (LINUX_VERSION_CODE < 0x020600)
#define pci_get_device(x, y, z)	pci_find_device(x, y, z)
#define pci_get_slot(x, y)	pci_find_slot((x)->number, y)
#define pci_dev_put(x)
#endif

#if (LINUX_VERSION_CODE < 0x020605)
#define pci_dma_sync_single_for_cpu(pdev, map, len, dir)	\
        pci_dma_sync_single(pdev, map, len, dir)
#define pci_dma_sync_single_for_device(pdev, map, len, dir)
#endif

#ifndef PCI_DEVICE
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5704S_2
#define PCI_DEVICE_ID_TIGON3_5704S_2	0x1649
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5705F
#define PCI_DEVICE_ID_TIGON3_5705F	0x166e
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5720
#define PCI_DEVICE_ID_TIGON3_5720	0x1658
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5721
#define PCI_DEVICE_ID_TIGON3_5721	0x1659
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5750
#define PCI_DEVICE_ID_TIGON3_5750	0x1676
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5751
#define PCI_DEVICE_ID_TIGON3_5751	0x1677
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5750M
#define PCI_DEVICE_ID_TIGON3_5750M	0x167c
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5751M
#define PCI_DEVICE_ID_TIGON3_5751M	0x167d
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5751F
#define PCI_DEVICE_ID_TIGON3_5751F	0x167e
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5789
#define PCI_DEVICE_ID_TIGON3_5789	0x169d
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5753
#define PCI_DEVICE_ID_TIGON3_5753	0x16f7
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5753M
#define PCI_DEVICE_ID_TIGON3_5753M	0x16fd
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5753F
#define PCI_DEVICE_ID_TIGON3_5753F	0x16fe
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5781
#define PCI_DEVICE_ID_TIGON3_5781	0x16dd
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5752
#define PCI_DEVICE_ID_TIGON3_5752	0x1600
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5752M
#define PCI_DEVICE_ID_TIGON3_5752M	0x1601
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5714
#define PCI_DEVICE_ID_TIGON3_5714	0x1668
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5714S
#define PCI_DEVICE_ID_TIGON3_5714S	0x1669
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5780
#define PCI_DEVICE_ID_TIGON3_5780	0x166a
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5780S
#define PCI_DEVICE_ID_TIGON3_5780S	0x166b
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5715
#define PCI_DEVICE_ID_TIGON3_5715	0x1678
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5715S
#define PCI_DEVICE_ID_TIGON3_5715S	0x1679
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5756
#define PCI_DEVICE_ID_TIGON3_5756	0x1674
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5754
#define PCI_DEVICE_ID_TIGON3_5754	0x167a
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5754M
#define PCI_DEVICE_ID_TIGON3_5754M	0x1672
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5755
#define PCI_DEVICE_ID_TIGON3_5755	0x167b
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5755M
#define PCI_DEVICE_ID_TIGON3_5755M	0x1673
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5722
#define PCI_DEVICE_ID_TIGON3_5722	0x165a
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5786
#define PCI_DEVICE_ID_TIGON3_5786	0x169a
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5787M
#define PCI_DEVICE_ID_TIGON3_5787M	0x1693
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5787
#define PCI_DEVICE_ID_TIGON3_5787	0x169b
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5787F
#define PCI_DEVICE_ID_TIGON3_5787F	0x167f
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5906
#define PCI_DEVICE_ID_TIGON3_5906	0x1712
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5906M
#define PCI_DEVICE_ID_TIGON3_5906M	0x1713
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5784
#define PCI_DEVICE_ID_TIGON3_5784	0x1698
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5764
#define PCI_DEVICE_ID_TIGON3_5764	0x1684
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5723
#define PCI_DEVICE_ID_TIGON3_5723	0x165b
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5761
#define PCI_DEVICE_ID_TIGON3_5761	0x1681
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5761E
#define PCI_DEVICE_ID_TIGON3_5761E	0x1680
#endif

#ifndef PCI_DEVICE_ID_APPLE_TIGON3
#define PCI_DEVICE_ID_APPLE_TIGON3	0x1645
#endif

#ifndef PCI_DEVICE_ID_APPLE_UNI_N_PCI15
#define PCI_DEVICE_ID_APPLE_UNI_N_PCI15	0x002e
#endif

#ifndef PCI_DEVICE_ID_VIA_8385_0
#define PCI_DEVICE_ID_VIA_8385_0	0x3188
#endif

#ifndef PCI_DEVICE_ID_AMD_8131_BRIDGE
#define PCI_DEVICE_ID_AMD_8131_BRIDGE	0x7450
#endif

#ifndef PCI_DEVICE_ID_SERVERWORKS_EPB
#define PCI_DEVICE_ID_SERVERWORKS_EPB	0x0103
#endif

#ifndef PCI_VENDOR_ID_ARIMA
#define PCI_VENDOR_ID_ARIMA		0x161f
#endif

#ifndef PCI_DEVICE_ID_INTEL_PXH_0
#define PCI_DEVICE_ID_INTEL_PXH_0	0x0329
#endif

#ifndef PCI_DEVICE_ID_INTEL_PXH_1
#define PCI_DEVICE_ID_INTEL_PXH_1	0x032A
#endif

#ifndef PCI_D0
typedef u32 pm_message_t;
typedef u32 pci_power_t;
#define PCI_D0		0
#define PCI_D1		1
#define PCI_D2		2
#define PCI_D3hot	3
#endif

#ifndef PCI_D3cold
#define PCI_D3cold	4
#endif

#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK ((u64) 0xffffffffffffffffULL)
#endif

#ifndef DMA_40BIT_MASK
#define DMA_40BIT_MASK ((u64) 0x000000ffffffffffULL)
#endif

#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK ((u64) 0x00000000ffffffffULL)
#endif

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n)  DMA_ ##n ##BIT_MASK
#endif

#ifndef DEFINE_DMA_UNMAP_ADDR
#define DEFINE_DMA_UNMAP_ADDR	DECLARE_PCI_UNMAP_ADDR
#endif

#if !defined(BCM_HAS_DMA_UNMAP_ADDR)
#define dma_unmap_addr		pci_unmap_addr
#endif

#if !defined(BCM_HAS_DMA_UNMAP_ADDR_SET)
#define dma_unmap_addr_set	pci_unmap_addr_set
#endif

#if !defined(BCM_HAS_PCI_TARGET_STATE) && !defined(BCM_HAS_PCI_CHOOSE_STATE)
static inline pci_power_t pci_choose_state(struct pci_dev *dev,
					   pm_message_t state)
{
	return state;
}
#endif

#ifndef BCM_HAS_PCI_ENABLE_WAKE
static int pci_enable_wake(struct pci_dev *dev, pci_power_t state, int enable)
{
	int pm_cap;
	u16 pmcsr;

	pm_cap = pci_find_capability(dev, PCI_CAP_ID_PM);
	if (pm_cap == 0)
		return -EIO;

	pci_read_config_word(dev, pm_cap + PCI_PM_CTRL, &pmcsr);

	/* Clear PME_Status by writing 1 to it */
	pmcsr |= PCI_PM_CTRL_PME_STATUS;

	if (enable)
		pmcsr |= PCI_PM_CTRL_PME_ENABLE;
	else
		pmcsr &= ~PCI_PM_CTRL_PME_ENABLE;

	pci_write_config_word(dev, pm_cap + PCI_PM_CTRL, pmcsr);

	return 0;
}
#endif /* BCM_HAS_PCI_ENABLE_WAKE */

#ifndef BCM_HAS_PCI_WAKE_FROM_D3
#ifndef BCM_HAS_PCI_PME_CAPABLE
static bool pci_pme_capable(struct pci_dev *dev, pci_power_t state)
{
	int pm_cap;
	u16 caps;
	bool ret = false;

	pm_cap = pci_find_capability(dev, PCI_CAP_ID_PM);
	if (pm_cap == 0)
		goto done;

	pci_read_config_word(dev, pm_cap + PCI_PM_PMC, &caps);

	if (state == PCI_D3cold &&
		(caps & PCI_PM_CAP_PME_D3cold))
			ret = true;

done:
	return ret;
}
#endif /* BCM_HAS_PCI_PME_CAPABLE */

static int pci_wake_from_d3(struct pci_dev *dev, bool enable)
{
	return pci_pme_capable(dev, PCI_D3cold) ?
			pci_enable_wake(dev, PCI_D3cold, enable) :
			pci_enable_wake(dev, PCI_D3hot, enable);
}
#endif /* BCM_HAS_PCI_WAKE_FROM_D3 */

#ifndef BCM_HAS_PCI_SET_POWER_STATE
static int pci_set_power_state(struct pci_dev *dev, pci_power_t state)
{
	int pm_cap;
	u16 pmcsr;

	if (state < PCI_D0 || state > PCI_D3hot)
		return -EINVAL;

	pm_cap = pci_find_capability(dev, PCI_CAP_ID_PM);
	if (pm_cap == 0)
		return -EIO;

	pci_read_config_word(dev, pm_cap + PCI_PM_CTRL, &pmcsr);

	pmcsr &= ~(PCI_PM_CTRL_STATE_MASK);
	pmcsr |= state;

	pci_write_config_word(dev, pm_cap + PCI_PM_CTRL, pmcsr);

	msleep(10);

	return 0;
}
#endif /* BCM_HAS_PCI_SET_POWER_STATE */

#ifdef __VMKLNX__
/* VMWare disables CONFIG_PM in their kernel configs.
 * This renders WOL inop, because device_may_wakeup() always returns false.
 */
#undef BCM_HAS_DEVICE_WAKEUP_API
#endif

#ifndef BCM_HAS_DEVICE_WAKEUP_API
#undef device_init_wakeup
#define device_init_wakeup(dev, val)
#undef device_can_wakeup
#define device_can_wakeup(dev) 1
#undef device_set_wakeup_enable
#define device_set_wakeup_enable(dev, val)
#undef device_may_wakeup
#define device_may_wakeup(dev) 1
#endif /* BCM_HAS_DEVICE_WAKEUP_API */

#ifndef BCM_HAS_DEVICE_SET_WAKEUP_CAPABLE
#define device_set_wakeup_capable(dev, val)
#endif /* BCM_HAS_DEVICE_SET_WAKEUP_CAPABLE */


#ifndef PCI_X_CMD_READ_2K
#define  PCI_X_CMD_READ_2K		0x0008
#endif
#ifndef PCI_CAP_ID_EXP
#define PCI_CAP_ID_EXP 0x10
#endif
#ifndef PCI_EXP_LNKCTL
#define PCI_EXP_LNKCTL 16
#endif
#ifndef PCI_EXP_LNKCTL_CLKREQ_EN
#define PCI_EXP_LNKCTL_CLKREQ_EN 0x100
#endif

#ifndef PCI_EXP_DEVCTL_NOSNOOP_EN
#define PCI_EXP_DEVCTL_NOSNOOP_EN 0x0800
#endif

#ifndef PCI_EXP_DEVCTL_RELAX_EN
#define PCI_EXP_DEVCTL_RELAX_EN		0x0010
#endif

#ifndef PCI_EXP_DEVCTL_PAYLOAD
#define PCI_EXP_DEVCTL_PAYLOAD		0x00e0
#endif

#ifndef PCI_EXP_DEVSTA
#define PCI_EXP_DEVSTA          10
#define  PCI_EXP_DEVSTA_CED     0x01
#define  PCI_EXP_DEVSTA_NFED    0x02
#define  PCI_EXP_DEVSTA_FED     0x04
#define  PCI_EXP_DEVSTA_URD     0x08
#endif

#ifndef PCI_EXP_LNKSTA
#define PCI_EXP_LNKSTA		18
#endif

#ifndef PCI_EXP_LNKSTA_CLS
#define  PCI_EXP_LNKSTA_CLS	0x000f
#endif

#ifndef PCI_EXP_LNKSTA_CLS_2_5GB
#define  PCI_EXP_LNKSTA_CLS_2_5GB 0x01
#endif

#ifndef PCI_EXP_LNKSTA_CLS_5_0GB
#define  PCI_EXP_LNKSTA_CLS_5_0GB 0x02
#endif

#ifndef PCI_EXP_LNKSTA_NLW
#define  PCI_EXP_LNKSTA_NLW	0x03f0
#endif

#ifndef PCI_EXP_LNKSTA_NLW_SHIFT
#define  PCI_EXP_LNKSTA_NLW_SHIFT 4
#endif

#ifndef PCI_EXP_DEVCTL
#define PCI_EXP_DEVCTL		8
#endif
#ifndef PCI_EXP_DEVCTL_READRQ
#define PCI_EXP_DEVCTL_READRQ	0x7000
#endif

#ifndef BCM_HAS_PCIE_GET_READRQ
int pcie_get_readrq(struct pci_dev *dev)
{
	int ret, cap;
	u16 ctl;

	cap = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!cap) {
		ret = -EINVAL;
		goto out;
	}

	ret = pci_read_config_word(dev, cap + PCI_EXP_DEVCTL, &ctl);
	if (!ret)
		ret = 128 << ((ctl & PCI_EXP_DEVCTL_READRQ) >> 12);

out:
	return ret;
}
#endif /* BCM_HAS_PCIE_GET_READRQ */

#ifndef BCM_HAS_PCIE_SET_READRQ
static inline int pcie_set_readrq(struct pci_dev *dev, int rq)
{
	int cap, err = -EINVAL;
	u16 ctl, v;

	if (rq < 128 || rq > 4096 || (rq & (rq-1)))
		goto out;

	v = (ffs(rq) - 8) << 12;

	cap = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!cap)
		goto out;

	err = pci_read_config_word(dev, cap + PCI_EXP_DEVCTL, &ctl);
	if (err)
		goto out;

	if ((ctl & PCI_EXP_DEVCTL_READRQ) != v) {
		ctl &= ~PCI_EXP_DEVCTL_READRQ;
		ctl |= v;
		err = pci_write_config_dword(dev, cap + PCI_EXP_DEVCTL, ctl);
	}

out:
	return err;
}
#endif /* BCM_HAS_PCIE_SET_READRQ */

#ifndef BCM_HAS_PCI_READ_VPD
#if !defined(PCI_CAP_ID_VPD)
#define  PCI_CAP_ID_VPD		0x03
#endif
#if !defined(PCI_VPD_ADDR)
#define PCI_VPD_ADDR		2
#endif
#if !defined(PCI_VPD_DATA)
#define PCI_VPD_DATA		4
#endif
static inline ssize_t
pci_read_vpd(struct pci_dev *dev, loff_t pos, size_t count, u8 *buf)
{
	int i, vpd_cap;

	vpd_cap = pci_find_capability(dev, PCI_CAP_ID_VPD);
	if (!vpd_cap)
		return -ENODEV;

	for (i = 0; i < count; i += 4) {
		u32 tmp, j = 0;
		__le32 v;
		u16 tmp16;

		pci_write_config_word(dev, vpd_cap + PCI_VPD_ADDR, i);
		while (j++ < 100) {
			pci_read_config_word(dev, vpd_cap +
					     PCI_VPD_ADDR, &tmp16);
			if (tmp16 & 0x8000)
				break;
			msleep(1);
		}
		if (!(tmp16 & 0x8000))
			break;

		pci_read_config_dword(dev, vpd_cap + PCI_VPD_DATA, &tmp);
		v = cpu_to_le32(tmp);
		memcpy(&buf[i], &v, sizeof(v));
	}

	return i;
}
#endif /* BCM_HAS_PCI_READ_VPD */

#ifndef PCI_VPD_RO_KEYWORD_CHKSUM
#define PCI_VPD_RO_KEYWORD_CHKSUM	"RV"
#endif

#ifndef PCI_VPD_LRDT
#define PCI_VPD_LRDT			0x80	/* Large Resource Data Type */
#define PCI_VPD_LRDT_ID(x)		(x | PCI_VPD_LRDT)

/* Large Resource Data Type Tag Item Names */
#define PCI_VPD_LTIN_ID_STRING		0x02	/* Identifier String */
#define PCI_VPD_LTIN_RO_DATA		0x10	/* Read-Only Data */
#define PCI_VPD_LTIN_RW_DATA		0x11	/* Read-Write Data */

#define PCI_VPD_LRDT_ID_STRING		PCI_VPD_LRDT_ID(PCI_VPD_LTIN_ID_STRING)
#define PCI_VPD_LRDT_RO_DATA		PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RO_DATA)
#define PCI_VPD_LRDT_RW_DATA		PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RW_DATA)

/* Small Resource Data Type Tag Item Names */
#define PCI_VPD_STIN_END		0x78	/* End */

#define PCI_VPD_SRDT_END		PCI_VPD_STIN_END

#define PCI_VPD_SRDT_TIN_MASK		0x78
#define PCI_VPD_SRDT_LEN_MASK		0x07

#define PCI_VPD_LRDT_TAG_SIZE		3
#define PCI_VPD_SRDT_TAG_SIZE		1

#define PCI_VPD_INFO_FLD_HDR_SIZE	3

#define PCI_VPD_RO_KEYWORD_PARTNO	"PN"
#define PCI_VPD_RO_KEYWORD_MFR_ID	"MN"
#define PCI_VPD_RO_KEYWORD_VENDOR0	"V0"

/**
 * pci_vpd_lrdt_size - Extracts the Large Resource Data Type length
 * @lrdt: Pointer to the beginning of the Large Resource Data Type tag
 *
 * Returns the extracted Large Resource Data Type length.
 */
static inline u16 pci_vpd_lrdt_size(const u8 *lrdt)
{
	return (u16)lrdt[1] + ((u16)lrdt[2] << 8);
}

/**
 * pci_vpd_srdt_size - Extracts the Small Resource Data Type length
 * @lrdt: Pointer to the beginning of the Small Resource Data Type tag
 *
 * Returns the extracted Small Resource Data Type length.
 */
static inline u8 pci_vpd_srdt_size(const u8 *srdt)
{
	return (*srdt) & PCI_VPD_SRDT_LEN_MASK;
}

/**
 * pci_vpd_info_field_size - Extracts the information field length
 * @lrdt: Pointer to the beginning of an information field header
 *
 * Returns the extracted information field length.
 */
static inline u8 pci_vpd_info_field_size(const u8 *info_field)
{
	return info_field[2];
}

static int pci_vpd_find_tag(const u8 *buf, unsigned int off, unsigned int len, u8 rdt)
{
	int i;

	for (i = off; i < len; ) {
		u8 val = buf[i];

		if (val & PCI_VPD_LRDT) {
			/* Don't return success of the tag isn't complete */
			if (i + PCI_VPD_LRDT_TAG_SIZE > len)
				break;

			if (val == rdt)
				return i;

			i += PCI_VPD_LRDT_TAG_SIZE +
			     pci_vpd_lrdt_size(&buf[i]);
		} else {
			u8 tag = val & ~PCI_VPD_SRDT_LEN_MASK;

			if (tag == rdt)
				return i;

			if (tag == PCI_VPD_SRDT_END)
				break;

			i += PCI_VPD_SRDT_TAG_SIZE +
			     pci_vpd_srdt_size(&buf[i]);
		}
	}

	return -ENOENT;
}

static int pci_vpd_find_info_keyword(const u8 *buf, unsigned int off,
			      unsigned int len, const char *kw)
{
	int i;

	for (i = off; i + PCI_VPD_INFO_FLD_HDR_SIZE <= off + len;) {
		if (buf[i + 0] == kw[0] &&
		    buf[i + 1] == kw[1])
			return i;

		i += PCI_VPD_INFO_FLD_HDR_SIZE +
		     pci_vpd_info_field_size(&buf[i]);
	}

	return -ENOENT;
}
#endif

#ifndef BCM_HAS_INTX_MSI_WORKAROUND
static inline void tg3_enable_intx(struct pci_dev *pdev)
{
#if (LINUX_VERSION_CODE < 0x2060e)
	u16 pci_command;

	pci_read_config_word(pdev, PCI_COMMAND, &pci_command);
	if (pci_command & PCI_COMMAND_INTX_DISABLE)
		pci_write_config_word(pdev, PCI_COMMAND,
				      pci_command & ~PCI_COMMAND_INTX_DISABLE);
#else
	pci_intx(pdev, 1);
#endif
}
#endif /* BCM_HAS_INTX_MSI_WORKAROUND */


#if (LINUX_VERSION_CODE >= 0x20613) || \
    (defined(__VMKLNX__) && defined(__USE_COMPAT_LAYER_2_6_18_PLUS__))
#define BCM_HAS_NEW_IRQ_SIG
#endif

#if defined(INIT_DELAYED_WORK_DEFERRABLE) || \
    defined(INIT_DEFERRABLE_WORK) || \
    defined(INIT_WORK_NAR) || \
    (defined(__VMKLNX__) && defined(__USE_COMPAT_LAYER_2_6_18_PLUS__))
#define BCM_HAS_NEW_INIT_WORK
#endif

#ifndef ETH_FCS_LEN
#define ETH_FCS_LEN 4
#endif

#ifndef BCM_HAS_PRINT_MAC

#ifndef DECLARE_MAC_BUF
#define DECLARE_MAC_BUF(_mac) char _mac[18]
#endif

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

static char *print_mac(char * buf, const u8 *addr)
{
	sprintf(buf, MAC_FMT,
	        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}
#endif


#ifndef NET_IP_ALIGN
#define NET_IP_ALIGN 2
#endif


#if !defined(BCM_HAS_ETHTOOL_OP_SET_TX_IPV6_CSUM) && \
    !defined(BCM_HAS_ETHTOOL_OP_SET_TX_HW_CSUM)   && \
     defined(BCM_HAS_SET_TX_CSUM)
static int tg3_set_tx_hw_csum(struct net_device *dev, u32 data)
{
	if (data)
		dev->features |= NETIF_F_HW_CSUM;
	else
		dev->features &= ~NETIF_F_HW_CSUM;

	return 0;
}
#endif

#ifndef NETDEV_TX_OK
#define NETDEV_TX_OK 0
#endif

#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY 1
#endif

#ifndef NETDEV_TX_LOCKED
#define NETDEV_TX_LOCKED -1
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif

#ifndef NETIF_F_IPV6_CSUM
#define NETIF_F_IPV6_CSUM 16
#define BCM_NO_IPV6_CSUM  1
#endif

#ifndef NETIF_F_RXCSUM
#define NETIF_F_RXCSUM		(1 << 29)
#endif

#ifndef NETIF_F_GRO
#define NETIF_F_GRO			16384
#endif

#ifndef NETIF_F_LOOPBACK
#define NETIF_F_LOOPBACK	(1 << 31)
#endif

#ifdef NETIF_F_TSO
#ifndef NETIF_F_GSO
#define gso_size tso_size
#define gso_segs tso_segs
#endif
#ifndef NETIF_F_TSO6
#define NETIF_F_TSO6	0
#define BCM_NO_TSO6     1
#endif
#ifndef NETIF_F_TSO_ECN
#define NETIF_F_TSO_ECN 0
#endif

#ifndef NETIF_F_ALL_TSO
#define NETIF_F_ALL_TSO	(NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_TSO_ECN)
#endif

#ifndef BCM_HAS_SKB_TX_TIMESTAMP
#define skb_tx_timestamp(skb)
#endif

#if (LINUX_VERSION_CODE < 0x2060c)
static inline int skb_header_cloned(struct sk_buff *skb) { return 0; }
#endif

#ifndef BCM_HAS_SKB_TRANSPORT_OFFSET
static inline int skb_transport_offset(const struct sk_buff *skb)
{
	return (int) (skb->h.raw - skb->data);
}
#endif

#ifndef BCM_HAS_IP_HDR
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return skb->nh.iph;
}
#endif

#ifndef BCM_HAS_IP_HDRLEN
static inline unsigned int ip_hdrlen(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl * 4;
}
#endif

#ifndef BCM_HAS_TCP_HDR
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return skb->h.th;
}
#endif

#ifndef BCM_HAS_TCP_HDRLEN
static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return tcp_hdr(skb)->doff * 4;
}
#endif

#ifndef BCM_HAS_TCP_OPTLEN
static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}
#endif

#ifndef NETIF_F_GSO
static struct sk_buff *skb_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = NULL;
	struct sk_buff *tail = NULL;
	unsigned int mss = skb_shinfo(skb)->gso_size;
	unsigned int doffset = skb->data - skb->mac.raw;
	unsigned int offset = doffset;
	unsigned int headroom;
	unsigned int len;
	int nfrags = skb_shinfo(skb)->nr_frags;
	int err = -ENOMEM;
	int i = 0;
	int pos;

	__skb_push(skb, doffset);
	headroom = skb_headroom(skb);
	pos = skb_headlen(skb);

	do {
		struct sk_buff *nskb;
		skb_frag_t *frag;
		int hsize;
		int k;
		int size;

		len = skb->len - offset;
		if (len > mss)
			len = mss;

		hsize = skb_headlen(skb) - offset;
		if (hsize < 0)
			hsize = 0;
		if (hsize > len)
			hsize = len;

		nskb = alloc_skb(hsize + doffset + headroom, GFP_ATOMIC);
		if (unlikely(!nskb))
			goto err;

		if (segs)
			tail->next = nskb;
		else
			segs = nskb;
		tail = nskb;

		nskb->dev = skb->dev;
		nskb->priority = skb->priority;
		nskb->protocol = skb->protocol;
		nskb->dst = dst_clone(skb->dst);
		memcpy(nskb->cb, skb->cb, sizeof(skb->cb));
		nskb->pkt_type = skb->pkt_type;
		nskb->mac_len = skb->mac_len;

		skb_reserve(nskb, headroom);
		nskb->mac.raw = nskb->data;
		nskb->nh.raw = nskb->data + skb->mac_len;
		nskb->h.raw = nskb->nh.raw + (skb->h.raw - skb->nh.raw);
		memcpy(skb_put(nskb, doffset), skb->data, doffset);

		frag = skb_shinfo(nskb)->frags;
		k = 0;

		nskb->ip_summed = CHECKSUM_PARTIAL;
		nskb->csum = skb->csum;
		memcpy(skb_put(nskb, hsize), skb->data + offset, hsize);

		while (pos < offset + len) {
			BUG_ON(i >= nfrags);

			*frag = skb_shinfo(skb)->frags[i];
			get_page(frag->page);
			size = frag->size;

			if (pos < offset) {
				frag->page_offset += offset - pos;
				frag->size -= offset - pos;
			}

			k++;

			if (pos + size <= offset + len) {
				i++;
				pos += size;
			} else {
				frag->size -= pos + size - (offset + len);
				break;
			}

			frag++;
		}

		skb_shinfo(nskb)->nr_frags = k;
		nskb->data_len = len - hsize;
		nskb->len += nskb->data_len;
		nskb->truesize += nskb->data_len;
	} while ((offset += len) < skb->len);

	return segs;

err:
	while ((skb = segs)) {
		segs = skb->next;
		kfree(skb);
	}
	return ERR_PTR(err);
}

static struct sk_buff *tcp_tso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct tcphdr *th;
	unsigned thlen;
	unsigned int seq;
	u32 delta;
	unsigned int oldlen;
	unsigned int len;

	if (!pskb_may_pull(skb, sizeof(*th)))
		goto out;

	th = skb->h.th;
	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	if (!pskb_may_pull(skb, thlen))
		goto out;

	oldlen = (u16)~skb->len;
	__skb_pull(skb, thlen);

	segs = skb_segment(skb, features);
	if (IS_ERR(segs))
		goto out;

	len = skb_shinfo(skb)->gso_size;
	delta = htonl(oldlen + (thlen + len));

	skb = segs;
	th = skb->h.th;
	seq = ntohl(th->seq);

	do {
		th->fin = th->psh = 0;

		th->check = ~csum_fold((u32)((u32)th->check +
				       (u32)delta));
		seq += len;
		skb = skb->next;
		th = skb->h.th;

		th->seq = htonl(seq);
		th->cwr = 0;
	} while (skb->next);

	delta = htonl(oldlen + (skb->tail - skb->h.raw) + skb->data_len);
	th->check = ~csum_fold((u32)((u32)th->check +
				(u32)delta));
out:
	return segs;
}

static struct sk_buff *inet_gso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct iphdr *iph;
	int ihl;
	int id;

	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
		goto out;

	iph = skb->nh.iph;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		goto out;

	if (unlikely(!pskb_may_pull(skb, ihl)))
		goto out;

	skb->h.raw = __skb_pull(skb, ihl);
	iph = skb->nh.iph;
	id = ntohs(iph->id);
	segs = ERR_PTR(-EPROTONOSUPPORT);

	segs = tcp_tso_segment(skb, features);

	if (!segs || IS_ERR(segs))
		goto out;

	skb = segs;
	do {
		iph = skb->nh.iph;
		iph->id = htons(id++);
		iph->tot_len = htons(skb->len - skb->mac_len);
		iph->check = 0;
		iph->check = ip_fast_csum(skb->nh.raw, iph->ihl);
	} while ((skb = skb->next));

out:
	return segs;
}

static struct sk_buff *skb_gso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EPROTONOSUPPORT);

	skb->mac.raw = skb->data;
	skb->mac_len = skb->nh.raw - skb->data;
	__skb_pull(skb, skb->mac_len);

	segs = inet_gso_segment(skb, features);

	__skb_push(skb, skb->data - skb->mac.raw);
	return segs;
}
#endif /* NETIF_F_GSO */

#endif /* NETIF_F_TSO */

#ifndef BCM_HAS_SKB_COPY_FROM_LINEAR_DATA
static inline void skb_copy_from_linear_data(const struct sk_buff *skb,
					     void *to,
					     const unsigned int len)
{
	memcpy(to, skb->data, len);
}
#endif

#if TG3_TSO_SUPPORT != 0
#if defined(BCM_NO_TSO6)
static inline int skb_is_gso_v6(const struct sk_buff *skb)
{
	return 0;
}
#else
#if !defined(BCM_HAS_SKB_IS_GSO_V6)
static inline int skb_is_gso_v6(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6;
}
#endif
#endif
#endif

#ifndef BCM_HAS_SKB_CHECKSUM_NONE_ASSERT
static inline void skb_checksum_none_assert(struct sk_buff *skb)
{
	skb->ip_summed = CHECKSUM_NONE;
}
#endif

#ifndef BCM_HAS_NETDEV_TX_T
typedef int	netdev_tx_t;
#endif

#ifndef BCM_HAS_NETDEV_FEATURES_T
typedef u64 netdev_features_t;
#endif

#ifndef BCM_HAS_NETDEV_NAME
#define netdev_name(netdev)	netdev->name
#endif

#if defined(netdev_printk) && (LINUX_VERSION_CODE < 0x020609)
/* SLES 9.X provides their own print routines, but they are not compatible
 * with the versions found in the latest upstream kernel.  The kernel
 * version check above was picked out of the air as a value greater than
 * 2.6.5-7.308, but any number that preserves this boundary should be
 * acceptable.
 */
#undef netdev_printk
#undef netdev_info
#undef netdev_err
#undef netdev_warn
#endif

#ifndef netdev_printk
#define netdev_printk(level, netdev, format, args...)	\
	dev_printk(level, tp->pdev->dev.parent,	\
		   "%s: " format,			\
		   netdev_name(tp->dev), ##args)
#endif

#ifndef netif_printk
#define netif_printk(priv, type, level, dev, fmt, args...)	\
do {								\
	if (netif_msg_##type(priv))				\
		netdev_printk(level, (dev), fmt, ##args);	\
} while (0)
#endif

#ifndef netif_info
#define netif_info(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_INFO, (dev), fmt, ##args)
#endif

#ifndef netdev_err
#define netdev_err(dev, format, args...)			\
	netdev_printk(KERN_ERR, dev, format, ##args)
#endif

#ifndef netdev_warn
#define netdev_warn(dev, format, args...)			\
	netdev_printk(KERN_WARNING, dev, format, ##args)
#endif

#ifndef netdev_notice
#define netdev_notice(dev, format, args...)			\
	netdev_printk(KERN_NOTICE, dev, format, ##args)
#endif

#ifndef netdev_info
#define netdev_info(dev, format, args...)			\
	netdev_printk(KERN_INFO, dev, format, ##args)
#endif

#ifndef BCM_HAS_NETIF_TX_LOCK
static inline void netif_tx_lock(struct net_device *dev)
{
	spin_lock(&dev->xmit_lock);
	dev->xmit_lock_owner = smp_processor_id();
}

static inline void netif_tx_unlock(struct net_device *dev)
{
	dev->xmit_lock_owner = -1;
	spin_unlock(&dev->xmit_lock);
}
#endif /* BCM_HAS_NETIF_TX_LOCK */

#if defined(BCM_HAS_STRUCT_NETDEV_QUEUE) || \
    (defined(__VMKLNX__) && defined(__USE_COMPAT_LAYER_2_6_18_PLUS__))

#define TG3_NAPI
#define tg3_netif_rx_complete(dev, napi)	napi_complete((napi))
#define tg3_netif_rx_schedule(dev, napi)	napi_schedule((napi))
#define tg3_netif_rx_schedule_prep(dev, napi)	napi_schedule_prep((napi))

#else  /* BCM_HAS_STRUCT_NETDEV_QUEUE */

#define netdev_queue	net_device
#define netdev_get_tx_queue(dev, i)		(dev)
#define netif_tx_start_queue(dev)		netif_start_queue((dev))
#define netif_tx_start_all_queues(dev)		netif_start_queue((dev))
#define netif_tx_stop_queue(dev)		netif_stop_queue((dev))
#define netif_tx_stop_all_queues(dev)		netif_stop_queue((dev))
#define netif_tx_queue_stopped(dev)		netif_queue_stopped((dev))
#define netif_tx_wake_queue(dev)		netif_wake_queue((dev))
#define netif_tx_wake_all_queues(dev)		netif_wake_queue((dev))
#define __netif_tx_lock(txq, procid)		netif_tx_lock((txq))
#define __netif_tx_unlock(txq)			netif_tx_unlock((txq))

#if defined(BCM_HAS_NEW_NETIF_INTERFACE)
#define TG3_NAPI
#define tg3_netif_rx_complete(dev, napi)	netif_rx_complete((dev), (napi))
#define tg3_netif_rx_schedule(dev, napi)	netif_rx_schedule((dev), (napi))
#define tg3_netif_rx_schedule_prep(dev, napi)	netif_rx_schedule_prep((dev), (napi))
#else  /* BCM_HAS_NEW_NETIF_INTERFACE */
#define tg3_netif_rx_complete(dev, napi)	netif_rx_complete((dev))
#define tg3_netif_rx_schedule(dev, napi)	netif_rx_schedule((dev))
#define tg3_netif_rx_schedule_prep(dev, napi)	netif_rx_schedule_prep((dev))
#endif /* BCM_HAS_NEW_NETIF_INTERFACE */

#endif /* BCM_HAS_STRUCT_NETDEV_QUEUE */

#if !defined(BCM_HAS_ALLOC_ETHERDEV_MQ) || !defined(TG3_NAPI)
#define alloc_etherdev_mq(size, numqs)		alloc_etherdev((size))
#endif

#if !defined(TG3_NAPI) || !defined(BCM_HAS_VLAN_GRO_RECEIVE)
#define vlan_gro_receive(nap, grp, tag, skb) \
        vlan_hwaccel_receive_skb((skb), (grp), (tag))
#endif

#if !defined(TG3_NAPI) || !defined(BCM_HAS_NAPI_GRO_RECEIVE)
#define napi_gro_receive(nap, skb) \
        netif_receive_skb((skb))
#endif

#if !defined(BCM_HAS_SKB_GET_QUEUE_MAPPING) || !defined(TG3_NAPI)
#define skb_get_queue_mapping(skb)		0
#endif

#ifdef TG3_NAPI
#if (LINUX_VERSION_CODE < 0x02061b) && !defined(__VMKLNX__)

static inline void netif_napi_del(struct napi_struct *napi)
{
#ifdef CONFIG_NETPOLL
	list_del(&napi->dev_list);
#endif
}
#endif

#endif
#if (LINUX_VERSION_CODE < 0x020612)
static inline struct sk_buff *netdev_alloc_skb(struct net_device *dev,
		unsigned int length)
{
	struct sk_buff *skb = dev_alloc_skb(length);
	if (skb)
		skb->dev = dev;
	return skb;
}
#endif

#ifndef BCM_HAS_NETDEV_PRIV
static inline void *netdev_priv(struct net_device *dev)
{
	return dev->priv;
}
#endif

#ifdef OLD_NETIF
static inline void netif_poll_disable(struct net_device *dev)
{
	while (test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state)) {
		/* No hurry. */
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
	}
}

static inline void netif_poll_enable(struct net_device *dev)
{
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

static inline void netif_tx_disable(struct net_device *dev)
{
	spin_lock_bh(&dev->xmit_lock);
	netif_stop_queue(dev);
	spin_unlock_bh(&dev->xmit_lock);
}
#endif /* OLD_NETIF */

#ifndef BCM_HAS_NETDEV_SENT_QUEUE
#define netdev_sent_queue(dev, bytes)
#endif

#ifndef BCM_HAS_NETDEV_TX_SENT_QUEUE
#define netdev_tx_sent_queue(q, bytes) \
	netdev_sent_queue(tp->dev, bytes)
#endif

#ifndef BCM_HAS_NETDEV_COMPLETED_QUEUE
#define netdev_completed_queue(dev, pkts, bytes)
#endif

#ifndef BCM_HAS_NETDEV_TX_COMPLETED_QUEUE
#define netdev_tx_completed_queue(q, pkt_cnt, byte_cnt) \
	netdev_completed_queue(tp->dev, pkt_cnt, byte_cnt)
#endif

#ifndef BCM_HAS_NETDEV_RESET_QUEUE
#define netdev_reset_queue(dev_queue)
#endif

#ifndef BCM_HAS_NETDEV_TX_RESET_QUEUE
#define netdev_tx_reset_queue(q) \
	netdev_reset_queue(tp->dev)
#endif

#ifndef BCM_HAS_NETIF_SET_REAL_NUM_TX_QUEUES
#define netif_set_real_num_tx_queues(dev, nq)	((dev)->real_num_tx_queues = (nq))
#endif

#ifndef BCM_HAS_NETIF_SET_REAL_NUM_RX_QUEUES
#define netif_set_real_num_rx_queues(dev, nq)	0
#endif

#ifndef netdev_mc_count
#define netdev_mc_count(dev) ((dev)->mc_count)
#endif

#ifndef netdev_mc_empty
#define netdev_mc_empty(dev) (netdev_mc_count(dev) == 0)
#endif

/*
 * Commit ID 22bedad3ce112d5ca1eaf043d4990fa2ed698c87 is the patch that
 * undefines dmi_addr and pivots the code to use netdev_hw_addr rather
 * than dev_mc_list.  Commit ID 6683ece36e3531fc8c75f69e7165c5f20930be88
 * is the patch that introduces netdev_for_each_mc_addr.  Commit ID
 * f001fde5eadd915f4858d22ed70d7040f48767cf is the patch that introduces
 * netdev_hw_addr.  These features are presented in reverse chronological
 * order.
 */
#ifdef BCM_HAS_NETDEV_HW_ADDR
#ifdef dmi_addr
#undef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(ha, dev) \
	struct dev_mc_list * oldmclist; \
	struct netdev_hw_addr foo; \
	ha = &foo; \
    for (oldmclist = dev->mc_list; oldmclist && memcpy(foo.addr, oldmclist->dmi_addr, 6); oldmclist = oldmclist->next)
#endif
#else /* BCM_HAS_NETDEV_HW_ADDR */
struct netdev_hw_addr {
	u8 * addr;
	struct dev_mc_list * curr;
};
#undef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(ha, dev) \
	struct netdev_hw_addr mclist; \
	ha = &mclist; \
    for (mclist.curr = dev->mc_list; mclist.curr && (mclist.addr = &mclist.curr->dmi_addr[0]); mclist.curr = mclist.curr->next)
#endif /* BCM_HAS_NETDEV_HW_ADDR */

#ifndef BCM_HAS_GET_STATS64
#define rtnl_link_stats64	net_device_stats
#endif /* BCM_HAS_GET_STATS64 */

#ifndef BCM_HAS_EXTERNAL_LB_DONE
#define ETH_TEST_FL_EXTERNAL_LB		(1 << 2)
#define ETH_TEST_FL_EXTERNAL_LB_DONE	(1 << 3)
#endif

#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
#define BCM_KERNEL_SUPPORTS_8021Q
#endif

#ifndef ETH_SS_TEST
#define ETH_SS_TEST  0
#endif
#ifndef ETH_SS_STATS
#define ETH_SS_STATS 1
#endif
#ifndef ADVERTISED_Pause
#define ADVERTISED_Pause		(1 << 13)
#endif
#ifndef ADVERTISED_Asym_Pause
#define ADVERTISED_Asym_Pause		(1 << 14)
#endif

#ifndef MII_CTRL1000
#define MII_CTRL1000			0x09
#endif
#ifndef ADVERTISE_1000HALF
#define ADVERTISE_1000HALF		0x0100
#endif
#ifndef ADVERTISE_1000FULL
#define ADVERTISE_1000FULL		0x0200
#endif
#ifndef CTL1000_AS_MASTER
#define CTL1000_AS_MASTER		0x0800
#endif
#ifndef CTL1000_ENABLE_MASTER
#define CTL1000_ENABLE_MASTER		0x1000
#endif
#ifndef MII_STAT1000
#define MII_STAT1000			0x0a
#endif
#ifndef BMCR_SPEED1000
#define BMCR_SPEED1000			0x0040
#endif
#ifndef ADVERTISE_1000XFULL
#define ADVERTISE_1000XFULL		0x0020
#endif
#ifndef ADVERTISE_1000XHALF
#define ADVERTISE_1000XHALF		0x0040
#endif
#ifndef ADVERTISE_1000XPAUSE
#define ADVERTISE_1000XPAUSE		0x0080
#endif
#ifndef ADVERTISE_1000XPSE_ASYM
#define ADVERTISE_1000XPSE_ASYM		0x0100
#endif
#ifndef ADVERTISE_PAUSE
#define ADVERTISE_PAUSE_CAP		0x0400
#endif
#ifndef ADVERTISE_PAUSE_ASYM
#define ADVERTISE_PAUSE_ASYM		0x0800
#endif
#ifndef LPA_1000XFULL
#define LPA_1000XFULL			0x0020
#endif
#ifndef LPA_1000XHALF
#define LPA_1000XHALF			0x0040
#endif
#ifndef LPA_1000XPAUSE
#define LPA_1000XPAUSE			0x0080
#endif
#ifndef LPA_1000XPAUSE_ASYM
#define LPA_1000XPAUSE_ASYM		0x0100
#endif
#ifndef LPA_PAUSE
#define LPA_PAUSE_CAP			0x0400
#endif
#ifndef LPA_PAUSE_ASYM
#define LPA_PAUSE_ASYM			0x0800
#endif
#ifndef LPA_1000FULL
#define LPA_1000FULL			0x0800
#endif
#ifndef LPA_1000HALF
#define LPA_1000HALF			0x0400
#endif

#ifndef ETHTOOL_FWVERS_LEN
#define ETHTOOL_FWVERS_LEN 32
#endif

#ifndef MDIO_MMD_AN
#define MDIO_MMD_AN			7
#endif

#ifndef MDIO_AN_EEE_ADV
#define MDIO_AN_EEE_ADV			60
#endif

#ifndef MDIO_AN_EEE_ADV_100TX
#define MDIO_AN_EEE_ADV_100TX		0x0002
#endif

#ifndef MDIO_AN_EEE_ADV_1000T
#define MDIO_AN_EEE_ADV_1000T		0x0004
#endif

#ifndef SPEED_UNKNOWN
#define SPEED_UNKNOWN			-1
#endif

#ifndef DUPLEX_UNKNOWN
#define DUPLEX_UNKNOWN			0xff
#endif

#ifndef BCM_HAS_ETHTOOL_ADV_TO_MII_ADV_T
static inline u32 ethtool_adv_to_mii_adv_t(u32 ethadv)
{
	u32 result = 0;

	if (ethadv & ADVERTISED_10baseT_Half)
		result |= ADVERTISE_10HALF;
	if (ethadv & ADVERTISED_10baseT_Full)
		result |= ADVERTISE_10FULL;
	if (ethadv & ADVERTISED_100baseT_Half)
		result |= ADVERTISE_100HALF;
	if (ethadv & ADVERTISED_100baseT_Full)
		result |= ADVERTISE_100FULL;
	if (ethadv & ADVERTISED_Pause)
		result |= ADVERTISE_PAUSE_CAP;
	if (ethadv & ADVERTISED_Asym_Pause)
		result |= ADVERTISE_PAUSE_ASYM;

	return result;
}

static inline u32 mii_adv_to_ethtool_adv_t(u32 adv)
{
	u32 result = 0;

	if (adv & ADVERTISE_10HALF)
		result |= ADVERTISED_10baseT_Half;
	if (adv & ADVERTISE_10FULL)
		result |= ADVERTISED_10baseT_Full;
	if (adv & ADVERTISE_100HALF)
		result |= ADVERTISED_100baseT_Half;
	if (adv & ADVERTISE_100FULL)
		result |= ADVERTISED_100baseT_Full;
	if (adv & ADVERTISE_PAUSE_CAP)
		result |= ADVERTISED_Pause;
	if (adv & ADVERTISE_PAUSE_ASYM)
		result |= ADVERTISED_Asym_Pause;

	return result;
}

static inline u32 ethtool_adv_to_mii_ctrl1000_t(u32 ethadv)
{
	u32 result = 0;

	if (ethadv & ADVERTISED_1000baseT_Half)
		result |= ADVERTISE_1000HALF;
	if (ethadv & ADVERTISED_1000baseT_Full)
		result |= ADVERTISE_1000FULL;

	return result;
}

static inline u32 mii_ctrl1000_to_ethtool_adv_t(u32 adv)
{
	u32 result = 0;

	if (adv & ADVERTISE_1000HALF)
		result |= ADVERTISED_1000baseT_Half;
	if (adv & ADVERTISE_1000FULL)
		result |= ADVERTISED_1000baseT_Full;

	return result;
}

static inline u32 mii_lpa_to_ethtool_lpa_t(u32 lpa)
{
	u32 result = 0;

	if (lpa & LPA_LPACK)
		result |= ADVERTISED_Autoneg;

	return result | mii_adv_to_ethtool_adv_t(lpa);
}

static inline u32 mii_stat1000_to_ethtool_lpa_t(u32 lpa)
{
	u32 result = 0;

	if (lpa & LPA_1000HALF)
		result |= ADVERTISED_1000baseT_Half;
	if (lpa & LPA_1000FULL)
		result |= ADVERTISED_1000baseT_Full;

	return result;
}

static inline u32 ethtool_adv_to_mii_adv_x(u32 ethadv)
{
	u32 result = 0;

	if (ethadv & ADVERTISED_1000baseT_Half)
		result |= ADVERTISE_1000XHALF;
	if (ethadv & ADVERTISED_1000baseT_Full)
		result |= ADVERTISE_1000XFULL;
	if (ethadv & ADVERTISED_Pause)
		result |= ADVERTISE_1000XPAUSE;
	if (ethadv & ADVERTISED_Asym_Pause)
		result |= ADVERTISE_1000XPSE_ASYM;

	return result;
}

static inline u32 mii_adv_to_ethtool_adv_x(u32 adv)
{
	u32 result = 0;

	if (adv & ADVERTISE_1000XHALF)
		result |= ADVERTISED_1000baseT_Half;
	if (adv & ADVERTISE_1000XFULL)
		result |= ADVERTISED_1000baseT_Full;
	if (adv & ADVERTISE_1000XPAUSE)
		result |= ADVERTISED_Pause;
	if (adv & ADVERTISE_1000XPSE_ASYM)
		result |= ADVERTISED_Asym_Pause;

	return result;
}

static inline u32 mii_lpa_to_ethtool_lpa_x(u32 lpa)
{
	u32 result = 0;

	if (lpa & LPA_LPACK)
		result |= ADVERTISED_Autoneg;

	return result | mii_adv_to_ethtool_adv_x(lpa);
}
#endif /* BCM_HAS_ETHTOOL_ADV_TO_MII_100BT */

#ifndef BCM_HAS_ETHTOOL_RXFH_INDIR_DEFAULT
static inline u32 ethtool_rxfh_indir_default(u32 index, u32 n_rx_rings)
{
	return index % n_rx_rings;
}
#endif /* BCM_HAS_ETHTOOL_RXFH_INDIR_DEFAULT */

#ifndef BCM_HAS_MII_RESOLVE_FLOWCTRL_FDX
#ifndef FLOW_CTRL_TX
#define FLOW_CTRL_TX	0x01
#endif
#ifndef FLOW_CTRL_RX
#define FLOW_CTRL_RX	0x02
#endif
static u8 mii_resolve_flowctrl_fdx(u16 lcladv, u16 rmtadv)
{
	u8 cap = 0;

	if (lcladv & rmtadv & ADVERTISE_PAUSE_CAP) {
		cap = FLOW_CTRL_TX | FLOW_CTRL_RX;
	} else if (lcladv & ADVERTISE_PAUSE_ASYM) {
		if (lcladv & LPA_PAUSE_CAP)
			cap = FLOW_CTRL_RX;
		if (rmtadv & LPA_PAUSE_CAP)
			cap = FLOW_CTRL_TX;
	}

	return cap;
}
#endif /* BCM_HAS_MII_RESOLVE_FLOWCTRL_FDX */

#ifndef BCM_HAS_MII_ADVERTISE_FLOWCTRL
static u16 mii_advertise_flowctrl(u8 flow_ctrl)
{
	u16 miireg;

	if ((flow_ctrl & FLOW_CTRL_TX) && (flow_ctrl & FLOW_CTRL_RX))
		miireg = ADVERTISE_PAUSE_CAP;
	else if (flow_ctrl & FLOW_CTRL_TX)
		miireg = ADVERTISE_PAUSE_ASYM;
	else if (flow_ctrl & FLOW_CTRL_RX)
		miireg = ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;
	else
		miireg = 0;

	return miireg;
}
#endif /* BCM_HAS_MII_ADVERTISE_FLOWCTRL */

#ifdef BCM_INCLUDE_PHYLIB_SUPPORT

#ifndef PHY_ID_BCM50610
#define PHY_ID_BCM50610			0x0143bd60
#endif
#ifndef PHY_ID_BCM50610M
#define PHY_ID_BCM50610M		0x0143bd70
#endif
#ifndef PHY_ID_BCM50612E
#define PHY_ID_BCM50612E		0x03625e20
#endif
#ifndef PHY_ID_BCMAC131
#define PHY_ID_BCMAC131			0x0143bc70
#endif
#ifndef PHY_ID_BCM57780
#define PHY_ID_BCM57780			0x03625d90
#endif
#ifndef PHY_BCM_OUI_MASK
#define PHY_BCM_OUI_MASK		0xfffffc00
#endif
#ifndef PHY_BCM_OUI_1
#define PHY_BCM_OUI_1			0x00206000
#endif
#ifndef PHY_BCM_OUI_2
#define PHY_BCM_OUI_2			0x0143bc00
#endif
#ifndef PHY_BCM_OUI_3
#define PHY_BCM_OUI_3			0x03625c00
#endif

#ifndef PHY_BRCM_STD_IBND_DISABLE
#define PHY_BRCM_STD_IBND_DISABLE	0x00000800
#define PHY_BRCM_EXT_IBND_RX_ENABLE	0x00001000
#define PHY_BRCM_EXT_IBND_TX_ENABLE	0x00002000
#endif

#ifndef PHY_BRCM_RX_REFCLK_UNUSED
#define PHY_BRCM_RX_REFCLK_UNUSED	0x00000400
#endif

#ifndef PHY_BRCM_CLEAR_RGMII_MODE
#define PHY_BRCM_CLEAR_RGMII_MODE	0x00004000
#endif

#ifndef PHY_BRCM_DIS_TXCRXC_NOENRGY
#define PHY_BRCM_DIS_TXCRXC_NOENRGY	0x00008000
#endif

#ifndef BCM_HAS_MDIOBUS_ALLOC
static struct mii_bus *mdiobus_alloc(void)
{
	struct mii_bus *bus;

	bus = kzalloc(sizeof(*bus), GFP_KERNEL);

	return bus;
}

void mdiobus_free(struct mii_bus *bus)
{
	kfree(bus);
}
#endif

#endif /* BCM_INCLUDE_PHYLIB_SUPPORT */

#ifndef BCM_HAS_ETHTOOL_CMD_SPEED
static inline __u32 ethtool_cmd_speed(struct ethtool_cmd *ep)
{
	return ep->speed;
}
#endif /* BCM_HAS_ETHTOOL_CMD_SPEED */

#ifndef BCM_HAS_ETHTOOL_CMD_SPEED_SET
static inline __u32 ethtool_cmd_speed_set(struct ethtool_cmd *ep, __u32 speed)
{
	ep->speed = speed;
	return 0;
}
#endif /* BCM_HAS_ETHTOOL_CMD_SPEED_SET */
