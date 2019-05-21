#ifndef _LINUX_PCI_H
#define _LINUX_PCI_H

#include <linux/mlx5/compat/config.h>

#include <linux/version.h>
#include_next <linux/pci.h>
#include <linux/pci.h>

#ifndef HAVE_PCI_PHYSFN
#define pci_physfn LINUX_BACKPORT(pci_physfn)
static inline struct pci_dev *pci_physfn(struct pci_dev *dev)
{
#ifdef CONFIG_PCI_IOV
	if (dev->is_virtfn)
		dev = dev->physfn;
#endif
	return dev;
}
#endif /* HAVE_PCI_PHYSFN */

#ifndef HAVE_PCI_NUM_VF
#define pci_num_vf LINUX_BACKPORT(pci_num_vf)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18))
int pci_num_vf(struct pci_dev *pdev);
#else
static inline int pci_num_vf(struct pci_dev *pdev)
{
	return 0;
}
#endif
#endif

#ifndef HAVE_PCI_VFS_ASSIGNED
#define pci_vfs_assigned LINUX_BACKPORT(pci_vfs_assigned)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18))
int pci_vfs_assigned(struct pci_dev *pdev);
#else
static inline int pci_vfs_assigned(struct pci_dev *pdev)
{
	return 0;
}
#endif
#endif

#ifndef HAVE_PCI_SRIOV_GET_TOTALVFS
#define pci_sriov_get_totalvfs LINUX_BACKPORT(pci_sriov_get_totalvfs)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18))
int pci_sriov_get_totalvfs(struct pci_dev *pdev);
#else
static inline int pci_sriov_get_totalvfs(struct pci_dev *pdev)
{
	return 0;
}
#endif
#endif

#ifndef HAVE_PCI_IRQ_GET_AFFINITY
static inline const struct cpumask *pci_irq_get_affinity(struct pci_dev *pdev,
							 int vec)
{
	return cpu_possible_mask;
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)) || \
    (defined(RHEL_MAJOR) && RHEL_MAJOR -0 == 7 && RHEL_MINOR -0 >= 2)
#ifndef HAVE_PCI_IRQ_GET_NODE
static inline int pci_irq_get_node(struct pci_dev *pdev, int vec)
{
#ifdef CONFIG_PCI_MSI
	const struct cpumask *mask;

	mask = pci_irq_get_affinity(pdev, vec);
	if (mask)
#ifdef CONFIG_HAVE_MEMORYLESS_NODES
		return local_memory_node(cpu_to_node(cpumask_first(mask)));
#else
		return cpu_to_node(cpumask_first(mask));
#endif
	return dev_to_node(&pdev->dev);
#else /* CONFIG_PCI_MSI */
	return first_online_node;
#endif /* CONFIG_PCI_MSI */
}
#endif /* pci_irq_get_node */
#endif

#ifdef CONFIG_PCI
#ifndef HAVE_PCI_REQUEST_MEM_REGIONS
static inline int
pci_request_mem_regions(struct pci_dev *pdev, const char *name)
{
	return pci_request_selected_regions(pdev,
			    pci_select_bars(pdev, IORESOURCE_MEM), name);
}
#endif

#ifndef HAVE_PCI_RELEASE_MEM_REGIONS
static inline void
pci_release_mem_regions(struct pci_dev *pdev)
{
	return pci_release_selected_regions(pdev,
			    pci_select_bars(pdev, IORESOURCE_MEM));
}
#endif
#endif /* CONFIG_PCI */

#ifndef HAVE_PCIE_LINK_WIDTH
/* These values come from the PCI Express Spec */
enum pcie_link_width {
	PCIE_LNK_WIDTH_RESRV	= 0x00,
	PCIE_LNK_X1		= 0x01,
	PCIE_LNK_X2		= 0x02,
	PCIE_LNK_X4		= 0x04,
	PCIE_LNK_X8		= 0x08,
	PCIE_LNK_X12		= 0x0C,
	PCIE_LNK_X16		= 0x10,
	PCIE_LNK_X32		= 0x20,
	PCIE_LNK_WIDTH_UNKNOWN  = 0xFF,
};
#endif

#ifndef HAVE_PCI_BUS_SPEED
/* Based on the PCI Hotplug Spec, but some values are made up by us */
enum pci_bus_speed {
	PCI_SPEED_33MHz			= 0x00,
	PCI_SPEED_66MHz			= 0x01,
	PCI_SPEED_66MHz_PCIX		= 0x02,
	PCI_SPEED_100MHz_PCIX		= 0x03,
	PCI_SPEED_133MHz_PCIX		= 0x04,
	PCI_SPEED_66MHz_PCIX_ECC	= 0x05,
	PCI_SPEED_100MHz_PCIX_ECC	= 0x06,
	PCI_SPEED_133MHz_PCIX_ECC	= 0x07,
	PCI_SPEED_66MHz_PCIX_266	= 0x09,
	PCI_SPEED_100MHz_PCIX_266	= 0x0a,
	PCI_SPEED_133MHz_PCIX_266	= 0x0b,
	AGP_UNKNOWN			= 0x0c,
	AGP_1X				= 0x0d,
	AGP_2X				= 0x0e,
	AGP_4X				= 0x0f,
	AGP_8X				= 0x10,
	PCI_SPEED_66MHz_PCIX_533	= 0x11,
	PCI_SPEED_100MHz_PCIX_533	= 0x12,
	PCI_SPEED_133MHz_PCIX_533	= 0x13,
	PCIE_SPEED_2_5GT		= 0x14,
	PCIE_SPEED_5_0GT		= 0x15,
	PCIE_SPEED_8_0GT		= 0x16,
	PCI_SPEED_UNKNOWN		= 0xff,
};
#endif

#define pcie_link_speed LINUX_BACKPORT(pcie_link_speed)
extern const unsigned char pcie_link_speed[];

#ifndef HAVE_PCIE_GET_MINIMUM_LINK
#define pcie_get_minimum_link LINUX_BACKPORT(pcie_get_minimum_link)
int pcie_get_minimum_link(struct pci_dev *dev, enum pci_bus_speed *speed,
			  enum pcie_link_width *width);
#endif

#ifndef HAVE_PCIE_PRINT_LINK_STATUS
u32 pcie_bandwidth_available(struct pci_dev *dev, struct pci_dev **limiting_dev,
			     enum pci_bus_speed *speed,
			     enum pcie_link_width *width);
void pcie_print_link_status(struct pci_dev *dev);
#define pcie_get_speed_cap LINUX_BACKPORT(pcie_get_speed_cap)
enum pci_bus_speed pcie_get_speed_cap(struct pci_dev *dev);
#endif

#ifndef PCIE_SPEED2MBS_ENC
/* PCIe speed to Mb/s reduced by encoding overhead */
#define PCIE_SPEED2MBS_ENC(speed) \
	((speed) == PCIE_SPEED_16_0GT ? 16000*128/130 : \
	 (speed) == PCIE_SPEED_8_0GT  ?  8000*128/130 : \
	 (speed) == PCIE_SPEED_5_0GT  ?  5000*8/10 : \
	 (speed) == PCIE_SPEED_2_5GT  ?  2500*8/10 : \
	 0)
#endif

#ifndef PCIE_SPEED2STR
/* PCIe link information */
#define PCIE_SPEED2STR(speed) \
	((speed) == PCIE_SPEED_16_0GT ? "16 GT/s" : \
	 (speed) == PCIE_SPEED_8_0GT ? "8 GT/s" : \
	 (speed) == PCIE_SPEED_5_0GT ? "5 GT/s" : \
	 (speed) == PCIE_SPEED_2_5GT ? "2.5 GT/s" : \
	 "Unknown speed")
#endif

#ifndef pci_info
#define pci_info(pdev, fmt, arg...)	dev_info(&(pdev)->dev, fmt, ##arg)
#endif

#ifndef HAVE_PCI_UPSTREAM_BRIDGE
#define pci_upstream_bridge LINUX_BACKPORT(pci_upstream_bridge)
static inline struct pci_dev *pci_upstream_bridge(struct pci_dev *dev)
{
	dev = pci_physfn(dev);
	if (pci_is_root_bus(dev->bus))
		return NULL;

	return dev->bus->self;
}
#endif

#ifndef HAVE_PCI_ENABLE_ATOMIC_OPS_TO_ROOT
int pci_enable_atomic_ops_to_root(struct pci_dev *dev, u32 comp_caps);
#endif

#endif /* _LINUX_PCI_H */
