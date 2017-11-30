/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XEN_PCI_H__
#define XEN_PCI_H__

#ifdef CONFIG_PCI_XEN

int register_pci_pxm_handler(struct notifier_block *nb, struct pci_dev *pdev);
int unregister_pci_pxm_handler(struct notifier_block *nb, struct pci_dev *pdev);
void do_kernel_pci_update_pxm(struct pci_dev *dev);

#else

static inline int register_pci_pxm_handler(struct notifier_block *nb,
					   struct pci_dev *pdev)
{
	return 0;
}

static inline int unregister_pci_pxm_handler(struct notifier_block *nb,
					     struct pci_dev *pdev)
{
	return 0;
}

#define do_kernel_pci_update_pxm (0)

#endif /* CONFIG_PCI_XEN */

#endif /* XEN_PCI_H__ */
