#ifndef _COMPAT_LINUX_PCI_REGS_H
#define _COMPAT_LINUX_PCI_REGS_H

#include <linux/mlx5/compat/config.h>
#include_next <linux/pci_regs.h>


#ifndef PCI_EXP_LNKCAP_SLS_2_5GB
#define  PCI_EXP_LNKCAP_SLS_2_5GB 0x00000001 /* LNKCAP2 SLS Vector bit 0 */
#endif

#ifndef PCI_EXP_LNKCAP_SLS_5_0GB
#define  PCI_EXP_LNKCAP_SLS_5_0GB 0x00000002 /* LNKCAP2 SLS Vector bit 1 */
#endif

#ifndef PCI_EXP_LNKCAP_SLS_8_0GB
#define  PCI_EXP_LNKCAP_SLS_8_0GB 0x00000003 /* LNKCAP2 SLS Vector bit 2 */
#endif

#ifndef PCI_EXP_LNKCAP2_SLS_16_0GB
#define PCI_EXP_LNKCAP2_SLS_16_0GB	0x00000010 /* Supported Speed 16GT/s */
#define PCIE_SPEED_16_0GT		0x17
#define PCI_EXP_LNKCAP_SLS_16_0GB	0x00000004 /* LNKCAP2 SLS Vector bit 3 */
#endif

#ifndef PCI_EXP_TYPE_PCIE_BRIDGE
#define PCI_EXP_TYPE_PCIE_BRIDGE 0x8   /* PCI/PCI-X to PCIe Bridge */
#endif

#ifndef PCI_EXP_DEVCAP2_ATOMIC_ROUTE
#define PCI_EXP_DEVCAP2_ATOMIC_ROUTE   0x00000040 /* Atomic Op routing */
#endif

#ifndef PCI_EXP_DEVCTL2_ATOMIC_REQ
#define PCI_EXP_DEVCTL2_ATOMIC_REQ      0x0040  /* Set Atomic requests */
#endif

#ifndef PCI_EXP_DEVCAP2_ATOMIC_COMP32
#define PCI_EXP_DEVCAP2_ATOMIC_COMP32  0x00000080 /* 32b AtomicOp completion */
#define PCI_EXP_DEVCAP2_ATOMIC_COMP64  0x00000100 /* 64b AtomicOp completion */
#define PCI_EXP_DEVCAP2_ATOMIC_COMP128 0x00000200 /* 128b AtomicOp completion */
#endif

#ifndef PCI_EXP_DEVCTL2_ATOMIC_EGRESS_BLOCK
#define PCI_EXP_DEVCTL2_ATOMIC_EGRESS_BLOCK 0x0080 /* Block atomic egress */
#endif

#endif /* _COMPAT_LINUX_PCI_REGS_H */
