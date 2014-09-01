/*******************************************************************************

  Intel 82599 Virtual Function driver
  Copyright (c) 1999 - 2014 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/


/* glue for the OS independent part of ixgbe
 * includes register access macros
 */

#ifndef _IXGBEVF_OSDEP_H_
#define _IXGBEVF_OSDEP_H_

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/sched.h>
#include "kcompat.h"

#define IXGBE_CPU_TO_BE16(_x) cpu_to_be16(_x)
#define IXGBE_BE16_TO_CPU(_x) be16_to_cpu(_x)
#define IXGBE_CPU_TO_BE32(_x) cpu_to_be32(_x)
#define IXGBE_BE32_TO_CPU(_x) be32_to_cpu(_x)

#ifndef msleep
#define msleep(x)	do { if(in_interrupt()) { \
				/* Don't mdelay in interrupt context! */ \
	                	BUG(); \
			} else { \
				msleep(x); \
			} } while (0)

#endif

#undef ASSERT

#ifdef DBG
#define hw_dbg(hw, S, A...)	printk(KERN_DEBUG S, ## A)
#else
#define hw_dbg(hw, S, A...)      do {} while (0)
#endif

#define IXGBE_REMOVED(a) unlikely(!(a))
#define IXGBE_FAILED_READ_REG 0xffffffffU

#define IXGBE_WRITE_REG_ARRAY(a, reg, offset, value) \
    IXGBE_WRITE_REG((a), (reg) + ((offset) << 2), (value))

#define IXGBE_READ_REG_ARRAY(a, reg, offset) \
    IXGBE_READ_REG((a), (reg) + ((offset) << 2))

#ifndef writeq
#define writeq(val, addr) writel((u32) (val), addr); \
	writel((u32) (val >> 32), (addr + 4));
#endif

#define IXGBE_WRITE_FLUSH(a) IXGBE_READ_REG(a, IXGBE_VFSTATUS)

struct ixgbe_hw;
struct ixgbevf_msg {
	u16 msg_enable;
};
struct net_device *ixgbevf_hw_to_netdev(const struct ixgbe_hw *hw);
struct ixgbevf_msg *ixgbevf_hw_to_msg(const struct ixgbe_hw *hw);

void ixgbevf_check_remove(struct ixgbe_hw *hw, u32 reg);
extern u16 ixgbe_read_pci_cfg_word(struct ixgbe_hw *hw, u32 reg);
extern void ixgbe_write_pci_cfg_word(struct ixgbe_hw *hw, u32 reg, u16 value);
#define IXGBE_READ_PCIE_WORD ixgbe_read_pci_cfg_word
#define IXGBE_WRITE_PCIE_WORD ixgbe_write_pci_cfg_word
#define IXGBE_EEPROM_GRANT_ATTEMPS 100
#define IXGBE_HTONL(_i) htonl(_i)
#define IXGBE_HTONS(_i) htons(_i)

enum {
	IXGBE_ERROR_SOFTWARE,
	IXGBE_ERROR_POLLING,
	IXGBE_ERROR_INVALID_STATE,
	IXGBE_ERROR_UNSUPPORTED,
	IXGBE_ERROR_ARGUMENT,
	IXGBE_ERROR_CAUTION,
};

#define ERROR_REPORT(level, format, arg...) do {				\
	switch (level) {							\
	case IXGBE_ERROR_SOFTWARE:						\
	case IXGBE_ERROR_CAUTION:						\
	case IXGBE_ERROR_POLLING:						\
		netif_warn(ixgbevf_hw_to_msg(hw), drv, ixgbevf_hw_to_netdev(hw),\
			   format, ## arg);					\
		break;								\
	case IXGBE_ERROR_INVALID_STATE:						\
	case IXGBE_ERROR_UNSUPPORTED:						\
	case IXGBE_ERROR_ARGUMENT:						\
		netif_err(ixgbevf_hw_to_msg(hw), hw, ixgbevf_hw_to_netdev(hw),	\
			  format, ## arg);					\
		break;								\
	default:								\
		break;								\
	}									\
} while (0)

#define ERROR_REPORT1 ERROR_REPORT
#define ERROR_REPORT2 ERROR_REPORT
#define ERROR_REPORT3 ERROR_REPORT

#define UNREFERENCED_XPARAMETER
#define UNREFERENCED_1PARAMETER(_p) do {		\
	uninitialized_var(_p);				\
} while (0)
#define UNREFERENCED_2PARAMETER(_p, _q) do {		\
	uninitialized_var(_p);				\
	uninitialized_var(_q);				\
} while (0)
#define UNREFERENCED_3PARAMETER(_p, _q, _r) do {	\
	uninitialized_var(_p);				\
	uninitialized_var(_q);				\
	uninitialized_var(_r);				\
} while (0)
#define UNREFERENCED_4PARAMETER(_p, _q, _r, _s) do {	\
	uninitialized_var(_p);				\
	uninitialized_var(_q);				\
	uninitialized_var(_r);				\
	uninitialized_var(_s);				\
} while (0)

#endif /* _IXGBEVF_OSDEP_H_ */
