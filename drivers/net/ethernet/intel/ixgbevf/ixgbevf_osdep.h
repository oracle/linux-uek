/*******************************************************************************

  Intel 82599 Virtual Function driver
  Copyright(c) 1999 - 2012 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

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

#ifndef NO_SURPRISE_REMOVE_SUPPORT
#define IXGBE_REMOVED(a) unlikely(!(a))
#else
#define IXGBE_REMOVED(a) (0)
#endif /* NO_SURPRISE_REMOVE_SUPPORT */

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

#ifndef NO_SURPRISE_REMOVE_SUPPORT
void ixgbevf_check_remove(struct ixgbe_hw *hw, u32 reg);

#endif /* NO_SURPRISE_REMOVE_SUPPORT */
extern u16 ixgbe_read_pci_cfg_word(struct ixgbe_hw *hw, u32 reg);
extern void ixgbe_write_pci_cfg_word(struct ixgbe_hw *hw, u32 reg, u16 value);
#define IXGBE_READ_PCIE_WORD ixgbe_read_pci_cfg_word
#define IXGBE_WRITE_PCIE_WORD ixgbe_write_pci_cfg_word
#define IXGBE_EEPROM_GRANT_ATTEMPS 100
#define IXGBE_HTONL(_i) htonl(_i)
#define IXGBE_HTONS(_i) htons(_i)

#define ERROR_REPORT(...) do {} while (0)
#define ERROR_REPORT1(...) do {} while (0)
#define ERROR_REPORT2(...) do {} while (0)

#endif /* _IXGBEVF_OSDEP_H_ */
