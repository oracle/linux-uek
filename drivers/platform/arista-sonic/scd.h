/*
 * Copyright (C) 2010-2025 Arista Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// scd linux kernel driver public definitions

#ifndef LINUX_DRIVER_SCD_H_
#define LINUX_DRIVER_SCD_H_
#include <linux/pci.h>

// Allow an ardma handler set to be registered.
struct scd_ardma_ops {
   void (*probe)(struct pci_dev *pdev, void *scdregs,
      unsigned long ardma_offset,
      void *localbus,
      unsigned long interrupt_mask_ardma,
      unsigned long interrupt_mask_read_offset,
      unsigned long interrupt_mask_set_offset,
      unsigned long interrupt_mask_clear_offset);
   void (*remove)(struct pci_dev *pdev);
   void (*shutdown)(struct pci_dev *pdev);
   bool (*interrupt)(struct pci_dev *pdev);
};

enum em_interrupt {
   SCD_EM_INT_HANDOVER = 1U<<0,
   SCD_EM_INT_TAKEOVER = 1U<<1,
   SCD_EM_INT_SELF_SUP_PRESENCE = 1U<<2,
};
// Allow scd-em callbacks to be registered
struct scd_em_ops {
   bool (*probe)(struct device *dev);
   void (*finish_init)(struct device *dev);
   void (*interrupt)(struct device *dev, enum em_interrupt which);
   void (*remove)(struct device *dev);
};

// Allow scd-ext callbacks to be registered
struct scd_ext_ops {
   int (*probe)(struct device *dev, size_t mem_len);
   void (*remove)(struct device *dev);
   int (*init_trigger)(struct device *dev);
   int (*finish_init)(struct device *dev);
};

struct scd_extension {
   const char *name;
   struct list_head list;
   struct scd_ext_ops *ops;
};

int scd_register_ardma_ops(struct scd_ardma_ops *ops);
void scd_unregister_ardma_ops(void);
int scd_register_em_ops(struct scd_em_ops *ops);
void scd_unregister_em_ops(void);
void scd_enable_em_interrupts(struct device *pdev, int interrupt_select,
   bool enable);
int scd_register_extension(struct scd_extension *ext);
void scd_unregister_extension(struct scd_extension *ext);
u32 scd_read_register(struct device *dev, u32 offset);
void scd_write_register(struct device *dev, u32 offset, u32 val);
unsigned int scd_get_interrupt_irq(struct device *dev);
void scd_timestamped_panic(const char *msg);
extern void (*update_shutdown_dev)(void *);
extern void (*put_shutdown_dev)(void *);

#endif /* !LINUX_DRIVER_SCD_H_ */
