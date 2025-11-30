/*
 * Copyright (c) 2006-2020 Arista Networks, Inc.  All rights reserved.
 * Arista Networks, Inc. Confidential and Proprietary.
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
 */

/*
 * SCD driver.
 *
 * When a PCI SCD device is detected, this driver initializes the PCI device and
 * maps its memory region 0 into virtual memory, but it delays registering an
 * interrupt handler for the device.  Instead, it creates several device attribute
 * files:
 *
 *   interrupt_status_offset
 *   interrupt_mask_read_offset
 *   interrupt_mask_set_offset
 *   interrupt_mask_clear_offset
 *   interrupt_mask
 *   interrupt_mask_powerloss
 *   interrupt_mask_watchdog
 *   interrupt_mask_ardma
 *   crc_error_irq
 *   ptp_high_offset
 *   ptp_low_offset
 *   msi_rearm_offset
 *   interrupt_irq
 *   ardma_offset
 *   interrupt_poll
 *   nmi_port_io_p
 *   nmi_control_reg_addr
 *   nmi_control_mask
 *   nmi_status_reg_addr
 *   nmi_status_mask
 *   nmi_gpio_status_reg_addr
 *   nmi_gpio_status_mask
 *   init_trigger
 *
 * which will appear in the directory /sys/devices/pciAAAA:BB/AAAA:BB:CC.D/.
 *
 * The first 13 are read/write.  The offset within memory region 0 of the interrupt
 * status and interrupt mask registers can be configured by writing their values to
 * the first four attribute files.  The mask of valid bits in the interrupt status
 * register can be set by writing its value to the fifth file (all 'invalid' bits
 * are expected always to be zero).  To handle
 * the CRC error interrupt (completely separate from the normal interrupt line),
 * write the IRQ number to crc_error_irq.  Similarly, if the device interrupt is not
 * the PCI interrupt, then write the interrupt_irq file.
 * The power_loss is set to 1 when the switch rebooted due to a Power Loss (not all
 * switches support this feature). Userland will clear this back to 0 once it has read
 * it as boot time. it can also set it back to 1 for testing purpses. This driver
 * will set to 1 when an interrupt in the interrupt_mask_powerloss is detected.
 *
 * The values written to each of these files should be in ASCII decimal.  Reading
 * from any of these files will return the value last written, also in ASCII decimal.
 *
 * After the other files have been written, writing (anything) to the
 * 'init_trigger' file will cause initialization of the driver to continue, creating
 * up to 32 UIO devices (/dev/uio<n>), one for each bit that was set in the
 * interrupt_mask, registering an interrupt handler. Reading from 'init_trigger'
 * returns a positive initialization error if one occurred, or 0 for success.
 * After successful initialization attribute files become read only. Attempts at
 * changing their values results in a warning.
 *
 * Each UIO device corresponds to a bit in the interrupt status/mask registers.
 * Reads on one of the UIO device files will complete when an interrupt has occurred
 * for that bit, at which point that bit will have been added to the interrupt mask.
 * It is up to the userspace code to remove that bit from the interrupt mask when it
 * has handled the interrupt and cleared the interrupt at source.
 *
 * NMI data is also stored per-scd. nmi_priv points to the scd_dev_priv for the
 * scd responsible for registering and maintaining the nmi handler. Only
 * one scd is configured to handle the nmi. Userspace code (the scd agent) is trusted
 * to pick the correct scd and correctly write to the corresponding attribute files.
 * nmi_priv is set when writing to the nmi_control_reg_addr file, attempts by other
 * devices to change nmi_priv after this point is an error. There is no protection
 * against multiple entities concurrently initializing scd attributes.
 *
 * Writing anything to /sys/class/scd/disable_nmi turns the nmi handler into a no-op.
 * Once disabled it cannot be re-enabled. This is intended for use during shutdown
 * to prevent an erroneous panic as the NMI line floats.
 */

#include <linux/uio_driver.h>
#include <linux/pci.h>
#include <linux/i2c.h>
#include "scd.h"
#include <linux/timer.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/kdebug.h>
#include <linux/version.h>
#include <asm/nmi.h>
#include <linux/sched.h>
#include <linux/regulator/machine.h>

#define SCD_MODULE_NAME "scd"

#define SCD_PCI_VENDOR_ID 0x3475
#define SCD_PCI_DEVICE_ID 0x0001
#define SCD_BAR_REGS 0
#define SCD_BAR_1    1
#define SCD_NUM_IRQ_REGISTERS 20
#define SCD_REVISION_OFFSET 0x100
#define SCD_MAGIC 0xdeadbeef
#define SCD_UNINITIALIZED 0xffffffff

#define AMD_PCI_VENDOR_ID 0x1022
#define AMD_PCI_EKABINI_18F5_DEVICE_ID 0x1535
#define AMD_PCI_STEPPEEAGLE_18F5_DEVICE_ID 0x1585
#define AMD_PCI_MERLINFALCON_157D_DEVICE_ID 0x157D
#define AMD_PCI_SNOWYOWL_1467_DEVICE_ID 0x1467
#define AMD_PCI_V1000_15EF_DEVICE_ID 0x15EF

#define INTEL_PCI_VENDOR_ID 0x8086
#define INTEL_PCI_BROADWELL_DEVICE_ID 0x6f76

#define RECONFIG_PCI_SUBSYSTEM_ID 0x14
#define RECONFIG_STATE_BAR_VALUE 0xdeadface

#define NUM_BITS_IN_WORD 32

#define ASSERT(expr) do { if (unlikely(!(expr))) \
   printk(KERN_ERR "Assertion failed! %s,%s,%s,line=%d (%s:%d)\n", \
   #expr,__FILE__,__FUNCTION__,__LINE__,current->comm,current->pid); } while (0)

#define INTR_POLL_INTERVAL ( HZ/10 )

#define IOSIZE 4

#ifndef _PAGE_CACHE_UC
# define _PAGE_CACHE_UC _PAGE_CACHE_MODE_UC
#endif

typedef struct scd_irq_info_s {
   unsigned long interrupt_status_offset;
   unsigned long interrupt_mask_read_offset;
   unsigned long interrupt_mask_set_offset;
   unsigned long interrupt_mask_clear_offset;
   unsigned long interrupt_mask;
   unsigned long interrupt_mask_powerloss;
   unsigned long interrupt_mask_watchdog;
   unsigned long interrupt_mask_ardma;
   unsigned long interrupt_valid_addr;
   unsigned long interrupt_valid_val;
   unsigned long interrupt_valid_mask;
   struct uio_info *uio_info[NUM_BITS_IN_WORD];
   unsigned long uio_count[NUM_BITS_IN_WORD];
   char uio_names[NUM_BITS_IN_WORD][40];
} scd_irq_info_t;

struct scd_dev_priv {
   struct list_head list;
   struct pci_dev *pdev;
   void __iomem *mem;
   size_t mem_len;
   scd_irq_info_t irq_info[SCD_NUM_IRQ_REGISTERS];
   unsigned long crc_error_irq;
   unsigned long ptp_high_offset;
   unsigned long ptp_low_offset;
   unsigned long ptp_offset_valid;
   unsigned long msi_rearm_offset;
   unsigned long interrupt_irq;
   unsigned long ardma_offset;
   void __iomem *localbus;
   unsigned long init_error;
   bool initialized;
   unsigned int magic;
   bool sysfs_initialized;
   u32 revision;
   u32 revision_error_reports;
   bool is_reconfig;
   unsigned long interrupt_poll;
   struct timer_list intr_poll_timer;

   unsigned long interrupts;
   unsigned long interrupt_claimed;
   unsigned long interrupt_ardma_cnt;
   unsigned long interrupt_powerloss_cnt;
   const struct scd_driver_cb *driver_cb;

   int lpc_device;
   int lpc_vendor;

   // SCD watchdog NMI delivered through GPIO
   unsigned long nmi_port_io_p;
   unsigned long nmi_control_reg_addr;
   unsigned long *nmi_control_reg;
   unsigned long nmi_control_mask;
   unsigned long nmi_status_reg_addr;
   unsigned long *nmi_status_reg;
   unsigned long nmi_status_mask;
   unsigned long nmi_gpio_status_reg_addr;
   unsigned long *nmi_gpio_status_reg;
   unsigned long nmi_gpio_status_mask;
   bool nmi_registered; // true if this instance registered and owns the NMI
};

// number of times to report a revision mismatch.
#define MAX_REV_ERR_RPTS 5

// non zero if debug logging is enabled.
static int debug = 0;
// true when nmi is disabled
static bool nmi_disabled = false;
// 1 if panic, 0 if not panic on crc error
static unsigned int crc_error_panic = 1;
// linked list of scd_dev_privs
static struct list_head scd_list;
// mutex and not spinlock because of kmallocs and ardma callbacks
static struct mutex scd_mutex;
// scd_dev_priv for scd running tod counter
static struct scd_dev_priv *ptp_master_priv = NULL;
// spinlock used instead of scd_mutex for reading supe scd timestamps
static spinlock_t scd_ptp_lock;
// nmi_priv points to the scd responsible for the nmi
static struct scd_dev_priv *nmi_priv = NULL;

void
scd_timestamped_panic(const char *msg)
{
   struct timespec64 now;
   struct tm t;

   ktime_get_real_ts64(&now);
   time64_to_tm(now.tv_sec, 0, &t);

   panic("%s (%02d:%02d:%02d)", msg, t.tm_hour, t.tm_min, t.tm_sec);
}
EXPORT_SYMBOL(scd_timestamped_panic);

/* prototypes */
static int scd_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static void scd_interrupt_poll(unsigned long data);
#else
static void scd_interrupt_poll(struct timer_list *t);
#endif
static void scd_remove(struct pci_dev *pdev);
static void scd_shutdown(struct pci_dev *pdev);
static void scd_mask_interrupts(struct scd_dev_priv *priv);
static void scd_lock(void);
static void scd_unlock(void);

static void scd_lock() {
   mutex_lock(&scd_mutex);
}

static void scd_unlock() {
   mutex_unlock(&scd_mutex);
}

struct scd_driver_cb {
   int (*enable) (struct pci_dev *dev);
   void (*disable) (struct pci_dev *dev);
};

// registered ardma handlers
static struct scd_ardma_ops *scd_ardma_ops = NULL;

int scd_register_ardma_ops(struct scd_ardma_ops *ops) {
   struct scd_dev_priv *priv;

   scd_lock();
   ASSERT(scd_ardma_ops == NULL);
   scd_ardma_ops = ops;

   // call ardma probe() for any existing scd having ardma
   list_for_each_entry(priv, &scd_list, list) {
      if (priv->initialized && priv->ardma_offset) {
         scd_ardma_ops->probe(priv->pdev, (void*)priv->mem,
            priv->ardma_offset,
            priv->localbus,
            priv->irq_info[0].interrupt_mask_ardma,
            priv->irq_info[0].interrupt_mask_read_offset,
            priv->irq_info[0].interrupt_mask_set_offset,
            priv->irq_info[0].interrupt_mask_clear_offset);
      }
   }
   scd_unlock();
   return 0;
}

void scd_unregister_ardma_ops() {
   struct scd_dev_priv *priv;

   scd_lock();
   if (!scd_ardma_ops) {
      goto out_unlock;
   }

   // call ardma remove() for any existing scd having ardma
   list_for_each_entry(priv, &scd_list, list) {
      if (priv->initialized && priv->ardma_offset) {
         scd_ardma_ops->remove(priv->pdev);
      }
   }
   scd_ardma_ops = NULL;

out_unlock:
   scd_unlock();
}

EXPORT_SYMBOL(scd_register_ardma_ops);
EXPORT_SYMBOL(scd_unregister_ardma_ops);

// list of registered extentions
static LIST_HEAD(scd_extensions);

static bool is_scd_extension_registered(struct scd_extension *ext) {
   struct scd_extension *tmp;

   list_for_each_entry(tmp, &scd_extensions, list) {
      if (tmp == ext) {
         return true;
      }
   }

   return false;
}

int scd_register_extension(struct scd_extension *ext) {
   struct scd_dev_priv *priv;

   printk(KERN_INFO "%s: loading extension %s", SCD_MODULE_NAME, ext->name);

   scd_lock();
   if (is_scd_extension_registered(ext)) {
      scd_unlock();
      printk(KERN_WARNING "%s: extension %s already loaded", SCD_MODULE_NAME,
             ext->name);
      return -EEXIST;
   }

   list_add_tail(&ext->list, &scd_extensions);

   // call probe() for any existing scd
   list_for_each_entry(priv, &scd_list, list) {
      if (ext->ops->probe) {
         ext->ops->probe(priv->pdev, priv->mem_len);
      }
      if (priv->initialized && ext->ops->finish_init) {
         ext->ops->finish_init(priv->pdev);
      }
   }
   scd_unlock();

   return 0;
}

void scd_unregister_extension(struct scd_extension *ext) {
   struct scd_dev_priv *priv;

   printk(KERN_INFO "%s: unloading extension %s", SCD_MODULE_NAME, ext->name);

   scd_lock();

   if (!is_scd_extension_registered(ext)) {
      scd_unlock();
      printk(KERN_WARNING "%s: extension %s already unloaded", SCD_MODULE_NAME,
             ext->name);
      return;
   }

   // call remove() for any existing scd
   list_for_each_entry(priv, &scd_list, list) {
      if (ext->ops->remove) {
         ext->ops->remove(priv->pdev);
      }
   }

   list_del(&ext->list);

   scd_unlock();
}

EXPORT_SYMBOL(scd_register_extension);
EXPORT_SYMBOL(scd_unregister_extension);

static irqreturn_t scd_interrupt(int irq, void *dev_id)
{
   struct device *dev = (struct device *) dev_id;
   struct scd_dev_priv *priv = dev_get_drvdata(dev);
   u32 interrupt_status;
   u32 interrupt_mask;
   u32 unmasked_interrupt_status;
   u32 interrupt_valid_val;
   irqreturn_t rc = IRQ_NONE;
   u32 irq_reg;
   u32 unexpected;
   u32 scd_ver;

   WARN_ON_ONCE( priv->magic != SCD_MAGIC );

   priv->interrupts++;
   for(irq_reg = 0; irq_reg < SCD_NUM_IRQ_REGISTERS; irq_reg++) {
      if( !priv->irq_info[irq_reg].interrupt_status_offset ) {
          continue;
      }

      scd_ver = ioread32( priv->mem + SCD_REVISION_OFFSET );
      if( scd_ver != priv->revision ) {
         // sanity check to make sure we are not trying to read
         // a scd that has just been hot removed before we
         // have been notified.
         // There is a problem with linecard hot removal, the power
         // fails very slowly (10ms) and something manages to generate
         // an interrupt, by the time we read the registers during the
         // 10ms power down we can get garbage back, not just all Fs
         // as you would expect from a powered down device.
         if( scd_ver != 0xffffffff &&
             priv->revision_error_reports < MAX_REV_ERR_RPTS ) {
            // Update the revision for a reconfigurable fpga. BAR0 and BAR1 will
            // initially read 0xdeadface until being reconfigured. After reconfig
            // BAR0 will function as a scd and return the correct version number.
            if(priv->is_reconfig && priv->revision == RECONFIG_STATE_BAR_VALUE) {
               priv->revision = scd_ver;
            } else {
               // we got garbage, this is bad so let someone know about it
               dev_info( dev, "scd: irq chk 0x%x!=0x%x\n",
                         priv->revision, scd_ver );
               priv->revision_error_reports++;
               if(priv->revision_error_reports == MAX_REV_ERR_RPTS) {
                  // there appear to be some cases where the kernel gets
                  // very confused with the scd, the physical devices seem
                  // to have been switched association with the kernel device
                  // structures, dump out the name of one of the uio, it should allow
                  // us to see if the device structure has become confused.
                  dev_err(dev, "scd: rev mismatch overflow, uio[0]:%s\n",
                          pci_name(priv->pdev));
               }
            }
         }
         break;
      }

      if( priv->irq_info[irq_reg].interrupt_valid_addr ) {
         interrupt_valid_val = ioread32(
            priv->mem + priv->irq_info[irq_reg].interrupt_valid_addr );
         if( ( interrupt_valid_val & priv->irq_info[irq_reg].interrupt_valid_mask )
            != priv->irq_info[irq_reg].interrupt_valid_val ) {
            continue;
         }
      }

      unexpected = 0;
      interrupt_status = ioread32(priv->mem +
                                  priv->irq_info[irq_reg].interrupt_status_offset);
      interrupt_mask = ioread32(priv->mem +
                                priv->irq_info[irq_reg].interrupt_mask_read_offset);
      unmasked_interrupt_status = interrupt_status & ~interrupt_mask;

      if(debug) {
         dev_info(dev, "interrupt status 0x%x interrupt mask 0x%x "
                       "interrupt status offset 0x%lx interrupt ",
                       interrupt_status, interrupt_mask,
                       priv->irq_info[irq_reg].interrupt_status_offset );
      }

      if (!unmasked_interrupt_status) {
         /* No unmasked interrupt bits are active.  Therefore the interrupt didn't
          * originate from the SCD. */
         continue;
      }

      /* see if this is an powerLoss interrupt
       this is to speed up the handling, we don't have much time if it is a
       real power loss */
      if(priv->irq_info[irq_reg].interrupt_mask_powerloss &
         unmasked_interrupt_status) {
         // it is the end of the line for this run, if this really is a power loss
         // we will never complete the printk before the power dies
         printk( KERN_INFO "Power Loss detected\n");
         priv->interrupt_powerloss_cnt++;
      }

      rc = IRQ_HANDLED;
      priv->interrupt_claimed++;
      /* Mask all active interrupt bits.  Note that we must only mask the bits that
      * were not already masked when we read the interrupt mask register above.
      * Otherwise, we may mask a bit that has subsequently been cleared by a process
      * running on another CPU, without generating another UIO event for that bit,
      * causing that process to get stuck waiting for an interrupt that will never
      * arrive. */
      iowrite32(unmasked_interrupt_status, priv->mem +
                priv->irq_info[irq_reg].interrupt_mask_set_offset);

      /* see if this was a watchdog interrupt, if so we do a kernel panic
         to ensure that we get a kdump */
      if(unmasked_interrupt_status &
                                priv->irq_info[irq_reg].interrupt_mask_watchdog) {
         // the panic will generate backtrace and cause the kdump kernel to kick in
         // which should provide us more data than if we did nothing before the
         // watchdog rebooted the system, we have 10 seconds before reboot
         scd_timestamped_panic( "SCD watchdog detected, system will reboot.\n" );
      }

      // ardma interrupt
      if ((unmasked_interrupt_status & priv->irq_info[irq_reg].interrupt_mask_ardma)
          && scd_ardma_ops) {
         scd_ardma_ops->interrupt(priv->pdev);
         unmasked_interrupt_status &= ~priv->irq_info[irq_reg].interrupt_mask_ardma;
         priv->interrupt_ardma_cnt++;
      }

      /* Notify the UIO layer for each of the newly active interrupt bits. */
      while (unmasked_interrupt_status) {
         int bit = ffs(unmasked_interrupt_status) - 1;
         if (likely(priv->irq_info[irq_reg].uio_info[bit])) {
            uio_event_notify(priv->irq_info[irq_reg].uio_info[bit]);
            priv->irq_info[irq_reg].uio_count[bit]++;
         } else {
            unexpected |= 1 << bit;
         }
         unmasked_interrupt_status ^= (1 << bit);
      }

      if( unexpected ) {
         dev_info(dev, "interrupt occurred for unexpected bits 0x%x "
                "interrupt_status 0x%x, interrupt_mask 0x%x"
                "scd_rev 0x%x interrupt status offset 0x%lx"
                "uio mask is 0x%lx\n" ,
                unexpected, interrupt_status,
                interrupt_mask, scd_ver,
                priv->irq_info[irq_reg].interrupt_status_offset,
                priv->irq_info[irq_reg].interrupt_mask );
      }
   }

   /* If using MSI rearm message generation */
   if (priv->msi_rearm_offset) {
      iowrite32(1, priv->mem + priv->msi_rearm_offset);
   }

   return rc;
}

static irqreturn_t scd_crc_error_interrupt(int irq, void *dev_id)
{
   struct device *dev = (struct device *) dev_id;
   struct scd_dev_priv *priv = dev_get_drvdata(dev);
   dev_emerg(dev, "scd: CRC error interrupt occurred!\n");

   if (priv->initialized && crc_error_panic == 1) {
      /* The scd crc error irq is currently NOT shared on any platform.
       * The irq source is not cleared to ensure that the capture kernel
       * is not interrupted by a corrupt scd.
       */
      panic( "scd_crc_error detected, system will reboot.\n" );
   }

   return IRQ_HANDLED;
}

static void scd_nmi_panic(struct pt_regs *regs, char *msg)
{
   if (nmi_priv->nmi_port_io_p) {
      u16 val =
         inw(nmi_priv->nmi_control_reg_addr) & ~nmi_priv->nmi_control_mask;
      outw(val, nmi_priv->nmi_control_reg_addr);
      outw(nmi_priv->nmi_status_mask, nmi_priv->nmi_status_reg_addr);
   } else {
      u32 val =
         (ioread32(nmi_priv->nmi_control_reg) & ~nmi_priv->nmi_control_mask);
      iowrite32(val, nmi_priv->nmi_control_reg);
      iowrite32(nmi_priv->nmi_status_mask, nmi_priv->nmi_status_reg);
   }

   nmi_panic(regs, msg);
}

static void scd_watchdog_panic(struct pt_regs *regs)
{
   scd_nmi_panic(regs, "SCD watchdog NMI detected, system will reboot.");
}

static int scd_nmi_notify(unsigned int cmd, struct pt_regs *regs)
{
   bool scd_nmi;

   BUG_ON(nmi_priv == NULL);

   /* Test for  a SCD NMI */

   if ( nmi_priv->nmi_port_io_p ) {
      /* IO-mapped: Intel PCH */
      scd_nmi =
         inw(nmi_priv->nmi_status_reg_addr) &
         nmi_priv->nmi_status_mask;
   } else {
      /* Memory-mapped: AMD Kabini, Sb800 */
      scd_nmi =
         ((ioread32(nmi_priv->nmi_status_reg) &
           nmi_priv->nmi_status_mask) &&

          /* Sb800 maps GPIO status to NMI, which we can test */
          (!nmi_priv->nmi_gpio_status_reg ||
           !(ioread8(nmi_priv->nmi_gpio_status_reg) &
             nmi_priv->nmi_gpio_status_mask)));
   }

   if (scd_nmi) {
      if (nmi_disabled) {
         printk(KERN_ALERT "SCD NMI detected, but handler is disabled\n");
      } else {
         /* A watchdog NMI has no SCD status */
         scd_watchdog_panic(regs);
      }
   }

   /*
    * Any of our NMIs are fatal (panic() is a __noreturn). We either
    * terminate, or didn't identify our source.
    */
   return NMI_DONE;
}

/*
 * Register a notifier to catch the NMI and call panic to generate a kernel
 * dump before power cycle.
 */
static int scd_register_nmi_handler(void)
{
   int err;
   ASSERT(!nmi_priv->nmi_registered);
   ASSERT(nmi_priv->nmi_port_io_p != SCD_UNINITIALIZED);
   ASSERT(nmi_priv->nmi_control_reg_addr != SCD_UNINITIALIZED);
   ASSERT(nmi_priv->nmi_status_reg_addr != SCD_UNINITIALIZED);
   ASSERT(nmi_priv->nmi_gpio_status_reg_addr != SCD_UNINITIALIZED);
   ASSERT(nmi_priv->nmi_gpio_status_mask != SCD_UNINITIALIZED);
   ASSERT(nmi_priv->nmi_status_mask != SCD_UNINITIALIZED);
   ASSERT(nmi_priv->nmi_control_mask != SCD_UNINITIALIZED);

   if (!nmi_priv->nmi_port_io_p) {
      nmi_priv->nmi_control_reg = ioremap(nmi_priv->nmi_control_reg_addr, IOSIZE);
      if (!nmi_priv->nmi_control_reg) {
         printk(KERN_ERR "failed to map SCD NMI control registers\n");
         err = -ENXIO;
         goto out;
      }
      nmi_priv->nmi_status_reg = ioremap(nmi_priv->nmi_status_reg_addr, IOSIZE);
      if (!nmi_priv->nmi_status_reg) {
         printk(KERN_ERR "failed to map SCD NMI status registers\n");
         err = -ENXIO;
         goto out_nmi_status_fail;
      }
   }

   if (nmi_priv->nmi_gpio_status_reg_addr) {
      nmi_priv->nmi_gpio_status_reg = ioremap(nmi_priv->nmi_gpio_status_reg_addr,
                                              IOSIZE);
      if (!nmi_priv->nmi_gpio_status_reg) {
         printk(KERN_ERR "failed to map SCD NMI GPIO status registers\n");
         err = -ENXIO;
         goto out_nmi_gpio_fail;
      }
   }

   err = register_nmi_handler(NMI_LOCAL, scd_nmi_notify, 0, "WATCHDOG_NMI");
   if (err) {
      printk(KERN_ERR "failed to register SCD NMI notifier (error %d)\n", err);
      goto out_register_fail;
   }
   nmi_priv->nmi_registered = true;
   return 0;

out_register_fail:
   if (nmi_priv->nmi_gpio_status_reg_addr) {
      iounmap(nmi_priv->nmi_gpio_status_reg);
      nmi_priv->nmi_gpio_status_reg = NULL;
   }

out_nmi_gpio_fail:
   if (!nmi_priv->nmi_port_io_p) {
      iounmap(nmi_priv->nmi_status_reg);
      nmi_priv->nmi_status_reg = NULL;
out_nmi_status_fail:
      iounmap(nmi_priv->nmi_control_reg);
      nmi_priv->nmi_control_reg = NULL;
   }
out:
   return err;
}

static int scd_finish_init(struct device *dev)
{
   struct scd_dev_priv *priv = dev_get_drvdata(dev);
   struct scd_extension *ext;
   int err;
   int i;
   unsigned int irq;
   u32 irq_reg;
   u32 scd_ver;

   dev_info(dev, "scd_finish_init\n");

   // store a copy of the dev->name() for debugging hotswap
   for(irq_reg = 0; irq_reg < SCD_NUM_IRQ_REGISTERS; irq_reg++) {
      // combine the power loss, watchdog and regular interrupt masks
      unsigned long interrupt_mask = priv->irq_info[irq_reg].interrupt_mask;

      interrupt_mask |= priv->irq_info[irq_reg].interrupt_mask_powerloss;
      interrupt_mask |= priv->irq_info[irq_reg].interrupt_mask_watchdog;

      /* Assign all elements to NULL to safely deallocate in case of failure. */
      for (i = 0; i < NUM_BITS_IN_WORD; i++) {
         priv->irq_info[irq_reg].uio_info[i] = NULL;
      }

      for (i = 0; i < NUM_BITS_IN_WORD; i++) {
         if (interrupt_mask & (1 << i)) {
            struct uio_info *info = kzalloc(sizeof(struct uio_info), GFP_KERNEL);
            if (!info) {
               dev_err(dev, "failed to allocate UIO device\n");
               err = -ENOMEM;
               goto err_out;
            }
            snprintf(priv->irq_info[irq_reg].uio_names[i],
                     sizeof(priv->irq_info[irq_reg].uio_names[i]),
                     "uio-%s-%x-%d", pci_name(to_pci_dev(dev)), irq_reg, i);
            info->name = priv->irq_info[irq_reg].uio_names[i];
            info->version = "0.0.1";
            info->irq = UIO_IRQ_CUSTOM;

            err = uio_register_device(dev, info);
            if (err) {
               dev_err(dev, "failed to register UIO device (%d)\n", err);
               kfree(info);
               goto err_out;
            }

            priv->irq_info[irq_reg].uio_info[i] = info;
         }
      }
   }

   if (priv->msi_rearm_offset) {
      err = pci_enable_msi(to_pci_dev(dev));
      if (err) {
         dev_err(dev, "failed to enable msi (%d)\n", err);
         goto err_out;
      }
      pci_set_master(to_pci_dev(dev));
   }

   /* if interrupt_irq has been set, use it instead of pdev->irq */
   irq = (priv->interrupt_irq != SCD_UNINITIALIZED) ?
      priv->interrupt_irq : to_pci_dev(dev)->irq;

   err = request_irq(irq, scd_interrupt, IRQF_SHARED, SCD_MODULE_NAME, dev);
   if (err) {
      dev_err(dev, "failed to request irq %d (%d)\n", irq, err);
      goto err_out_misc_dereg;
   }

   if (priv->crc_error_irq != SCD_UNINITIALIZED) {
      err = request_irq(priv->crc_error_irq, scd_crc_error_interrupt, 0,
                        SCD_MODULE_NAME, dev);
      if (err) {
         dev_err(dev, "failed to request CRC error IRQ %lu (%d)\n",
                 priv->crc_error_irq, err);
         goto err_out_free_irq;
      }
   }

   // enable power loss interrupts
   for(irq_reg = 0; irq_reg < SCD_NUM_IRQ_REGISTERS; irq_reg++) {
      if(priv->irq_info[irq_reg].interrupt_mask_powerloss &&
         priv->irq_info[irq_reg].interrupt_mask_clear_offset) {
         iowrite32(priv->irq_info[irq_reg].interrupt_mask_powerloss, priv->mem +
                   priv->irq_info[irq_reg].interrupt_mask_clear_offset);
      }
   }

   // enable watchdog interrupts
   for(irq_reg = 0; irq_reg < SCD_NUM_IRQ_REGISTERS; irq_reg++) {
      if(priv->irq_info[irq_reg].interrupt_mask_watchdog &&
         priv->irq_info[irq_reg].interrupt_mask_clear_offset) {
         iowrite32(priv->irq_info[irq_reg].interrupt_mask_watchdog, priv->mem +
                   priv->irq_info[irq_reg].interrupt_mask_clear_offset);
      }
   }

   // ardma probe
   if (priv->ardma_offset && scd_ardma_ops) {
      scd_ardma_ops->probe(priv->pdev, (void*)priv->mem,
         priv->ardma_offset,
         priv->localbus,
         priv->irq_info[0].interrupt_mask_ardma,
         priv->irq_info[0].interrupt_mask_read_offset,
         priv->irq_info[0].interrupt_mask_set_offset,
         priv->irq_info[0].interrupt_mask_clear_offset);
   }

   list_for_each_entry(ext, &scd_extensions, list) {
      // scd_extension init_trigger
      if (ext->ops->init_trigger) {
         ext->ops->init_trigger(priv->pdev);
      }
      // scd_extension finish_init
      if (ext->ops->finish_init) {
         ext->ops->finish_init(priv->pdev);
      }
   }

   // interrupt polling
   if( priv->interrupt_poll != SCD_UNINITIALIZED ) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
      setup_timer(&priv->intr_poll_timer, scd_interrupt_poll, (unsigned long)priv);
#else
      timer_setup(&priv->intr_poll_timer, scd_interrupt_poll, 0);
#endif
      priv->intr_poll_timer.expires = jiffies + INTR_POLL_INTERVAL;
      add_timer( &priv->intr_poll_timer );
   }

   // If using MSI rearm message generation
   if (priv->msi_rearm_offset) {
      iowrite32(1, priv->mem + priv->msi_rearm_offset);
   }

   // verify that the scd is actually programmed by performing a sanity check
   // on the revision register
   scd_ver = ioread32( priv->mem + SCD_REVISION_OFFSET );
   if (scd_ver == SCD_UNINITIALIZED) {
      dev_err(dev, "scd is not programmed\n");
      err = -ENODEV;
      goto err_out_free_irq;
   }

   // Register scd nmi handler
   if (priv == nmi_priv && !priv->nmi_registered) {
      err = scd_register_nmi_handler();
      if (err) {
         dev_err(dev, "scd_register_nmi_handler() failed (%d)\n", err);
         goto err_out_free_irq;
      }
   }

   dev_info(dev, "scd device initialization complete\n");
   return 0;

err_out_free_irq:
   free_irq(irq, dev);

err_out_misc_dereg:
   if (priv->msi_rearm_offset) {
      pci_disable_msi(to_pci_dev(dev));
   }

err_out:
   for(irq_reg = 0; irq_reg < SCD_NUM_IRQ_REGISTERS; irq_reg++) {
      for (i = 0; i < NUM_BITS_IN_WORD; i++) {
         if (priv->irq_info[irq_reg].uio_info[i]) {
            uio_unregister_device(priv->irq_info[irq_reg].uio_info[i]);
            kfree(priv->irq_info[irq_reg].uio_info[i]);
            priv->irq_info[irq_reg].uio_info[i] = NULL;
         }
      }
   }
   dev_err( dev, "scd device initialization failed with error %d", err );
   return err;
}

static ssize_t show_attr(struct scd_dev_priv *priv, unsigned long *value, char *buf)
{
   ssize_t ret;

   /* The pointer value points out to a mapped memory region of SCD
    * and accessing through it has to be protected with scd_mutex.
    */
   scd_lock();
   ret = sprintf(buf, "%lu\n", *value);
   scd_unlock();

   return ret;
}

static ssize_t store_attr(struct device *dev, const char *name,
                          unsigned long *value, const char *buf, size_t count)
{
   struct scd_dev_priv *priv = dev_get_drvdata(dev);
   unsigned long new_value = simple_strtoul(buf, NULL, 10);
   scd_lock();
   if (!priv->initialized) {
      *value = new_value;
   } else if (new_value != *value) {
      dev_warn(dev, "attempt to change %s after device initialized\n", name);
   }
   scd_unlock();
   return count;
}

#define SCD_DEVICE_ATTR(_name)                                          \
static ssize_t show_##_name(struct device *dev,                         \
                            struct device_attribute *attr,              \
                            char *buf)                                  \
{                                                                       \
   struct scd_dev_priv *priv = dev_get_drvdata(dev);                    \
   return show_attr(priv, &priv->_name, buf);                           \
}                                                                       \
static ssize_t store_##_name(struct device *dev,                        \
                             struct device_attribute *attr,             \
                             const char *buf, size_t count)             \
{                                                                       \
   struct scd_dev_priv *priv = dev_get_drvdata(dev);                    \
   return store_attr(dev, #_name, &priv->_name, buf, count);            \
}                                                                       \
static DEVICE_ATTR(_name, S_IRUGO|S_IWUSR|S_IWGRP, show_##_name, store_##_name);


#define SCD_IRQ_DEVICE_ATTR(_name, _num)                                \
static ssize_t show_##_name##_num(struct device *dev,                   \
                                  struct device_attribute *attr,        \
                                  char *buf)                            \
{                                                                       \
   struct scd_dev_priv *priv = dev_get_drvdata(dev);                    \
   return show_attr(priv, &priv->irq_info[_num]._name, buf);            \
}                                                                       \
static ssize_t store_##_name##_num(struct device *dev,                  \
                                   struct device_attribute *attr,       \
                                   const char *buf, size_t count)       \
{                                                                       \
   struct scd_dev_priv *priv = dev_get_drvdata(dev);                    \
   return store_attr(dev, #_name #_num,                                 \
                     &priv->irq_info[_num]._name, buf, count);          \
}                                                                       \
static DEVICE_ATTR(_name##_num, S_IRUGO|S_IWUSR|S_IWGRP,                \
                   show_##_name##_num, store_##_name##_num);

#define SCD_IRQ_ATTRS(num)                              \
SCD_IRQ_DEVICE_ATTR(interrupt_status_offset, num);      \
SCD_IRQ_DEVICE_ATTR(interrupt_mask_read_offset, num);   \
SCD_IRQ_DEVICE_ATTR(interrupt_mask_set_offset, num);    \
SCD_IRQ_DEVICE_ATTR(interrupt_mask_clear_offset, num);  \
SCD_IRQ_DEVICE_ATTR(interrupt_mask, num);               \
SCD_IRQ_DEVICE_ATTR(interrupt_mask_powerloss, num);     \
SCD_IRQ_DEVICE_ATTR(interrupt_mask_watchdog, num);      \
SCD_IRQ_DEVICE_ATTR(interrupt_mask_ardma, num); \
SCD_IRQ_DEVICE_ATTR(interrupt_valid_addr, num); \
SCD_IRQ_DEVICE_ATTR(interrupt_valid_val, num); \
SCD_IRQ_DEVICE_ATTR(interrupt_valid_mask, num);

#define SCD_IRQ_ATTRS_POINTERS(num)                     \
&dev_attr_interrupt_status_offset##num.attr,            \
&dev_attr_interrupt_mask_read_offset##num.attr,         \
&dev_attr_interrupt_mask_set_offset##num.attr,          \
&dev_attr_interrupt_mask_clear_offset##num.attr,        \
&dev_attr_interrupt_mask##num.attr,                     \
&dev_attr_interrupt_mask_powerloss##num.attr,           \
&dev_attr_interrupt_mask_watchdog##num.attr,            \
&dev_attr_interrupt_mask_ardma##num.attr, \
&dev_attr_interrupt_valid_addr##num.attr, \
&dev_attr_interrupt_valid_val##num.attr, \
&dev_attr_interrupt_valid_mask##num.attr

u32
scd_read_register(struct pci_dev *pdev, u32 offset)
{
   void __iomem *reg;
   u32 res = 0;
   struct scd_dev_priv *priv;

   priv = pci_get_drvdata(pdev);
   ASSERT( priv );
   ASSERT( offset < priv->mem_len );
   if (priv) {
      reg = priv->mem + offset;
      res = ioread32(reg);
   }
   dev_dbg(&pdev->dev, "io:read 0x%04x => 0x%08x", offset, res);
   return res;
}
EXPORT_SYMBOL(scd_read_register);

void
scd_write_register(struct pci_dev *pdev, u32 offset, u32 val)
{
   void __iomem *reg;
   struct scd_dev_priv *priv;

   priv = pci_get_drvdata(pdev);
   ASSERT( priv );
   ASSERT( offset < priv->mem_len );
   dev_dbg(&pdev->dev, "io:write 0x%04x <= 0x%08x", offset, val);
   if (priv) {
      reg = priv->mem + offset;
      iowrite32(val, reg);
   }
}
EXPORT_SYMBOL(scd_write_register);

// scd_list_lock mutex is not held in this function.
// scd_lock mutex is not held in this function.
u64
scd_ptp_timestamp(void)
{
   unsigned long ptp_lock_flags;
   u64 ts = 0;
   u32 low = 0;
   u32 high = 0;
   struct scd_dev_priv *priv = ptp_master_priv;

   spin_lock_irqsave(&scd_ptp_lock, ptp_lock_flags);

   if (priv && priv->initialized && (priv->ptp_offset_valid != SCD_UNINITIALIZED)) {
      ASSERT(priv->ptp_low_offset != SCD_UNINITIALIZED);
      ASSERT(priv->ptp_high_offset != SCD_UNINITIALIZED);
      // Reading the high register also latches the current time into the low
      // register, so we don't need any special handling of the rollover case.
      high = ioread32(priv->mem + priv->ptp_high_offset);
      low = ioread32(priv->mem + priv->ptp_low_offset);
      ts = (((u64)high) << 32) | low;
   }

   spin_unlock_irqrestore(&scd_ptp_lock, ptp_lock_flags);
   if (ts == 0)
      printk(KERN_INFO "%s %s returned zero\n", SCD_MODULE_NAME, __FUNCTION__);

   return ts;
}
EXPORT_SYMBOL(scd_ptp_timestamp);

static ssize_t show_init_trigger(struct device *dev, struct device_attribute *attr,
                                 char *buf)
{
   struct scd_dev_priv *priv = dev_get_drvdata(dev);
   return show_attr(priv, &priv->init_error, buf);
}

static ssize_t store_init_trigger(struct device *dev, struct device_attribute *attr,
                                  const char *buf, size_t count)
{
   struct scd_dev_priv *priv;
   int error = 0;

   priv = dev_get_drvdata(dev);

   scd_lock();

   // If private data is dead, return
   if( priv->magic != SCD_MAGIC ) {
      scd_unlock();
      return -ENODEV;
   }

   if (!priv->initialized) {
      if (!(error = scd_finish_init(dev))) {
         priv->initialized = 1;
      }
   }

   // Save the error code from scd_finish_init.
   // We flip this back to positive so that the conversion to unsigned won't
   // produce weird, hard to read values
   priv->init_error = -error;

   scd_unlock();

   return error ? error : count;
}

static ssize_t scd_set_debug(struct device *dev, struct device_attribute *attr,
                             const char *buf, size_t count) {
    sscanf( buf, "%d", &debug );
    return count;
}

static ssize_t scd_set_ptp_offset_valid(struct device *dev,
                                        struct device_attribute *attr,
                                        const char *buf, size_t count) {

   struct scd_dev_priv *priv = dev_get_drvdata(dev);
   unsigned long valid = simple_strtoul(buf, NULL, 10);

   scd_lock();
   if (!priv->initialized) {
      priv->ptp_offset_valid = valid;
      if((priv->ptp_offset_valid != SCD_UNINITIALIZED) && !ptp_master_priv) {
         ptp_master_priv = priv;
      }
   } else if (priv->ptp_offset_valid != valid) {
      dev_warn(dev, "attempt to change ptp_offset_valid after device initialized\n");
   }
   scd_unlock();
   return count;
}

static ssize_t scd_set_nmi_control_reg_addr(struct device *dev,
                                            struct device_attribute *attr,
                                            const char *buf, size_t count) {

   struct scd_dev_priv *priv = dev_get_drvdata(dev);
   unsigned long value = (unsigned int)simple_strtoul(buf, NULL, 10);
   scd_lock();
   if (!priv->initialized) {
      if (nmi_priv && priv != nmi_priv) {
         dev_err(dev, "Multiple devices attempting to set NMI attributes\n");
         scd_unlock();
         return count;
      }
      if (value != SCD_UNINITIALIZED && !nmi_priv) {
         nmi_priv = priv;
      }
      priv->nmi_control_reg_addr = value;
   } else if (priv->nmi_control_reg_addr != value) {
      dev_warn(dev,
               "attempt to change nmi_control_reg_addr after device initialized\n");
   }
   scd_unlock();
   return count;
}


static DEVICE_ATTR(init_trigger, S_IRUGO|S_IWUSR|S_IWGRP,
                   show_init_trigger, store_init_trigger);
static DEVICE_ATTR(debug, S_IWUSR|S_IWGRP, NULL, scd_set_debug);
static DEVICE_ATTR(ptp_offset_valid, S_IWUSR|S_IWGRP,
                   NULL, scd_set_ptp_offset_valid);
static DEVICE_ATTR(nmi_control_reg_addr, S_IWUSR|S_IWGRP,
                   NULL, scd_set_nmi_control_reg_addr);

SCD_DEVICE_ATTR(crc_error_irq);
SCD_DEVICE_ATTR(ptp_high_offset);
SCD_DEVICE_ATTR(ptp_low_offset);
SCD_DEVICE_ATTR(msi_rearm_offset);
SCD_DEVICE_ATTR(interrupt_irq);
SCD_DEVICE_ATTR(ardma_offset);
SCD_DEVICE_ATTR(interrupt_poll);

SCD_DEVICE_ATTR(nmi_port_io_p);
SCD_DEVICE_ATTR(nmi_control_mask);
SCD_DEVICE_ATTR(nmi_status_reg_addr);
SCD_DEVICE_ATTR(nmi_status_mask);
SCD_DEVICE_ATTR(nmi_gpio_status_reg_addr);
SCD_DEVICE_ATTR(nmi_gpio_status_mask);

/* the number of SCD_IRQ_ATTRS() must match SCD_NUM_IRQ_REGISTERS above */
SCD_IRQ_ATTRS(0);
SCD_IRQ_ATTRS(1);
SCD_IRQ_ATTRS(2);
SCD_IRQ_ATTRS(3);
SCD_IRQ_ATTRS(4);
SCD_IRQ_ATTRS(5);
SCD_IRQ_ATTRS(6);
SCD_IRQ_ATTRS(7);
SCD_IRQ_ATTRS(8);
SCD_IRQ_ATTRS(9);
SCD_IRQ_ATTRS(10);
SCD_IRQ_ATTRS(11);
SCD_IRQ_ATTRS(12);
SCD_IRQ_ATTRS(13);
SCD_IRQ_ATTRS(14);
SCD_IRQ_ATTRS(15);
SCD_IRQ_ATTRS(16);
SCD_IRQ_ATTRS(17);
SCD_IRQ_ATTRS(18);
SCD_IRQ_ATTRS(19);

static struct attribute *scd_attrs[] = {
   SCD_IRQ_ATTRS_POINTERS(0),
   SCD_IRQ_ATTRS_POINTERS(1),
   SCD_IRQ_ATTRS_POINTERS(2),
   SCD_IRQ_ATTRS_POINTERS(3),
   SCD_IRQ_ATTRS_POINTERS(4),
   SCD_IRQ_ATTRS_POINTERS(5),
   SCD_IRQ_ATTRS_POINTERS(6),
   SCD_IRQ_ATTRS_POINTERS(7),
   SCD_IRQ_ATTRS_POINTERS(8),
   SCD_IRQ_ATTRS_POINTERS(9),
   SCD_IRQ_ATTRS_POINTERS(10),
   SCD_IRQ_ATTRS_POINTERS(11),
   SCD_IRQ_ATTRS_POINTERS(12),
   SCD_IRQ_ATTRS_POINTERS(13),
   SCD_IRQ_ATTRS_POINTERS(14),
   SCD_IRQ_ATTRS_POINTERS(15),
   SCD_IRQ_ATTRS_POINTERS(16),
   SCD_IRQ_ATTRS_POINTERS(17),
   SCD_IRQ_ATTRS_POINTERS(18),
   SCD_IRQ_ATTRS_POINTERS(19),
   &dev_attr_crc_error_irq.attr,
   &dev_attr_ptp_high_offset.attr,
   &dev_attr_ptp_low_offset.attr,
   &dev_attr_msi_rearm_offset.attr,
   &dev_attr_interrupt_irq.attr,
   &dev_attr_ardma_offset.attr,
   &dev_attr_init_trigger.attr,
   &dev_attr_interrupt_poll.attr,
   &dev_attr_debug.attr,
   &dev_attr_nmi_port_io_p.attr,
   &dev_attr_nmi_control_reg_addr.attr,
   &dev_attr_nmi_control_mask.attr,
   &dev_attr_nmi_status_reg_addr.attr,
   &dev_attr_nmi_status_mask.attr,
   &dev_attr_nmi_gpio_status_reg_addr.attr,
   &dev_attr_nmi_gpio_status_mask.attr,
   &dev_attr_ptp_offset_valid.attr,
   NULL,
};

static struct attribute_group scd_attr_group = {
   .attrs = scd_attrs,
};

static void scd_pci_disable(struct pci_dev *pdev)
{
   struct scd_dev_priv *priv = pci_get_drvdata(pdev);

   if (priv->localbus) {
      pci_iounmap(pdev, priv->localbus);
      pci_release_region(pdev, SCD_BAR_1);
      priv->localbus = NULL;
   }

   if (priv->mem) {
      pci_iounmap(pdev, priv->mem);
      pci_release_region(pdev, SCD_BAR_REGS);
      priv->mem = NULL;
   }

   pci_disable_device(pdev);
}

static int
scd_pci_enable(struct pci_dev *pdev)
{
   struct scd_dev_priv *priv = pci_get_drvdata(pdev);
   int err;
   u16 ssid;

   err = pci_enable_device(pdev);
   if (err) {
      dev_err(&pdev->dev, "cannot enable PCI device (%d)\n", err);
      goto out;
   }

   err = pci_request_region(pdev, SCD_BAR_REGS, SCD_MODULE_NAME);
   if (err) {
      dev_err(&pdev->dev, "cannot obtain PCI memory region (%d)\n", err);
      goto out_disable;
   }

   priv->mem = pci_iomap(pdev, SCD_BAR_REGS, 0);
   if (!priv->mem) {
      dev_err(&pdev->dev, "cannot remap PCI memory region\n");
      err = -ENXIO;
      goto out_release_bar_regs;
   }

   priv->mem_len = pci_resource_len(pdev, SCD_BAR_REGS);

   // check if this device uses partial reconfiguration to load the scd image
   pci_read_config_word(pdev, PCI_SUBSYSTEM_ID, &ssid);
   if (ssid == RECONFIG_PCI_SUBSYSTEM_ID) {
      priv->is_reconfig = true;
   } else {
      if (pci_resource_flags(pdev, SCD_BAR_1) & IORESOURCE_MEM) {
         err = pci_request_region(pdev, SCD_BAR_1, SCD_MODULE_NAME);
         if (err) {
            dev_err(&pdev->dev, "cannot obtain PCI memory region 1 (%d)\n", err);
            goto out_unmap_bar_regs;
         }
         priv->localbus = pci_iomap(pdev, SCD_BAR_1, 0);
         if (!priv->localbus) {
            dev_err(&pdev->dev, "cannot remap memory region 1\n");
            err = -ENXIO;
            goto out_release_bar_1;
         }
      }
   }

   return 0;

out_release_bar_1:
   pci_release_region(pdev, SCD_BAR_1);

out_unmap_bar_regs:
   pci_iounmap(pdev, priv->mem);
   priv->mem = NULL;

out_release_bar_regs:
   pci_release_region(pdev, SCD_BAR_REGS);

out_disable:
   pci_disable_device(pdev);

out:
   return err;
}

static const struct scd_driver_cb scd_pci_cb = {
   .enable = scd_pci_enable,
   .disable = scd_pci_disable,
};

static int scd_lpc_enable(struct pci_dev *pdev);
static void scd_lpc_disable(struct pci_dev *pdev);
static const struct scd_driver_cb scd_lpc_cb = {
   .enable = scd_lpc_enable,
   .disable = scd_lpc_disable,
};

static struct pci_device_id scd_lpc_table[] = {
   { PCI_DEVICE( AMD_PCI_VENDOR_ID, AMD_PCI_EKABINI_18F5_DEVICE_ID ) },
   { PCI_DEVICE( AMD_PCI_VENDOR_ID, AMD_PCI_STEPPEEAGLE_18F5_DEVICE_ID ) },
   { PCI_DEVICE( INTEL_PCI_VENDOR_ID, INTEL_PCI_BROADWELL_DEVICE_ID ) },
   { PCI_DEVICE( AMD_PCI_VENDOR_ID, AMD_PCI_MERLINFALCON_157D_DEVICE_ID ) },
   { PCI_DEVICE( AMD_PCI_VENDOR_ID, AMD_PCI_SNOWYOWL_1467_DEVICE_ID ) },
   { PCI_DEVICE( AMD_PCI_VENDOR_ID, AMD_PCI_V1000_15EF_DEVICE_ID ) },
   { 0 },
};

//
// the LPC driver takes three parameters
//    scd.lpc_res_addr - beginning of the LPC physical memory
//    scd.lpc_res_size - size of the LPC block, in 4K increments
//    scd.lpc_irq - assigned interrupt number
// this driver uses the LPC-ISA bridge available in the AMD-Kabini chip
// as the PCI device to export the resource0 for EOS application code to
// map.
static unsigned long lpc_res_addr;
module_param(lpc_res_addr, long, 0);
MODULE_PARM_DESC(lpc_res_addr, "physical address of LPC resource");
static int lpc_res_size;
module_param(lpc_res_size, int, 0);
MODULE_PARM_DESC(lpc_res_size, "size of LPC resource");
static int lpc_irq = -1;
module_param(lpc_irq, int, 0);
MODULE_PARM_DESC(lpc_irq, "interrupt of LPC SCD");
static const struct scd_driver_cb scd_lpc_cb;

static int scd_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
   struct scd_dev_priv *priv;
   struct scd_extension *ext;
   u32 fpga_rev, board_rev;
   int err;
   const struct scd_driver_cb *scd_cb;

   if (pci_match_id(scd_lpc_table, pdev)) {
      // matched LPC device
      if (!((lpc_irq >= 0) || lpc_res_addr || lpc_res_size)) {
         // nothing is enabled, we are not running in LPC mode, return
         return -ENODEV;
      }

      if (lpc_irq < 0) {
         dev_err(&pdev->dev, "Invalid LPC interrupt %d", lpc_irq);
         return -EINVAL;
      }

      if (!lpc_res_addr) {
         dev_err(&pdev->dev, "No LPC scd address specified");
         return -EINVAL;
      }

      if (!lpc_res_size) {
         dev_err(&pdev->dev, "No LPC scd size specified");
         return -EINVAL;
      }
      scd_cb = &scd_lpc_cb;
   } else {
      scd_cb = &scd_pci_cb;
   }

   if (pci_get_drvdata(pdev)) {
      dev_warn(&pdev->dev, "private data already attached %p",
               pci_get_drvdata(pdev));
   }

   priv = kmalloc(sizeof(struct scd_dev_priv), GFP_KERNEL);
   if (priv == NULL)  {
      dev_err(&pdev->dev, "cannot allocate private data, aborting\n");
      err = -ENOMEM;
      goto fail;
   }

   memset(priv, 0, sizeof (struct scd_dev_priv));
   INIT_LIST_HEAD(&priv->list);
   priv->pdev = pdev;
   priv->crc_error_irq = SCD_UNINITIALIZED;
   priv->interrupt_irq = SCD_UNINITIALIZED;
   priv->interrupt_poll = SCD_UNINITIALIZED;
   priv->ptp_high_offset = SCD_UNINITIALIZED;
   priv->ptp_low_offset = SCD_UNINITIALIZED;
   priv->ptp_offset_valid = SCD_UNINITIALIZED;

   priv->nmi_port_io_p = SCD_UNINITIALIZED;
   priv->nmi_control_reg_addr = SCD_UNINITIALIZED;
   priv->nmi_control_reg = NULL;
   priv->nmi_control_mask = SCD_UNINITIALIZED;
   priv->nmi_status_reg_addr = SCD_UNINITIALIZED;
   priv->nmi_status_reg = NULL;
   priv->nmi_status_mask = SCD_UNINITIALIZED;
   priv->nmi_gpio_status_reg_addr = SCD_UNINITIALIZED;
   priv->nmi_gpio_status_reg = NULL;
   priv->nmi_gpio_status_mask = SCD_UNINITIALIZED;
   priv->nmi_registered = false;

   priv->magic = SCD_MAGIC;
   priv->localbus = NULL;
   priv->driver_cb = scd_cb;

   pci_set_drvdata(pdev, priv);

   err = scd_cb->enable(pdev);
   if (err) {
      goto fail;
   }

   err = sysfs_create_group(&pdev->dev.kobj, &scd_attr_group);
   if (err) {
      dev_err(&pdev->dev, "sysfs_create_group() error %d\n", err);
      goto fail;
   }
   priv->sysfs_initialized = 1;
   priv->initialized = 0;

   // add to our list
   scd_lock();
   list_add_tail(&priv->list, &scd_list);
   list_for_each_entry(ext, &scd_extensions, list) {
      if (ext->ops->probe) {
         ext->ops->probe(priv->pdev, priv->mem_len);
      }
   }
   scd_unlock();

   priv->revision = ioread32(priv->mem + SCD_REVISION_OFFSET);
   fpga_rev = (priv->revision & 0xffff0000) >> 16;
   board_rev = priv->revision & 0x00000fff;

   if (priv->is_reconfig && (priv->revision==RECONFIG_STATE_BAR_VALUE)) {
      dev_info(&pdev->dev, "scd detected\n   FPGA in reconfig state\n");
   } else {
      dev_info(&pdev->dev, "scd detected\n   FPGA revision %d, board revision %d\n",
               fpga_rev, board_rev);
   }

   return 0;

fail:
   scd_remove(pdev);

   return err;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static void scd_interrupt_poll(unsigned long data)
{
   struct scd_dev_priv *dev = (struct scd_dev_priv *)data;
#else
static void scd_interrupt_poll(struct timer_list *t)
{
   struct scd_dev_priv *dev = from_timer(dev, t, intr_poll_timer);
#endif
   struct pci_dev * pdev = dev->pdev;
   scd_interrupt( 0, ( void* ) &pdev->dev );
   dev->intr_poll_timer.expires = jiffies + INTR_POLL_INTERVAL;
   add_timer( &dev->intr_poll_timer );
}

static void scd_remove(struct pci_dev *pdev)
{
   struct scd_dev_priv *priv = pci_get_drvdata(pdev);
   struct scd_extension *ext;
   unsigned int irq;
   int i;
   u32 irq_reg;

   dev_info(&pdev->dev, "scd removed\n");

   if (priv == NULL)
      return;

   spin_lock(&scd_ptp_lock);
   if(ptp_master_priv == priv) {
      ptp_master_priv = NULL;
   }
   spin_unlock(&scd_ptp_lock);

   scd_lock();

   if (priv == nmi_priv) {
      if (priv->nmi_registered) {
         unregister_nmi_handler(NMI_LOCAL, "WATCHDOG_NMI");
         priv->nmi_registered = false;
      }
      nmi_priv = NULL;
   }

   // call ardma remove() if scd has ardma
   if (priv->initialized && priv->ardma_offset && scd_ardma_ops) {
      scd_ardma_ops->remove(pdev);
   }

   // call scd_extension remove callback
   list_for_each_entry(ext, &scd_extensions, list) {
      if (ext->ops->remove) {
         ext->ops->remove(priv->pdev);
      }
   }

   //stop interrupt polling if we've initialized it
   if( priv->interrupt_poll != SCD_UNINITIALIZED ) {
      del_timer_sync( &priv->intr_poll_timer );
   }

   // remove from our list
   list_del_init(&priv->list);

   irq = (priv->interrupt_irq != SCD_UNINITIALIZED) ?
      priv->interrupt_irq : pdev->irq;

   if (priv->initialized) {
      scd_mask_interrupts(priv);
      free_irq(irq, &pdev->dev);
      if (priv->crc_error_irq != SCD_UNINITIALIZED)
         free_irq(priv->crc_error_irq, &pdev->dev);
      if (priv->msi_rearm_offset) {
         pci_disable_msi(pdev);
      }
   }

   // call pci bits to release
   priv->driver_cb->disable( pdev );

   if (priv->initialized) {
      for(irq_reg = 0; irq_reg < SCD_NUM_IRQ_REGISTERS; irq_reg++) {
         for (i = 0; i < NUM_BITS_IN_WORD; i++) {
            if (priv->irq_info[irq_reg].uio_info[i]) {
               uio_unregister_device(priv->irq_info[irq_reg].uio_info[i]);
               kfree(priv->irq_info[irq_reg].uio_info[i]);
               priv->irq_info[irq_reg].uio_info[i] = NULL;
            }
         }
      }
   }
   priv->magic = 0;

   // release lock before removing sysfs to avoid deadlocks
   scd_unlock();

   if (priv->sysfs_initialized) {
      sysfs_remove_group(&pdev->dev.kobj, &scd_attr_group);
   }

   ASSERT( !priv->localbus );
   ASSERT( !priv->mem );
   if( priv->initialized ) {
      for(irq_reg = 0; irq_reg < SCD_NUM_IRQ_REGISTERS; irq_reg++) {
         for (i = 0; i < NUM_BITS_IN_WORD; i++) {
            ASSERT( !priv->irq_info[irq_reg].uio_info[i] );
         }
      }
   }

   pci_set_drvdata(pdev, NULL);
   memset(priv, 0, sizeof (struct scd_dev_priv));

   kfree(priv);
}

static void scd_shutdown(struct pci_dev *pdev) {
   struct scd_dev_priv *priv = pci_get_drvdata(pdev);
   dev_info(&pdev->dev, "scd shutdown\n");
   scd_mask_interrupts(priv);

   // call ardma shutdown() if scd has ardma
   if (priv->initialized && priv->ardma_offset && scd_ardma_ops) {
      scd_ardma_ops->shutdown(pdev);
   }
}

static void scd_mask_interrupts(struct scd_dev_priv *priv) {
   u32 i;

   if (priv == NULL || !priv->initialized) {
      return;
   }

   for (i = 0; i < SCD_NUM_IRQ_REGISTERS; i++) {
      if (priv->irq_info[i].interrupt_mask_set_offset) {
         iowrite32(0xffffffff,
                   priv->mem + priv->irq_info[i].interrupt_mask_set_offset);
         // stall until previous write completes
         (void) ioread32(priv->mem + priv->irq_info[i].interrupt_mask_set_offset);
      }
   }
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
static pci_ers_result_t scd_error_detected(struct pci_dev *pdev,
                                           enum pci_channel_state state) {
#else
static pci_ers_result_t scd_error_detected(struct pci_dev *pdev,
                                           pci_channel_state_t state) {
#endif
   dev_err(&pdev->dev, "error detected (state=%d)\n", state);
   return PCI_ERS_RESULT_DISCONNECT;
}

static struct pci_device_id scd_pci_table[] = {
   { PCI_DEVICE( SCD_PCI_VENDOR_ID, SCD_PCI_DEVICE_ID ) },
   { PCI_DEVICE( AMD_PCI_VENDOR_ID, AMD_PCI_EKABINI_18F5_DEVICE_ID ) },
   { PCI_DEVICE( AMD_PCI_VENDOR_ID, AMD_PCI_STEPPEEAGLE_18F5_DEVICE_ID ) },
   { PCI_DEVICE( INTEL_PCI_VENDOR_ID, INTEL_PCI_BROADWELL_DEVICE_ID ) },
   { PCI_DEVICE( AMD_PCI_VENDOR_ID, AMD_PCI_MERLINFALCON_157D_DEVICE_ID ) },
   { PCI_DEVICE( AMD_PCI_VENDOR_ID, AMD_PCI_SNOWYOWL_1467_DEVICE_ID ) },
   { PCI_DEVICE( AMD_PCI_VENDOR_ID, AMD_PCI_V1000_15EF_DEVICE_ID ) },
   { 0, },
};

static int scd_dump(struct seq_file *m, void *p) {
   struct scd_dev_priv *priv;
   u32 irq_reg;
   int i;
   unsigned long uio_count;

   scd_lock();
   seq_printf(m, "\ndebug 0x%x\n\n", debug);

   list_for_each_entry(priv, &scd_list, list) {
      if(priv->magic == SCD_MAGIC) {
         seq_printf(m, "scd %s\n", pci_name(priv->pdev));

         seq_printf(m, "revision 0x%x revision_error_reports %u\n",
                       priv->revision,
                       priv->revision_error_reports);

         seq_printf(m, "initialized %d sysfs_initialized %d"
                       " interrupt_poll %lu magic 0x%x"
                       " is_reconfig %d\n", priv->initialized,
                                            priv->sysfs_initialized,
                                            priv->interrupt_poll,
                                            priv->magic,
                                            priv->is_reconfig);

         seq_printf(m, "ptp_offset_valid 0x%lx ptp_high_offset 0x%lx"
                    " ptp_low_offset 0x%lx ardma_offset %lu msi_rearm_offset %lu\n",
                    priv->ptp_offset_valid, priv->ptp_high_offset,
                    priv->ptp_low_offset, priv->ardma_offset,
                    priv->msi_rearm_offset);

         seq_printf(m, "nmi_port_io_p 0x%lx nmi_control_reg_addr 0x%lx "
                    "nmi_control_mask 0x%lx\nnmi_status_reg_addr 0x%lx "
                    "nmi_status_mask 0x%lx nmi_gpio_status_reg_addr 0x%lx\n"
                    "nmi_gpio_status_mask 0x%lx nmi_registered %d "
                    "nmi_disabled %d\n",
                    priv->nmi_port_io_p, priv->nmi_control_reg_addr,
                    priv->nmi_control_mask, priv->nmi_status_reg_addr,
                    priv->nmi_status_mask, priv->nmi_gpio_status_reg_addr,
                    priv->nmi_gpio_status_mask, priv->nmi_registered,
                    nmi_disabled);

         for(irq_reg = 0; irq_reg < SCD_NUM_IRQ_REGISTERS; irq_reg++) {
            if(!priv->irq_info[irq_reg].interrupt_status_offset ||
               !priv->irq_info[irq_reg].interrupt_mask_read_offset ||
               !priv->irq_info[irq_reg].interrupt_mask_set_offset) {
                continue;
            }
            seq_printf(m, "interrupt register %u:\n", irq_reg);
            seq_printf(m, "interrupt_status_offset 0x%lx "
                          "interrupt_mask_read_offset 0x%lx "
                          "interrupt_mask_set_offset 0x%lx\n"
                          "interrupt_mask_clear_offset 0x%lx "
                          "interrupt_mask 0x%lx "
                          "interrupt_mask_power_loss 0x%lx\n"
                          "interrupt_mask_watchdog 0x%lx "
                          "ardma_interrupt_mask 0x%lx "
                          "interrupt_valid_addr 0x%lx "
                          "interrupt_valid_val 0x%lx "
                          "interrupt_valid_mask 0x%lx\n",
                       priv->irq_info[irq_reg].interrupt_status_offset,
                       priv->irq_info[irq_reg].interrupt_mask_read_offset,
                       priv->irq_info[irq_reg].interrupt_mask_set_offset,
                       priv->irq_info[irq_reg].interrupt_mask_clear_offset,
                       priv->irq_info[irq_reg].interrupt_mask,
                       priv->irq_info[irq_reg].interrupt_mask_powerloss,
                       priv->irq_info[irq_reg].interrupt_mask_watchdog,
                       priv->irq_info[irq_reg].interrupt_mask_ardma,
                       priv->irq_info[irq_reg].interrupt_valid_addr,
                       priv->irq_info[irq_reg].interrupt_valid_val,
                       priv->irq_info[irq_reg].interrupt_valid_mask);

         }

         seq_printf(m, "irq %u\n", priv->pdev->irq );
         seq_printf(m, "interrupts %lu interrupts_claimed %lu\n",
                        priv->interrupts, priv->interrupt_claimed );

         seq_printf(m, "interrupt status bit counts:\n");

         for(irq_reg = 0; irq_reg < SCD_NUM_IRQ_REGISTERS; irq_reg++) {
            if(!priv->irq_info[irq_reg].interrupt_status_offset ||
               !priv->irq_info[irq_reg].interrupt_mask_read_offset ||
               !priv->irq_info[irq_reg].interrupt_mask_set_offset) {
                continue;
            }

            for (i = 0; i < NUM_BITS_IN_WORD; i++) {
               uio_count = priv->irq_info[irq_reg].uio_count[i];
               if(uio_count) {
                  seq_printf(m, "%d[%d] %lu\n", irq_reg, i, uio_count );
               }
            }

            if(priv->interrupt_ardma_cnt)
               seq_printf(m, "ardma interrupts %lu ", priv->interrupt_ardma_cnt);
            if(priv->interrupt_powerloss_cnt)
               seq_printf(m, "power loss interrupts %lu\n",
                              priv->interrupt_powerloss_cnt);
         }
      }
      seq_printf(m, "\n");
   }

   scd_unlock();
   return 0;
}

static int scd_dump_open( struct inode *inode, struct file *file ) {
   return single_open(file, scd_dump, NULL);
}

/*
 * commit 75a2d4226b53 ("driver core: class: mark the struct class for sysfs
 * callbacks as constant") in v6.4
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
static ssize_t disable_nmi_store(struct class *cls, struct class_attribute *attr,
                                const char *buf, size_t count)
#else
static ssize_t disable_nmi_store(const struct class *cls,
                                const struct class_attribute *attr,
                                const char *buf, size_t count)
#endif
{
   nmi_disabled = true;
   printk(KERN_INFO "Disabled SCD NMI handler\n");
   return count;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
static ssize_t crc_error_panic_store(struct class *cls,
                                     struct class_attribute *attr,
                                     const char *buf,
                                     size_t count)
#else
static ssize_t crc_error_panic_store(const struct class *cls,
                                     const struct class_attribute *attr,
                                     const char *buf,
                                     size_t count)
#endif
{
   int ret;

   ret = kstrtoint(buf, 10, &crc_error_panic);
   if (ret < 0) {
      return ret;
   }
   // value of the crc_error_panic is always 0 or 1
   if (crc_error_panic != 0) {
      crc_error_panic = 1;
   }
   return count;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
static struct class_attribute scd_class_attrs[] = {
   __ATTR_WO(disable_nmi),
   __ATTR_WO(crc_error_panic),
   __ATTR_NULL
};
#else
static CLASS_ATTR_WO(disable_nmi);
static CLASS_ATTR_WO(crc_error_panic);
static struct attribute *scd_class_attrs[] = {
   &class_attr_disable_nmi.attr,
   &class_attr_crc_error_panic.attr,
   NULL,
};
ATTRIBUTE_GROUPS(scd_class);
#endif

static struct class scd_class =
{
   .name = SCD_MODULE_NAME,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
   .class_attrs = scd_class_attrs,
#else
   .class_groups = scd_class_groups,
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
static const struct file_operations scd_dump_proc_ops = {
   .owner = THIS_MODULE,
   .open = scd_dump_open,
   .read = seq_read,
   .llseek = seq_lseek,
   .release = single_release,
};
#else
static const struct proc_ops scd_dump_proc_ops = {
   .proc_open = scd_dump_open,
   .proc_read = seq_read,
   .proc_lseek = seq_lseek,
   .proc_release = single_release,
};
#endif

static struct proc_dir_entry *scd_procfs_create(void) {
   return proc_create(SCD_MODULE_NAME, 0, NULL, &scd_dump_proc_ops);
}

static void scd_procfs_remove(void) {
   remove_proc_entry(SCD_MODULE_NAME, NULL);
}

MODULE_DEVICE_TABLE(pci, scd_pci_table);

static struct pci_error_handlers scd_error_handlers = {
   .error_detected = scd_error_detected,
};

static struct pci_driver scd_driver = {
   .name        = SCD_MODULE_NAME,
   .id_table    = scd_pci_table,
   .probe       = scd_probe,
   .remove      = scd_remove,
   .err_handler = &scd_error_handlers,
   .shutdown    = &scd_shutdown,
};

static int
scd_lpc_mmap_resource(struct file *filp, struct kobject *kobj,
                      struct bin_attribute *attr,
                      struct vm_area_struct *vma)
{
   struct pci_dev *pdev = to_pci_dev(container_of(kobj,
                                                  struct device, kobj));
   unsigned long prot;
   int rc;

   // validate range of mapping
   if ((vma->vm_pgoff + ((vma->vm_end - vma->vm_start) >> PAGE_SHIFT)) >
       (attr->size >> PAGE_SHIFT)) {
      dev_err(&pdev->dev, "invalid vm region addr 0x%lx-0x%lx offset pages %lu\n",
              vma->vm_start, vma->vm_end, vma->vm_pgoff);
      return -EINVAL;
   }

   vma->vm_pgoff += lpc_res_addr >> PAGE_SHIFT;
   prot = pgprot_val(vma->vm_page_prot);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
   prot |= _PAGE_CACHE_UC;
#else
   prot |= cachemode2protval(_PAGE_CACHE_MODE_UC);
#endif
   vma->vm_page_prot = __pgprot(prot);

   // map resource0 into user space
   rc = remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
                        vma->vm_end - vma->vm_start,
                        vma->vm_page_prot);
   if (rc) {
      dev_err(&pdev->dev, "resource mapping failed.  rc %d", rc);
   }

   return rc;
}

static int
scd_lpc_enable(struct pci_dev *pdev)
{
   struct scd_dev_priv *priv = pci_get_drvdata(pdev);
   struct bin_attribute *res_attr = NULL;
   int rc = 0;

   if (pdev->res_attr[0]) {
      dev_err(&pdev->dev, "Resources already attached at %d\n", 0);
      return -EINVAL;
   }

   // map address specified into kernel
   priv->mem = (void __iomem *)ioremap((unsigned int)lpc_res_addr, lpc_res_size);
   if (!priv->mem) {
      rc = -ENXIO;
      goto cleanup;
   }

   priv->mem_len = lpc_res_size;

   // save the irq for later use, application can still override later
   // by writing into /sys/devices/.../interrupt_irq
   priv->interrupt_irq = lpc_irq;

   priv->lpc_vendor = pdev->vendor;
   priv->lpc_device = pdev->device;
   pdev->vendor = SCD_PCI_VENDOR_ID;
   pdev->device = SCD_PCI_DEVICE_ID;

   // create the resource0 file for the scd
   res_attr = kzalloc(sizeof(*res_attr), GFP_ATOMIC);
   if (!res_attr) {
      rc = -ENOMEM;
      goto cleanup;
   }

   sysfs_bin_attr_init(res_attr);
   res_attr->attr.name = "resource0";
   res_attr->attr.mode = S_IRUSR | S_IWUSR;
   res_attr->size = lpc_res_size;
   res_attr->mmap = scd_lpc_mmap_resource;
   res_attr->private = &pdev->resource[0];
   rc = sysfs_create_bin_file(&pdev->dev.kobj, res_attr);
   if (rc) {
      dev_err(&pdev->dev, "sysfs resource0 creation failed %d\n", rc);
      goto cleanup;
   }
   pdev->res_attr[0] = res_attr;
   return rc;

cleanup:
   // let the general cleanup handle unrolling records already created
   if (res_attr) {
      kfree(res_attr);
   }

   if (priv->mem) {
      iounmap(priv->mem);
      priv->mem = NULL;
   }

   return rc;
}

static void
scd_lpc_disable(struct pci_dev *pdev)
{
   struct scd_dev_priv *priv = pci_get_drvdata(pdev);

   if (pdev->res_attr[0]) {
      sysfs_remove_bin_file(&pdev->dev.kobj, pdev->res_attr[0]);
      kfree(pdev->res_attr[0]);
      pdev->res_attr[0] = NULL;
   }

   if (priv->mem) {
      iounmap(priv->mem);
      priv->mem = NULL;
   }

   pdev->vendor = priv->lpc_vendor;
   pdev->device = priv->lpc_device;

   return;
}

static int __init scd_init(void)
{
   int err;
   mutex_init(&scd_mutex);
   spin_lock_init(&scd_ptp_lock);
   INIT_LIST_HEAD(&scd_list);

   printk(KERN_INFO "scd module installed\n");
   err = pci_register_driver(&scd_driver);
   if (unlikely(err)) {
      printk(KERN_ERR "pci_register_driver failed\n");
      goto out_fail;
   }

   if (unlikely(scd_procfs_create() == NULL)) {
      printk(KERN_ERR "scd_procfs_create failed\n");
      err = -EIO;
      goto out_procfs_fail;
   }

   err = class_register(&scd_class);
   if (unlikely(err)) {
      printk(KERN_ERR "class_register failed\n");
      goto out_class_fail;
   }

   // for devm_regulator_get() in lm90.c when acpi=off
   regulator_has_full_constraints();

   return err;

out_class_fail:
   scd_procfs_remove();
out_procfs_fail:
   pci_unregister_driver(&scd_driver);
out_fail:
   return err;
}

static void __exit scd_exit(void)
{
   pci_unregister_driver(&scd_driver);
   scd_procfs_remove();
   class_unregister(&scd_class);
   mutex_destroy(&scd_mutex);
   printk(KERN_INFO "scd module removed\n");
}

module_init(scd_init);
module_exit(scd_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hugh Holbrook and James Lingard");
MODULE_DESCRIPTION("scd driver");
