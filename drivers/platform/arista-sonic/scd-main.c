/* Copyright (c) 2017 Arista Networks, Inc.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/version.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/pci.h>
#include <linux/gpio.h>
#include <linux/stat.h>

#include "scd.h"
#include "scd-attrs.h"
#include "scd-fan.h"
#include "scd-gpio.h"
#include "scd-hwmon.h"
#include "scd-led.h"
#include "scd-mdio.h"
#include "scd-reset.h"
#include "scd-smbus.h"
#include "scd-spi.h"
#include "scd-xcvr.h"
#include "scd-uart.h"

#define SCD_MODULE_NAME "scd-hwmon"

#define MAX_CONFIG_LINE_SIZE 100

/* locking functions */
static struct mutex scd_hwmon_mutex;

static void module_lock(void)
{
   mutex_lock(&scd_hwmon_mutex);
}

static void module_unlock(void)
{
   mutex_unlock(&scd_hwmon_mutex);
}

static void scd_lock(struct scd_context *ctx)
{
   mutex_lock(&ctx->mutex);
}

static void scd_unlock(struct scd_context *ctx)
{
   mutex_unlock(&ctx->mutex);
}

static struct list_head scd_list;

static struct scd_context *get_context_for_pdev(struct pci_dev *pdev)
{
   struct scd_context *ctx;

   module_lock();
   list_for_each_entry(ctx, &scd_list, list) {
      if (ctx->pdev == pdev) {
         module_unlock();
         return ctx;
      }
   }
   module_unlock();

   return NULL;
}

static struct scd_context *get_context_for_dev(struct device *dev)
{
   struct scd_context *ctx;

   module_lock();
   list_for_each_entry(ctx, &scd_list, list) {
      if (get_scd_dev(ctx) == dev) {
         module_unlock();
         return ctx;
      }
   }
   module_unlock();

   return NULL;
}

#define PARSE_INT_OR_RETURN(Buf, Tmp, Type, Ptr)        \
   do {                                                 \
      int ___ret = 0;                                   \
      Tmp = strsep(Buf, " ");                           \
      if (!Tmp || !*Tmp) {                              \
         return -EINVAL;                                \
      }                                                 \
      ___ret = kstrto##Type(Tmp, 0, Ptr);               \
      if (___ret) {                                     \
         return ___ret;                                 \
      }                                                 \
   } while(0)

#define PARSE_ADDR_OR_RETURN(Buf, Tmp, Type, Ptr, Size) \
   do {                                                 \
      PARSE_INT_OR_RETURN(Buf, Tmp, Type, Ptr);         \
      if (*(Ptr) > (Size)) {                            \
         return -EINVAL;                                \
      }                                                 \
   } while(0)

#define PARSE_STR_OR_RETURN(Buf, Tmp, Ptr)              \
   do {                                                 \
      Tmp = strsep(Buf, " ");                           \
      if (!Tmp || !*Tmp) {                              \
         return -EINVAL;                                \
      }                                                 \
      Ptr = Tmp;                                        \
   } while(0)

#define PARSE_END_OR_RETURN(Buf, Tmp)                   \
   do {                                                 \
      Tmp = strsep(Buf, " ");                           \
      if (Tmp) {                                        \
         return -EINVAL;                                \
      }                                                 \
   } while(0)


// new_smbus_master <addr> <accel_id> <bus_count:8>
static ssize_t parse_new_object_smbus_master(struct scd_context *ctx,
                                             char *buf, size_t count)
{
   u32 id;
   u32 addr;
   u32 bus_count = MASTER_DEFAULT_BUS_COUNT;

   const char *tmp;
   int res;

   if (!buf)
      return -EINVAL;

   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &addr, ctx->res_size);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &id);

   tmp = strsep(&buf, " ");
   if (tmp && *tmp) {
      res = kstrtou32(tmp, 0, &bus_count);
      if (res)
         return res;
      PARSE_END_OR_RETURN(&buf, tmp);
   }

   res = scd_smbus_master_add(ctx, addr, id, bus_count);
   if (res)
      return res;

   return count;
}

// new_mdio_device <master> <bus> <id> <portAddr> <devAddr> <clause>
static ssize_t parse_new_object_mdio_device(struct scd_context *ctx,
                                            char *buf, size_t count)
{
   u16 master;
   u16 bus;
   u16 id;
   u16 prtad;
   u16 devad;
   u16 clause;
   const char *tmp;
   int res;

   if (!buf)
      return -EINVAL;

   PARSE_INT_OR_RETURN(&buf, tmp, u16, &master);
   PARSE_INT_OR_RETURN(&buf, tmp, u16, &bus);
   PARSE_INT_OR_RETURN(&buf, tmp, u16, &id);
   PARSE_INT_OR_RETURN(&buf, tmp, u16, &prtad);
   PARSE_INT_OR_RETURN(&buf, tmp, u16, &devad);
   PARSE_INT_OR_RETURN(&buf, tmp, u16, &clause);
   PARSE_END_OR_RETURN(&buf, tmp);

   res = scd_mdio_device_add(ctx, master, bus, id, prtad, devad, clause);
   if (res)
      return res;

   return count;
}

// new_mdio_master <addr> <id> <bus_count> <speed>
static ssize_t parse_new_object_mdio_master(struct scd_context *ctx,
                                            char *buf, size_t count)
{
   u32 addr;
   u16 id;
   u16 bus_count;
   u16 bus_speed;
   const char *tmp;
   int res;

   if (!buf)
      return -EINVAL;

   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &addr, ctx->res_size);
   PARSE_INT_OR_RETURN(&buf, tmp, u16, &id);
   PARSE_INT_OR_RETURN(&buf, tmp, u16, &bus_count);
   PARSE_INT_OR_RETURN(&buf, tmp, u16, &bus_speed);
   PARSE_END_OR_RETURN(&buf, tmp);

   res = scd_mdio_master_add(ctx, addr, id, bus_count, bus_speed);
   if (res)
      return res;

   return count;
}

// new_led <addr> <name>
static ssize_t parse_new_object_led(struct scd_context *ctx,
                                    char *buf, size_t count)
{
   u32 addr;
   u32 kind;
   const char *name;

   const char *tmp;
   int res;

   if (!buf)
      return -EINVAL;

   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &addr, ctx->res_size);
   PARSE_STR_OR_RETURN(&buf, tmp, name);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &kind);
   PARSE_END_OR_RETURN(&buf, tmp);

   res = scd_led_add(ctx, name, addr, kind);
   if (res)
      return res;

   return count;
}

// new_led_ctrl <flashaddr> <paletteaddr>
static ssize_t parse_new_object_led_ctrl(struct scd_context *ctx,
                                               char *buf, size_t count)
{
   u32 flash_addr;
   u32 palette_addr;

   const char *tmp;
   int res;

   if (!buf)
      return -EINVAL;

   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &flash_addr, ctx->res_size);
   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &palette_addr, ctx->res_size);
   PARSE_END_OR_RETURN(&buf, tmp);

   res = scd_led_ctrl_add(ctx, flash_addr, palette_addr);
   if (res)
      return res;

   return count;
}

enum xcvr_type {
   XCVR_TYPE_SFP,
   XCVR_TYPE_QSFP,
   XCVR_TYPE_OSFP,
};

static ssize_t parse_new_object_xcvr(struct scd_context *ctx, enum xcvr_type type,
                                     char *buf, size_t count)
{
   u32 addr;
   u32 id;

   const char *tmp;
   int res;

   if (!buf)
      return -EINVAL;

   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &addr, ctx->res_size);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &id);
   PARSE_END_OR_RETURN(&buf, tmp);

   if (type == XCVR_TYPE_SFP)
      res = scd_xcvr_sfp_add(ctx, addr, id);
   else if (type == XCVR_TYPE_QSFP)
      res = scd_xcvr_qsfp_add(ctx, addr, id);
   else if (type == XCVR_TYPE_OSFP)
      res = scd_xcvr_osfp_add(ctx, addr, id);
   else
      res = -EINVAL;

   if (res)
      return res;

   return count;
}

// new_osfp <addr> <id>
static ssize_t parse_new_object_osfp(struct scd_context *ctx,
                                     char *buf, size_t count)
{
   return parse_new_object_xcvr(ctx, XCVR_TYPE_OSFP, buf, count);
}

// new_qsfp <addr> <id>
static ssize_t parse_new_object_qsfp(struct scd_context *ctx,
                                     char *buf, size_t count)
{
   return parse_new_object_xcvr(ctx, XCVR_TYPE_QSFP, buf, count);
}

// new_sfp <addr> <id>
static ssize_t parse_new_object_sfp(struct scd_context *ctx,
                                     char *buf, size_t count)
{
   return parse_new_object_xcvr(ctx, XCVR_TYPE_SFP, buf, count);
}

// new_reset <addr> <name> <bitpos>
static ssize_t parse_new_object_reset(struct scd_context *ctx,
                                      char *buf, size_t count)
{
   u32 addr;
   const char *name;
   u32 bitpos;

   const char *tmp;
   int res;

   if (!buf)
      return -EINVAL;

   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &addr, ctx->res_size);
   PARSE_STR_OR_RETURN(&buf, tmp, name);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &bitpos);
   PARSE_END_OR_RETURN(&buf, tmp);

   res = scd_reset_add(ctx, name, addr, bitpos);
   if (res)
      return res;

   return count;
}

// new_fan_group <addr> <platform> <fan_count>
static ssize_t parse_new_object_fan_group(struct scd_context *ctx,
                                          char *buf, size_t count)
{
   const char *tmp;
   u32 addr;
   u32 platform_id;
   u32 slot_count;
   u32 fan_count;
   int res;

   if (!buf)
      return -EINVAL;

   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &addr, ctx->res_size);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &platform_id);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &slot_count);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &fan_count);
   PARSE_END_OR_RETURN(&buf, tmp);

   res = scd_fan_group_add(ctx, addr, platform_id, slot_count, fan_count);
   if (res)
      return res;

   return count;
}

// new_gpio <addr> <name> <bitpos> <ro> <activeLow>
static ssize_t parse_new_object_gpio(struct scd_context *ctx,
                                     char *buf, size_t count)
{
   u32 addr;
   const char *name;
   u32 bitpos;
   u32 read_only;
   u32 active_low;

   const char *tmp;
   int res;

   if (!buf)
      return -EINVAL;

   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &addr, ctx->res_size);
   PARSE_STR_OR_RETURN(&buf, tmp, name);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &bitpos);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &read_only);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &active_low);
   PARSE_END_OR_RETURN(&buf, tmp);

   res = scd_gpio_add(ctx, name, addr, bitpos, read_only, active_low);
   if (res)
      return res;

   return count;
}

// new_uart <addr> <name>
static ssize_t parse_new_object_uart(struct scd_context *ctx,
                                     char *buf, size_t count)
{
   u32 addr;
   u32 id;
   int res;

   const char *tmp;

   if (!buf)
      return -EINVAL;

   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &addr, ctx->res_size);
   PARSE_INT_OR_RETURN(&buf, tmp, u32, &id);
   PARSE_END_OR_RETURN(&buf, tmp);

   res = scd_uart_add(ctx, addr, id);
   if (res)
      return res;

   return count;
}

static ssize_t parse_new_object_spi_controller(struct scd_context *ctx,
                                               char *buf, size_t count)
{
   u32 addr;
   u32 stride;
   s16 bus;
   u16 num_chipselect;
   int res;

   const char *tmp;

   if (!buf)
      return -EINVAL;

   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &addr, ctx->res_size);
   PARSE_ADDR_OR_RETURN(&buf, tmp, u32, &stride, ctx->res_size);
   PARSE_INT_OR_RETURN(&buf, tmp, s16, &bus);
   PARSE_INT_OR_RETURN(&buf, tmp, u16, &num_chipselect);
   PARSE_END_OR_RETURN(&buf, tmp);

   res = scd_spi_controller_add(ctx, addr, stride, bus, num_chipselect);
   if (res)
      return res;

   return count;
}

static ssize_t parse_new_object_spi_device(struct scd_context *ctx, 
                                           char *buf, size_t count)
{
   s16 bus;
   u16 chip_select;
   const char *modalias;
   int res;

   const char *tmp;

   if (!buf)
      return -EINVAL;

   PARSE_INT_OR_RETURN(&buf, tmp, s16, &bus);
   PARSE_INT_OR_RETURN(&buf, tmp, u16, &chip_select);
   PARSE_STR_OR_RETURN(&buf, tmp, modalias);
   PARSE_END_OR_RETURN(&buf, tmp);

   res = scd_spi_device_add(ctx, bus, chip_select, modalias);
   if (res)
      return res;

   return count;
}

typedef ssize_t (*new_object_parse_func)(struct scd_context*, char*, size_t);
static struct {
   const char *name;
   new_object_parse_func func;
} funcs[] = {
   { "fan_group",       parse_new_object_fan_group},
   { "gpio",            parse_new_object_gpio },
   { "led",             parse_new_object_led },
   { "led_ctrl",        parse_new_object_led_ctrl },
   { "mdio_device",     parse_new_object_mdio_device },
   { "mdio_master",     parse_new_object_mdio_master },
   { "osfp",            parse_new_object_osfp },
   { "qsfp",            parse_new_object_qsfp },
   { "reset",           parse_new_object_reset },
   { "sfp",             parse_new_object_sfp },
   { "smbus_master",    parse_new_object_smbus_master },
   { "spi_controller",  parse_new_object_spi_controller },
   { "spi_device",      parse_new_object_spi_device },
   { "uart",            parse_new_object_uart },
   { NULL, NULL }
};

static ssize_t parse_new_object(struct scd_context *ctx, const char *buf,
                                size_t count)
{
   char tmp[MAX_CONFIG_LINE_SIZE];
   char *ptr = tmp;
   char *tok;
   int i = 0;
   ssize_t err;

   if (count >= MAX_CONFIG_LINE_SIZE) {
      dev_err(get_scd_dev(ctx), "new_object line is too long\n");
      return -EINVAL;
   }

   strncpy(tmp, buf, count);
   tmp[count] = 0;
   tok = strsep(&ptr, " ");
   if (!tok)
      return -EINVAL;

   while (funcs[i].name) {
      if (!strcmp(tok, funcs[i].name))
         break;
      i++;
   }

   if (!funcs[i].name)
      return -EINVAL;

   err = funcs[i].func(ctx, ptr, count - (ptr - tmp));
   if (err < 0)
      return err;

   return count;
}

typedef ssize_t (*line_parser_func)(struct scd_context *ctx, const char *buf,
   size_t count);

static ssize_t parse_lines(struct scd_context *ctx, const char *buf,
                           size_t count, line_parser_func parser)
{
   ssize_t res;
   size_t left = count;
   const char *nl;

   if (count == 0)
      return 0;

   while (true) {
      nl = strnchr(buf, left, '\n');
      if (!nl)
         nl = buf + left; // points on the \0

      res = parser(ctx, buf, nl - buf);
      if (res < 0)
         return res;
      left -= res;

      buf = nl;
      while (left && *buf == '\n') {
         buf++;
         left--;
      }
      if (!left)
         break;
   }

   return count;
}

static ssize_t new_object(struct device *dev, struct device_attribute *attr,
                          const char *buf, size_t count)
{
   ssize_t res;
   struct scd_context *ctx = get_context_for_dev(dev);

   if (!ctx) {
      return -ENODEV;
   }

   scd_lock(ctx);
   if (ctx->initialized) {
      scd_unlock(ctx);
      return -EBUSY;
   }
   res = parse_lines(ctx, buf, count, parse_new_object);
   scd_unlock(ctx);
   return res;
}

static DEVICE_ATTR(new_object, S_IWUSR|S_IWGRP, 0, new_object);

static ssize_t parse_smbus_tweak(struct scd_context *ctx, const char *buf,
                                 size_t count)
{
   char buf_copy[MAX_CONFIG_LINE_SIZE];
   struct bus_params params;
   ssize_t err;
   char *ptr = buf_copy;
   const char *tmp;
   u16 bus;

   if (count >= MAX_CONFIG_LINE_SIZE) {
      dev_err(get_scd_dev(ctx), "smbus_tweak line is too long: %zu\n", count);
      return -EINVAL;
   }

   strncpy(buf_copy, buf, count);
   buf_copy[count] = 0;

   PARSE_INT_OR_RETURN(&ptr, tmp, u16, &bus);
   PARSE_INT_OR_RETURN(&ptr, tmp, u16, &params.addr);
   PARSE_INT_OR_RETURN(&ptr, tmp, u8, &params.t);
   PARSE_INT_OR_RETURN(&ptr, tmp, u8, &params.datr);
   PARSE_INT_OR_RETURN(&ptr, tmp, u8, &params.datw);
   PARSE_INT_OR_RETURN(&ptr, tmp, u8, &params.ed);

   err = scd_set_smbus_params(ctx, bus, &params);
   if (err == 0)
      return count;
   return err;
}

static ssize_t smbus_tweaks(struct device *dev, struct device_attribute *attr,
                            const char *buf, size_t count)
{
   ssize_t res;
   struct scd_context *ctx = get_context_for_dev(dev);

   if (!ctx) {
      return -ENODEV;
   }

   scd_lock(ctx);
   res = parse_lines(ctx, buf, count, parse_smbus_tweak);
   scd_unlock(ctx);
   return res;
}

static ssize_t scd_dump_smbus_tweaks(struct scd_context *ctx, char *buf, size_t max)
{
   const struct scd_smbus_master *master;
   const struct scd_smbus *bus;
   const struct bus_params *params;
   ssize_t count = 0;

   list_for_each_entry(master, &ctx->smbus_master_list, list) {
      list_for_each_entry(bus, &master->bus_list, list) {
         list_for_each_entry(params, &bus->params, list) {
            count += scnprintf(buf + count, max - count,
                  "%d/%d/%02x: adap=%d t=%d datr=%d datw=%d ed=%d\n",
                  master->id, bus->id, params->addr, bus->adap.nr,
                  params->t, params->datr, params->datw, params->ed);
            if (count == max) {
               return count;
            }
         }
      }
   }

   return count;
}

static ssize_t show_smbus_tweaks(struct device *dev, struct device_attribute *attr,
                                 char *buf)
{
   struct scd_context *ctx = get_context_for_dev(dev);
   ssize_t count;

   if (!ctx) {
      return -ENODEV;
   }

   scd_lock(ctx);
   count = scd_dump_smbus_tweaks(ctx, buf, PAGE_SIZE);
   scd_unlock(ctx);

   return count;
}

static DEVICE_ATTR(smbus_tweaks, S_IRUSR|S_IRGRP|S_IWUSR|S_IWGRP,
                   show_smbus_tweaks, smbus_tweaks);

static int scd_create_sysfs_files(struct scd_context *ctx) {
   int err;

   err = sysfs_create_file(get_scd_kobj(ctx), &dev_attr_new_object.attr);
   if (err) {
      dev_err(get_scd_dev(ctx), "could not create %s attribute: %d",
              dev_attr_new_object.attr.name, err);
      goto fail_new_object;
   }

   err = sysfs_create_file(get_scd_kobj(ctx), &dev_attr_smbus_tweaks.attr);
   if (err) {
      dev_err(get_scd_dev(ctx), "could not create %s attribute for smbus tweak: %d",
              dev_attr_smbus_tweaks.attr.name, err);
      goto fail_smbus_tweaks;
   }

   return 0;

fail_smbus_tweaks:
   sysfs_remove_file(get_scd_kobj(ctx), &dev_attr_new_object.attr);
fail_new_object:
   return err;
}

static int scd_ext_hwmon_probe(struct pci_dev *pdev, size_t mem_len)
{
   struct scd_context *ctx = get_context_for_pdev(pdev);
   int err;

   if (ctx) {
      dev_warn(get_scd_dev(ctx), "this pci device has already been probed\n");
      return -EEXIST;
   }

   ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
   if (!ctx) {
      return -ENOMEM;
   }

   ctx->pdev = pdev;
   get_device(&pdev->dev);
   INIT_LIST_HEAD(&ctx->list);

   ctx->initialized = false;
   mutex_init(&ctx->mutex);

   ctx->res_size = mem_len;

   INIT_LIST_HEAD(&ctx->led_list);
   INIT_LIST_HEAD(&ctx->smbus_master_list);
   INIT_LIST_HEAD(&ctx->mdio_master_list);
   INIT_LIST_HEAD(&ctx->spi_controller_list);
   INIT_LIST_HEAD(&ctx->gpio_list);
   INIT_LIST_HEAD(&ctx->reset_list);
   INIT_LIST_HEAD(&ctx->xcvr_list);
   INIT_LIST_HEAD(&ctx->fan_group_list);

   kobject_get(&pdev->dev.kobj);

   module_lock();
   list_add_tail(&ctx->list, &scd_list);
   module_unlock();

   err = scd_create_sysfs_files(ctx);
   if (err) {
      goto fail_sysfs;
   }

   return 0;

fail_sysfs:
   module_lock();
   list_del(&ctx->list);
   module_unlock();

   kobject_put(&pdev->dev.kobj);
   kfree(ctx);
   put_device(&pdev->dev);

   return err;
}

static void scd_ext_hwmon_remove(struct pci_dev *pdev)
{
   struct scd_context *ctx = get_context_for_pdev(pdev);

   if (!ctx) {
      return;
   }

   dev_info(get_scd_dev(ctx), "removing scd components\n");

   scd_lock(ctx);
   scd_smbus_remove_all(ctx);
   scd_mdio_remove_all(ctx);
   scd_led_remove_all(ctx);
   scd_gpio_remove_all(ctx);
   scd_reset_remove_all(ctx);
   scd_xcvr_remove_all(ctx);
   scd_fan_group_remove_all(ctx);
   scd_uart_remove_all(ctx);
   scd_spi_controller_remove_all(ctx);
   scd_unlock(ctx);

   module_lock();
   list_del(&ctx->list);
   module_unlock();

   sysfs_remove_file(&pdev->dev.kobj, &dev_attr_new_object.attr);
   sysfs_remove_file(&pdev->dev.kobj, &dev_attr_smbus_tweaks.attr);

   kfree(ctx);

   kobject_put(&pdev->dev.kobj);
   put_device(&pdev->dev);
}

static int scd_ext_hwmon_init_trigger(struct pci_dev *pdev)
{
   struct scd_context *ctx = get_context_for_pdev(pdev);

   if (!ctx) {
      return -ENODEV;
   }

   scd_lock(ctx);
   ctx->initialized = true;
   scd_unlock(ctx);
   return 0;
}

static struct scd_ext_ops scd_hwmon_ops = {
   .probe  = scd_ext_hwmon_probe,
   .remove = scd_ext_hwmon_remove,
   .init_trigger = scd_ext_hwmon_init_trigger,
};

static struct scd_extension scd_hwmon_ext = {
   .name = SCD_MODULE_NAME,
   .ops = &scd_hwmon_ops,
};

static int __init scd_hwmon_init(void)
{
   int err = 0;

   pr_info("scd-hwmon: loading scd hwmon driver\n");
   mutex_init(&scd_hwmon_mutex);
   INIT_LIST_HEAD(&scd_list);

   err = scd_register_extension(&scd_hwmon_ext);
   if (err) {
      pr_warn("scd-hwmon: scd_register_extension failed\n");
      return err;
   }

   return err;
}

static void __exit scd_hwmon_exit(void)
{
   pr_info("scd-hwmon: unloading scd hwmon driver\n");
   scd_unregister_extension(&scd_hwmon_ext);
}

module_init(scd_hwmon_init);
module_exit(scd_hwmon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arista Networks");
MODULE_DESCRIPTION("SCD component driver");
