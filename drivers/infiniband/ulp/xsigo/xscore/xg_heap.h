/*
 * This software is available to you under the OpenIB.org BSD license,
 * available in the LICENSE.TXT file accompanying this software.
 * These details are also available at <http://openib.org/license.html>.
 *
 */

#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/scatterlist.h>
#include <linux/io.h>
#include <linux/in.h>
#include <linux/workqueue.h>
#include <linux/log2.h>
#include <linux/byteorder/swab.h>
#include <linux/mutex.h>
#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#define for_each_netdev(a, dev)	for ((dev) = dev_base;\
				(dev) != NULL;\
				(dev) = (dev)->next)

void *memmove(void *dest, const void *src, size_t count);

#ifndef bool
#define bool int
#define true 1
#define false 0
#endif
